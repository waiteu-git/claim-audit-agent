"""SafeFetch: 外向き HTTP の唯一の出口（設計 §2・§5-3）。FetchPort を実装する。

1回の fetch の流れ（リダイレクトの各ホップでも同じ検査をやり直す）:
  validate_url（https・443・userinfo 無し・ホスト形式・長さ・パスの正規化）
  → 取得スコープ（URL 接頭辞）… ここまで DNS は引かない（スコープ外は名前も漏らさない）
  → GuardedResolver（全応答を検査。1つでも非グローバルなら全体拒否）
  → PinnedBackend（検査済み IP にだけ接続。SNI・証明書検証・Host は元のホスト名）
  → GET のみ・手動リダイレクト（最大3ホップ）・時間とサイズの上限・Content-Type の許可リスト・gzip 爆弾対策
  → 本文に数えられない受信の上限（応答の先頭・本文それぞれの受信バイト予算、塊の数）。1xx の洪水・chunk-extension・1バイトずつの塊
  → 同名ヘッダの重複行は RFC どおり読み、食い違う Content-Type / Location は決めずに拒否する（読み手による見せ分けの封じ）

想定内の失敗は例外にせず FetchResult の outcome で返す（拒否は blocked＋policy_id）。例外は CancelledError だけが通る。
このモジュール（と app/net 配下）だけが httpcore を import してよい（tests/test_safefetch_layout.py が固定）。

G3 に回したもの: fetcher（S3）へのクライアント実装。この SafeFetch は S1 のプロセス内用で、S3 側のサーバーも同じものを使う。
"""
import asyncio
import re
import ssl
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from time import monotonic
from urllib.parse import urljoin

import httpcore
from pydantic import ValidationError

from app.config import FETCH_LIMITS, FetchLimits
from app.contracts import (
    ALLOWED_RESPONSE_HEADERS,
    FETCH_BODY_MAX_BYTES,
    PROBE_BODY_MAX_BYTES,
    ContentKind,
    FetchLimit,
    FetchMode,
    FetchOutcome,
    FetchRequest,
    FetchResult,
    PolicyId,
    RedirectHop,
    UrlPrefix,
)
from app.jsonlog import log_event, log_exception
from app.net.backend import PinnedBackend, PinViolation, WireBudgetExceeded, WireMeter
from app.net.decode import BodyDecoder, DecodeError, UnsupportedEncoding, parse_content_encoding
from app.net.resolver import GuardedResolver, HostResolver, IpBlocked, ResolveFailed, system_resolver
from app.net.urlcheck import NormalizedUrl, UrlReject, UrlRejected, in_scope, validate_url
from app.textsafe import escape_for_display, is_unsafe_char, strip_unsafe

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_ACCEPT = "text/html,application/xhtml+xml,text/plain,text/markdown,application/json;q=0.9"
_URL_FIELD_MAX = 2048  # FetchResult / RedirectHop の URL 欄の上限（contracts と同じ）
_MAX_HEADER_VALUE = 300  # FetchResult.headers の値の上限（contracts と同じ）
_REDIRECT_BAD_LOCATION = "redirect.bad_location"
_SCHEME_PREFIX = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*:")
_AUTHORITY_FORM = re.compile(r"//[^/?#]")  # スラッシュ2本の直後に権限部（ホスト）が始まる形

# 受信量・塊の数の上限（本文のバイト数の上限とは別の物差し。敵対レビューで追加）。
# 本文の上限は「展開後 1MiB」「生の受信 3MB」だが、1xx の洪水・chunk-extension の肥大・1バイトずつの chunked は
# 本文に数えられないまま受信とCPUだけを使う（実測 CPU 5〜8 秒）。TLS の内側で受け取った全バイトと、本文の塊の数を別に数える。
_HEAD_WIRE_BUDGET = 256 * 1024  # 応答の先頭（1xx・ステータス行・ヘッダ）を受け終えるまで。h11 のヘッダ上限 100KB と最初の本文の読み 64KB に余裕
_BODY_WIRE_FACTOR = 2  # 本文の段階の受信量 ≦ max_content_length × この倍率（塊の長さ行・chunk-extension の分を見込む）
_MAX_BODY_EVENTS = 32_768  # 本文の塊（h11 の Data イベント）の数。1MiB を 32 バイト未満の塊で刻む応答は受けない（1イベント約 5µs＝上限でも約 0.2 秒）


def classify_content_type(value: str | None) -> ContentKind:
    """Content-Type → 許可リストの種別（html / xhtml / plain / markdown / json）。それ以外・無しは UNSUPPORTED（§4）。"""
    if not value:
        return ContentKind.UNSUPPORTED
    media = value.split(";", 1)[0].strip().lower()
    if media == "text/html":
        return ContentKind.HTML
    if media == "application/xhtml+xml":
        return ContentKind.XHTML
    if media == "text/plain":
        return ContentKind.PLAIN
    if media in ("text/markdown", "text/x-markdown"):
        return ContentKind.MARKDOWN
    if media in ("application/json", "text/json") or (media.startswith("application/") and media.endswith("+json")):
        return ContentKind.JSON
    return ContentKind.UNSUPPORTED


@dataclass(frozen=True)
class FetchDetail:
    """fetch の結果に、内部の拒否・失敗の理由コードを添えたもの。

    notes は非公開ログとテスト用（例 "block:url.scheme" / "hop1:ip.metadata" / "net:ConnectError"）。
    公開面（trace・SSE）へ出してよいのは FetchResult の blocked_policy だけ。
    """

    result: FetchResult
    notes: tuple[str, ...] = ()


class _Denied(Exception):
    """URL 検証・スコープ・IP 検査のどれかで拒否した（P-SCOPE-01 / P-SSRF-IP-01）。"""

    def __init__(self, policy: PolicyId, note: str, *, scope_ok: bool) -> None:
        super().__init__(note)
        self.policy = policy
        self.note = note
        self.scope_ok = scope_ok  # スコープ内だった（IP 検査で拒否した）か


class _DnsFailed(Exception):
    def __init__(self, note: str) -> None:
        super().__init__(note)
        self.note = note


@dataclass
class _Reply:
    """1回の HTTP 応答（または、その途中の結末）。"""

    status: int
    headers: dict[str, str]
    location_raw: bytes | None = None
    outcome: FetchOutcome = FetchOutcome.OK
    limit_hit: FetchLimit | None = None
    body: bytes = b""
    truncated: bool = False
    content_kind: ContentKind | None = None
    note: str | None = None


@dataclass
class _Run:
    requested_url: str
    started: float
    hops: list[RedirectHop] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    final_url: str | None = None


def _clean_header_value(raw: bytes) -> str:
    text = " ".join(raw.decode("latin-1").split())  # 改行・タブ・U+001E などの空白類を1個の空白へ
    return strip_unsafe(text)


def _allowed_headers(raw: Iterable[tuple[bytes, bytes]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in raw:
        name = k.decode("latin-1").strip().lower()
        if name not in ALLOWED_RESPONSE_HEADERS:
            continue
        val = _clean_header_value(v)
        out[name] = f"{out[name]}, {val}" if name in out else val
        out[name] = out[name][:_MAX_HEADER_VALUE]
    return out


def _first_header(raw: Iterable[tuple[bytes, bytes]], name: bytes) -> bytes | None:
    for k, v in raw:
        if k.strip().lower() == name:
            return v
    return None


def _header_lines(raw: Iterable[tuple[bytes, bytes]], name: bytes) -> list[bytes]:
    """同じ名前のヘッダの全行（出現順）。"""
    return [v.strip() for k, v in raw if k.strip().lower() == name]


def _single_header(raw: Iterable[tuple[bytes, bytes]], name: bytes) -> tuple[bytes | None, bool]:
    """単一の値を取るヘッダ。(値, 食い違いか)。同じ値の重複は食い違いではない。

    複数行で値が違うと、「先頭の1行」を読む実装と他の実装（ブラウザ）で応答の読みが割れる。割れたまま採ると、提出物が
    監査側にだけ別の種別・別の転送先を見せられる（クローキング）ので、決めずに拒否側へ倒す。
    """
    lines = _header_lines(raw, name)
    if not lines:
        return None, False
    return lines[0], any(v.lower() != lines[0].lower() for v in lines[1:])


def _content_length(raw_value: bytes | None) -> int | None:
    if raw_value is None:
        return None
    text = raw_value.strip()
    return int(text) if text.isdigit() and len(text) <= 15 else None


def _clip_location(raw: bytes) -> str:
    return strip_unsafe(raw.decode("utf-8", errors="replace"))[:_URL_FIELD_MAX]


class SafeFetch:
    """FetchPort 実装（プロセス内）。インスタンスは並行して使ってよい（1回の取得ごとに接続を作り、閉じる）。

    resolver・network_backend・ssl_context は注入できる（テストは完全オフラインでフェイクを渡す）。
    既定は実際の DNS・httpcore.AnyIOBackend・システムの CA（certifi）。
    """

    def __init__(
        self,
        allowed_prefixes: Sequence[UrlPrefix],
        *,
        limits: FetchLimits = FETCH_LIMITS,
        resolver: HostResolver | None = None,
        network_backend: httpcore.AsyncNetworkBackend | None = None,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self._prefixes = tuple(allowed_prefixes)  # 空なら何も取れない（fail-closed）
        self._limits = limits
        self._guard = GuardedResolver(resolver or system_resolver, timeout_s=limits.connect_timeout_s)
        self._inner = network_backend or httpcore.AnyIOBackend()
        self._ssl = ssl_context or httpcore.default_ssl_context()
        self._body_wire_budget = max(limits.max_content_length * _BODY_WIRE_FACTOR, _HEAD_WIRE_BUDGET)
        if self._ssl.verify_mode != ssl.CERT_REQUIRED or not self._ssl.check_hostname:
            # 検証を外した文脈を黙って受け取ると、ピン留め（IP へ接続）の安全が証明書の名前検証に依っていることが崩れる
            raise ValueError("ssl_context must verify certificates and host names (CERT_REQUIRED and check_hostname)")

    # ------------------------------------------------------------------ 公開 API
    async def fetch(self, request: FetchRequest) -> FetchResult:
        return (await self.fetch_ex(request)).result

    async def fetch_ex(self, request: FetchRequest) -> FetchDetail:
        run = _Run(requested_url=escape_for_display(request.url, _URL_FIELD_MAX), started=monotonic())
        deadline = asyncio.timeout(self._limits.total_timeout_s)  # 転送を含む1回の取得の全体
        try:
            async with deadline:
                result = await self._run(request, run)
        except TimeoutError:
            if deadline.expired():
                result = self._failure(run, FetchOutcome.TIMEOUT, limit_hit=FetchLimit.TOTAL_TIMEOUT, note="net.total_timeout")
            else:  # 全体の期限ではない TimeoutError（内側の想定外）。例外は外へ出さない
                result = self._failure(run, FetchOutcome.NETWORK_ERROR, note="net.unexpected_timeout")
        except Exception as e:  # noqa: BLE001 想定外でも例外を外へ出さない（CancelledError は BaseException なので通る）
            log_exception("safefetch.unexpected", e)
            result = self._failure(run, FetchOutcome.NETWORK_ERROR, note="net.unexpected")
        return FetchDetail(result=result, notes=tuple(run.notes))

    # ------------------------------------------------------------------ 本体
    async def _run(self, request: FetchRequest, run: _Run) -> FetchResult:
        limits = self._limits
        pins: dict[str, tuple[str, ...]] = {}
        meter = WireMeter()  # 転送を含む1回の取得で、TLS の内側として受け取った全バイトを数える
        pool = httpcore.AsyncConnectionPool(
            ssl_context=self._ssl,
            max_connections=2,
            max_keepalive_connections=0,  # 使い回さない（force_close 相当）。ホップごとに検査済み IP へ接続し直す
            http1=True,
            http2=False,
            retries=0,
            network_backend=PinnedBackend(pins, self._inner, meter=meter),
        )
        try:
            try:
                cur = await self._admit(request.url, pins)
            except _Denied as d:
                run.notes.append(f"block:{d.note}")
                log_event("safefetch.blocked", severity="WARNING", policy=d.policy.value, reason=d.note, hop=0)
                return self._result(run, blocked_policy=d.policy)
            except _DnsFailed as f:
                run.notes.append(f"dns:{f.note}")
                return self._failure(run, FetchOutcome.NETWORK_ERROR, note=None)

            followed = 0
            while True:
                meter.arm(_HEAD_WIRE_BUDGET, "head")  # ホップごとに引き直す
                reply = await self._exchange(pool, cur, request.mode, meter)
                run.final_url = cur.url
                if reply.note:
                    run.notes.append(reply.note)
                if reply.outcome is not FetchOutcome.OK or reply.status not in REDIRECT_STATUSES:
                    return self._result(run, reply)

                location = reply.location_raw
                if not location:  # Location の無い（または空の）3xx は、そのまま最終応答
                    run.hops.append(RedirectHop(url=cur.url[:_URL_FIELD_MAX], status=reply.status))
                    return self._result(run, reply)
                hop = RedirectHop(
                    url=cur.url[:_URL_FIELD_MAX], status=reply.status, location=_clip_location(location)
                )
                if followed >= limits.max_redirects:  # 3ホップ追跡済みで、さらに転送
                    run.hops.append(hop)
                    return self._result(
                        run, reply, outcome=FetchOutcome.TOO_MANY_REDIRECTS, limit_hit=FetchLimit.REDIRECTS
                    )
                try:
                    nxt = await self._admit(self._join_location(cur, location), pins)
                except _Denied as d:  # 追跡しない。Location だけ残す（認証壁の証拠になる）
                    run.hops.append(
                        hop.model_copy(update={"in_scope": d.scope_ok, "blocked_policy": d.policy})
                    )
                    run.notes.append(f"hop{followed + 1}:{d.note}")
                    log_event(
                        "safefetch.blocked", severity="WARNING", policy=d.policy.value, reason=d.note, hop=followed + 1
                    )
                    return self._result(run, reply)
                except _DnsFailed as f:
                    run.hops.append(hop.model_copy(update={"in_scope": True}))
                    run.notes.append(f"hop{followed + 1}:dns:{f.note}")
                    return self._failure(run, FetchOutcome.NETWORK_ERROR, note=None)
                run.hops.append(hop.model_copy(update={"followed": True, "in_scope": True}))
                followed += 1
                cur = nxt
        except httpcore.ConnectTimeout:
            return self._failure(run, FetchOutcome.TIMEOUT, limit_hit=FetchLimit.CONNECT_TIMEOUT, note="net.connect_timeout")
        except httpcore.ReadTimeout:
            return self._failure(run, FetchOutcome.TIMEOUT, limit_hit=FetchLimit.READ_TIMEOUT, note="net.read_timeout")
        except (httpcore.WriteTimeout, httpcore.PoolTimeout):
            return self._failure(run, FetchOutcome.TIMEOUT, limit_hit=FetchLimit.TOTAL_TIMEOUT, note="net.write_timeout")
        except PinViolation as e:  # 検査していないホストへの接続要求。起きてはいけない
            log_exception("safefetch.pin_violation", e)
            return self._failure(run, FetchOutcome.NETWORK_ERROR, note="net.pin_violation")
        except WireBudgetExceeded as e:  # 応答の先頭が終わらない（1xx の洪水・巨大なヘッダの連打）。本文の段階は _exchange が結果にする
            if e.phase == "head":
                return self._failure(run, FetchOutcome.NETWORK_ERROR, note="net.head_flood")
            return self._failure(run, FetchOutcome.TOO_LARGE, limit_hit=FetchLimit.CONTENT_LENGTH, note="size.wire")
        except (httpcore.NetworkError, httpcore.ProtocolError, httpcore.UnsupportedProtocol) as e:
            return self._failure(run, FetchOutcome.NETWORK_ERROR, note=f"net.{type(e).__name__}")
        finally:
            try:
                await asyncio.wait_for(pool.aclose(), timeout=1.0)
            except Exception:  # noqa: BLE001, S110 後始末の失敗で結果を失わない
                pass

    async def _admit(self, url: str, pins: dict[str, tuple[str, ...]]) -> NormalizedUrl:
        """URL 検証 → スコープ → 名前解決＋IP 検査。通ったら pins に検査済み IP を入れる。"""
        try:
            normalized = validate_url(url, max_length=self._limits.max_url_length)
        except UrlRejected as e:
            raise _Denied(PolicyId.SCOPE, e.code.value, scope_ok=False) from e
        if not in_scope(normalized, self._prefixes):
            raise _Denied(PolicyId.SCOPE, UrlReject.SCOPE_OUT.value, scope_ok=False)
        try:
            pins[normalized.host] = await self._guard.resolve(normalized.host)
        except IpBlocked as e:
            raise _Denied(PolicyId.SSRF_IP, e.verdict.code, scope_ok=True) from e
        except ResolveFailed as e:
            raise _DnsFailed(e.code) from e
        return normalized

    @staticmethod
    def _join_location(current: NormalizedUrl, location: bytes) -> str:
        """Location（相対も可）を絶対 URL にする。解釈の割れる文字を含むものは、解決前に拒否する。"""
        try:
            text = location.decode("utf-8")  # 厳格。UTF-8 でない Location は追跡しない
            if any(ord(c) <= 0x20 or ord(c) == 0x7F or c == "\\" or c.isspace() or is_unsafe_char(c) for c in text):
                raise ValueError(_REDIRECT_BAD_LOCATION)
            # スラッシュ3本以上（`///host`・`https:///host`）は、ブラウザ（WHATWG）が余分なスラッシュを読み飛ばして別のホストへ行くのに、
            # urljoin は同じホストのパスと読む。スラッシュ2本で始まるなら、その直後にホストが続く形だけを通す（`//` や `https://` だけも拒否）
            rest = text[m.end():] if (m := _SCHEME_PREFIX.match(text)) else text
            if rest.startswith("//") and not _AUTHORITY_FORM.match(rest):
                raise ValueError(_REDIRECT_BAD_LOCATION)
            return urljoin(current.url, text)
        except (UnicodeDecodeError, ValueError) as e:
            raise _Denied(PolicyId.SCOPE, _REDIRECT_BAD_LOCATION, scope_ok=False) from e

    async def _exchange(
        self, pool: httpcore.AsyncConnectionPool, cur: NormalizedUrl, mode: FetchMode, meter: WireMeter
    ) -> _Reply:
        limits = self._limits
        headers = [
            (b"Host", cur.host.encode("ascii")),
            (b"User-Agent", limits.user_agent.encode("ascii", "replace")),
            (b"Accept", _ACCEPT.encode("ascii")),
            (b"Accept-Encoding", limits.accept_encoding.encode("ascii")),
            (b"Connection", b"close"),
        ]  # Cookie・Authorization・Referer は付けない
        timeouts = {
            "connect": limits.connect_timeout_s,
            "read": limits.sock_read_timeout_s,
            "write": limits.sock_read_timeout_s,
            "pool": limits.connect_timeout_s,
        }
        async with pool.stream("GET", cur.url, headers=headers, extensions={"timeout": timeouts}) as resp:
            meter.arm(self._body_wire_budget, "body")  # 応答の先頭を受け終えた。ここからは本文の段階の予算
            raw_headers = list(resp.headers)
            status = resp.status
            reply = _Reply(status=status, headers=_allowed_headers(raw_headers))
            if 300 <= status < 400:  # 転送の本文は読まない
                location, conflict = _single_header(raw_headers, b"location")
                if conflict:  # Location が食い違う（ブラウザは追跡しない）。先頭を追わず、決めない
                    reply.outcome, reply.note = FetchOutcome.NETWORK_ERROR, "header.conflict:location"
                    return reply
                reply.location_raw = location
                return reply

            content_length = _content_length(_first_header(raw_headers, b"content-length"))
            if status in (204, 205) or content_length == 0:
                return reply  # 本文なし。型の確認は要らない
            ctype, type_conflict = _single_header(raw_headers, b"content-type")
            if type_conflict:  # Content-Type が食い違う。先頭だけで種別を決めない
                reply.outcome, reply.content_kind, reply.note = FetchOutcome.UNSUPPORTED_TYPE, ContentKind.UNSUPPORTED, "type.conflict"
                return reply
            kind = classify_content_type(ctype.decode("latin-1") if ctype is not None else None)
            if kind is ContentKind.UNSUPPORTED:
                reply.outcome, reply.content_kind, reply.note = FetchOutcome.UNSUPPORTED_TYPE, kind, "type.unsupported"
                return reply
            try:
                # 複数行はカンマで連ねたものと同じ（RFC 9110 5.3）。先頭の1行だけを読むと、identity の後ろの gzip を見落とす
                encoding = parse_content_encoding(b", ".join(_header_lines(raw_headers, b"content-encoding")).decode("latin-1"))
            except UnsupportedEncoding as e:
                reply.outcome, reply.content_kind, reply.note = FetchOutcome.UNSUPPORTED_TYPE, kind, str(e)
                return reply
            if mode is FetchMode.PAGE and content_length is not None and content_length > limits.max_content_length:
                reply.outcome, reply.limit_hit, reply.note = FetchOutcome.TOO_LARGE, FetchLimit.CONTENT_LENGTH, "size.content_length"
                return reply  # 読む前に拒否

            if mode is FetchMode.PROBE:  # http_probe は先頭だけ。上限を超える Content-Length でも先頭を読む
                cap, cap_limit = min(limits.probe_prefix_bytes, PROBE_BODY_MAX_BYTES), FetchLimit.PROBE_PREFIX
            else:
                cap, cap_limit = min(limits.max_decoded_bytes, FETCH_BODY_MAX_BYTES), FetchLimit.DECODED_SIZE
            decoder = BodyDecoder(encoding, cap)
            raw_total = 0
            events = 0
            try:
                async for chunk in resp.aiter_stream():
                    events += 1
                    if events > _MAX_BODY_EVENTS:  # 1バイトずつ刻んで CPU を使わせる応答。本文の上限に届く前に止める
                        reply.outcome, reply.note = FetchOutcome.NETWORK_ERROR, "net.fragmented_stream"
                        return reply
                    raw_total += len(chunk)
                    if raw_total > limits.max_content_length:  # 展開後が小さくても、生の受信が際限なく続くものを止める
                        reply.outcome, reply.limit_hit, reply.note = FetchOutcome.TOO_LARGE, FetchLimit.CONTENT_LENGTH, "size.raw_stream"
                        return reply
                    decoder.feed(chunk)
                    if decoder.over:
                        break
                decoder.finish()
            except DecodeError as e:
                reply.outcome, reply.note = FetchOutcome.NETWORK_ERROR, str(e)
                return reply
            except WireBudgetExceeded:  # 本文に数えられない受信（chunk-extension など）で、受信量の予算を超えた
                reply.outcome, reply.limit_hit, reply.note = FetchOutcome.TOO_LARGE, FetchLimit.CONTENT_LENGTH, "size.wire"
                return reply
            reply.content_kind = kind
            reply.body = decoder.data
            if decoder.truncated:
                reply.truncated, reply.limit_hit = True, cap_limit
            return reply

    # ------------------------------------------------------------------ 結果の組み立て
    def _elapsed_ms(self, run: _Run) -> int:
        return max(int((monotonic() - run.started) * 1000), 0)

    def _build(self, run: _Run, **fields) -> FetchResult:  # noqa: ANN003
        """契約の不変条件に違反する組み合わせでも例外を出さない（出したら fail-closed の NETWORK_ERROR）。"""
        try:
            return FetchResult(requested_url=run.requested_url, elapsed_ms=self._elapsed_ms(run), **fields)
        except ValidationError as e:
            log_exception("safefetch.result_invalid", e)
            return FetchResult(
                requested_url=run.requested_url, outcome=FetchOutcome.NETWORK_ERROR, elapsed_ms=self._elapsed_ms(run)
            )

    def _result(
        self,
        run: _Run,
        reply: _Reply | None = None,
        *,
        outcome: FetchOutcome | None = None,
        limit_hit: FetchLimit | None = None,
        blocked_policy: PolicyId | None = None,
    ) -> FetchResult:
        if reply is None:  # 最初の URL を拒否した（blocked。転送・状態は持たない）
            return self._build(run, outcome=FetchOutcome.BLOCKED, blocked_policy=blocked_policy)
        return self._build(
            run,
            final_url=run.final_url,
            redirects=tuple(run.hops),
            outcome=outcome or reply.outcome,
            status=reply.status,
            headers=reply.headers,
            body=reply.body,
            truncated=reply.truncated,
            content_kind=reply.content_kind,
            limit_hit=limit_hit or reply.limit_hit,
        )

    def _failure(
        self,
        run: _Run,
        outcome: FetchOutcome,
        *,
        limit_hit: FetchLimit | None = None,
        note: str | None = None,
    ) -> FetchResult:
        if note:
            run.notes.append(note)
        return self._build(run, redirects=tuple(run.hops), outcome=outcome, limit_hit=limit_hit)
