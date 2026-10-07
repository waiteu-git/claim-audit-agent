"""フィクスチャの配信（/fx/）の唯一の定義と、それをプロセス内で引く FetchPort（FixtureFetch）。

公開面（S2）の `/fx/{path}` はこの FixtureSite.resolve を呼ぶ。評価（eval.py）とリプレイの生成は FixtureFetch で同じ定義を引くので、
「配信の挙動」と「オフラインで試した挙動」が割れない。

配信の規則（閉じた集合だけを返す。ファイルシステムを直接は見せない）:
  * 起動時に site/ 配下を読み込んだ辞書（相対パス → バイト列）だけを返す。パスは英数と - _ . / だけ、`..`・`//` は 404。
  * `x/` は `x/index.html`、`x/` に REDIRECT ファイルがあれば 302（中身が Location）。`x` に対して `x/index.html` があれば 301 → `x/`。
  * 本文の `{{CLOUD_RUN_HOST}}` は配信時に架空のサービスホストへ置き換える（ソースに run.app 系のホストを書かないため）。
  * 応答には sandbox の CSP を付ける（フィクスチャは信頼しないページ。スクリプトもフォーム送信も動かさない）。
"""
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from app.contracts import (
    MAX_REDIRECT_HOPS,
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

FX_PREFIX = "/fx/"
SITE_DIR = Path(__file__).resolve().parent / "site"
REDIRECT_FILE = "REDIRECT"
CLOUD_RUN_PLACEHOLDER = "{{CLOUD_RUN_HOST}}"
# 架空のサービスホスト（D3 の「公開説明文に載った内部URL」）。実在しない名前を連結で組む（ソースに run.app 系ホストを直書きしない）
FAKE_CLOUD_RUN_HOST = "otoshimono-api-7q2k9x-an.a" + "." + "run" + "." + "app"
FIXTURE_CSP = (
    "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; form-action 'none'; base-uri 'none'; "
    "frame-ancestors 'none'"
)
HTML_TYPE = "text/html; charset=utf-8"
_SAFE_PATH = re.compile(r"^[A-Za-z0-9_\-./]*$")


@dataclass(frozen=True)
class FxResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes = b""


def _base_headers(content_type: str | None) -> list[tuple[str, str]]:
    h = [("content-security-policy", FIXTURE_CSP), ("x-content-type-options", "nosniff"), ("cache-control", "no-store")]
    if content_type:
        h.insert(0, ("content-type", content_type))
    return h


class FixtureSite:
    """相対パス（`defect/spec/index.html`）→ 本文。resolve は URL のパス（`/fx/defect/spec/`）を受ける。"""

    def __init__(self, files: Mapping[str, bytes | str]) -> None:
        self._files: dict[str, bytes] = {}
        for k, v in files.items():
            raw = v.encode("utf-8") if isinstance(v, str) else v
            self._files[k] = raw.replace(CLOUD_RUN_PLACEHOLDER.encode(), FAKE_CLOUD_RUN_HOST.encode())

    @classmethod
    def load(cls, root: Path = SITE_DIR) -> "FixtureSite":
        files = {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}
        return cls(files)

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(sorted(self._files))

    def file(self, rel: str) -> bytes | None:
        return self._files.get(rel)

    def resolve(self, path: str) -> FxResponse:
        """URL のパス → 応答。見つからない・形が不正なら 404（本文なし）。"""
        if not path.startswith(FX_PREFIX):
            return FxResponse(404, tuple(_base_headers(None)))
        rel = path[len(FX_PREFIX) :]
        if not _SAFE_PATH.match(rel) or ".." in rel.split("/") or "//" in rel or rel.startswith("/"):
            return FxResponse(404, tuple(_base_headers(None)))
        if rel == "" or rel.endswith("/"):
            redirect = self._files.get(rel + REDIRECT_FILE)
            if redirect is not None:
                location = redirect.decode("utf-8").strip()
                return FxResponse(302, (("location", location), *_base_headers(HTML_TYPE)), b"")
            body = self._files.get(rel + "index.html")
            if body is not None:
                return FxResponse(200, tuple(_base_headers(HTML_TYPE)), body)
            return FxResponse(404, tuple(_base_headers(None)))
        if rel.rsplit("/", 1)[-1] == REDIRECT_FILE:
            return FxResponse(404, tuple(_base_headers(None)))  # 転送の定義ファイルそのものは配らない
        body = self._files.get(rel)
        if body is not None:
            ctype = HTML_TYPE if rel.endswith(".html") else "text/plain; charset=utf-8"
            return FxResponse(200, tuple(_base_headers(ctype)), body)
        if (rel + "/index.html") in self._files or (rel + "/" + REDIRECT_FILE) in self._files:
            return FxResponse(301, (("location", path + "/"), *_base_headers(None)), b"")
        return FxResponse(404, tuple(_base_headers(None)))


class FixtureFetch:
    """FetchPort（プロセス内）。FixtureSite をネットワーク無しで引き、SafeFetch と同じ形の FetchResult を返す。

    スコープ（UrlPrefix.matches）外の最初の要求は BLOCKED（P-SCOPE-01）、範囲外への転送は追跡せず最後のホップに残す
    （契約 FetchResult の「リダイレクトの表し方」）。評価とリプレイの生成専用（公開面のライブ実行は SafeFetch→fetcher を通る）。
    """

    def __init__(self, site: FixtureSite, host: str, allowed_prefixes: Sequence[UrlPrefix]) -> None:
        self.site = site
        self.host = host
        self.prefixes = tuple(allowed_prefixes)
        self.calls: list[FetchRequest] = []

    def _in_scope(self, url: str) -> bool:
        p = urlsplit(url)
        return p.scheme == "https" and (p.hostname or "") == self.host and any(
            x.matches(self.host, p.path or "/") for x in self.prefixes
        )

    async def fetch(self, request: FetchRequest) -> FetchResult:
        self.calls.append(request)
        url = request.url
        if not self._in_scope(url):
            return FetchResult(requested_url=url[:2048], outcome=FetchOutcome.BLOCKED, blocked_policy=PolicyId.SCOPE)
        hops: list[RedirectHop] = []
        current = url
        while True:
            resp = self.site.resolve(urlsplit(current).path or "/")
            headers = {k: v for k, v in resp.headers if k in ("content-type", "location")}
            if 300 <= resp.status < 400:
                location = headers.get("location", "")
                target = urljoin(current, location)
                if len([h for h in hops if h.followed]) >= MAX_REDIRECT_HOPS:
                    hops.append(RedirectHop(url=current, status=resp.status, location=location))
                    return FetchResult(
                        requested_url=url, final_url=current, redirects=tuple(hops), outcome=FetchOutcome.TOO_MANY_REDIRECTS,
                        limit_hit=FetchLimit.REDIRECTS,
                    )  # fmt: skip
                if not self._in_scope(target):
                    hops.append(RedirectHop(url=current, status=resp.status, location=location, blocked_policy=PolicyId.SCOPE))
                    return FetchResult(
                        requested_url=url, final_url=current, redirects=tuple(hops), outcome=FetchOutcome.OK,
                        status=resp.status, headers=headers, content_kind=ContentKind.HTML,
                    )  # fmt: skip
                hops.append(RedirectHop(url=current, status=resp.status, location=location, followed=True, in_scope=True))
                current = target
                continue
            body = resp.body
            truncated = False
            if request.mode is FetchMode.PROBE and len(body) > PROBE_BODY_MAX_BYTES:
                body, truncated = body[:PROBE_BODY_MAX_BYTES], True
            return FetchResult(
                requested_url=url,
                final_url=current,
                redirects=tuple(hops),
                outcome=FetchOutcome.OK,
                status=resp.status,
                headers={k: v for k, v in headers.items() if k == "content-type"},
                body=body,
                truncated=truncated,
                limit_hit=FetchLimit.PROBE_PREFIX if truncated else None,
                content_kind=ContentKind.HTML if "html" in headers.get("content-type", "") else ContentKind.PLAIN,
                elapsed_ms=5,
            )
