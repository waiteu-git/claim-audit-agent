"""http_probe: デプロイURLの到達性と「誰が開けるか」を実測する（設計 §4）。

FetchPort（SafeFetch。S1 はプロセス内・S2 は fetcher 経由）に probe モードで1回取りに行き、観測を作る。
保持するのは sha256 でなく、コード算出の指標だけ（ステータス・転送の連なり・password 欄・本文長・Cloud Run 署名の印）。
本文のテキストは観測にも Planner にも渡さない。認証壁の判定はここ（コード）で行い、モデルは判定に関与しない。

判定（_classify。上から順）:
  転送の連なりにログイン用パス／IdP への転送がある → AUTH_WALL（強）       例: 302→/login、外部 IdP への転送
  401 → AUTH_WALL（強）
  403 → Cloud Run の既定ドメイン（run.app＋Google Frontend）なら AUTH_WALL（強。IAM の壁）／それ以外は AUTH_WALL・不確定
        （取得元 IP を弾く WAF・CDN と区別できない。判定表で「人の判断が必要」にする）
  <meta refresh>（待ち10秒以内）の行き先がログイン／IdP → AUTH_WALL（強）／それ以外の行き先 → BLOCKED・不確定（行き先を見ていない）
  タイムアウト・接続失敗・429/503（X-Audit-App 無し）・502/504 → TRANSIENT（不適合にしない。2秒後に1回だけ再試行 S-04）
  404/410 → ERROR・不適合（強）／500 など → ERROR・不適合（弱）／その他の 4xx → ERROR・不確定
  追跡しなかった転送（行き先がスコープ外など）で、ログインの印が無い → BLOCKED・不確定（OUT_OF_SCOPE の材料）
  2xx で HTML（上から順）:
              password 欄つきの短い本文 → AUTH_WALL（強）／本文が空に近い JS 描画（描画先の印あり、または本文が空で script だけ）→ SPA_SHELL・不確定
              内容の多いページの password 欄 → AUTH_WALL・不確定／生の文字列にだけ password 欄らしい記述 → AUTH_WALL・不確定（form_unconfirmed）
              <meta refresh> の行き先を見ていない → BLOCKED・不確定／ログインを促すだけの短い画面 → AUTH_WALL・不確定（login_prompt）
              拒否・エラーの文言だけの短い画面（HTTP 200 のソフト403・ソフト404）→ AUTH_WALL・不確定（error_page）
              文字が1つも見えない・埋め込み（iframe 等）だけの短い本文 → ERROR・不確定（empty_page）
              先頭 64KB で打ち切られ本文が短い → ERROR・不確定（probe_partial。続きにログイン画面があるかもしれない）
              それ以外 → NO_AUTH_WALL（合格・強）
「不確定」は判定表で確認不能になる（理由コード付き）。

再試行の回数は ProbeResult.attempts で返す（予算に数えるかは呼び出し側＝T7 の裁定。契約監査の open_questions）。
"""
import asyncio
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from app.checks.auth_wall import (
    LOGIN_PAGE_TEXT_MAX,
    META_REFRESH_REDIRECT_MAX_S,
    LoginEvidence,
    hop_login_evidence,
    is_login_form_page,
    is_empty_page,
    is_login_prompt_page,
    is_soft_error_page,
    is_spa_shell,
    last_location_path,
    meta_refresh_evidence,
    path_fact,
)
from app.checks.html_signals import HtmlSignals, analyze_html
from app.checks.probe_facts import TARGET_SUBMISSION, Access
from app.config import FETCH_LIMITS
from app.contracts import (
    ContentKind,
    FetchMode,
    FetchOutcome,
    FetchPort,
    FetchRequest,
    FetchResult,
    Observation,
    ObsCode,
    ObsOutcome,
    ToolName,
)
from app.errors import AppError, ErrorCode, classify

# Cloud Run の既定ドメインの接尾辞（署名の判定にだけ使う。ホスト名そのものは facts にも証拠チップにも載せない）
RUN_APP_SUFFIX = ".run.app"
_GOOGLE_FRONTEND = "google frontend"
# アプリが応答に付ける固有ヘッダ（設計 §4）。無い 429/503 は基盤（Cloud Run・LB）由来の一時的な失敗として扱う。
_TRANSIENT_ALWAYS = frozenset({502, 504})  # ゲートウェイ系は常に一時的な失敗
_TRANSIENT_WITHOUT_APP_HEADER = frozenset({429, 503})
_HTML_KINDS = frozenset({ContentKind.HTML, ContentKind.XHTML})
_TARGET = re.compile(r"^(?:SUBMISSION_URL|L[0-9]{1,3})$")  # 契約の ProbeTarget と同じ形


@dataclass(frozen=True)
class ProbeResult:
    observation: Observation
    attempts: int  # FetchPort を呼んだ回数（再試行を含む。予算の計上に使う）
    access: Access


@dataclass(frozen=True)
class _Classified:
    code: ObsCode
    outcome: ObsOutcome
    strong: bool
    access: Access


def _host(url: str | None) -> str:
    if not url:
        return ""
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def is_transient(result: FetchResult) -> bool:
    """一時的な失敗か（タイムアウト・接続失敗・基盤由来の 429/502/503/504）。ログイン転送の証拠があれば一時的とは言わない。"""
    if result.outcome in (FetchOutcome.TIMEOUT, FetchOutcome.NETWORK_ERROR):
        return hop_login_evidence(result.redirects, _host(result.requested_url)) is None
    if result.outcome is not FetchOutcome.OK or result.status is None:
        return False
    if result.status in _TRANSIENT_ALWAYS:
        return True
    return result.status in _TRANSIENT_WITHOUT_APP_HEADER and not result.has_audit_app_header


def _html_signals(result: FetchResult) -> HtmlSignals | None:
    """最終応答が 2xx の HTML の時だけ本文を解析する（先頭 64KB）。"""
    if result.outcome is not FetchOutcome.OK or result.status is None or not (200 <= result.status < 300):
        return None
    ctype = result.headers.get("content-type")
    is_html = result.content_kind in _HTML_KINDS or (
        result.content_kind is None and ctype is not None and "html" in ctype.lower()
    )
    if not is_html or not result.body:
        return None
    return analyze_html(result.body, ctype)


def _is_cloud_run_response(result: FetchResult) -> bool:
    """最終応答が Cloud Run の既定ドメイン（run.app）から、Google Frontend の応答として返ったか。"""
    host = _host(result.final_url) or _host(result.requested_url)
    return host.endswith(RUN_APP_SUFFIX) and _GOOGLE_FRONTEND in result.headers.get("server", "").lower()


def _meta_refresh_is_a_redirect(result: FetchResult, sig: HtmlSignals) -> bool:
    """<meta refresh> が別の場所への転送か（待ちが短く、行き先が自分自身でない）。再読み込みだけ・自分自身へは転送ではない。"""
    if not sig.meta_refresh_target or (sig.meta_refresh_delay or 0) > META_REFRESH_REDIRECT_MAX_S:
        return False
    try:
        here = urlsplit(result.final_url or result.requested_url).path or "/"
    except ValueError:
        here = "/"
    return (sig.meta_refresh_path or "/") != unquote(here)


def _classify(result: FetchResult, sig: HtmlSignals | None, ev: LoginEvidence | None) -> _Classified:
    inconclusive, fail, passed = ObsOutcome.INCONCLUSIVE, ObsOutcome.FAIL, ObsOutcome.PASS
    o, st = result.outcome, result.status
    if ev is not None:  # 転送の連なりにログイン／IdP がある。最終応答が何でも、未認証の要求は壁に当たっている
        acc = Access.IDP_REDIRECT if ev.kind == "idp_host" else Access.LOGIN_REDIRECT
        return _Classified(ObsCode.AUTH_WALL, fail, True, acc)
    meta_ev = meta_refresh_evidence(sig, _host(result.requested_url)) if sig is not None else None
    if meta_ev is not None:  # <meta refresh> の行き先がログイン／IdP（静的ホスティングの転送）
        acc = Access.IDP_REDIRECT if meta_ev.kind == "idp_host" else Access.LOGIN_REDIRECT
        return _Classified(ObsCode.AUTH_WALL, fail, True, acc)
    if o in (FetchOutcome.TIMEOUT, FetchOutcome.NETWORK_ERROR):
        return _Classified(ObsCode.TRANSIENT, inconclusive, False, Access.UNREACHABLE)
    if o is FetchOutcome.BLOCKED:
        return _Classified(ObsCode.BLOCKED, inconclusive, False, Access.BLOCKED)
    if o is FetchOutcome.UNSUPPORTED_TYPE:
        return _Classified(ObsCode.UNSUPPORTED_TYPE, inconclusive, False, Access.UNSUPPORTED_TYPE)
    if o is FetchOutcome.TOO_LARGE:
        return _Classified(ObsCode.ERROR, inconclusive, False, Access.TOO_LARGE)
    if o is FetchOutcome.TOO_MANY_REDIRECTS:
        return _Classified(ObsCode.ERROR, inconclusive, False, Access.REDIRECT_LIMIT)
    if st is None:  # outcome=ok には status がある（契約）。型の外から来た場合の安全側
        return _Classified(ObsCode.ERROR, inconclusive, False, Access.UNEXPECTED)
    if is_transient(result):
        return _Classified(ObsCode.TRANSIENT, inconclusive, False, Access.UNREACHABLE)
    if st == 401:
        return _Classified(ObsCode.AUTH_WALL, fail, True, Access.HTTP_401)
    if st == 403:
        if _is_cloud_run_response(result):  # Cloud Run の既定ドメインの 403 は IAM の壁（審査員も開けない）
            return _Classified(ObsCode.AUTH_WALL, fail, True, Access.HTTP_403)
        # それ以外の 403 は、認証の壁か、取得元 IP（データセンター）を弾く WAF・CDN かを区別できない
        return _Classified(ObsCode.AUTH_WALL, inconclusive, False, Access.HTTP_403)
    if 300 <= st < 400:  # 追跡しなかった転送（スコープ外・http・上限）。ログインの印は上で見た
        if result.redirects and not result.redirects[-1].followed:
            return _Classified(ObsCode.BLOCKED, inconclusive, False, Access.UNKNOWN_REDIRECT)
        return _Classified(ObsCode.ERROR, inconclusive, False, Access.UNEXPECTED)
    if st in (404, 410):
        return _Classified(ObsCode.ERROR, fail, True, Access.NOT_FOUND)
    if st >= 500:
        return _Classified(ObsCode.ERROR, fail, False, Access.HTTP_ERROR)
    if st >= 400:  # 400・405・406・451 など。こちらの取得の仕方による拒否と区別できない
        return _Classified(ObsCode.ERROR, inconclusive, False, Access.HTTP_ERROR)
    if st < 200:
        return _Classified(ObsCode.ERROR, inconclusive, False, Access.UNEXPECTED)
    if sig is not None:
        if is_login_form_page(sig):
            return _Classified(ObsCode.AUTH_WALL, fail, True, Access.LOGIN_FORM)
        if is_spa_shell(sig):
            return _Classified(ObsCode.SPA_SHELL, inconclusive, False, Access.SPA_SHELL)
        if sig.has_password_input:
            return _Classified(ObsCode.AUTH_WALL, inconclusive, False, Access.FORM_ON_CONTENT)
        if sig.password_unconfirmed:  # パーサが見落とした password 欄かもしれない（コメント・CDATA の解釈の食い違い等）
            return _Classified(ObsCode.AUTH_WALL, inconclusive, False, Access.FORM_UNCONFIRMED)
        if _meta_refresh_is_a_redirect(result, sig):  # 別の場所へ飛ぶ。飛んだ先（ログイン画面かもしれない）を見ていない
            return _Classified(ObsCode.BLOCKED, inconclusive, False, Access.UNKNOWN_REDIRECT)
        if is_login_prompt_page(sig):
            return _Classified(ObsCode.AUTH_WALL, inconclusive, False, Access.LOGIN_PROMPT)
        if is_soft_error_page(sig):  # 200 で返る「アクセスできません」「見つかりません」の短い画面（ソフト403・ソフト404）
            return _Classified(ObsCode.AUTH_WALL, inconclusive, False, Access.ERROR_PAGE)
        if is_empty_page(sig):  # 文字が見えない・埋め込みだけ。ログインを促す画面や閉じた別サービスの埋め込みと区別できない
            return _Classified(ObsCode.ERROR, inconclusive, False, Access.EMPTY_PAGE)
        if result.truncated and sig.text_len <= LOGIN_PAGE_TEXT_MAX:  # 本文が短いうちに先頭 64KB が尽きた
            return _Classified(ObsCode.ERROR, inconclusive, False, Access.PROBE_PARTIAL)
    return _Classified(ObsCode.NO_AUTH_WALL, passed, True, Access.PUBLIC)


def observe_probe(
    result: FetchResult, *, obs_id: str, target: str = TARGET_SUBMISSION, attempts: int = 1
) -> Observation:
    """FetchResult → http_probe の観測（純関数。取得は行わない）。"""
    if not _TARGET.match(target):
        raise ValueError("target は SUBMISSION_URL か link_id（L1…）だけ")
    request_host = _host(result.requested_url)
    sig = _html_signals(result)
    ev = hop_login_evidence(result.redirects, request_host)
    c = _classify(result, sig, ev)
    meta_ev = meta_refresh_evidence(sig, request_host) if sig is not None and ev is None else None

    facts: dict[str, bool | int | str] = {
        "target": target,
        "outcome": result.outcome.value,
        "attempts": attempts,
        "elapsed_ms": result.elapsed_ms,
        "access": c.access.value,
    }
    if result.status is not None:
        facts["status"] = result.status
    if result.redirects:
        facts["redirect_hops"] = len(result.redirects)
        if ev is not None:
            facts["redirect_status"] = ev.status
            facts["location_path"] = ev.path
        else:
            facts["redirect_status"] = result.redirects[0].status
            facts["location_path"] = last_location_path(result.redirects)
        if not result.redirects[-1].followed:
            facts["unfollowed"] = True
    if sig is not None:
        facts["has_password_input"] = sig.has_password_input
        facts["text_len"] = sig.text_len
        facts["spa_shell"] = c.access is Access.SPA_SHELL
        if ev is None and meta_ev is not None:  # <meta> の行き先がログイン／IdP
            facts["redirect_status"] = 0  # 0 は <meta> による転送（HTTP の転送ではない）
            facts["location_path"] = meta_ev.path
        elif ev is None and c.access is Access.UNKNOWN_REDIRECT:  # <meta> の行き先を見ていない
            facts["redirect_status"] = 0
            facts["location_path"] = path_fact(sig.meta_refresh_path or "/")
            facts["unfollowed"] = True
    if result.truncated:
        facts["truncated"] = True
    if result.outcome is FetchOutcome.BLOCKED and result.blocked_policy is not None:
        facts["policy"] = result.blocked_policy.value
    if result.outcome is not FetchOutcome.BLOCKED:
        final_host = _host(result.final_url) or request_host
        facts["run_app_host"] = final_host.endswith(RUN_APP_SUFFIX)
        facts["gfe"] = _GOOGLE_FRONTEND in result.headers.get("server", "").lower()

    return Observation(
        obs_id=obs_id,
        tool=ToolName.HTTP_PROBE,
        code=c.code,
        outcome=c.outcome,
        strong=c.strong,
        facts=facts,
    )


async def http_probe(
    fetch: FetchPort,
    url: str,
    *,
    obs_id: str,
    target: str = TARGET_SUBMISSION,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> ProbeResult:
    """url（SUBMISSION_URL など、呼び出し側が target から解決したもの）を probe モードで取得し、観測にする。

    一時的な失敗（is_transient）は FETCH_LIMITS.probe_retry_delay_s 待って FETCH_LIMITS.probe_retry_max 回だけ再試行する（S-04）。
    sleep は注入できる（テストで待たない）。想定内の失敗は FetchResult の outcome で届く。FetchPort が例外を投げた場合は、
    一時的（RETRYABLE）なら再試行し、取得の拒否（FETCH_BLOCKED）は BLOCKED の観測にする。それ以外は呼び出し側へ伝える。
    """
    if not _TARGET.match(target):
        raise ValueError("target は SUBMISSION_URL か link_id（L1…）だけ")
    request = FetchRequest(url=url, mode=FetchMode.PROBE)
    attempts = 0
    result: FetchResult | None = None
    while True:
        attempts += 1
        try:
            result = await fetch.fetch(request)
        except AppError as e:
            code = classify(e)
            if code is ErrorCode.FETCH_BLOCKED:
                return _blocked(obs_id, target, attempts)
            if code is not ErrorCode.RETRYABLE:
                raise
            result = None
        except OSError:
            result = None  # 接続断など。一時的な失敗として扱う
        transient = result is None or is_transient(result)
        if not transient or attempts > FETCH_LIMITS.probe_retry_max:
            break
        await sleep(FETCH_LIMITS.probe_retry_delay_s)
    if result is None:
        obs = Observation(
            obs_id=obs_id,
            tool=ToolName.HTTP_PROBE,
            code=ObsCode.TRANSIENT,
            outcome=ObsOutcome.INCONCLUSIVE,
            facts={"target": target, "outcome": FetchOutcome.NETWORK_ERROR.value, "attempts": attempts,
                   "access": Access.UNREACHABLE.value},
        )  # fmt: skip
        return ProbeResult(obs, attempts, Access.UNREACHABLE)
    obs = observe_probe(result, obs_id=obs_id, target=target, attempts=attempts)
    return ProbeResult(obs, attempts, Access(str(obs.facts["access"])))


def _blocked(obs_id: str, target: str, attempts: int) -> ProbeResult:
    obs = Observation(
        obs_id=obs_id,
        tool=ToolName.HTTP_PROBE,
        code=ObsCode.BLOCKED,
        outcome=ObsOutcome.INCONCLUSIVE,
        facts={"target": target, "outcome": FetchOutcome.BLOCKED.value, "attempts": attempts,
               "access": Access.BLOCKED.value},
    )  # fmt: skip
    return ProbeResult(obs, attempts, Access.BLOCKED)
