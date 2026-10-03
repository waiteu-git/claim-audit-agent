"""認証壁の検出（設計 §3 AUTORUN・§4 http_probe・run_check の auth_wall）。

2つの層に分ける:
  1. 検出の部品（純関数）: ログイン用パス・外部の認証基盤（IdP）への転送・password 欄／ログインフォーム。http_probe が使う。
  2. チェッカー check_auth_wall: 保存済みの http_probe 観測を要件に結び付け、req_id 付きの観測にする（run_check の auth_wall）。

原則（設計 §5-2 S-03）: 検査を減らす方向の判断（認証壁と断定して中身を見ない）は、コードが取れた証拠が揃った時だけ。
  * 強い証拠（OBS強）: 401、ログイン用パス／IdP への転送、password 欄つきの短いログイン画面。
  * 弱い証拠: 403（取得元 IP を弾く WAF と区別できない）。
  * 断定しない: 内容の多いページにある password 欄（ヘッダのログイン窓など）。→ 不確定。
検索フォーム（type=search・name=q）や、本文中の「パスワード」という語は、password 欄とは数えない。

敵対レビューで足したもの:
  * ログインを促すだけの短い画面（password 欄もフォームも無い「Googleでログイン」）は、壁とも言い切れず「開ける」とも言えない（不確定）。
  * 描画先の印が無くても、本文が空で script だけの殻（Flutter など）は JS 描画の殻。
  * <meta refresh> の行き先も、転送と同じ規則（ログイン用パス・外部 IdP）で判定する。
  * 同じ URL の観測が食い違う（壁と合格が両方ある）なら、最新の観測を採らず不確定にする。
  * facts に載せるパスは、ログインの形が分かる語だけ残し、ID・鍵・メール・長い文は伏せる。
"""
import re
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlsplit

from app.checks.html_signals import HtmlSignals
from app.checks.probe_facts import TARGET_SUBMISSION, fact_str, probes_conflict, select_probe
from app.contracts import Checker, Observation, ObsCode, ObsOutcome, RedirectHop, ToolName, VerifiedRequirement

# ログイン画面とみなす本文の長さ（空白を1つにまとめた可視テキスト）。これ以下で password 欄があれば壁とする。
LOGIN_PAGE_TEXT_MAX = 1500

# ログイン用パスのセグメント（セグメント単位で照合する。/author や /sessions を誤認しない）
_LOGIN_SEGMENT = re.compile(
    r"^(?:log-?in|sign-?in|sign_in|sign-?on|logon|sso|auth(?:enticate|orize)?|oauth2?|oidc|saml2?|adfs|wp-login)"
    r"(?:[-_.].*)?$",
    re.IGNORECASE,
)

# 外部の認証基盤（IdP）のホスト。完全一致と接尾辞。
_IDP_HOSTS = frozenset(
    {
        "accounts.google.com",
        "login.microsoftonline.com",
        "login.live.com",
        "appleid.apple.com",
        "id.atlassian.com",
        "auth.atlassian.com",
    }
)
_IDP_SUFFIXES = (
    ".auth0.com",
    ".okta.com",
    ".oktapreview.com",
    ".onelogin.com",
    ".amazoncognito.com",
    ".b2clogin.com",
    ".pingone.com",
    ".pingidentity.com",
)
# ホストの最初のラベルがこれなら認証用ホストとみなす（login.example.invalid など）
_IDP_FIRST_LABELS = frozenset({"login", "signin", "sso", "auth", "accounts", "idp", "identity", "oauth", "adfs"})
# 認可要求の印（クエリのキー）。パスがログインらしくなくても IdP への転送と判断できる
_OAUTH_QUERY_KEYS = frozenset({"client_id", "redirect_uri", "response_type", "samlrequest", "wtrealm"})

_PATH_FACT_OK = re.compile(r"[^A-Za-z0-9_.:/\-]")
_LONG_TOKEN = re.compile(r"[A-Za-z0-9]{20,}")


def is_login_path(path: str) -> bool:
    """パスがログイン用か。セグメント単位で照合（"/login"・"/users/sign_in"・"/login.php"・"/oauth/authorize"）。"""
    try:
        decoded = unquote(path)
    except Exception:  # noqa: BLE001
        return False
    return any(_LOGIN_SEGMENT.match(seg) for seg in decoded.split("/") if seg)


def is_idp_host(host: str) -> bool:
    h = host.lower().rstrip(".")
    if not h:
        return False
    if h in _IDP_HOSTS or h.endswith(_IDP_SUFFIXES):
        return True
    first = h.split(".", 1)[0]
    return first in _IDP_FIRST_LABELS and "." in h


_SEGMENT_TOKEN = re.compile(r"[A-Za-z]{1,16}[0-9]{0,2}|[0-9]{1,3}")
_SEGMENT_SPLIT = re.compile(r"[-_.]+")


def _segment_fact(seg: str) -> str:
    """パスの1区間を facts に載せられる形にする。ログインの形が分かる短い語だけ残し、他は "_" に伏せる。

    伏せるもの: 英数と . _ : - 以外の文字を含む区間（%・@・非 ASCII）、24字を超える区間、語が4つを超える区間、
    数字で始まる語・3桁を超える数字・語の途中の数字を含むもの（UUID・APIキー・セッションID・連番の ID）。
    提出物の側が決められる文（this-submission-is-fully-compliant）が証拠チップに出るのも防ぐ。
    """
    if not seg:
        return seg
    if len(seg) > 24 or _PATH_FACT_OK.search(seg):
        return "_"
    tokens = [t for t in _SEGMENT_SPLIT.split(seg) if t]
    if not tokens or len(tokens) > 3 or not all(_SEGMENT_TOKEN.fullmatch(t) for t in tokens):
        return "_"
    return seg


def path_fact(path: str) -> str:
    """facts に載せられる形のパス断片にする（区間ごとに _segment_fact・64字）。ホスト・クエリは捨てる。"""
    p = "/".join(_segment_fact(seg) for seg in path.split("?", 1)[0].split("#", 1)[0].split("/"))
    p = re.sub(r"/{2,}", "/", p)
    return p[:64]


@dataclass(frozen=True)
class LoginEvidence:
    """転送の連なりの中で見つけた、認証壁の証拠。"""

    kind: str  # "login_path" | "idp_host"
    status: int  # その転送の応答コード（302 など）
    path: str  # 証拠チップ用のパス断片（path_fact 済み）


def _split_location(location: str) -> tuple[str, str, str] | None:
    """Location → (host, path, query)。壊れていれば None。相対 URL は host が空。

    ブラウザと同じ読み方に揃える: バックスラッシュはスラッシュとして読む（円記号2つで始まる idp.example/login は //idp.example/login）、
    ホストのパーセント符号化は復号する（%61ccounts.example は accounts.example）。読み方が割れると IdP への転送を見落とす。
    """
    try:
        p = urlsplit(location.strip().replace("\\", "/"))
        host = unquote(p.hostname or "").lower()
    except ValueError:
        return None
    return host, p.path or "/", p.query


def location_login_evidence(location: str, status: int, request_host: str = "") -> LoginEvidence | None:
    """1つの転送先（Location・<meta refresh> の URL）がログイン／IdP への転送か。ホストは facts に載せない。"""
    parts = _split_location(location)
    if parts is None:
        return None
    host, path, query = parts
    cross_host = bool(host) and host != request_host.lower()
    if cross_host and (is_idp_host(host) or _OAUTH_QUERY_KEYS & {k.lower() for k in parse_qs(query)}):
        return LoginEvidence("idp_host", status, path_fact(path))
    if is_login_path(path):
        return LoginEvidence("login_path", status, path_fact(path))
    return None


def hop_login_evidence(redirects: Sequence[RedirectHop], request_host: str = "") -> LoginEvidence | None:
    """転送の連なり（3xx 応答）からログイン／IdP への転送を探す。最初に見つかった1件を返す。"""
    for hop in redirects:
        if not hop.location:
            continue
        ev = location_login_evidence(hop.location, hop.status, request_host)
        if ev is not None:
            return ev
    return None


# <meta refresh> を「転送」とみなす待ち秒数の上限（これより長く待つなら、内容が先に見える＝転送とは言わない）
META_REFRESH_REDIRECT_MAX_S = 10


def meta_refresh_evidence(sig: HtmlSignals, request_host: str = "") -> LoginEvidence | None:
    """<meta http-equiv=refresh> の行き先がログイン／IdP なら証拠。status は 0（HTTP の転送ではない）。"""
    if not sig.meta_refresh_target or (sig.meta_refresh_delay or 0) > META_REFRESH_REDIRECT_MAX_S:
        return None
    return location_login_evidence(sig.meta_refresh_target, 0, request_host)


def last_location_path(redirects: Sequence[RedirectHop]) -> str:
    """証拠が無い転送でも、最後の転送先のパス断片を facts に残す（行き先の手掛かり。ホストは載せない）。"""
    for hop in reversed(redirects):
        if hop.location:
            parts = _split_location(hop.location)
            if parts is not None:
                return path_fact(parts[1])
    return ""


def is_login_form_page(sig: HtmlSignals) -> bool:
    """本文がログイン画面か（短い本文で、password 欄／ログイン用 action の form がある。または題名がログイン系）。

    password 欄の語だけ・type=search の検索窓・hidden の欄では成立しない（HtmlSignals が数えない）。
    """
    login_form = sig.has_password_input or any(is_login_path(f.action_path) for f in sig.forms)
    if not login_form:
        return False
    return sig.text_len <= LOGIN_PAGE_TEXT_MAX or (sig.has_password_input and sig.title_login_words)


def is_spa_shell(sig: HtmlSignals) -> bool:
    """本文がほぼ空で、script がある（JS 描画。ブラウザを持たないので中身は見えない）。

    描画先の印（id・カスタム要素・noscript の案内）がある殻は本文200字まで。印が無くても、本文が完全に空で script だけの
    ページ（Flutter・Vite の既定の殻など）は殻とする。短い静的ページに解析用の script があるだけ（本文あり・印なし）は殻としない。
    """
    if sig.script_count < 1:
        return False
    return (sig.text_len <= 200 and sig.mount_marker) or sig.text_len == 0


def is_empty_page(sig: HtmlSignals) -> bool:
    """文字が1つも見えない、または短い本文に別の場所の内容（iframe など）を埋め込んでいるだけのページか。

    画像・canvas・iframe だけの画面は、ログインを促す画面でも、IAM で閉じた別サービスの埋め込みでも、同じ HTML になる。
    中身を判断できないページを「ログイン不要で開ける」と言わない。
    """
    return sig.text_len == 0 or (sig.text_len <= 200 and sig.embed_count >= 1)


def is_soft_error_page(sig: HtmlSignals) -> bool:
    """HTTP 200 なのに、短い画面が拒否・エラーの文言（Access Denied・404 Not Found・権限がありません）を出しているか。

    ステータスだけでは「開ける」と言えない（ソフト403・ソフト404）。壁と言い切れる証拠も無いので、不確定にする。
    """
    return sig.error_prompt and not sig.has_password_input


def is_login_prompt_page(sig: HtmlSignals) -> bool:
    """短い画面がログインを促しているだけか（password 欄・ログインフォームは無い。それらがあれば is_login_form_page）。

    「Googleでログイン」のボタンだけの画面は、認証壁のようで、壁と言い切れるだけの証拠（password 欄・転送）も無い。
    「ログイン不要で開ける」とは言えないので、不確定にする。題名にログインの語があっても本文が長い説明ページなら対象外。
    """
    return sig.login_prompt and not sig.has_password_input


# ---------------------------------------------------------------------------
# チェッカー（run_check の auth_wall）
# ---------------------------------------------------------------------------
def check_auth_wall(
    req: VerifiedRequirement,
    probes: Sequence[Observation],
    obs_id: str,
    *,
    target: str = TARGET_SUBMISSION,
) -> Observation:
    """保存済みの http_probe 観測を要件に結び付ける（ネットワーク・LLM 不使用）。

    code・outcome・strong は http_probe の判断をそのまま引き継ぐ（再判定しない＝同じ入力から2通りの答えを出さない）。
    対象の http_probe 観測が無ければ、不確定（ERROR・reason=no_probe）。判定表はこれを確認不能にする。
    結論つきの観測に不適合と合格が両方あれば、不確定（ERROR・reason=probe_conflict）。
    """
    probe = select_probe(probes, target)
    if probe is None or probes_conflict(probes, target):
        # 同じ URL の観測が食い違う（壁と合格が両方ある）なら、最新の観測を採らない。応答を見分けて変える提出物や不安定な提出物を、
        # 1回の観測で「開ける」と言い切らない。
        return Observation(
            obs_id=obs_id,
            tool=ToolName.RUN_CHECK,
            checker=Checker.AUTH_WALL,
            req_id=req.req_id,
            code=ObsCode.ERROR,
            outcome=ObsOutcome.INCONCLUSIVE,
            facts={"target": target, "reason": "no_probe" if probe is None else "probe_conflict"},
        )
    facts = {k: v for k, v in probe.facts.items() if k != "attempts"}
    if fact_str(probe, "access") is None:
        facts["reason"] = "no_access"
    return Observation(
        obs_id=obs_id,
        tool=ToolName.RUN_CHECK,
        checker=Checker.AUTH_WALL,
        req_id=req.req_id,
        code=probe.code,
        outcome=probe.outcome,
        strong=probe.strong,
        facts=facts,
    )
