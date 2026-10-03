"""http_probe の観測（Observation.facts）の語彙と読み取りの道具。

http_probe が書き、auth_wall・cloud_run_signature チェッカーと判定表が読む。facts は契約の制約（bool・int・短い識別子だけ。
URL・ホスト・本文は載せられない）に従う。第三者のホストやサービスの run.app 系ホスト名は、facts にも証拠チップにも載せない
（載せるのは真偽の印だけ。設計 §7 の漏洩防止）。
"""
from collections.abc import Sequence
from enum import StrEnum

from app.contracts import Observation, ObsCode, ObsOutcome, ToolName

# http_probe の target（契約の ProbeTarget と同じ語）。観測の facts["target"] に残し、チェッカーが取り違えずに選ぶ。
TARGET_SUBMISSION = "SUBMISSION_URL"


class Access(StrEnum):
    """「誰が開けるか」の判定結果を1語にしたもの（facts["access"]）。証拠チップと確認不能の理由の材料。"""

    PUBLIC = "public"  # ログイン無しで開ける（認証壁の印なし）
    LOGIN_REDIRECT = "login_redirect"  # ログイン用パスへの転送（302→/login など）
    IDP_REDIRECT = "idp_redirect"  # 外部の認証基盤（IdP）への転送
    LOGIN_FORM = "login_form"  # 本文が password 欄つきのログイン画面
    HTTP_401 = "http_401"
    HTTP_403 = "http_403"
    NOT_FOUND = "not_found"  # 404 / 410
    HTTP_ERROR = "http_error"  # 上記以外の 4xx/5xx
    SPA_SHELL = "spa_shell"  # 本文が空に近く JS 描画。ログインの有無は判断できない
    FORM_ON_CONTENT = "form_on_content"  # 内容の多いページに password 欄がある（壁とは言い切れない）
    UNKNOWN_REDIRECT = "unknown_redirect"  # 追跡しなかった転送（行き先が範囲外など）。ログインの印なし
    UNREACHABLE = "unreachable"  # タイムアウト・接続失敗・429/502/503/504（一時的）
    BLOCKED = "blocked"  # スコープ・SSRF 規則で取得を拒否
    UNSUPPORTED_TYPE = "unsupported_type"
    TOO_LARGE = "too_large"
    REDIRECT_LIMIT = "redirect_limit"
    UNEXPECTED = "unexpected"  # 1xx・転送先の無い 3xx など
    LOGIN_PROMPT = "login_prompt"  # 短い画面がログインを促すだけ（password 欄もフォームも無い）。壁と言い切れない
    FORM_UNCONFIRMED = "form_unconfirmed"  # 生の文字列には password 欄らしい記述があるが、パーサが入力欄と確認できない
    ERROR_PAGE = "error_page"  # HTTP 200 の短い画面が拒否・エラーの文言を出している（ソフト403・ソフト404）。壁と言い切れない
    EMPTY_PAGE = "empty_page"  # 文字が見えない／埋め込み（iframe 等）だけのページ。中身を判断できない
    PROBE_PARTIAL = "probe_partial"  # 先頭 64KB で打ち切られ、本文が短いうちに終わった（続きにログイン画面があるかもしれない）


def select_probe(probes: Sequence[Observation], target: str = TARGET_SUBMISSION) -> Observation | None:
    """保存済みの http_probe 観測から、target に対する最新の結論つきの1件（無ければ最新の1件）を選ぶ。"""
    mine = [o for o in probes if o.tool is ToolName.HTTP_PROBE and o.facts.get("target") == target]
    if not mine:
        return None
    for o in reversed(mine):
        if o.outcome is not ObsOutcome.INCONCLUSIVE:
            return o
    return mine[-1]


def _conclusive_probes(probes: Sequence[Observation], target: str) -> list[Observation]:
    return [
        o
        for o in probes
        if o.tool is ToolName.HTTP_PROBE and o.facts.get("target") == target and o.outcome is not ObsOutcome.INCONCLUSIVE
    ]


def probes_conflict(probes: Sequence[Observation], target: str = TARGET_SUBMISSION) -> bool:
    """同じ target の観測が、「開ける」と「壁（または壁の疑い）」に割れているか。

    1回目は壁・2回目は開く（または逆）のように応答が揺れる提出物を、最新の観測だけで「開ける」にしない
    （取得元を見分けて応答を変える・不安定に壊れている、のどちらも、1回の観測では言い切れない）。
    割れとみなす組: 合格と不適合／合格と「壁の疑い」（403・ログインを促す画面・password 欄らしい記述の不確定な観測）。
    一時的な失敗（429/503・時間切れ）が間に挟まるだけなら、揺れとは言わない。
    """
    mine = [o for o in probes if o.tool is ToolName.HTTP_PROBE and o.facts.get("target") == target]
    outcomes = {o.outcome for o in mine}
    if ObsOutcome.PASS not in outcomes:
        return False
    wall_suspected = any(o.outcome is ObsOutcome.INCONCLUSIVE and o.code is ObsCode.AUTH_WALL for o in mine)
    return ObsOutcome.FAIL in outcomes or wall_suspected


def signature_flips(probes: Sequence[Observation], target: str = TARGET_SUBMISSION) -> bool:
    """結論つきの観測の間で、Cloud Run 署名の材料（run.app ホスト・Google Frontend・応答が成立）が食い違うか。"""
    views = {
        (fact_bool(o, "run_app_host"), fact_bool(o, "gfe"), _served(o)) for o in _conclusive_probes(probes, target)
    }
    return len(views) > 1


def _served(obs: Observation) -> bool:
    status = fact_int(obs, "status")
    return status is not None and 200 <= status < 400


def fact_int(obs: Observation, key: str) -> int | None:
    v = obs.facts.get(key)
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def fact_bool(obs: Observation, key: str) -> bool:
    return obs.facts.get(key) is True


def fact_str(obs: Observation, key: str) -> str | None:
    v = obs.facts.get(key)
    return v if isinstance(v, str) else None
