"""判定表（設計 §3）。要件と観測から Verdict を出す。判定を書くのはこのコードだけで、モデルは判定を書けない。

入力は AdjudicationInput（検証済みの要件・文書のメタ・観測・確認不能の印）。要件ごとに Verdict を1つ、入力と同じ順で返す。
純関数（ネットワーク・LLM・時計を使わない）。同じ入力には必ず同じ判定を返す。

判定表（優先順。上が先）:
  参考      kind=推測。観測があっても集計外（RunRecord の規則: 推測は必ず参考）。
  不適合    不適合の観測がある（合格の強い観測と食い違う場合を除く）。
            ／必須要件で、要求された語が無く、文書が完全（truncated=false・page_class=content）。
  確認不能  不適合の観測と合格の強い観測が食い違う（同じ要件に対する観測の矛盾は結論にしない。理由 NO_EVIDENCE）。
  適合      OBS強の合格（機械検証）。
  推定適合  contains_terms が語を見つけた（弱い合格）。語が在ることの証明であって内容の保証ではない。
  確認不能  上記以外。理由コードは 印（確認不能の印）→ 観測の不確定の種類 → 既定 の順で決める。
            証拠（不適合・合格）がある要件は、印があっても証拠を採る＝印で不適合を確認不能に洗えない（S-03）。

観測を証拠にする前の検査（取り違え・食い違いを証拠にしない）:
  * 要件クラスの checker と違う checker の観測は使わない（CHECK_CLASS_CHECKER）。検査できないクラス（none）は観測を使わない。
  * 要件クラス（check_class。モデルが付ける）が引用の内容と合わない要件には、検査の観測を適用しない（class_screen。確認不能・OUT_OF_SCOPE）。
    モデルの取り違え・注入で、無関係な要件に別の検査の合格が付いて「機械検証の適合」と見えるのを防ぐ。
  * 語が在ることを確かめる検査（contains_terms）は「禁止」の要件に当てはまらない（向きが逆。確認不能・OUT_OF_SCOPE）。
  * 提出物の本文を調べる checker（text_length・leak_scan・contains_terms）の結論は、提出物（role=submission）の文書の観測だけを採る
    （要項側の文書を測った観測を「提出物の本文は…」と言わない）。
  * 提出URL（SUBMISSION_URL）以外を target にした観測（リンク先の probe）は、提出物の要件の証拠にしない。
  * 403（認証の壁か取得元IPを弾くWAFか区別できない）の弱い観測は、不適合にせず確認不能（HUMAN_ONLY）にする。
  * checker とコード、コードと outcome の組み合わせが想定外の観測は証拠にしない（不確定として NO_EVIDENCE）。
  * 本文を調べる checker（text_length・leak_scan・contains_terms）の合格・語の発見は、文書が完全（truncated=false）で
    page_class=content の時だけ採る。不完全・ログイン壁・JS 描画・エラーページの本文は「無い」を証明しない。
    不適合は、文書の続きが増えても覆らない（字数超過・漏洩の発見）ので、打切りでも採る。
  * Planner が付けた印（by_planner）は、P-UNVERIF-01 の前提を再確認する（NEEDS_AUTH は認証壁の観測、NEEDS_JS は spa_shell の観測）。

理由コードの対応（契約の12語に収める。足りない語は契約監査の open_questions に書いた）:
  TRANSIENT→TRANSIENT／SPA_SHELL→NEEDS_JS／BLOCKED→OUT_OF_SCOPE（追跡しなかった転送）か FETCH_BLOCKED／UNSUPPORTED_TYPE→UNSUPPORTED_TYPE／
  LIMIT_UNDECIDABLE→HUMAN_ONLY（数え方は人が決める）／too_large→TRUNCATED／転送の上限→FETCH_BLOCKED／検査できないクラス→引用の文面から HUMAN_ONLY／FUTURE／NOT_PUBLIC（迷えば OUT_OF_SCOPE。checks/unverifiable_reason）／他→NO_EVIDENCE。
"""
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from app.checks.class_screen import quote_supports_class
from app.checks.probe_facts import TARGET_SUBMISSION
from app.checks.unverifiable_reason import unverifiable_reason
from app.contracts import (
    CHECK_CLASS_CHECKER,
    REASON_LABEL_JA,
    AdjudicationInput,
    Checker,
    Contradiction,
    ContradictionBasis,
    DemotionReason,
    DocMeta,
    DocRole,
    EvidenceRef,
    Kind,
    Observation,
    ObsCode,
    ObsOutcome,
    PageClass,
    Slot,
    UnverifiableMark,
    UnverifiableReason,
    Verdict,
    VerdictLabel,
    VerifiedRequirement,
)

# --- 観測の整合表（これに合わない観測は証拠にしない）---------------------------------------------
_PASS, _FAIL, _INC = ObsOutcome.PASS, ObsOutcome.FAIL, ObsOutcome.INCONCLUSIVE
_CODE_OUTCOMES: dict[ObsCode, frozenset[ObsOutcome]] = {
    ObsCode.OK: frozenset({_PASS, _INC}),
    ObsCode.AUTH_WALL: frozenset({_FAIL, _INC}),  # 不確定＝壁の印はあるが言い切れない（内容の多いページの password 欄）
    ObsCode.NO_AUTH_WALL: frozenset({_PASS}),
    ObsCode.SPA_SHELL: frozenset({_INC}),
    ObsCode.TRANSIENT: frozenset({_INC}),
    ObsCode.WITHIN_LIMIT: frozenset({_PASS}),
    ObsCode.OVER_LIMIT: frozenset({_FAIL}),
    ObsCode.LIMIT_UNDECIDABLE: frozenset({_INC}),
    ObsCode.TERMS_FOUND: frozenset({_PASS}),
    ObsCode.TERMS_ABSENT: frozenset({_FAIL, _INC}),  # outcome はどちらでも判定表が決める（下の _effective）
    ObsCode.LEAK_FOUND: frozenset({_FAIL}),
    ObsCode.NO_LEAK: frozenset({_PASS}),
    ObsCode.SIGNATURE_PRESENT: frozenset({_PASS}),
    ObsCode.SIGNATURE_ABSENT: frozenset({_INC}),  # 署名が無いことは Cloud Run でない証明ではない（不適合にしない）
    ObsCode.BLOCKED: frozenset({_INC}),
    ObsCode.UNSUPPORTED_TYPE: frozenset({_INC}),
    ObsCode.NO_PARAMETER: frozenset({_INC}),
    ObsCode.ERROR: frozenset({_FAIL, _INC}),  # 不適合の ERROR は http_probe の 404・500 など
}
_CHECKER_CODES: dict[Checker, frozenset[ObsCode]] = {
    Checker.TEXT_LENGTH: frozenset(
        {ObsCode.WITHIN_LIMIT, ObsCode.OVER_LIMIT, ObsCode.LIMIT_UNDECIDABLE, ObsCode.NO_PARAMETER, ObsCode.ERROR}
    ),
    Checker.AUTH_WALL: frozenset(
        {
            ObsCode.AUTH_WALL,
            ObsCode.NO_AUTH_WALL,
            ObsCode.SPA_SHELL,
            ObsCode.TRANSIENT,
            ObsCode.BLOCKED,
            ObsCode.UNSUPPORTED_TYPE,
            ObsCode.ERROR,
        }
    ),
    Checker.CLOUD_RUN_SIGNATURE: frozenset(
        {ObsCode.SIGNATURE_PRESENT, ObsCode.SIGNATURE_ABSENT, ObsCode.TRANSIENT, ObsCode.BLOCKED, ObsCode.UNSUPPORTED_TYPE, ObsCode.ERROR}
    ),
    Checker.CONTAINS_TERMS: frozenset({ObsCode.TERMS_FOUND, ObsCode.TERMS_ABSENT, ObsCode.NO_PARAMETER, ObsCode.ERROR}),
    Checker.LEAK_SCAN: frozenset({ObsCode.LEAK_FOUND, ObsCode.NO_LEAK, ObsCode.ERROR}),
}
# 本文（文書の可視テキスト）を調べる checker。合格・語の発見は、完全で content の文書だけが証明できる。
_BODY_CHECKERS = frozenset({Checker.TEXT_LENGTH, Checker.LEAK_SCAN, Checker.CONTAINS_TERMS})
# 不適合が、文書の続きが増えても覆らない checker（字数超過・漏洩の発見）。打切り文書の不適合も採る。
_MONOTONE_FAIL = frozenset({Checker.TEXT_LENGTH, Checker.LEAK_SCAN})


class _K(StrEnum):
    FAIL = "fail"
    PASS = "pass"
    WEAK = "weak"  # 弱い合格（contains_terms の語の発見）
    ABSENT = "absent"  # contains_terms の語が無い
    NONE = "none"  # 証拠にならない（不確定・取り違え・文書が不完全）


@dataclass(frozen=True)
class _Ev:
    obs: Observation
    kind: _K
    reason: UnverifiableReason | None = None  # kind=NONE の時の確認不能の理由


# --- 小さな道具 ---------------------------------------------------------------------------------
def _int(o: Observation, key: str) -> int | None:
    v = o.facts.get(key)
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _str(o: Observation, key: str) -> str | None:
    v = o.facts.get(key)
    return v if isinstance(v, str) else None


def _true(o: Observation, key: str) -> bool:
    return o.facts.get(key) is True


def _clip(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def _n(v: int | None) -> str:
    return f"{v:,}" if v is not None else "?"


def _page_reason(page_class: PageClass) -> UnverifiableReason | None:
    """content でない文書の本文が証拠にならない理由。content なら None。"""
    return {
        PageClass.LOGIN_WALL: UnverifiableReason.NEEDS_AUTH,
        PageClass.SPA_SHELL: UnverifiableReason.NEEDS_JS,
        PageClass.ERROR_PAGE: UnverifiableReason.NO_EVIDENCE,
        PageClass.EMPTY: UnverifiableReason.NO_EVIDENCE,
    }.get(page_class)


def _inconclusive_reason(o: Observation) -> UnverifiableReason:
    """不確定な観測 → 確認不能の理由コード。"""
    c = o.code
    if c is ObsCode.TRANSIENT:
        return UnverifiableReason.TRANSIENT
    if c is ObsCode.SPA_SHELL:
        return UnverifiableReason.NEEDS_JS
    if c is ObsCode.BLOCKED:
        return UnverifiableReason.OUT_OF_SCOPE if _true(o, "unfollowed") else UnverifiableReason.FETCH_BLOCKED
    if c is ObsCode.UNSUPPORTED_TYPE:
        return UnverifiableReason.UNSUPPORTED_TYPE
    if c is ObsCode.LIMIT_UNDECIDABLE:
        return UnverifiableReason.HUMAN_ONLY
    access = _str(o, "access")
    if c is ObsCode.AUTH_WALL:
        if access in ("http_403", "error_page"):  # 認証の壁か、取得元IPを弾くWAF・CDNか／200 の拒否・エラー画面。人が開いて確かめる
            return UnverifiableReason.HUMAN_ONLY
        if access == "login_prompt":  # ログインを促す画面。その先は検査できない
            return UnverifiableReason.NEEDS_AUTH
    if c is ObsCode.ERROR:
        if access in ("too_large", "probe_partial"):
            return UnverifiableReason.TRUNCATED
        if access == "redirect_limit":
            return UnverifiableReason.FETCH_BLOCKED
    return UnverifiableReason.NO_EVIDENCE


# --- 証拠チップのラベル（コードが観測から組む。Display60）---------------------------------------
# leak_scan の facts のキー → 証拠チップの語（見つけた文字列そのものは載せない。種類と件数だけ）
_LEAK_KIND_JA = (
    ("email", "メール"),
    ("service_url", "サービスの直URL"),
    ("private_ip", "内部IP"),
    ("google_api_key", "APIキー"),
    ("oauth_token", "トークン"),
    ("private_key", "秘密鍵"),
    ("service_account", "サービスアカウント"),
    ("github_token", "トークン"),
    ("aws_key_id", "アクセスキー"),
)


def evidence_label(o: Observation) -> str:
    """観測 → 証拠チップの短い文（60字以内）。例「302→/login・password欄あり」「1,130字（上限800字）」。"""
    c = o.code
    if c in (ObsCode.OVER_LIMIT, ObsCode.WITHIN_LIMIT, ObsCode.LIMIT_UNDECIDABLE):
        ws, nows, limit = _int(o, "chars_with_ws"), _int(o, "chars_no_ws"), _int(o, "limit")
        if c is ObsCode.WITHIN_LIMIT:
            return _clip(f"{_n(ws)}字（上限{_n(limit)}字）", 60)
        return _clip(f"{_n(ws)}字・空白除き{_n(nows)}字（上限{_n(limit)}字）", 60)
    if c is ObsCode.NO_PARAMETER:
        return "字数の上限を引用から取れず"
    if c is ObsCode.AUTH_WALL:
        access = _str(o, "access")
        rs = _int(o, "redirect_status")
        head = "meta転送" if rs == 0 else str(rs) if rs is not None else ""
        if access == "idp_redirect":
            return _clip(f"{head}→外部の認証サービスへ転送", 60)
        if access == "login_redirect":
            pw = "・password欄あり" if _true(o, "has_password_input") else ""
            return _clip(f"{head}→{_str(o, 'location_path') or '/'}{pw}", 60)
        if access == "login_form":
            return _clip(f"{_int(o, 'status') or ''}・ログイン画面（password欄あり）", 60)
        if access == "http_401":
            return "401・認証が必要"
        if access == "http_403":
            if o.outcome is ObsOutcome.FAIL:
                return "403・アクセス拒否"
            return "403・認証か取得元の制限か不明"
        if access == "form_on_content":
            return _clip(f"password欄あり・ページの文字{_n(_int(o, 'text_len'))}字（壁と言い切れず）", 60)
        if access == "form_unconfirmed":
            return "password欄らしい記述あり（確認できず）"
        if access == "login_prompt":
            return _clip(f"ログインを促す画面・ページの文字{_n(_int(o, 'text_len'))}字（壁と言い切れず）", 60)
        if access == "error_page":
            return _clip(f"200・拒否やエラーの文言の短い画面（{_n(_int(o, 'text_len'))}字）", 60)
        return "認証壁の印"
    if c is ObsCode.NO_AUTH_WALL:
        return _clip(f"{_int(o, 'status') or ''}・ログイン不要で開ける", 60)
    if c is ObsCode.SPA_SHELL:
        return _clip(f"JS描画が必要（ページの文字{_n(_int(o, 'text_len'))}字）", 60)
    if c is ObsCode.TRANSIENT:
        return "一時的に取得できず"
    if c is ObsCode.BLOCKED:
        return "取得は許可の範囲外" if not _true(o, "unfollowed") else "転送先は取得の範囲外"
    if c is ObsCode.UNSUPPORTED_TYPE:
        return "対応していない形式"
    if c is ObsCode.SIGNATURE_PRESENT:
        return "Cloud Run署名あり（サービスのドメイン＋Google Frontend）"
    if c is ObsCode.SIGNATURE_ABSENT:
        return "Cloud Run署名を確認できず"
    if c is ObsCode.ERROR:
        status = _int(o, "status")
        access = _str(o, "access")
        if access == "not_found":
            return _clip(f"{status or 404}・ページが見つからない", 60)
        if access == "http_error":
            return _clip(f"{status or ''}・サーバーエラーなど", 60)
        if access == "too_large":
            return "応答が大きすぎて読めず"
        if access == "redirect_limit":
            return "転送が上限を超えた"
        if access == "probe_partial":
            return _clip(f"先頭64KBだけでは判断できず（ページの文字{_n(_int(o, 'text_len'))}字）", 60)
        if access == "empty_page":
            return "文字が見えない・埋め込みだけ（判断できず）"
        if _str(o, "reason") == "probe_conflict":
            return "同じURLの観測が食い違う"
        return "観測に失敗"
    if c is ObsCode.TERMS_FOUND:
        return "求められた語が提出物のページにある（自己申告）"
    if c is ObsCode.TERMS_ABSENT:
        return "求められた語が提出物のページに無い"
    if c is ObsCode.LEAK_FOUND:
        kinds = [f"{ja}{_n(_int(o, key))}件" for key, ja in _LEAK_KIND_JA if _int(o, key)]
        return _clip("公開してはいけない文字列あり" + (f"（{'・'.join(kinds)}）" if kinds else ""), 60)
    if c is ObsCode.NO_LEAK:
        return "公開してはいけない文字列なし"
    return _clip(f"観測 {c.value}", 60)


def _ref(o: Observation) -> EvidenceRef:
    return EvidenceRef(obs_id=o.obs_id, event_seq=o.event_seq, label=evidence_label(o))


def _refs(obs: Sequence[Observation]) -> tuple[EvidenceRef, ...]:
    return tuple(_ref(o) for o in obs[:8])


# --- 理由文（コードのテンプレ。140字以内・自由文でない）-----------------------------------------
def _fail_reason(o: Observation) -> str:
    c = o.code
    if c is ObsCode.OVER_LIMIT:
        return _clip(
            f"提出物のページの文字は{_n(_int(o, 'chars_with_ws'))}字（空白を除くと{_n(_int(o, 'chars_no_ws'))}字）で、"
            f"要項の上限{_n(_int(o, 'limit'))}字を超えています。",
            140,
        )
    if c is ObsCode.AUTH_WALL:
        access = _str(o, "access")
        if access == "idp_redirect":
            return "提出物のURLは外部の認証サービスへ転送されます。審査員がログインなしで開けない恐れがあります。"
        if access == "login_redirect":
            return "提出物のURLはログイン画面へ転送されます。審査員がログインなしで開けない恐れがあります。"
        if access == "login_form":
            return "提出物のURLはログイン画面（password欄あり）を返します。審査員がログインなしで開けない恐れがあります。"
        if access == "http_401":
            return "提出物のURLは認証を要求します（401）。審査員がログインなしで開けない恐れがあります。"
        if access == "http_403":
            return "提出物のURLは403で拒否されます。認証または取得元の制限で、審査員が開けない恐れがあります。"
        return "提出物のURLに認証壁の印があります。"
    if c is ObsCode.ERROR:
        if _str(o, "access") == "not_found":
            return "提出物のURLが見つかりません（404/410）。審査員が開けません。"
        return _clip(f"提出物のURLがエラー（{_int(o, 'status') or '?'}）を返しました。審査員が開けない恐れがあります。", 140)
    if c is ObsCode.TERMS_ABSENT:
        return "要項が求める案内（語）が、提出物のページに見つかりません。"
    if c is ObsCode.LEAK_FOUND:
        return "提出物のページに、公開してはいけない文字列が含まれています。"
    return "観測が要項に適合していません。"


def _pass_reason(o: Observation) -> str:
    c = o.code
    if c is ObsCode.WITHIN_LIMIT:
        return _clip(
            f"提出物のページの文字は{_n(_int(o, 'chars_with_ws'))}字で、上限{_n(_int(o, 'limit'))}字以内です"
            "（空白あり・なし、どの数え方でも）。",
            140,
        )
    if c is ObsCode.NO_AUTH_WALL:
        return "提出物のURLは、ログインなしでHTMLが返ることを確認しました（認証壁の印なし。JavaScript で動くログインは検査できません）。"
    if c is ObsCode.SIGNATURE_PRESENT:
        return "Cloud Run のドメインと Google Frontend の応答を確認しました。"
    if c is ObsCode.NO_LEAK:
        return "提出物のページに、公開してはいけない文字列は見つかりませんでした。"
    return "観測が要項に適合しています。"


# 検査できないクラスの要件の理由文（コードごとに1つの固定文。引用の中身・数値・URL は埋め込まない）
_NONE_CLASS_TEXT: dict[UnverifiableReason, str] = {
    UnverifiableReason.HUMAN_ONLY: "提出物のURLからは確かめられない条件です。ご自身で確認してください。",
    UnverifiableReason.FUTURE: "提出後の約束や将来の事項で、今は検査できません。ご自身で守ってください。",
    UnverifiableReason.NOT_PUBLIC: "非公開の情報が要るため、この道具は検査していません。ご自身で確認してください。",
    UnverifiableReason.OUT_OF_SCOPE: "この道具では検査していません。要項を読んで、ご自身で確認してください。",
}


GATE_REASON_TEXTS = frozenset(_NONE_CLASS_TEXT.values())  # report が、見出しと重なる固定文の前に理由ラベルを付けないために使う


def _unverifiable_text(code: UnverifiableReason, o: Observation | None = None) -> str:
    label = REASON_LABEL_JA[code]
    if o is not None and o.code is ObsCode.LIMIT_UNDECIDABLE:
        return _clip(
            f"数え方で結論が割れます（空白込み{_n(_int(o, 'chars_with_ws'))}字・除き{_n(_int(o, 'chars_no_ws'))}字、"
            f"上限{_n(_int(o, 'limit'))}字）。数え方は人が決めてください。",
            140,
        )
    if o is not None and o.code is ObsCode.NO_PARAMETER:
        return "要項の引用から、検査に使う値（字数の上限など）を一意に取り出せませんでした。"
    if o is not None and _str(o, "reason") == "probe_conflict":
        return "同じURLへの観測が食い違うため、結論にしません（開けたり開けなかったりします）。"
    if o is not None and o.code is ObsCode.BLOCKED and _true(o, "unfollowed"):
        return "提出物のURLは別の場所へ転送されますが、転送先は検査の範囲外で見ていません（ログイン画面かもしれません）。"
    if o is not None and o.code is ObsCode.AUTH_WALL:
        access = _str(o, "access")
        if access == "http_403":
            return "提出物のURLが403を返しました。認証の壁か取得元の制限かを区別できないため、人が開いて確かめてください。"
        if access == "login_prompt":
            return "提出物のURLの画面はログインを促していますが、壁と言い切れる証拠がありません。ログインの先は検査できません。"
        if access == "error_page":
            return "提出物のURLは200を返しますが、画面は拒否やエラーの文言です。審査員が開けるか判断できないため、人が確かめてください。"
        if access == "form_unconfirmed":
            return "提出物のURLの画面に、password欄らしい記述がありますが、入力欄と確認できませんでした。"
    if o is not None and o.code is ObsCode.ERROR and _str(o, "access") == "probe_partial":
        return "提出物のURLの先頭64KBにはページの文字が少なく、続きにログイン画面があるか判断できません。"
    if o is not None and o.code is ObsCode.ERROR and _str(o, "access") == "empty_page":
        return "提出物のURLの画面は、文字が見えないか埋め込みだけで、ログインなしで中身を見られるか判断できません。"
    return label + "。"


# --- 観測 → 証拠の種類 -----------------------------------------------------------------------------
def _effective(o: Observation, docs: Mapping[str, DocMeta]) -> _Ev:
    """観測1件が、この要件の証拠として何を言えるか。取り違え・食い違い・不完全な文書は証拠にしない。"""
    if o.checker is None or o.code not in _CHECKER_CODES.get(o.checker, frozenset()):
        return _Ev(o, _K.NONE, UnverifiableReason.NO_EVIDENCE)
    if o.outcome not in _CODE_OUTCOMES[o.code]:
        return _Ev(o, _K.NONE, UnverifiableReason.NO_EVIDENCE)
    target = o.facts.get("target")
    if isinstance(target, str) and target != TARGET_SUBMISSION:  # リンク先（L2…）を調べた観測。提出URLの証拠ではない
        return _Ev(o, _K.NONE, UnverifiableReason.NO_EVIDENCE)
    doc = docs.get(o.doc_id) if o.doc_id is not None else None
    body = o.checker in _BODY_CHECKERS
    conclusive = o.outcome is not ObsOutcome.INCONCLUSIVE or o.code is ObsCode.TERMS_ABSENT
    if body and conclusive and (doc is None or doc.role is not DocRole.SUBMISSION):
        # どの文書の本文か分からない、または要項側の文書を調べた観測は、提出物の証拠にしない
        return _Ev(o, _K.NONE, UnverifiableReason.NO_EVIDENCE)

    if o.code is ObsCode.TERMS_ABSENT:  # 不適合にするかは文書の完全性と kind で決める（_decide）
        return _Ev(o, _K.ABSENT)
    if o.outcome is ObsOutcome.FAIL:
        if o.code is ObsCode.ERROR and o.checker is not Checker.AUTH_WALL:  # 不適合の ERROR は http_probe 由来だけ
            return _Ev(o, _K.NONE, UnverifiableReason.NO_EVIDENCE)
        if o.code is ObsCode.AUTH_WALL and not o.strong and _str(o, "access") == "http_403":
            # 403 は認証の壁とも、取得元IPを弾くWAF・CDNとも区別できない。弱い観測だけで不適合にしない
            return _Ev(o, _K.NONE, UnverifiableReason.HUMAN_ONLY)
        if o.checker is Checker.TEXT_LENGTH and doc is not None:  # 説明文でない本文（ログイン画面・エラーページ等）の字数は証拠にならない
            page = _page_reason(doc.page_class)
            if page is not None:
                return _Ev(o, _K.NONE, page)
        return _Ev(o, _K.FAIL)
    if o.outcome is ObsOutcome.PASS:
        if body:
            assert doc is not None  # 上で、本文の checker の結論つきの観測は文書を持つことを確かめた
            page = _page_reason(doc.page_class)
            if page is not None:
                return _Ev(o, _K.NONE, page)
            if doc.truncated and o.checker is not Checker.CONTAINS_TERMS:
                return _Ev(o, _K.NONE, UnverifiableReason.TRUNCATED)
        if o.checker is Checker.CONTAINS_TERMS:
            return _Ev(o, _K.WEAK)
        if not o.strong:  # 強くない合格は適合の根拠にならない（推定適合は contains_terms だけ）
            return _Ev(o, _K.NONE, UnverifiableReason.NO_EVIDENCE)
        return _Ev(o, _K.PASS)
    return _Ev(o, _K.NONE, _inconclusive_reason(o))


# Planner（モデル）が前提なしで選べる理由コード（governor.PLANNER_MARK_CODES のうち、前提の観測を要しないもの）。
# 検査できないクラスの要件では、この印を採らず、引用の文面から関門（checks/unverifiable_reason）が理由と固定文を決める。
_MODEL_CHOSEN_CODES = frozenset(
    {UnverifiableReason.HUMAN_ONLY, UnverifiableReason.FUTURE, UnverifiableReason.OUT_OF_SCOPE, UnverifiableReason.NOT_PUBLIC}
)


def _gate_overrides_mark(m: UnverifiableMark, checker: Checker | None) -> bool:
    return checker is None and m.by_planner and m.reason_code in _MODEL_CHOSEN_CODES


def _mark_valid(m: UnverifiableMark, obs_by_id: Mapping[str, Observation]) -> bool:
    """Planner の印は P-UNVERIF-01 の前提を再確認する。コードが付けた印は無条件に採る。

    前提の観測は提出URLについてのもの（リンク先を probe した観測で、提出物の確認不能の理由を言わない）。
    NEEDS_AUTH は、認証壁の観測（不適合）か、ログインを促す画面の観測（login_prompt）が前提。
    """
    if not m.by_planner or m.reason_code not in (UnverifiableReason.NEEDS_AUTH, UnverifiableReason.NEEDS_JS):
        return True
    premise = obs_by_id.get(m.premise_obs_id) if m.premise_obs_id is not None else None
    target = premise.facts.get("target") if premise is not None else None
    if isinstance(target, str) and target != TARGET_SUBMISSION:
        return False
    if m.reason_code is UnverifiableReason.NEEDS_AUTH:
        if premise is None or premise.code is not ObsCode.AUTH_WALL:
            return False
        if _str(premise, "access") == "http_403" and not premise.strong:
            return False  # 取得元IPの制限かもしれない 403 は、ログインが要る理由にならない
        return premise.outcome is ObsOutcome.FAIL or _str(premise, "access") == "login_prompt"
    return premise is not None and premise.code is ObsCode.SPA_SHELL  # NEEDS_JS


# --- 判定 ---------------------------------------------------------------------------------------
def _unverifiable(
    req: VerifiedRequirement, code: UnverifiableReason, text: str, evidence: Sequence[Observation] = ()
) -> Verdict:
    return Verdict(
        req_id=req.req_id,
        label=VerdictLabel.UNVERIFIABLE,
        reason_code=code,
        reason=text,
        evidence=_refs(evidence),
    )


_REFERENCE_TAIL = "参考として表示し、判定の集計に含めません。"


def _reference_reason(req: VerifiedRequirement) -> str:
    """推測（参考）にした理由の文。引用が原文と一致しているのに「原文に引用できない」と書かない（降格の理由ごとに言い分ける）。"""
    if req.span is None:  # 引用が逐語一致せず、モデルの言い換え（推論）だけが残った
        return "要項に引用できないモデルの推論のため、" + _REFERENCE_TAIL
    if req.demotion is DemotionReason.NO_OBLIGATION_WORD:
        return "引用は要項と一致しますが、義務の語が無いため、確かな要件としては扱わず、" + _REFERENCE_TAIL
    if req.demotion is DemotionReason.NEGATION_OR_EXCEPTION:
        return "引用は要項と一致しますが、否定・例外を含む文のため、確かな要件としては扱わず、" + _REFERENCE_TAIL
    if req.demotion is DemotionReason.SENTENCE_TOO_LONG:
        return "引用は要項と一致しますが、文が長く、範囲を確かめきれないため、確かな要件としては扱わず、" + _REFERENCE_TAIL
    return "モデルが推測と申告した要件のため、" + _REFERENCE_TAIL  # 引用は検証済みで、申告が推測のまま


def _decide(
    req: VerifiedRequirement,
    observations: Sequence[Observation],
    mark: UnverifiableMark | None,
    docs: Mapping[str, DocMeta],
    obs_by_id: Mapping[str, Observation],
) -> Verdict:
    if req.kind is Kind.SPECULATIVE:
        return Verdict(req_id=req.req_id, label=VerdictLabel.REFERENCE, reason=_reference_reason(req))

    checker = CHECK_CLASS_CHECKER[req.check_class]
    if checker is not None:
        if req.span is None or not quote_supports_class(req.check_class, req.span.original_span):
            return _unverifiable(
                req,
                UnverifiableReason.OUT_OF_SCOPE,
                "この要件の引用は、割り当てられた検査の内容と合わないため、検査の結果を適用しません。",
            )
        if checker is Checker.CONTAINS_TERMS and req.kind is Kind.PROHIBITED:
            return _unverifiable(
                req,
                UnverifiableReason.OUT_OF_SCOPE,
                "語が在ることを確かめる検査は、禁止の要件には当てはまりません（見つかることが違反になり、向きが逆です）。",
            )
    evs = [_effective(o, docs) for o in observations if checker is not None and o.checker is checker]
    fails = [e.obs for e in evs if e.kind is _K.FAIL]
    passes = [e.obs for e in evs if e.kind is _K.PASS]
    weaks = [e.obs for e in evs if e.kind is _K.WEAK]
    absents = [e.obs for e in evs if e.kind is _K.ABSENT]

    if fails and passes:  # 矛盾する観測は結論にしない（食い違いの両方を証拠として見せる）
        return _unverifiable(
            req,
            UnverifiableReason.NO_EVIDENCE,
            "同じ要件に対する観測が食い違うため、結論にしません（不適合と合格の観測が両方あります）。",
            [*fails, *passes],
        )
    if fails:
        return Verdict(
            req_id=req.req_id, label=VerdictLabel.FAIL, reason=_fail_reason(fails[0]), evidence=_refs(fails)
        )
    if passes:
        return Verdict(
            req_id=req.req_id, label=VerdictLabel.PASS, reason=_pass_reason(passes[0]), evidence=_refs(passes)
        )
    if weaks:
        return Verdict(
            req_id=req.req_id,
            label=VerdictLabel.PRESUMED_PASS,
            reason="提出物のページに求められた語が見つかりました。語が在ることの証明であり、内容の保証ではありません。",
            evidence=_refs(weaks),
        )
    for o in absents:  # 必須要件で語が無く、文書が完全なら不適合
        d = docs.get(o.doc_id) if o.doc_id is not None else None
        if req.kind is Kind.REQUIRED and d is not None and not d.truncated and d.page_class is PageClass.CONTENT:
            return Verdict(
                req_id=req.req_id, label=VerdictLabel.FAIL, reason=_fail_reason(o), evidence=_refs([o])
            )

    if mark is not None and not _gate_overrides_mark(mark, checker) and _mark_valid(mark, obs_by_id):
        premise = obs_by_id.get(mark.premise_obs_id) if mark.premise_obs_id is not None else None
        return _unverifiable(req, mark.reason_code, _unverifiable_text(mark.reason_code), [premise] if premise else [])

    if absents:  # 語が無いが、不適合とは言えない（文書が不完全・content でない・必須でない）
        o = absents[-1]
        d = docs.get(o.doc_id) if o.doc_id is not None else None
        if d is not None and d.truncated:
            code = UnverifiableReason.TRUNCATED
        else:
            code = (_page_reason(d.page_class) if d is not None else None) or UnverifiableReason.NO_EVIDENCE
        return _unverifiable(req, code, _unverifiable_text(code), [o])

    inconclusive = [e for e in evs if e.kind is _K.NONE and e.reason is not None]
    if inconclusive:  # 最新（入力で後ろ）の不確定な観測の理由を採る
        e = inconclusive[-1]
        reason = e.reason or UnverifiableReason.NO_EVIDENCE
        return _unverifiable(req, reason, _unverifiable_text(reason, e.obs), [e.obs])

    if checker is None:  # 検査できないクラス: 引用の文面から、人が確かめる条件か・約束か等を決める（迷えば OUT_OF_SCOPE）
        span = req.span
        if span is None or span.quote_clipped:  # 同梱用に切った引用は文の前半だけ。前半の語で理由を決めない
            code = UnverifiableReason.OUT_OF_SCOPE
        else:
            code = unverifiable_reason(span.original_span, req.kind)
        return _unverifiable(req, code, _NONE_CLASS_TEXT[code])
    code = UnverifiableReason.NO_EVIDENCE
    return _unverifiable(req, code, _unverifiable_text(code))


def adjudicate(inp: AdjudicationInput) -> tuple[Verdict, ...]:
    """要件ごとに Verdict を1つ返す（入力の要件と同じ順）。矛盾（要項間）は判定表の外で別集計する。"""
    docs = {d.doc_id: d for d in inp.docs}
    obs_by_id = {o.obs_id: o for o in inp.observations}
    by_req: dict[str, list[Observation]] = {}
    for o in inp.observations:
        if o.req_id is not None:
            by_req.setdefault(o.req_id, []).append(o)
    marks = {m.req_id: m for m in inp.marks}
    return tuple(
        _decide(r, by_req.get(r.req_id, []), marks.get(r.req_id), docs, obs_by_id) for r in inp.requirements
    )


# --- 要項間の矛盾（判定表の外で別集計。設計 §5-1）----------------------------------------------------
# 矛盾はコードが決める: 同じ slot（Reader が付ける固定語彙）を持つ、異なる文書の2つの検証済み引用から、日付・同単位の数値を
# コードの正規表現で取り出し、両方に値があって1つも重ならない時だけ矛盾とする（ContradictionBasis.TOKEN_DIFF）。
# モデルの「同じ話題だ」という主張は根拠にしない（引用の中の値だけを比べる）。排他属性ペア（現地↔オンライン）は未実装。
_DATE = re.compile(
    r"(?<!\d)(\d{1,2})\s*(?:月\s*(\d{1,2})\s*日|/(\d{1,2})(?!\d))"  # 10月15日・10/15
    r"(?:\s*\([^)]{1,6}\))?"  # （水）などの曜日
    r"(?:\s*(\d{1,2})\s*(?::|時)\s*(\d{2})?)?"  # 23:59・12時
)
_NUMBER_BY_SLOT: dict[Slot, re.Pattern[str]] = {
    Slot.CHAR_LIMIT: re.compile(r"(\d[\d,]*)\s*(文字|字)"),
    Slot.TEAM_SIZE: re.compile(r"(\d+)\s*(名|人)"),
    Slot.VIDEO_LENGTH: re.compile(r"(\d+)\s*(分|秒)"),
}
MAX_CONTRADICTIONS = 16


def slot_tokens(slot: Slot, text: str) -> tuple[str, ...]:
    """引用（コードが原文から切り出した1文）から、矛盾の比較に使う値を取り出す。順序を保ち重複を除く。"""
    flat = unicodedata.normalize("NFKC", text)
    out: list[str] = []
    if slot is Slot.DEADLINE:
        for m in _DATE.finditer(flat):
            month, day = int(m.group(1)), int(m.group(2) or m.group(3))
            if not (1 <= month <= 12 and 1 <= day <= 31):
                continue
            tok = f"{month}/{day}"
            if m.group(4) is not None:
                hour, minute = int(m.group(4)), int(m.group(5) or 0)
                if hour <= 24 and minute < 60:
                    tok += f" {hour}:{minute:02d}"
            out.append(tok)
    elif slot in _NUMBER_BY_SLOT:
        for m in _NUMBER_BY_SLOT[slot].finditer(flat):
            out.append(f"{int(m.group(1).replace(',', ''))}{m.group(2).replace('文字', '字')}")
    return tuple(dict.fromkeys(out))


def find_contradictions(requirements: Sequence[VerifiedRequirement]) -> tuple[Contradiction, ...]:
    """要項間の矛盾（RunRecord.contradictions）。検証済みの引用（span あり）の対だけを、異なる文書どうしで比べる。"""
    cands = [
        (r, toks)
        for r in requirements
        if r.span is not None and r.slot is not Slot.NONE and (toks := slot_tokens(r.slot, r.span.original_span))
    ]
    out: list[Contradiction] = []
    for i, (a, ta) in enumerate(cands):
        for b, tb in cands[i + 1 :]:
            assert a.span is not None and b.span is not None
            if a.slot is not b.slot or a.span.doc_id == b.span.doc_id or set(ta) & set(tb):
                continue
            out.append(
                Contradiction(
                    slot=a.slot, req_ids=(a.req_id, b.req_id), basis=ContradictionBasis.TOKEN_DIFF, tokens=(ta[0][:40], tb[0][:40])
                )
            )
            if len(out) >= MAX_CONTRADICTIONS:
                return tuple(out)
    return tuple(out)
