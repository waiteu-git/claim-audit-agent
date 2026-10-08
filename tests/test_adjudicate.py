"""判定表（adjudicate.py）の全分岐: 適合・推定適合・不適合・確認不能（理由コード）・参考・観測の食い違い・印の扱い。"""
from typing import Any

import pytest

import app.contracts as C
from app.adjudicate import adjudicate, evidence_label
from app.textsafe import BLOCK_SEP
from tests.factories import make_doc, make_record, make_verified, seal

L = C.VerdictLabel
U = C.UnverifiableReason
CC = C.CheckClass

SENTENCES = {
    "len": "提出物の説明は800字以内とする。",
    "auth": "提出URLは審査員がログインなしで開けること。",
    "guide": "テストアカウントの案内を記載すること。",
    "runtime": "提出物はCloud Run上で動作すること。",
    "leak": "公開物にメールアドレスを載せてはならない。",
    "free": "プライバシーポリシーを整備すること。",
    "video": "動画のURLを記載できます。",
}
SPEC = make_doc("D1", BLOCK_SEP.join(SENTENCES.values()))


def R(req_id: str, key: str, cls: C.CheckClass, kind: C.Kind = C.Kind.REQUIRED, **kw: Any) -> C.VerifiedRequirement:
    return make_verified(req_id, doc=SPEC, needle=SENTENCES[key], kind=kind, check_class=cls, **kw)


def sub_doc(doc_id: str = "D3", *, truncated: bool = False, page_class: C.PageClass = C.PageClass.CONTENT) -> C.SanitizedDoc:
    return make_doc(doc_id, "提出物の本文", role=C.DocRole.SUBMISSION, truncated=truncated, page_class=page_class,
                    url="https://svc.example.invalid/fx/defect/submission/")  # fmt: skip


def O(
    obs_id: str,
    req_id: str | None,
    checker: C.Checker | None,
    code: C.ObsCode,
    outcome: C.ObsOutcome,
    *,
    strong: bool = False,
    doc_id: str | None = None,
    facts: dict | None = None,
    tool: C.ToolName = C.ToolName.RUN_CHECK,
    event_seq: int | None = None,
) -> C.Observation:
    return C.Observation(obs_id=obs_id, tool=tool, checker=checker, req_id=req_id, doc_id=doc_id, code=code, outcome=outcome,
                         strong=strong, facts=facts or {}, event_seq=event_seq)  # fmt: skip


def run(reqs, observations=(), marks=(), docs=None) -> tuple[C.Verdict, ...]:
    metas = tuple(d.meta() for d in (docs if docs is not None else [SPEC, sub_doc()]))
    return adjudicate(C.AdjudicationInput(requirements=tuple(reqs), docs=metas, observations=tuple(observations), marks=tuple(marks)))


def one(req, observations=(), marks=(), docs=None) -> C.Verdict:
    (v,) = run([req], observations, marks, docs)
    return v


OVER = dict(code=C.ObsCode.OVER_LIMIT, outcome=C.ObsOutcome.FAIL, strong=True,
            facts={"limit": 800, "chars_with_ws": 1130, "chars_no_ws": 1002, "over_with_ws": True, "over_no_ws": True})  # fmt: skip
WITHIN = dict(code=C.ObsCode.WITHIN_LIMIT, outcome=C.ObsOutcome.PASS, strong=True,
              facts={"limit": 800, "chars_with_ws": 700, "chars_no_ws": 650, "over_with_ws": False, "over_no_ws": False})  # fmt: skip
WALL = dict(code=C.ObsCode.AUTH_WALL, outcome=C.ObsOutcome.FAIL, strong=True,
            facts={"access": "login_redirect", "status": 200, "redirect_status": 302, "location_path": "/fx/defect/login/", "has_password_input": True})  # fmt: skip
OPEN = dict(code=C.ObsCode.NO_AUTH_WALL, outcome=C.ObsOutcome.PASS, strong=True, facts={"access": "public", "status": 200})


def len_obs(obs_id="O1", **spec) -> C.Observation:
    base = dict(OVER)
    base.update(spec)
    return O(obs_id, "R1", C.Checker.TEXT_LENGTH, doc_id="D3", **base)


def auth_obs(obs_id="O2", **spec) -> C.Observation:
    base = dict(WALL)
    base.update(spec)
    return O(obs_id, "R2", C.Checker.AUTH_WALL, **base)


# ---------------------------------------------------------------------------
# 適合・不適合（OBS強）
# ---------------------------------------------------------------------------
def test_strong_pass_is_a_machine_verified_pass_with_a_chip():
    v = one(R("R1", "len", CC.LENGTH_LIMIT), [len_obs(**WITHIN)])
    assert v.label is L.PASS and v.reason_code is None
    assert [e.label for e in v.evidence] == ["700字（上限800字）"] and v.evidence[0].obs_id == "O1"


def test_demo_d1_over_the_limit_by_both_measures_is_a_fail_with_the_counts_in_the_chip():
    v = one(R("R1", "len", CC.LENGTH_LIMIT), [len_obs(event_seq=3)])
    assert v.label is L.FAIL
    assert v.evidence[0].label == "1,130字・空白除き1,002字（上限800字）" and v.evidence[0].event_seq == 3
    assert "1,130" in v.reason and "800" in v.reason


def test_demo_d2_login_redirect_with_a_password_field_is_a_fail_and_the_hero_chip():
    v = one(R("R2", "auth", CC.AUTH_WALL), [auth_obs(event_seq=4)])
    assert v.label is L.FAIL
    assert v.evidence[0].label == "302→/fx/defect/login/・password欄あり" and v.evidence[0].event_seq == 4


@pytest.mark.parametrize(
    ("spec", "label"),
    [
        (dict(facts={"access": "http_401", "status": 401}), "401・認証が必要"),
        (dict(facts={"access": "http_403", "status": 403}, strong=True), "403・アクセス拒否"),  # 強い 403 は Cloud Run の IAM の壁
        (dict(facts={"access": "idp_redirect", "redirect_status": 302}), "302→外部の認証サービスへ転送"),
        (dict(facts={"access": "login_form", "status": 200, "has_password_input": True}), "200・ログイン画面（password欄あり）"),
        (dict(facts={"access": "login_redirect", "redirect_status": 0, "location_path": "/login"}), "meta転送→/login"),
    ],
)
def test_every_wall_kind_is_a_fail_with_its_own_chip(spec, label):
    v = one(R("R2", "auth", CC.AUTH_WALL), [auth_obs(**spec)])
    assert v.label is L.FAIL and v.evidence[0].label == label


def test_open_page_is_a_pass_for_the_auth_wall_class():
    v = one(R("R2", "auth", CC.AUTH_WALL), [auth_obs(**OPEN)])
    assert v.label is L.PASS and v.evidence[0].label == "200・ログイン不要で開ける"


def test_http_errors_are_fails_for_the_auth_wall_class():
    nf = auth_obs(code=C.ObsCode.ERROR, outcome=C.ObsOutcome.FAIL, strong=True, facts={"access": "not_found", "status": 404})
    v = one(R("R2", "auth", CC.AUTH_WALL), [nf])
    assert v.label is L.FAIL and v.evidence[0].label == "404・ページが見つからない"
    se = auth_obs(code=C.ObsCode.ERROR, outcome=C.ObsOutcome.FAIL, strong=False, facts={"access": "http_error", "status": 500})
    assert one(R("R2", "auth", CC.AUTH_WALL), [se]).label is L.FAIL


def test_runtime_signature_present_is_a_pass_and_absent_is_never_a_fail():
    req = R("R4", "runtime", CC.RUNTIME_SIGNATURE)
    present = O("O1", "R4", C.Checker.CLOUD_RUN_SIGNATURE, C.ObsCode.SIGNATURE_PRESENT, C.ObsOutcome.PASS, strong=True)
    v = one(req, [present])
    assert v.label is L.PASS and "run.app" not in v.evidence[0].label  # 証拠チップにホスト名（run.app）を載せない
    absent = O("O1", "R4", C.Checker.CLOUD_RUN_SIGNATURE, C.ObsCode.SIGNATURE_ABSENT, C.ObsOutcome.INCONCLUSIVE)
    va = one(req, [absent])
    assert (va.label, va.reason_code) == (L.UNVERIFIABLE, U.NO_EVIDENCE)
    forged = O("O1", "R4", C.Checker.CLOUD_RUN_SIGNATURE, C.ObsCode.SIGNATURE_ABSENT, C.ObsOutcome.FAIL)  # 不適合と書かれても採らない
    assert one(req, [forged]).label is L.UNVERIFIABLE


def test_leak_found_is_a_fail_and_no_leak_needs_a_complete_content_doc():
    req = R("R5", "leak", CC.LEAK, kind=C.Kind.PROHIBITED)
    found = O("O1", "R5", C.Checker.LEAK_SCAN, C.ObsCode.LEAK_FOUND, C.ObsOutcome.FAIL, strong=True, doc_id="D3")
    assert one(req, [found]).label is L.FAIL
    clean = O("O1", "R5", C.Checker.LEAK_SCAN, C.ObsCode.NO_LEAK, C.ObsOutcome.PASS, strong=True, doc_id="D3")
    assert one(req, [clean]).label is L.PASS
    assert one(req, [clean], docs=[SPEC, sub_doc(truncated=True)]).reason_code is U.TRUNCATED  # 読み切れていない「漏洩なし」は適合にしない
    assert one(req, [found], docs=[SPEC, sub_doc(truncated=True)]).label is L.FAIL  # 漏洩の発見は打切りでも覆らない


# ---------------------------------------------------------------------------
# 確認不能: 不確定な観測ごとの理由コード
# ---------------------------------------------------------------------------
INC = C.ObsOutcome.INCONCLUSIVE


@pytest.mark.parametrize(
    ("cls", "checker", "code", "facts", "reason"),
    [
        (CC.AUTH_WALL, C.Checker.AUTH_WALL, C.ObsCode.TRANSIENT, {"access": "unreachable"}, U.TRANSIENT),
        (CC.AUTH_WALL, C.Checker.AUTH_WALL, C.ObsCode.SPA_SHELL, {"access": "spa_shell"}, U.NEEDS_JS),
        (CC.AUTH_WALL, C.Checker.AUTH_WALL, C.ObsCode.BLOCKED, {"access": "unknown_redirect", "unfollowed": True}, U.OUT_OF_SCOPE),
        (CC.AUTH_WALL, C.Checker.AUTH_WALL, C.ObsCode.BLOCKED, {"access": "blocked", "policy": "P-SCOPE-01"}, U.FETCH_BLOCKED),
        (CC.AUTH_WALL, C.Checker.AUTH_WALL, C.ObsCode.UNSUPPORTED_TYPE, {"access": "unsupported_type"}, U.UNSUPPORTED_TYPE),
        (CC.AUTH_WALL, C.Checker.AUTH_WALL, C.ObsCode.ERROR, {"access": "too_large"}, U.TRUNCATED),
        (CC.AUTH_WALL, C.Checker.AUTH_WALL, C.ObsCode.ERROR, {"access": "redirect_limit"}, U.FETCH_BLOCKED),
        (CC.AUTH_WALL, C.Checker.AUTH_WALL, C.ObsCode.ERROR, {"access": "http_error", "status": 400}, U.NO_EVIDENCE),
        (CC.AUTH_WALL, C.Checker.AUTH_WALL, C.ObsCode.ERROR, {"reason": "no_probe"}, U.NO_EVIDENCE),
        (CC.AUTH_WALL, C.Checker.AUTH_WALL, C.ObsCode.AUTH_WALL, {"access": "form_on_content", "text_len": 4000}, U.NO_EVIDENCE),
        (CC.LENGTH_LIMIT, C.Checker.TEXT_LENGTH, C.ObsCode.LIMIT_UNDECIDABLE, {"limit": 800, "chars_with_ws": 810, "chars_no_ws": 790}, U.HUMAN_ONLY),
        (CC.LENGTH_LIMIT, C.Checker.TEXT_LENGTH, C.ObsCode.NO_PARAMETER, {"why": "no_upper_limit"}, U.NO_EVIDENCE),
        (CC.LENGTH_LIMIT, C.Checker.TEXT_LENGTH, C.ObsCode.ERROR, {"why": "no_submission_doc"}, U.NO_EVIDENCE),
    ],
)  # fmt: skip
def test_inconclusive_observations_become_unverifiable_with_the_matching_reason(cls, checker, code, facts, reason):
    req = R("R9", "auth" if cls is CC.AUTH_WALL else "len", cls)
    obs = O("O1", "R9", checker, code, INC, doc_id="D3" if checker is C.Checker.TEXT_LENGTH else None, facts=facts)
    v = one(req, [obs])
    assert (v.label, v.reason_code) == (L.UNVERIFIABLE, reason)
    assert v.evidence and v.evidence[0].obs_id == "O1"  # 確認不能の根拠になった観測も見せる


def test_undecidable_count_explains_that_a_person_must_pick_the_counting_rule():
    obs = len_obs(code=C.ObsCode.LIMIT_UNDECIDABLE, outcome=INC, strong=False,
                  facts={"limit": 800, "chars_with_ws": 810, "chars_no_ws": 790})  # fmt: skip
    v = one(R("R1", "len", CC.LENGTH_LIMIT), [obs])
    assert v.reason_code is U.HUMAN_ONLY and "810" in v.reason and "790" in v.reason and "800" in v.reason
    assert v.evidence[0].label == "810字・空白除き790字（上限800字）"


def test_latest_inconclusive_observation_decides_the_reason():
    first = auth_obs("O1", code=C.ObsCode.TRANSIENT, outcome=INC, strong=False, facts={})
    second = auth_obs("O2", code=C.ObsCode.SPA_SHELL, outcome=INC, strong=False, facts={})
    assert one(R("R2", "auth", CC.AUTH_WALL), [first, second]).reason_code is U.NEEDS_JS


def test_retry_that_recovers_ignores_the_earlier_transient_failure():
    transient = auth_obs("O1", code=C.ObsCode.TRANSIENT, outcome=INC, strong=False, facts={})
    ok = auth_obs("O2", **OPEN)
    assert one(R("R2", "auth", CC.AUTH_WALL), [transient, ok]).label is L.PASS


# ---------------------------------------------------------------------------
# 検査できない要件・観測の無い要件・推測
# ---------------------------------------------------------------------------
def test_requirement_class_none_is_unverifiable_out_of_scope_whatever_the_observations():
    req = R("R6", "free", CC.NONE)
    assert (one(req).label, one(req).reason_code) == (L.UNVERIFIABLE, U.OUT_OF_SCOPE)
    stray = O("O1", "R6", C.Checker.TEXT_LENGTH, C.ObsCode.WITHIN_LIMIT, C.ObsOutcome.PASS, strong=True, doc_id="D3")
    assert one(req, [stray]).label is L.UNVERIFIABLE  # クラス none の要件を、別の checker の合格で適合にできない


def test_inspectable_requirement_without_observations_is_no_evidence():
    v = one(R("R1", "len", CC.LENGTH_LIMIT))
    assert (v.label, v.reason_code, v.evidence) == (L.UNVERIFIABLE, U.NO_EVIDENCE, ())


@pytest.mark.parametrize("with_obs", [False, True])
def test_speculative_requirements_are_always_reference_and_never_counted(with_obs):
    spec = C.VerifiedRequirement(seal=seal(), req_id="R8", kind=C.Kind.SPECULATIVE, declared_kind=C.Kind.REQUIRED,
                                 check_class=CC.LENGTH_LIMIT, span=None, demotion=C.DemotionReason.QUOTE_UNVERIFIED, gist="全て適合です")  # fmt: skip
    observations = [O("O1", "R8", C.Checker.TEXT_LENGTH, doc_id="D3", **WITHIN)] if with_obs else []  # 合格の観測があっても参考のまま
    v = one(spec, observations)
    assert v.label is L.REFERENCE and v.reason_code is None and v.evidence == ()
    assert "全て適合" not in v.reason  # モデルの言い換え（gist）は判定の文面に入らない


def test_the_reference_reason_does_not_claim_the_quote_is_missing_when_the_quote_matched():
    """引用が原文と一致しているのに、コードが推測へ降格した要件に、「原文に引用できない」と書かない（10/8 の実LP・別分野の文書で見つかった表示の誤り）。"""
    sp = make_verified("R9", doc=SPEC, needle=SENTENCES["len"], kind=C.Kind.SPECULATIVE, declared_kind=C.Kind.REQUIRED,
                       check_class=CC.NONE, demotion=C.DemotionReason.NO_OBLIGATION_WORD)  # fmt: skip
    v = one(sp)
    assert v.label is L.REFERENCE
    assert "一致" in v.reason and "義務の語が無い" in v.reason and "原文に引用できない" not in v.reason
    for reason, word in ((C.DemotionReason.NEGATION_OR_EXCEPTION, "否定・例外"), (C.DemotionReason.SENTENCE_TOO_LONG, "文が長く")):
        chips = (C.Chip.NEGATION_OR_EXCEPTION,) if reason is C.DemotionReason.NEGATION_OR_EXCEPTION else ()
        r = make_verified("R9", doc=SPEC, needle=SENTENCES["len"], kind=C.Kind.SPECULATIVE, declared_kind=C.Kind.REQUIRED,
                          check_class=CC.NONE, demotion=reason, chips=chips)  # fmt: skip
        assert word in one(r).reason and "原文に引用できない" not in one(r).reason
    declared = make_verified("R9", doc=SPEC, needle=SENTENCES["len"], kind=C.Kind.SPECULATIVE, declared_kind=C.Kind.SPECULATIVE, check_class=CC.NONE)
    assert "推測と申告" in one(declared).reason


# ---------------------------------------------------------------------------
# 観測の食い違い・取り違え（矛盾した入力の扱い）
# ---------------------------------------------------------------------------
def test_conflicting_strong_observations_are_not_a_conclusion_and_both_are_shown():
    fail = len_obs("O1")
    ok = len_obs("O2", **WITHIN)
    v = one(R("R1", "len", CC.LENGTH_LIMIT), [fail, ok])
    assert (v.label, v.reason_code) == (L.UNVERIFIABLE, U.NO_EVIDENCE)
    assert {e.obs_id for e in v.evidence} == {"O1", "O2"} and "食い違" in v.reason


def test_a_fail_beats_inconclusive_observations_and_a_pass_beats_them_too():
    inc = auth_obs("O1", code=C.ObsCode.TRANSIENT, outcome=INC, strong=False, facts={})
    assert one(R("R2", "auth", CC.AUTH_WALL), [inc, auth_obs("O2")]).label is L.FAIL
    assert one(R("R2", "auth", CC.AUTH_WALL), [auth_obs("O2", **OPEN), inc]).label is L.PASS


def test_observation_from_another_checker_is_ignored():
    """text_length の合格を auth_wall 要件の適合に使えない（Planner が checker を取り違えても）。"""
    wrong = O("O1", "R2", C.Checker.TEXT_LENGTH, C.ObsCode.WITHIN_LIMIT, C.ObsOutcome.PASS, strong=True, doc_id="D3")
    v = one(R("R2", "auth", CC.AUTH_WALL), [wrong])
    assert (v.label, v.reason_code, v.evidence) == (L.UNVERIFIABLE, U.NO_EVIDENCE, ())


def test_observation_without_a_checker_is_not_evidence_for_a_requirement():
    probe_like = O("O1", "R2", None, C.ObsCode.NO_AUTH_WALL, C.ObsOutcome.PASS, strong=True, tool=C.ToolName.HTTP_PROBE)
    assert one(R("R2", "auth", CC.AUTH_WALL), [probe_like]).label is L.UNVERIFIABLE


def test_probe_observations_not_bound_to_a_requirement_do_not_decide_anything():
    probe = O("O1", None, None, C.ObsCode.AUTH_WALL, C.ObsOutcome.FAIL, strong=True, tool=C.ToolName.HTTP_PROBE)
    assert one(R("R2", "auth", CC.AUTH_WALL), [probe]).label is L.UNVERIFIABLE


@pytest.mark.parametrize(
    "bad",
    [
        dict(code=C.ObsCode.OVER_LIMIT, outcome=C.ObsOutcome.PASS, strong=True),  # コードと結末が逆
        dict(code=C.ObsCode.WITHIN_LIMIT, outcome=C.ObsOutcome.FAIL, strong=True),
        dict(code=C.ObsCode.NO_AUTH_WALL, outcome=C.ObsOutcome.PASS, strong=True),  # checker とコードの組が違う（auth_wall のコード）
        dict(code=C.ObsCode.LEAK_FOUND, outcome=C.ObsOutcome.FAIL, strong=True),
        dict(code=C.ObsCode.TRANSIENT, outcome=C.ObsOutcome.PASS),
    ],
)
def test_inconsistent_observations_are_not_evidence(bad):
    v = one(R("R1", "len", CC.LENGTH_LIMIT), [O("O1", "R1", C.Checker.TEXT_LENGTH, doc_id="D3", **bad)])
    assert (v.label, v.reason_code) == (L.UNVERIFIABLE, U.NO_EVIDENCE)


def test_a_weak_pass_from_a_checker_other_than_contains_terms_is_not_a_pass():
    weak = len_obs(code=C.ObsCode.WITHIN_LIMIT, outcome=C.ObsOutcome.PASS, strong=False, facts={})
    v = one(R("R1", "len", CC.LENGTH_LIMIT), [weak])
    assert (v.label, v.reason_code) == (L.UNVERIFIABLE, U.NO_EVIDENCE)


def test_observation_that_points_at_another_requirement_is_not_used():
    other = O("O1", "R1", C.Checker.TEXT_LENGTH, doc_id="D3", **WITHIN)
    v1, v2 = run([R("R1", "len", CC.LENGTH_LIMIT), R("R2", "auth", CC.AUTH_WALL)], [other])
    assert v1.label is L.PASS and v2.label is L.UNVERIFIABLE


# ---------------------------------------------------------------------------
# 文書の状態: 打切り・ログイン壁・JS 描画の本文は「無い」を証明しない
# ---------------------------------------------------------------------------
def test_pass_on_a_truncated_document_is_not_a_pass_but_a_fail_still_is():
    docs = [SPEC, sub_doc(truncated=True)]
    v_pass = one(R("R1", "len", CC.LENGTH_LIMIT), [len_obs(**WITHIN)], docs=docs)
    assert (v_pass.label, v_pass.reason_code) == (L.UNVERIFIABLE, U.TRUNCATED)
    v_fail = one(R("R1", "len", CC.LENGTH_LIMIT), [len_obs()], docs=docs)  # 続きが増えても字数は減らない
    assert v_fail.label is L.FAIL


@pytest.mark.parametrize(
    ("page", "reason"),
    [
        (C.PageClass.LOGIN_WALL, U.NEEDS_AUTH),
        (C.PageClass.SPA_SHELL, U.NEEDS_JS),
        (C.PageClass.ERROR_PAGE, U.NO_EVIDENCE),
        (C.PageClass.EMPTY, U.NO_EVIDENCE),
    ],
)
def test_text_length_on_a_page_that_is_not_the_description_is_unverifiable(page, reason):
    docs = [SPEC, sub_doc(page_class=page)]
    for spec in (WITHIN, OVER):  # ログイン画面の字数で、合格にも不適合にもしない
        v = one(R("R1", "len", CC.LENGTH_LIMIT), [len_obs(**spec)], docs=docs)
        assert (v.label, v.reason_code) == (L.UNVERIFIABLE, reason)


def test_body_observation_without_a_document_cannot_pass():
    nodoc = O("O1", "R1", C.Checker.TEXT_LENGTH, **WITHIN)
    assert one(R("R1", "len", CC.LENGTH_LIMIT), [nodoc]).label is L.UNVERIFIABLE


# ---------------------------------------------------------------------------
# 推定適合・語の不在（contains_terms。G3 の観測の形を判定表が前提にしている）
# ---------------------------------------------------------------------------
def terms_obs(code: C.ObsCode, outcome: C.ObsOutcome, doc_id: str | None = "D3", obs_id: str = "O1") -> C.Observation:
    return O(obs_id, "R3", C.Checker.CONTAINS_TERMS, code, outcome, doc_id=doc_id)


def test_terms_found_is_a_presumed_pass_with_the_self_declared_caveat():
    v = one(R("R3", "guide", CC.GUIDANCE_PRESENT), [terms_obs(C.ObsCode.TERMS_FOUND, C.ObsOutcome.PASS)])
    assert v.label is L.PRESUMED_PASS and "保証ではありません" in v.reason
    assert v.evidence[0].label == "求められた語が本文にある（自己申告）"


def test_terms_found_is_presumed_pass_even_on_a_truncated_document():
    v = one(R("R3", "guide", CC.GUIDANCE_PRESENT), [terms_obs(C.ObsCode.TERMS_FOUND, C.ObsOutcome.PASS)], docs=[SPEC, sub_doc(truncated=True)])
    assert v.label is L.PRESUMED_PASS  # 在るものは在る（無いことの証明ではない）


def test_terms_found_on_a_login_page_is_not_presumed_pass():
    v = one(R("R3", "guide", CC.GUIDANCE_PRESENT), [terms_obs(C.ObsCode.TERMS_FOUND, C.ObsOutcome.PASS)], docs=[SPEC, sub_doc(page_class=C.PageClass.LOGIN_WALL)])
    assert (v.label, v.reason_code) == (L.UNVERIFIABLE, U.NEEDS_AUTH)


@pytest.mark.parametrize("outcome", [C.ObsOutcome.INCONCLUSIVE, C.ObsOutcome.FAIL])  # チェッカーがどちらで返しても判定表が決める
def test_required_terms_absent_on_a_complete_content_doc_is_a_fail(outcome):
    v = one(R("R3", "guide", CC.GUIDANCE_PRESENT), [terms_obs(C.ObsCode.TERMS_ABSENT, outcome)])
    assert v.label is L.FAIL and v.evidence[0].label == "求められた語が本文に無い"


@pytest.mark.parametrize(
    ("docs", "reason"),
    [
        ([SPEC, sub_doc(truncated=True)], U.TRUNCATED),  # 続きにあるかもしれない
        ([SPEC, sub_doc(page_class=C.PageClass.LOGIN_WALL)], U.NEEDS_AUTH),
        ([SPEC, sub_doc(page_class=C.PageClass.SPA_SHELL)], U.NEEDS_JS),
        ([SPEC, sub_doc(page_class=C.PageClass.ERROR_PAGE)], U.NO_EVIDENCE),
    ],
)
@pytest.mark.parametrize("outcome", [C.ObsOutcome.INCONCLUSIVE, C.ObsOutcome.FAIL])
def test_terms_absent_on_an_incomplete_document_is_unverifiable_never_a_fail(docs, reason, outcome):
    v = one(R("R3", "guide", CC.GUIDANCE_PRESENT), [terms_obs(C.ObsCode.TERMS_ABSENT, outcome)], docs=docs)
    assert (v.label, v.reason_code) == (L.UNVERIFIABLE, reason)


@pytest.mark.parametrize("kind", [C.Kind.OPTIONAL, C.Kind.REQUEST])  # 禁止は向きが逆なので検査を当てない（tests/test_adversarial_adjudicate.py）
def test_terms_absent_is_a_fail_only_for_a_required_requirement(kind):
    v = one(R("R3", "guide", CC.GUIDANCE_PRESENT, kind=kind), [terms_obs(C.ObsCode.TERMS_ABSENT, C.ObsOutcome.INCONCLUSIVE)])
    assert (v.label, v.reason_code) == (L.UNVERIFIABLE, U.NO_EVIDENCE)


def test_terms_absent_without_a_document_is_not_a_fail():
    v = one(R("R3", "guide", CC.GUIDANCE_PRESENT), [terms_obs(C.ObsCode.TERMS_ABSENT, C.ObsOutcome.INCONCLUSIVE, doc_id=None)])
    assert v.label is L.UNVERIFIABLE


def test_terms_found_beats_terms_absent_on_another_document():
    found = terms_obs(C.ObsCode.TERMS_FOUND, C.ObsOutcome.PASS, "D3", "O1")
    absent = terms_obs(C.ObsCode.TERMS_ABSENT, C.ObsOutcome.INCONCLUSIVE, "D4", "O2")
    docs = [SPEC, sub_doc("D3"), sub_doc("D4")]
    assert one(R("R3", "guide", CC.GUIDANCE_PRESENT), [found, absent], docs=docs).label is L.PRESUMED_PASS


# ---------------------------------------------------------------------------
# 確認不能の印（mark_unverifiable・コードの確定）
# ---------------------------------------------------------------------------
def mark(code: U, *, premise: str | None = None, by_planner: bool = False, req_id: str = "R1") -> C.UnverifiableMark:
    return C.UnverifiableMark(req_id=req_id, reason_code=code, premise_obs_id=premise, by_planner=by_planner)


def test_code_set_mark_gives_the_reason_when_nothing_else_decides():
    v = one(R("R1", "len", CC.LENGTH_LIMIT), marks=[mark(U.BUDGET)])
    assert (v.label, v.reason_code) == (L.UNVERIFIABLE, U.BUDGET)


@pytest.mark.parametrize("code", [U.HUMAN_ONLY, U.NOT_PUBLIC, U.FUTURE, U.OUT_OF_SCOPE, U.NO_EVIDENCE])
def test_planner_marks_without_a_premise_requirement_are_accepted(code):
    v = one(R("R6", "free", CC.NONE), marks=[mark(code, by_planner=True, req_id="R6")])
    assert v.reason_code is code


def probe_obs(obs_id: str = "O2", **spec) -> C.Observation:
    """前提の観測になる http_probe の観測（要件に結び付かない）。"""
    base = dict(WALL)
    base.update(spec)
    return O(obs_id, None, None, tool=C.ToolName.HTTP_PROBE, **base)


def test_planner_needs_auth_requires_an_auth_wall_observation_as_premise():
    req = R("R3", "guide", CC.GUIDANCE_PRESENT)
    ok_mark = mark(U.NEEDS_AUTH, premise="O2", by_planner=True, req_id="R3")
    v = one(req, [probe_obs("O2")], marks=[ok_mark])
    assert v.reason_code is U.NEEDS_AUTH and v.evidence[0].obs_id == "O2"
    # 前提が無い・別の観測・不確定な観測 → 印は採らない（Planner が理由を自由に付けられない）
    cases = (
        ([], None),
        ([probe_obs("O2", **OPEN)], "O2"),
        ([probe_obs("O2", code=C.ObsCode.TRANSIENT, outcome=INC, strong=False, facts={})], "O2"),
    )
    for premise_obs, premise_id in cases:
        bad = mark(U.NEEDS_AUTH, premise=premise_id, by_planner=True, req_id="R3")
        assert one(req, premise_obs, marks=[bad]).reason_code is U.NO_EVIDENCE, premise_obs


def test_planner_needs_js_requires_a_spa_shell_observation_as_premise():
    spa = probe_obs("O2", code=C.ObsCode.SPA_SHELL, outcome=INC, strong=False, facts={"access": "spa_shell"})
    req = R("R3", "guide", CC.GUIDANCE_PRESENT)
    needs_js = mark(U.NEEDS_JS, premise="O2", by_planner=True, req_id="R3")
    assert one(req, [spa], marks=[needs_js]).reason_code is U.NEEDS_JS
    assert one(req, [probe_obs("O2")], marks=[needs_js]).reason_code is U.NO_EVIDENCE
    assert one(req, [], marks=[mark(U.NEEDS_JS, by_planner=True, req_id="R3")]).reason_code is U.NO_EVIDENCE


def test_code_set_needs_auth_mark_is_accepted_without_a_premise():
    """コードが付けた印（ACQUIRE で非 content の文書を見つけた等）は前提の再確認を要しない。"""
    v = one(R("R3", "guide", CC.GUIDANCE_PRESENT), marks=[mark(U.NEEDS_AUTH, req_id="R3")])
    assert v.reason_code is U.NEEDS_AUTH


def test_a_mark_never_turns_a_fail_or_a_pass_or_a_presumed_pass_into_unverifiable():
    """S-03: 不適合を確認不能に洗浄できない。証拠がある要件は、印があっても証拠を採る。"""
    m = mark(U.HUMAN_ONLY, by_planner=True)
    req = R("R1", "len", CC.LENGTH_LIMIT)
    assert one(req, [len_obs()], marks=[m]).label is L.FAIL
    assert one(req, [len_obs(**WITHIN)], marks=[m]).label is L.PASS
    r3 = R("R3", "guide", CC.GUIDANCE_PRESENT)
    found = terms_obs(C.ObsCode.TERMS_FOUND, C.ObsOutcome.PASS)
    assert one(r3, [found], marks=[mark(U.HUMAN_ONLY, by_planner=True, req_id="R3")]).label is L.PRESUMED_PASS
    absent = terms_obs(C.ObsCode.TERMS_ABSENT, C.ObsOutcome.INCONCLUSIVE)
    assert one(r3, [absent], marks=[mark(U.HUMAN_ONLY, by_planner=True, req_id="R3")]).label is L.FAIL


def test_a_mark_overrides_the_reason_derived_from_inconclusive_observations():
    transient = auth_obs("O1", code=C.ObsCode.TRANSIENT, outcome=INC, strong=False, facts={})
    v = one(R("R2", "auth", CC.AUTH_WALL), [transient], marks=[mark(U.BUDGET, req_id="R2")])
    assert v.reason_code is U.BUDGET


def test_a_mark_does_not_apply_to_other_requirements():
    v1, v2 = run([R("R1", "len", CC.LENGTH_LIMIT), R("R2", "auth", CC.AUTH_WALL)], marks=[mark(U.BUDGET)])
    assert v1.reason_code is U.BUDGET and v2.reason_code is U.NO_EVIDENCE


def test_a_mark_does_not_make_a_speculative_requirement_anything_but_reference():
    spec = C.VerifiedRequirement(seal=seal(), req_id="R8", kind=C.Kind.SPECULATIVE, declared_kind=C.Kind.SPECULATIVE,
                                 span=None, demotion=C.DemotionReason.QUOTE_UNVERIFIED, gist="推測")  # fmt: skip
    v = one(spec, marks=[mark(U.BUDGET, req_id="R8")])
    assert v.label is L.REFERENCE and v.reason_code is None


# ---------------------------------------------------------------------------
# 全体の性質: 順序・1要件1判定・決定論・証拠チップ・RunRecord との整合
# ---------------------------------------------------------------------------
def build_run():
    reqs = [
        R("R1", "len", CC.LENGTH_LIMIT),
        R("R2", "auth", CC.AUTH_WALL),
        R("R3", "guide", CC.GUIDANCE_PRESENT),
        R("R4", "runtime", CC.RUNTIME_SIGNATURE),
        R("R5", "leak", CC.LEAK, kind=C.Kind.PROHIBITED),
        R("R6", "free", CC.NONE),
        R("R7", "video", CC.URL_PRESENT, kind=C.Kind.OPTIONAL),
        C.VerifiedRequirement(seal=seal(), req_id="R8", kind=C.Kind.SPECULATIVE, declared_kind=C.Kind.REQUIRED,
                              span=None, demotion=C.DemotionReason.QUOTE_UNVERIFIED, gist="推測です"),
    ]  # fmt: skip
    observations = [
        len_obs("O1"),
        auth_obs("O2", event_seq=4),
        O("O3", "R4", C.Checker.CLOUD_RUN_SIGNATURE, C.ObsCode.SIGNATURE_PRESENT, C.ObsOutcome.PASS, strong=True),
        O("O4", None, None, C.ObsCode.AUTH_WALL, C.ObsOutcome.FAIL, strong=True, tool=C.ToolName.HTTP_PROBE),
    ]  # fmt: skip
    marks = [mark(U.HUMAN_ONLY, req_id="R6", by_planner=True), mark(U.BUDGET, req_id="R7")]
    return reqs, observations, marks


def test_one_verdict_per_requirement_in_input_order():
    reqs, observations, marks = build_run()
    verdicts = run(reqs, observations, marks)
    assert [v.req_id for v in verdicts] == [r.req_id for r in reqs]
    assert [v.label for v in verdicts] == [L.FAIL, L.FAIL, L.UNVERIFIABLE, L.PASS, L.UNVERIFIABLE, L.UNVERIFIABLE, L.UNVERIFIABLE, L.REFERENCE]
    assert [v.reason_code for v in verdicts] == [None, None, U.NO_EVIDENCE, None, U.NO_EVIDENCE, U.HUMAN_ONLY, U.BUDGET, None]


def test_adjudication_is_deterministic_and_independent_of_unrelated_observations_order():
    reqs, observations, marks = build_run()
    a = run(reqs, observations, marks)
    assert a == run(reqs, observations, marks)
    swapped = [observations[3], observations[2], observations[1], observations[0]]  # 別の要件の観測の並びは結果に影響しない
    assert a == run(reqs, swapped, marks)


def test_verdicts_fit_the_run_record_rules():
    """RunRecord の規則（全要件に判定・推測は必ず参考・証拠は記録済みの観測を指す）を、判定表の出力がそのまま満たす。"""
    reqs, observations, marks = build_run()
    verdicts = run(reqs, observations, marks)
    docs = (SPEC.meta(), sub_doc().meta())
    rec = make_record(requirements=tuple(reqs), docs=docs, verdicts=verdicts, observations=tuple(observations))
    assert rec.summary.verdict_counts[L.FAIL] == 2 and rec.summary.verdict_counts[L.REFERENCE] == 1
    assert C.RunRecord.restore_json(C.serialize_report(rec), seal=seal()) == rec


def test_reasons_never_embed_requirement_text_or_model_text():
    reqs, observations, marks = build_run()
    for v in run(reqs, observations, marks):
        for key in ("提出物の説明は", "メールアドレス", "テストアカウント", "推測です"):
            assert key not in v.reason and all(key not in e.label for e in v.evidence)


def test_every_evidence_label_fits_a_chip_and_never_names_a_host():
    facts = {"limit": 1_000_000, "chars_with_ws": 9_999_999, "chars_no_ws": 9_999_999, "status": 599, "text_len": 99_999,
             "redirect_status": 308, "location_path": "/" + "a" * 62, "has_password_input": True, "unfollowed": True}  # fmt: skip
    for code in C.ObsCode:
        for access in (None, "idp_redirect", "login_redirect", "login_form", "http_401", "http_403", "form_on_content",
                       "not_found", "http_error", "too_large", "redirect_limit"):  # fmt: skip
            f = dict(facts)
            if access:
                f["access"] = access
            o = C.Observation(obs_id="O1", tool=C.ToolName.RUN_CHECK, code=code, outcome=C.ObsOutcome.FAIL, facts=f)
            label = evidence_label(o)
            assert 0 < len(label) <= 60 and C.EvidenceRef(obs_id="O1", label=label)
            assert "run.app" not in label


def test_evidence_is_capped_at_eight_chips():
    many = [len_obs(f"O{i}") for i in range(1, 12)]
    v = one(R("R1", "len", CC.LENGTH_LIMIT), many)
    assert v.label is L.FAIL and len(v.evidence) == 8


def test_an_error_fail_is_only_trusted_from_the_http_probe_family():
    """ERROR＋不適合は http_probe 由来（404・500）だけ。字数チェッカーの ERROR 不適合（想定外の組）は証拠にしない。"""
    bogus = len_obs(code=C.ObsCode.ERROR, outcome=C.ObsOutcome.FAIL, strong=True, facts={})
    v = one(R("R1", "len", CC.LENGTH_LIMIT), [bogus])
    assert (v.label, v.reason_code) == (L.UNVERIFIABLE, U.NO_EVIDENCE)


def test_all_reason_templates_fit_a_verdict_and_stay_free_of_hosts():
    """理由文のテンプレートは、どの組み合わせでも Verdict（140字・表示安全）に収まり、ホスト名を含まない。"""
    import app.adjudicate as A

    accesses = (None, "idp_redirect", "login_redirect", "login_form", "http_401", "http_403", "not_found", "http_error", "form_on_content")
    for code in C.ObsCode:
        for access in accesses:
            facts = {"limit": 1_000_000, "chars_with_ws": 9_999_999, "chars_no_ws": 9_999_999, "status": 599}
            if access:
                facts["access"] = access
            o = C.Observation(obs_id="O1", tool=C.ToolName.RUN_CHECK, code=code, outcome=C.ObsOutcome.FAIL, facts=facts)
            ev = (C.EvidenceRef(obs_id="O1", label=A.evidence_label(o)),)
            for text in (A._fail_reason(o), A._pass_reason(o)):
                assert text and "run.app" not in text
                C.Verdict(req_id="R1", label=L.FAIL, reason=text, evidence=ev)  # ValidationError にならない
    for reason in U:
        text = A._unverifiable_text(reason)
        C.Verdict(req_id="R1", label=L.UNVERIFIABLE, reason_code=reason, reason=text)
        assert text.endswith("。")
