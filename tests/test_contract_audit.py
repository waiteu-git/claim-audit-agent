"""契約の監査（T1 の契約を後続 T3 / T4 / T5 / T9 の目で突き合わせた結果）の回帰テスト。

設計書 §3・§4・§5・§7 と §10 の各モジュールが必要とする入出力が、過不足なく契約にあることを
「後続が実際に組み立てる形」で固定する（デモ② D1〜D4 の流れを契約の型だけで通す）。
"""
import hashlib
from typing import Any

import pytest
from pydantic import ValidationError

import app.config as cfg
import app.contracts as C
from app.textsafe import BLOCK_SEP, escape_for_display
from tests.factories import (
    make_budget,
    make_doc,
    make_event,
    make_record,
    make_span,
    make_verified,
    planner_request,
    reader_request,
    seal,
    sha,
)


# ---------------------------------------------------------------------------
# スコープ照合の唯一の定義（T3 SafeFetch・Governor・Preset が共有。S-07）
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("prefix", "path", "expected"),
    [
        # 末尾が "/" の接頭辞は配下だけ。"/fxx/" や "/fx"（スラッシュ無し）は範囲外
        (dict(path_prefix="/fx/"), "/fx/a", True),
        (dict(path_prefix="/fx/"), "/fx/", True),
        (dict(path_prefix="/fx/"), "/fxx/", False),
        (dict(path_prefix="/fx/"), "/fx", False),
        (dict(path_prefix="/fx/"), "/api/run", False),
        (dict(path_prefix="/"), "/anything/at/all", True),
        # 末尾が "/" でない接頭辞は、そのパス自身と配下（セグメント境界）
        (dict(path_prefix="/event"), "/event", True),
        (dict(path_prefix="/event"), "/event/x", True),
        (dict(path_prefix="/event"), "/eventx", False),
        (dict(path_prefix="/event"), "/events/", False),
        # exact は完全一致だけ
        (dict(path_prefix="/event", exact=True), "/event", True),
        (dict(path_prefix="/event", exact=True), "/event/", False),
        (dict(path_prefix="/event", exact=True), "/event/x", False),
        (dict(path_prefix="/", exact=True), "/", True),
        (dict(path_prefix="/", exact=True), "/fx/", False),
    ],
)
def test_url_prefix_matches_uses_segment_boundaries(prefix, path, expected):
    p = C.UrlPrefix(host="svc.example.invalid", **prefix)
    assert p.matches("svc.example.invalid", path) is expected


def test_url_prefix_matches_requires_the_same_host():
    p = C.UrlPrefix(host="svc.example.invalid", path_prefix="/fx/")
    assert not p.matches("svc.example.invalid.attacker.invalid", "/fx/a")
    assert not p.matches("other.example.invalid", "/fx/a")


def test_preset_validator_uses_the_shared_scope_rule():
    """非 exact の "/event" に "/eventx" のシードが通っていた（接頭辞一致の誤り）。共有ルールで弾く。"""
    prefix = C.UrlPrefix(host="lp.example.invalid", path_prefix="/event")
    with pytest.raises(ValidationError):
        C.Preset(preset_id="lp_self", label_ja="x", kind=C.PresetKind.LIVE_LP,
                 spec_seed_urls=("https://lp.example.invalid/eventx",), allowed_prefixes=(prefix,))  # fmt: skip
    ok = C.Preset(preset_id="lp_self", label_ja="x", kind=C.PresetKind.LIVE_LP,
                  spec_seed_urls=("https://lp.example.invalid/event/faq",), allowed_prefixes=(prefix,))  # fmt: skip
    assert ok.spec_seed_urls


# ---------------------------------------------------------------------------
# FetchResult / RedirectHop: リダイレクトの表し方を1通りに（T3 が作り、T4・T9 が読む）
# ---------------------------------------------------------------------------
def hop(**kw: Any) -> C.RedirectHop:
    base: dict[str, Any] = dict(url="https://svc.example.invalid/fx/defect/submission/", status=302, location="/fx/defect/login/")
    base.update(kw)
    return C.RedirectHop(**base)


def test_unfollowed_redirect_is_ok_with_the_3xx_status_and_a_reason():
    """スコープ外（IdP など）への転送は追跡せず Location だけ記録＝BLOCKED でなく ok・3xx（認証壁の証拠）。"""
    idp = hop(location="https://idp.example.invalid/signin", followed=False, in_scope=False, blocked_policy=C.PolicyId.SCOPE)
    r = C.FetchResult(
        requested_url="https://svc.example.invalid/fx/defect/submission/",
        final_url="https://svc.example.invalid/fx/defect/submission/",
        redirects=(idp,), outcome=C.FetchOutcome.OK, status=302, headers={"location": "https://idp.example.invalid/signin"},
    )  # fmt: skip
    assert r.redirects[-1].blocked_policy is C.PolicyId.SCOPE and r.status == 302 and not r.body
    assert C.FetchResult.model_validate_json(r.model_dump_json()) == r


def test_hop_rules():
    with pytest.raises(ValidationError):  # 追跡したホップは範囲内で、拒否理由を持てない
        hop(followed=True, in_scope=False)
    with pytest.raises(ValidationError):
        hop(followed=True, in_scope=True, blocked_policy=C.PolicyId.SSRF_IP)
    with pytest.raises(ValidationError):  # 拒否理由は SafeFetch が使う2つだけ
        hop(blocked_policy=C.PolicyId.KILL)
    assert hop(blocked_policy=C.PolicyId.SSRF_IP).blocked_policy is C.PolicyId.SSRF_IP


def test_redirect_chain_rules():
    followed = hop(followed=True, in_scope=True)
    stop = hop(url="https://svc.example.invalid/fx/defect/login/", location="/fx/x/", followed=False, in_scope=False,
              blocked_policy=C.PolicyId.SCOPE)  # fmt: skip
    base: dict[str, Any] = dict(requested_url="https://svc.example.invalid/fx/defect/submission/", outcome=C.FetchOutcome.OK, status=302)
    assert C.FetchResult(redirects=(followed, stop), **base)
    with pytest.raises(ValidationError):  # 追跡しなかった転送は最後でなければならない
        C.FetchResult(redirects=(stop, followed), **base)
    with pytest.raises(ValidationError):  # blocked は最初のリクエストの拒否だけ（転送の途中では使わない）
        C.FetchResult(requested_url=base["requested_url"], outcome=C.FetchOutcome.BLOCKED, blocked_policy=C.PolicyId.SCOPE, redirects=(followed,))
    with pytest.raises(ValidationError):  # blocked の policy は SafeFetch が使う2つだけ
        C.FetchResult(requested_url=base["requested_url"], outcome=C.FetchOutcome.BLOCKED, blocked_policy=C.PolicyId.KILL)
    loop = hop(followed=False, in_scope=True)  # 上限超過で追跡しなかった（理由なし）
    too_many = C.FetchResult(
        requested_url=base["requested_url"], outcome=C.FetchOutcome.TOO_MANY_REDIRECTS, limit_hit=C.FetchLimit.REDIRECTS,
        redirects=(followed, followed, followed, loop),
    )  # fmt: skip
    assert len(too_many.redirects) == 4
    with pytest.raises(ValidationError):  # too_many_redirects は追跡しなかった最後の転送を持つ
        C.FetchResult(requested_url=base["requested_url"], outcome=C.FetchOutcome.TOO_MANY_REDIRECTS, limit_hit=C.FetchLimit.REDIRECTS, redirects=(followed,))


def test_fetch_kinds_are_budgeted_separately_from_fetch_modes():
    b = make_budget()
    for _ in range(2):  # http_probe は1実行2回まで（§4）
        assert b.can_fetch(kind=C.FetchKind.HTTP_PROBE)
        b.charge_fetch(kind=C.FetchKind.HTTP_PROBE)
    assert not b.can_fetch(kind=C.FetchKind.HTTP_PROBE)
    assert b.can_fetch(kind=C.FetchKind.FETCH_LINK) and b.can_fetch()  # 他の種別・合計はまだ余裕がある
    for _ in range(3):
        b.charge_fetch(kind=C.FetchKind.FETCH_LINK)
    assert not b.can_fetch(kind=C.FetchKind.FETCH_LINK)  # fetch_link は1実行3回まで
    for _ in range(3):
        b.charge_fetch(kind=C.FetchKind.ACQUIRE)
    assert b.fetches == 8 and not b.can_fetch() and b.exhausted() is C.BudgetDimension.FETCHES
    assert dict(b.fetches_by_kind) == {C.FetchKind.HTTP_PROBE: 2, C.FetchKind.FETCH_LINK: 3, C.FetchKind.ACQUIRE: 3}
    assert [b.kind_cap(k) for k in C.FetchKind] == [3, 3, 2]  # acquire / fetch_link / http_probe


# ---------------------------------------------------------------------------
# SanitizedDoc: page_class の裏取り材料（T4 が作り、T6・T9 が読む）
# ---------------------------------------------------------------------------
def test_sanitized_doc_carries_code_computed_page_signals():
    d = make_doc("D2", "ログイン", role=C.DocRole.SUBMISSION,
                 page_class=C.PageClass.LOGIN_WALL, signals=C.PageSignals(http_status=200, has_password_input=True, script_count=2))  # fmt: skip
    assert d.signals.has_password_input and d.signals.http_status == 200
    assert make_doc().signals == C.PageSignals()  # 既定は「指標なし」
    assert C.SanitizedDoc.model_validate_json(d.model_dump_json()) == d
    with pytest.raises(ValidationError):
        C.PageSignals(http_status=99)
    with pytest.raises(ValidationError):
        C.PageSignals(script_count=-1)


# ---------------------------------------------------------------------------
# Observation facts: 「302→/login」の材料はパス断片まで。URL は載せられない
# ---------------------------------------------------------------------------
def test_observation_facts_allow_a_path_fragment_but_never_a_url():
    ok = C.Observation(obs_id="O1", tool=C.ToolName.HTTP_PROBE, code=C.ObsCode.AUTH_WALL, outcome=C.ObsOutcome.FAIL, strong=True,
                       facts={"status": 302, "location_path": "/login", "has_password_input": True})  # fmt: skip
    assert ok.facts["location_path"] == "/login"
    for bad in ("https://idp.example.invalid/x", "//evil.example.invalid", "/a//b", "x" * 65, "a b", "日本語", "/login?next=1"):
        with pytest.raises(ValidationError):
            C.Observation(obs_id="O1", tool=C.ToolName.HTTP_PROBE, code=C.ObsCode.OK, outcome=C.ObsOutcome.PASS, facts={"p": bad})


# ---------------------------------------------------------------------------
# TraceEvent: verdict / budget_snapshot の中身を型で持つ（日本語の判定名は Token に載らない）
# ---------------------------------------------------------------------------
def test_verdict_and_budget_snapshot_events_carry_their_payload():
    ev = make_event(type=C.TraceType.VERDICT, actor=C.Actor.ADJUDICATOR, req_id="R1", verdict=C.VerdictLabel.FAIL, obs_id="O1")
    assert ev.verdict is C.VerdictLabel.FAIL
    assert C.TraceEvent.model_validate_json(ev.model_dump_json()) == ev
    with pytest.raises(ValidationError):  # verdict イベントには判定名が要る
        make_event(type=C.TraceType.VERDICT, req_id="R1")
    with pytest.raises(ValidationError):  # どの要件の判定か分からないものは出せない
        make_event(type=C.TraceType.VERDICT, verdict=C.VerdictLabel.FAIL)
    with pytest.raises(ValidationError):  # 他の種別には載せられない
        make_event(verdict=C.VerdictLabel.PASS)
    snap = make_event(type=C.TraceType.BUDGET_SNAPSHOT, budget=make_budget().snapshot())
    assert snap.budget is not None and snap.json_size() <= C.MAX_EVENT_BYTES
    with pytest.raises(ValidationError):
        make_event(type=C.TraceType.BUDGET_SNAPSHOT)
    with pytest.raises(ValidationError):
        make_event(budget=make_budget().snapshot())


# ---------------------------------------------------------------------------
# VerifiedRequirement: 申告が推測のまま引用を検証できなかった要件（Reader は推測も申告する）
# ---------------------------------------------------------------------------
def test_declared_speculative_with_an_unverified_quote_is_a_quote_less_speculative_not_a_demotion():
    r = C.VerifiedRequirement(seal=seal(), req_id="R5", kind=C.Kind.SPECULATIVE, declared_kind=C.Kind.SPECULATIVE, span=None,
                              demotion=C.DemotionReason.QUOTE_UNVERIFIED, gist="動画があると有利（推論）")  # fmt: skip
    assert r.span is None and r.display_quote(80) == ""
    for demotion in (None, C.DemotionReason.NO_OBLIGATION_WORD):  # 引用が無いのに他の理由は付けられない
        with pytest.raises(ValidationError):
            C.VerifiedRequirement(seal=seal(), req_id="R5", kind=C.Kind.SPECULATIVE, declared_kind=C.Kind.SPECULATIVE, span=None, demotion=demotion)
    # 他の降格理由は、kind が変わった時だけ（申告と同じ kind の降格は引き続き不可）
    doc = make_doc()
    with pytest.raises(ValidationError):
        C.VerifiedRequirement(seal=seal(), req_id="R1", kind=C.Kind.SPECULATIVE, declared_kind=C.Kind.SPECULATIVE,
                              span=make_span(doc, "提出物の説明は800字以内とする。"), demotion=C.DemotionReason.NEGATION_OR_EXCEPTION,
                              chips=(C.Chip.NEGATION_OR_EXCEPTION,))  # fmt: skip


def test_summary_counts_only_real_demotions_as_demoted_to_speculative():
    declared_spec = C.VerifiedRequirement(seal=seal(), req_id="R5", kind=C.Kind.SPECULATIVE, declared_kind=C.Kind.SPECULATIVE,
                                          span=None, demotion=C.DemotionReason.QUOTE_UNVERIFIED, gist="推論")  # fmt: skip
    demoted = C.VerifiedRequirement(seal=seal(), req_id="R6", kind=C.Kind.SPECULATIVE, declared_kind=C.Kind.REQUIRED,
                                    span=None, demotion=C.DemotionReason.QUOTE_UNVERIFIED, gist="推論")  # fmt: skip
    s = C.RunSummary.compute((make_verified("R1"), declared_spec, demoted), (), (), (), ())
    assert s.demoted_to_speculative == 1  # 最初から推測と申告した R5 は「降格」に数えない
    assert s.quotes_checked == 3 and s.quotes_verbatim == 1


# ---------------------------------------------------------------------------
# ModelRequest: Reader は response_schema 強制、Planner は関数呼び出しのみ
# ---------------------------------------------------------------------------
def test_reader_and_planner_are_separated_by_type_while_the_schema_duty_stays_with_the_reader_module():
    """型が強制するのは分離だけ（Reader はツール不可・Planner は schema 不可）。Reader の schema 強制は T6 のテスト。"""
    assert reader_request().response_model is C.ReaderOutput and reader_request().tools == ()
    assert reader_request(response_model=None).response_model is None  # 実測スクリプト（ops）が schema 無しで使う
    assert planner_request().response_model is None  # Planner は schema を持たず、関数呼び出しだけ
    with pytest.raises(ValidationError):
        planner_request(response_model=C.ReaderOutput)


def test_planner_and_reader_digests_differ_by_schema_and_tools():
    assert reader_request().request_digest() != planner_request().request_digest()


# ---------------------------------------------------------------------------
# RunCaps / config: 設計の数値（§3・§5-3・§4）
# ---------------------------------------------------------------------------
def test_run_caps_have_the_consecutive_denial_stop():
    assert cfg.RUN_CAPS.consecutive_denials_stop == 3  # 拒否3連続で DEGRADED（§3）
    assert C.RunCaps.model_fields["consecutive_denials_stop"].default == 3  # 既存の RunCaps 構築でも設計の値になる


def test_fetch_limits_match_the_design_and_the_contract_constants():
    f = cfg.FETCH_LIMITS
    assert (f.connect_timeout_s, f.total_timeout_s, f.sock_read_timeout_s) == (3.0, 8.0, 4.0)
    assert f.max_content_length == 3 * 1024 * 1024 and f.max_decoded_bytes == 1024 * 1024
    assert f.max_decoded_bytes == C.FETCH_BODY_MAX_BYTES and f.probe_prefix_bytes == C.PROBE_BODY_MAX_BYTES
    assert f.max_redirects == C.MAX_REDIRECT_HOPS == 3 and f.max_url_length == 2048
    assert f.user_agent == "claim-audit-agent/1 (hackathon demo; read-only)" and f.accept_encoding == "gzip, deflate"
    assert (f.probe_retry_delay_s, f.probe_retry_max) == (2.0, 1)


def test_check_classes_map_to_the_five_checkers():
    assert set(C.CHECK_CLASS_CHECKER) == set(C.CheckClass)
    assert C.CHECK_CLASS_CHECKER[C.CheckClass.NONE] is None
    used = {c for c in C.CHECK_CLASS_CHECKER.values() if c is not None}
    assert used == set(C.Checker)  # 5本の checker すべてがどこかの要件クラスに使われる
    assert C.CHECK_CLASS_CHECKER[C.CheckClass.GUIDANCE_PRESENT] is C.CHECK_CLASS_CHECKER[C.CheckClass.URL_PRESENT] is C.Checker.CONTAINS_TERMS
    assert len([c for c in C.CheckClass if c is not C.CheckClass.NONE]) == 6  # 検査できる要件クラスは6つだけ


# ---------------------------------------------------------------------------
# 判定表の入力
# ---------------------------------------------------------------------------
def obs(obs_id: str = "O1", **kw: Any) -> C.Observation:
    base: dict[str, Any] = dict(obs_id=obs_id, tool=C.ToolName.RUN_CHECK, code=C.ObsCode.WITHIN_LIMIT, outcome=C.ObsOutcome.PASS, strong=True)
    base.update(kw)
    return C.Observation(**base)


def test_adjudication_input_validates_its_references():
    doc = make_doc("D2", "説明", role=C.DocRole.SUBMISSION)
    req = make_verified("R1")
    ok = C.AdjudicationInput(
        requirements=(req,), docs=(doc.meta(),), observations=(obs(req_id="R1", doc_id="D2", checker=C.Checker.TEXT_LENGTH),),
        marks=(C.UnverifiableMark(req_id="R1", reason_code=C.UnverifiableReason.NEEDS_AUTH, premise_obs_id="O1", by_planner=True),),
    )  # fmt: skip
    assert ok.marks[0].by_planner
    base: dict[str, Any] = dict(requirements=(req,), docs=(doc.meta(),))
    with pytest.raises(ValidationError):  # 存在しない要件の観測
        C.AdjudicationInput(observations=(obs(req_id="R9"),), **base)
    with pytest.raises(ValidationError):  # docs に無い文書の観測
        C.AdjudicationInput(observations=(obs(doc_id="D9"),), **base)
    with pytest.raises(ValidationError):  # obs_id の重複
        C.AdjudicationInput(observations=(obs(), obs()), **base)
    with pytest.raises(ValidationError):  # 存在しない要件への印
        C.AdjudicationInput(marks=(C.UnverifiableMark(req_id="R9", reason_code=C.UnverifiableReason.BUDGET),), **base)
    with pytest.raises(ValidationError):  # 1要件に印が複数
        m = C.UnverifiableMark(req_id="R1", reason_code=C.UnverifiableReason.BUDGET)
        C.AdjudicationInput(marks=(m, m), **base)
    with pytest.raises(ValidationError):  # 前提の観測が無い（P-UNVERIF-01 は前提の OBS を要求する）
        C.AdjudicationInput(marks=(C.UnverifiableMark(req_id="R1", reason_code=C.UnverifiableReason.NEEDS_JS, premise_obs_id="O7"),), **base)
    with pytest.raises(ValidationError):  # 要件の重複
        C.AdjudicationInput(requirements=(req, req))


# ---------------------------------------------------------------------------
# RunRecord: 判定の証拠は observations にある観測を指す
# ---------------------------------------------------------------------------
def test_run_record_evidence_must_point_at_recorded_observations():
    chip = C.EvidenceRef(obs_id="O1", event_seq=1, label="1,130字（上限800字）")
    fail = C.Verdict(req_id="R1", label=C.VerdictLabel.FAIL, evidence=(chip,), reason="説明文が上限を超えています")
    with pytest.raises(ValidationError):  # 証拠の観測が記録に無い
        make_record(verdicts=(fail,))
    rec = make_record(verdicts=(fail,), observations=(obs("O1", req_id="R1", code=C.ObsCode.OVER_LIMIT, outcome=C.ObsOutcome.FAIL),))
    assert rec.observations[0].obs_id == "O1"
    with pytest.raises(ValidationError):  # obs_id の重複
        make_record(verdicts=(fail,), observations=(obs("O1"), obs("O1")))
    with pytest.raises(ValidationError):  # 存在しない要件・文書の観測
        make_record(verdicts=(fail,), observations=(obs("O1", req_id="R9"),))
    with pytest.raises(ValidationError):
        make_record(verdicts=(fail,), observations=(obs("O1", doc_id="D9"),))


# ---------------------------------------------------------------------------
# 通しの確認: デモ② D1・D2・D4 を、後続が組み立てる形（契約の型だけ）で通す
# ---------------------------------------------------------------------------
def test_demo_defect_walkthrough_d1_d2_d4_fits_the_contract():
    # --- T3: 提出URL → 302 → ログイン（範囲内・追跡）→ 200。T4: password 欄を検出 -----------------
    sub_url = "https://svc.example.invalid/fx/defect/submission/"
    login = "https://svc.example.invalid/fx/defect/login/"
    scope = (C.UrlPrefix(host="svc.example.invalid", path_prefix="/fx/defect/"),)
    assert all(any(p.matches("svc.example.invalid", path) for p in scope) for path in ("/fx/defect/submission/", "/fx/defect/login/"))
    probe = C.FetchResult(
        requested_url=sub_url, final_url=login,
        redirects=(C.RedirectHop(url=sub_url, status=302, location="/fx/defect/login/", followed=True, in_scope=True),),
        outcome=C.FetchOutcome.OK, status=200,
        headers={"content-type": "text/html; charset=utf-8", "server": "Google Frontend"},
        body='<form><input type="password"></form>'.encode(), content_kind=C.ContentKind.HTML,
    )  # fmt: skip
    sub_text = f"ログイン{BLOCK_SEP}パスワード"
    submission = C.SanitizedDoc(
        doc_id="D3", role=C.DocRole.SUBMISSION, label="提出物", url=sub_url, sha256=probe.body_sha256, byte_length=len(probe.body),
        page_class=C.PageClass.LOGIN_WALL, signals=C.PageSignals(http_status=probe.status, has_password_input=True),
        visible_text=sub_text,
    )  # fmt: skip
    assert submission.meta().page_class is C.PageClass.LOGIN_WALL

    # --- T5: 検証済みの要件（D1: 800字上限／D2: 開ける提出物／D4: 締切が要項とFAQで違う）-----------
    spec = make_doc("D1", f"説明は800字以内とする。{BLOCK_SEP}提出URLは審査員が開けること。{BLOCK_SEP}締切は10月15日である。")
    faq = make_doc("D2", "締切は10月16日である。", url="https://faq.example.invalid/faq")
    r1 = make_verified("R1", doc=spec, needle="説明は800字以内とする。", check_class=C.CheckClass.LENGTH_LIMIT)
    r2 = make_verified("R2", doc=spec, needle="提出URLは審査員が開けること。", check_class=C.CheckClass.AUTH_WALL)
    r3 = make_verified("R3", doc=spec, needle="締切は10月15日である。", slot=C.Slot.DEADLINE, check_class=C.CheckClass.NONE)
    r4 = make_verified("R4", doc=faq, needle="締切は10月16日である。", slot=C.Slot.DEADLINE, check_class=C.CheckClass.NONE)

    # --- T9: 観測（OBS強）。字数は両方式で超過、認証壁はパス断片つき ---------------------------------
    o1 = C.Observation(
        obs_id="O1", tool=C.ToolName.RUN_CHECK, checker=C.CHECK_CLASS_CHECKER[C.CheckClass.LENGTH_LIMIT], req_id="R1", doc_id="D3",
        code=C.ObsCode.OVER_LIMIT, outcome=C.ObsOutcome.FAIL, strong=True,
        facts={"limit": 800, "chars_with_ws": 1130, "chars_no_ws": 1002, "over_with_ws": True, "over_no_ws": True},
    )  # fmt: skip
    o2 = C.Observation(
        obs_id="O2", tool=C.ToolName.RUN_CHECK, checker=C.Checker.AUTH_WALL, req_id="R2", doc_id="D3",
        code=C.ObsCode.AUTH_WALL, outcome=C.ObsOutcome.FAIL, strong=True,
        facts={"status": 200, "redirect_hops": 1, "location_path": "/fx/defect/login/", "has_password_input": True, "elapsed_ms": 380},
    )  # fmt: skip
    inp = C.AdjudicationInput(
        requirements=(r1, r2, r3, r4), docs=(spec.meta(), faq.meta(), submission.meta()), observations=(o1, o2),
        marks=(C.UnverifiableMark(req_id="R3", reason_code=C.UnverifiableReason.HUMAN_ONLY),
               C.UnverifiableMark(req_id="R4", reason_code=C.UnverifiableReason.HUMAN_ONLY)),
    )  # fmt: skip
    assert len(inp.observations) == 2

    # --- 判定表の出力（証拠チップは観測から組む）と、実行記録 ---------------------------------------
    chip2 = C.EvidenceRef(obs_id="O2", event_seq=4, label="302→/fx/defect/login/・password欄あり")
    verdicts = (
        C.Verdict(req_id="R1", label=C.VerdictLabel.FAIL, evidence=(C.EvidenceRef(obs_id="O1", event_seq=3, label="1,130字（上限800字）"),),
                  reason="説明文は1,130字で、上限800字を超えています"),
        C.Verdict(req_id="R2", label=C.VerdictLabel.FAIL, evidence=(chip2,), reason="提出URLはログインを要求します"),
        C.Verdict(req_id="R3", label=C.VerdictLabel.UNVERIFIABLE, reason_code=C.UnverifiableReason.HUMAN_ONLY),
        C.Verdict(req_id="R4", label=C.VerdictLabel.UNVERIFIABLE, reason_code=C.UnverifiableReason.HUMAN_ONLY),
    )  # fmt: skip
    contradiction = C.Contradiction(slot=C.Slot.DEADLINE, req_ids=("R3", "R4"), basis=C.ContradictionBasis.TOKEN_DIFF, tokens=("10月15日", "10月16日"))
    events = (
        make_event(3, type=C.TraceType.TOOL_RESULT, actor=C.Actor.TOOL, name="run_check", obs_id="O1", req_id="R1"),
        make_event(4, type=C.TraceType.TOOL_RESULT, actor=C.Actor.TOOL, name="run_check", obs_id="O2", req_id="R2", attrs=o2.facts),
        make_event(5, type=C.TraceType.VERDICT, actor=C.Actor.ADJUDICATOR, req_id="R2", verdict=C.VerdictLabel.FAIL, obs_id="O2"),
    )  # fmt: skip
    rec = make_record(
        docs=(spec.meta(), faq.meta(), submission.meta()), requirements=(r1, r2, r3, r4), verdicts=verdicts,
        contradictions=(contradiction,), observations=(o1, o2), events=events,
    )  # fmt: skip
    assert rec.summary.verdict_counts[C.VerdictLabel.FAIL] == 2 and rec.summary.contradictions == 1
    again = C.RunRecord.restore_json(C.serialize_report(rec), seal=seal())
    assert again == rec and "visible_text" not in C.serialize_report(rec)


def test_model_quote_escaped_for_display_fits_a_quote_step():
    """T5: ゼロ幅・bidi 入りの棄却された引用は、escape_for_display を通して載せる（そのままは契約違反）。"""
    dirty = "締切は10月15日​" + "あ" * 400 + "‮"
    with pytest.raises(ValidationError):
        C.QuoteStep(attempt=1, outcome=C.QuoteStepOutcome.REJECTED, reason_code="not_found", model_quote=dirty[:100], quote_digest=sha("q")[:16])
    step = C.QuoteStep(attempt=1, outcome=C.QuoteStepOutcome.REJECTED, reason_code="not_found",
                       model_quote=escape_for_display(dirty, C.QUOTE_SPAN_MAX_CHARS), quote_digest=hashlib.sha256(dirty.encode()).hexdigest()[:16])  # fmt: skip
    assert "​" not in (step.model_quote or "") and len(step.model_quote or "") <= C.QUOTE_SPAN_MAX_CHARS



# ---------------------------------------------------------------------------
# 終端の理由（§3: DEGRADED = 予算切れ・Vertex 失敗・拒否3連続／ABORTED = kill・切断・75秒超過）
# ---------------------------------------------------------------------------
def test_run_record_end_reasons_match_the_terminal_status():
    assert make_record().degraded_reason is None and make_record().aborted_reason is None  # DONE は理由を持たない
    d = make_record(status=C.RunStatus.DEGRADED, degraded_reason=C.DegradedReason.BUDGET)  # 部分結果でも全要件に判定は要る
    assert d.degraded_reason is C.DegradedReason.BUDGET
    a = make_record(status=C.RunStatus.ABORTED, aborted_reason=C.AbortReason.CLIENT_DISCONNECT, verdicts=())
    assert a.aborted_reason is C.AbortReason.CLIENT_DISCONNECT
    with pytest.raises(ValidationError):  # DEGRADED には理由が要る
        make_record(status=C.RunStatus.DEGRADED)
    with pytest.raises(ValidationError):  # ABORTED には理由が要る
        make_record(status=C.RunStatus.ABORTED, verdicts=())
    with pytest.raises(ValidationError):  # DONE に理由は付けない
        make_record(degraded_reason=C.DegradedReason.BUDGET)
    with pytest.raises(ValidationError):  # 終端と理由の種類が合わない
        make_record(status=C.RunStatus.DEGRADED, aborted_reason=C.AbortReason.KILL, degraded_reason=C.DegradedReason.BUDGET)
    assert {r.value for r in C.DegradedReason} == {"BUDGET", "MODEL_FAILURE", "DENIAL_STREAK"}
    assert {r.value for r in C.AbortReason} == {"KILL", "CLIENT_DISCONNECT", "WALL_CLOCK"}
