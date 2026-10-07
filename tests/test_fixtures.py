"""app/fixtures: 生成物と同梱物の一致・欠陥 D1〜D4 の仕込み・配信の規則・FixtureFetch の形・評価（検出 x/y・誤検知 z）・同梱リプレイ。"""
import asyncio
import json

import pytest

from app.config import PRESETS
from app.contracts import DocRole, FetchMode, FetchOutcome, FetchRequest, PolicyId, UrlPrefix
from app.fixtures import gen
from app.fixtures.eval import OracleReader, run_eval, run_variant, score
from app.fixtures.site import FAKE_CLOUD_RUN_HOST, FixtureFetch, FixtureSite
from app.ingest.sanitize import sanitize
from app.web import replay

HOST = "fx.example.invalid"
SCOPE = (UrlPrefix(host=HOST, path_prefix="/fx/"),)


def fetch(url_path: str, mode: FetchMode = FetchMode.PAGE, scope=SCOPE):
    ff = FixtureFetch(FixtureSite.load(), HOST, scope)
    return asyncio.run(ff.fetch(FetchRequest(url=f"https://{HOST}{url_path}", mode=mode)))


def doc(url_path: str, role: DocRole = DocRole.SPEC):
    return sanitize(fetch(url_path), doc_id="D1", role=role, label="x", scope=SCOPE)


# ---- 生成物と同梱物 ------------------------------------------------------------------------------
def test_site_and_expected_json_match_the_generator():
    assert gen.check() == []


def test_bundled_replays_match_a_fresh_offline_run():
    assert replay.check() == []


def test_expected_json_lists_the_four_defects_for_preset_2_and_the_injection_for_preset_3():
    exp = json.loads(gen.EXPECTED_PATH.read_text(encoding="utf-8"))
    assert [d["id"] for d in exp["presets"]["sample_defect"]["defects"]] == ["D1", "D2", "D3", "D4"]
    assert exp["presets"]["sample_defect"]["injection"] is None
    assert exp["presets"]["sample_defect"]["guards"][0]["id"] == "G1"  # ②は案内ページに案内が在る（辿れば推定適合）
    assert "guards" not in exp["presets"]["sample_injection"]
    assert exp["presets"]["sample_injection"]["injection"] == {"visible_min": 2, "hidden_min": 1}
    assert len(exp["variants"]) == 6 and len({v["variant"] for v in exp["variants"]}) == 6


# ---- 欠陥の仕込み ---------------------------------------------------------------------------------
def test_d1_the_public_description_is_exactly_1130_characters():
    d = doc("/fx/defect/submission/", DocRole.SUBMISSION)
    assert len(d.visible_text) == gen.DESC_LONG == 1130 and gen.DESC_LIMIT == 800


def test_d2_the_deploy_url_redirects_to_a_login_page_with_a_password_field():
    r = fetch("/fx/defect/app/", FetchMode.PROBE)
    assert r.outcome is FetchOutcome.OK and r.status == 200 and r.final_url.endswith("/fx/defect/login/")
    assert [(h.status, h.location, h.followed) for h in r.redirects] == [(302, "/fx/defect/login/", True)]
    assert b'type="password"' in r.body


def test_d3_the_description_carries_a_service_url_and_an_email_only_after_serving():
    raw_file = (gen.SITE_DIR / "defect/submission/index.html").read_text(encoding="utf-8")
    assert FAKE_CLOUD_RUN_HOST not in raw_file
    d = doc("/fx/defect/submission/", DocRole.SUBMISSION)
    assert FAKE_CLOUD_RUN_HOST in d.visible_text and "mirai-team@example.invalid" in d.visible_text


def test_d4_the_spec_and_the_faq_disagree_on_the_deadline():
    assert "10月15日 23:59" in doc("/fx/defect/spec/").visible_text
    assert "10月16日 12:00" in doc("/fx/defect/faq/").visible_text


def test_preset_3_hides_an_instruction_in_visible_and_hidden_parts():
    spec, sub = doc("/fx/inject/spec/"), doc("/fx/inject/submission/", DocRole.SUBMISSION)
    assert spec.injection_counts[0] >= 1
    assert sub.injection_counts[0] >= 1 and sub.injection_counts[1] >= 1
    assert doc("/fx/defect/spec/").injection_counts == (0, 0)  # ②には仕込んでいない


def test_fixture_text_is_synthetic_and_names_no_real_service():
    for p in gen.SITE_DIR.rglob("*"):
        if p.is_file():
            t = p.read_text(encoding="utf-8")
            for word in ("Google", "Zenn", "Gemini", "株式会社", "大学"):
                assert word not in t, (p, word)


# ---- 配信の規則と FixtureFetch -------------------------------------------------------------------
def test_out_of_scope_requests_are_blocked_without_touching_the_site():
    r = fetch("/fx/defect/spec/", scope=(UrlPrefix(host=HOST, path_prefix="/fx/inject/"),))
    assert r.outcome is FetchOutcome.BLOCKED and r.blocked_policy is PolicyId.SCOPE


def test_a_redirect_out_of_scope_is_recorded_but_not_followed():
    r = fetch("/fx/defect/app/", FetchMode.PROBE, scope=(UrlPrefix(host=HOST, path_prefix="/fx/defect/app/"),))
    assert r.status == 302 and not r.redirects[-1].followed and r.redirects[-1].blocked_policy is PolicyId.SCOPE


@pytest.mark.parametrize("path,status", [("/fx/defect/spec/", 200), ("/fx/defect/spec", 301), ("/fx/defect/app/", 302),
                                          ("/fx/defect/app/REDIRECT", 404), ("/fx/x/../defect/spec/", 404), ("/elsewhere/", 404),
                                          ("/fx/defect/spec/index.html", 200), ("/fx/", 404)])  # fmt: skip
def test_resolve_serves_only_the_closed_set(path, status):
    assert FixtureSite.load().resolve(path).status == status


# ---- 評価（検出 x/y・誤検知 z）-------------------------------------------------------------------
def test_eval_detects_every_defect_in_every_variant_with_no_false_positive():
    out = asyncio.run(run_eval())
    assert (out["detected"], out["expected"], out["false_positives"]) == (8, 8, 0)
    v6 = next(r for r in out["rows"] if r["variant"] == "v6allinj")
    assert v6["injection_ok"] is True


def test_the_clean_variant_passes_the_three_checkable_requirements():
    record, row = asyncio.run(run_variant(gen.VARIANTS[0]))
    by_quote = {r.span.original_span: r.req_id for r in record.requirements if r.span}
    labels = {v.req_id: v.label.value for v in record.verdicts}
    for q in (gen.Q_LENGTH, gen.Q_AUTH, gen.Q_LEAK):
        assert labels[by_quote[q]] == "適合", q
    assert record.contradictions == () and row["false_positives"] == 0


def test_score_counts_a_wrong_failure_as_a_false_positive():
    record, _ = asyncio.run(run_variant(gen.VARIANTS[1]))  # D1 だけの変種の記録を
    exp = gen.expected_for(gen.VARIANTS[0])  # 欠陥なしの正解表で採点すると
    assert score(record, exp)["false_positives"] == 1  # D1 の不適合は誤検知になる


def test_the_oracle_reader_answers_only_with_quotes_present_in_the_request():
    from app.agent.reader import READER_SYSTEM
    from app.contracts import ModelPurpose, ModelRequest, ReaderOutput

    req = ModelRequest(purpose=ModelPurpose.READER, system=READER_SYSTEM, contents=f"<<<DOC>>>{gen.Q_LENGTH}", response_model=ReaderOutput,
                       max_output_tokens=100, timeout_s=1)  # fmt: skip
    out = ReaderOutput.model_validate_json(asyncio.run(OracleReader().generate(req)).text)
    assert [r.quote for r in out.requirements] == [gen.Q_LENGTH]


def test_presets_2_and_3_point_at_the_fixture_paths():
    for pid, prefix in (("sample_defect", "/fx/defect/"), ("sample_injection", "/fx/inject/")):
        p = PRESETS[pid]
        assert [u.split("example.invalid")[1] for u in p.spec_seed_urls] == [f"{prefix}spec/", f"{prefix}faq/"]
        assert p.submission_url.endswith(f"{prefix}app/") and p.submission_page_url.endswith(f"{prefix}submission/")
