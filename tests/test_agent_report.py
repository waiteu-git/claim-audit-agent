"""report.py: JSON は契約の入口だけ・HTML は素の表で、画面に出る文字を無害化する。"""
import json

import pytest

from app.agent.report import report_html, report_json
from app.contracts import (
    DemotionReason,
    EvidenceRef,
    Kind,
    RunRecord,
    RunStatus,
    UnverifiableReason,
    UnverifiedSerializationError,
    Verdict,
    VerdictLabel,
    VerifiedRequirement,
)
from tests.factories import make_doc, make_record, make_verified, seal

XSS = '<script>alert(1)</script><img src=x onerror=alert(2)>"&'


def test_json_is_the_contract_serialization_and_round_trips():
    rec = make_record()
    back = RunRecord.restore_json(report_json(rec), seal=seal())
    assert back.run_id == rec.run_id and back.requirements == rec.requirements


def test_json_refuses_a_record_built_by_bypassing_validation():
    rec = make_record()
    forged = rec.model_construct(**{**rec.__dict__, "requirements": ({"quote": "x"},)})  # 検証を迂回した記録
    with pytest.raises(UnverifiedSerializationError):
        report_json(forged)


def speculative(gist: str) -> VerifiedRequirement:
    return VerifiedRequirement(seal=seal(), req_id="R2", kind=Kind.SPECULATIVE, declared_kind=Kind.REQUIRED, span=None,
                               demotion=DemotionReason.QUOTE_UNVERIFIED, gist=gist)


def test_html_escapes_everything_that_came_from_the_model():
    doc = make_doc()
    reqs = (make_verified("R1", doc=doc), speculative(XSS))
    verdicts = (Verdict(req_id="R1", label=VerdictLabel.UNVERIFIABLE, reason_code=UnverifiableReason.HUMAN_ONLY, reason="人の判断"),
                Verdict(req_id="R2", label=VerdictLabel.REFERENCE))
    html = report_html(make_record(requirements=reqs, verdicts=verdicts, docs=(doc.meta(),)))
    assert "<script" not in html and "onerror=alert" not in html.replace("&lt;img src=x onerror=alert(2)&gt;", "")
    assert "&lt;script&gt;" in html and "&quot;" in html and "&amp;" in html
    assert html.count("<table") == 1 and "<a " not in html and "http" not in html


def test_html_shows_quote_source_verdict_reason_and_evidence_chip():
    doc = make_doc()
    req = make_verified("R1", doc=doc)
    v = Verdict(req_id="R1", label=VerdictLabel.PASS, reason="観測どおり。", evidence=(EvidenceRef(obs_id="O1", label="186字（上限100字）"),))
    from app.contracts import Observation, ObsCode, ObsOutcome, ToolName

    obs = Observation(obs_id="O1", tool=ToolName.RUN_CHECK, checker="text_length", req_id="R1", code=ObsCode.WITHIN_LIMIT,  # type: ignore[arg-type]
                      outcome=ObsOutcome.PASS, strong=True)
    html = report_html(make_record(requirements=(req,), verdicts=(v,), docs=(doc.meta(),), observations=(obs,)))
    for needle in ("提出物の説明は800字以内とする。", "D1 架空の要項", "適合", "観測どおり。", "186字（上限100字）", "再検証前"):
        assert needle in html


def test_unverifiable_reason_is_shown_in_japanese_and_status_notes_are_shown():
    rec = make_record(status=RunStatus.DEGRADED, degraded_reason="BUDGET")
    html = report_html(rec)
    assert "部分結果" in html and "（BUDGET）" in html
    assert "合っているかどうかを決められませんでした" not in html
    rec2 = make_record(status=RunStatus.ABORTED, aborted_reason="KILL", verdicts=())
    assert "中止" in report_html(rec2)


def test_demoted_requirement_shows_the_chip_and_the_models_declared_kind():
    from app.contracts import Chip

    doc = make_doc()
    req = make_verified("R1", doc=doc, kind=Kind.OPTIONAL, declared_kind=Kind.REQUIRED,
                        demotion=DemotionReason.REQUEST_WORDING, chips=(Chip.REQUEST_WORDING,))
    rec = make_record(requirements=(req,), docs=(doc.meta(),))
    html = report_html(rec)
    assert "依頼文言（違反時の扱い不明）" in html and "（申告: 必須）" in html
    assert json.loads(report_json(rec))["requirements"][0]["demotion"] == "request_wording"
