"""評価の骨組み: 欠陥の変種（gen.VARIANTS）を通しで実行し、正解表と照らして「検出 x/y・誤検知 z」を出す。

実 LLM は呼ばない。Reader は OracleReader（正解表 reader_oracle の要件のうち、渡された本文に現れるものだけを返す台本）、
検査は router（LLM 無しの決定論。Planner を試す時は planner_model を渡す）。取得は FixtureFetch（ネットワーク無し）。
ここで測るのは「正しく読めた時に、コード側（取得・検査・判定表・矛盾）が欠陥を拾えるか」で、Reader の読みの精度ではない。

  python -m app.fixtures.eval          # 表で出す
  python -m app.fixtures.eval --json   # JSON で出す

採点の規則（score）:
  * verdict 型の欠陥: 引用（原文の1文）が一致する要件の判定が、正解のラベル（不適合）なら検出。
  * contradiction 型の欠陥: 同じ slot で、相違した値の組が一致する矛盾があれば検出。
  * 誤検知: 正解表に無い要件の「不適合」と、正解表に無い矛盾の件数。
"""
import argparse
import asyncio
import json
import sys
from collections.abc import Sequence
from typing import Any

from app.agent.budget import estimate_tokens
from app.agent.planner import InspectMode
from app.agent.run import run_audit
from app.config import Settings
from app.contracts import (
    CheckClass,
    Kind,
    ModelRequest,
    ModelResponse,
    PresetKind,
    Preset,
    RawRequirement,
    ReaderOutput,
    PageClass,
    RunRecord,
    Slot,
    UrlPrefix,
    Usage,
    VerdictLabel,
)
from app.fixtures import gen
from app.fixtures.site import FixtureFetch, FixtureSite
from app.model.port import ModelPort

EVAL_HOST = "fixtures.example.invalid"
EVAL_ORIGIN = f"https://{EVAL_HOST}"


class OracleReader:
    """Reader の代わりの台本（ModelPort）。正解表の要件のうち、要求の本文に逐語で現れるものだけを返す。

    再引用の要求（ReaderOutput 以外の response_model）には空の応答を返す。モデルを呼ばないので費用は 0。
    """

    def __init__(self, oracle: Sequence[dict[str, str]] = gen.READER_ORACLE, model_id: str = "oracle-reader") -> None:
        self._oracle = tuple(oracle)
        self._model_id = model_id
        self.calls = 0

    @property
    def model_id(self) -> str:
        return self._model_id

    async def generate(self, request: ModelRequest) -> ModelResponse:
        self.calls += 1
        if request.response_model is ReaderOutput:
            reqs = [
                RawRequirement(quote=o["quote"], kind=Kind(o["kind"]), check_class=CheckClass(o["check_class"]), slot=Slot(o["slot"]))
                for o in self._oracle
                if o["quote"] in request.contents
            ]
            text = ReaderOutput(page_class=PageClass.CONTENT, requirements=reqs).model_dump_json()
        else:
            text = json.dumps({"items": []})
        return ModelResponse(
            model=self._model_id,
            text=text,
            usage=Usage(prompt_tokens=estimate_tokens(request.system + request.contents), candidates_tokens=estimate_tokens(text)),
            finish_reason="STOP",
        )


def variant_preset(v: gen.Variant, origin: str = EVAL_ORIGIN) -> Preset:
    host = origin.removeprefix("https://")
    return Preset(
        preset_id=f"eval_{v.name}",
        label_ja=f"評価用の変種 {v.name}",
        kind=PresetKind.FIXTURE_INJECTION if v.injection else PresetKind.FIXTURE_DEFECT,
        spec_seed_urls=(f"{origin}{v.prefix}spec/", f"{origin}{v.prefix}faq/"),
        submission_url=f"{origin}{v.prefix}app/",
        submission_page_url=f"{origin}{v.prefix}submission/",
        allowed_prefixes=(UrlPrefix(host=host, path_prefix=v.prefix),),
    )


def score(record: RunRecord, expected: dict[str, Any]) -> dict[str, Any]:
    by_quote = {r.span.original_span: r for r in record.requirements if r.span is not None}
    verdicts = {v.req_id: v for v in record.verdicts}
    detected: list[str] = []
    missed: list[str] = []
    expected_fail_reqs: set[str] = set()
    matched_contradictions: set[int] = set()
    for d in expected["defects"]:
        if d["type"] == "verdict":
            r = by_quote.get(d["quote"])
            v = verdicts.get(r.req_id) if r is not None else None
            if r is not None:
                expected_fail_reqs.add(r.req_id)
            (detected if v is not None and v.label.value == d["label"] else missed).append(d["id"])
        else:
            hit = next(
                (
                    i
                    for i, c in enumerate(record.contradictions)
                    if c.slot.value == d["slot"] and set(c.tokens) == set(d["tokens"])
                ),
                None,
            )
            if hit is None:
                missed.append(d["id"])
            else:
                matched_contradictions.add(hit)
                detected.append(d["id"])
    false_fails = [v.req_id for v in record.verdicts if v.label is VerdictLabel.FAIL and v.req_id not in expected_fail_reqs]
    false_contra = [i for i in range(len(record.contradictions)) if i not in matched_contradictions]
    inj = expected.get("injection")
    injection_ok = None
    if inj is not None:
        s = record.summary
        injection_ok = s.injection_visible >= inj["visible_min"] and s.injection_hidden >= inj["hidden_min"]
    return {
        "variant": expected["variant"],
        "status": record.status.value,
        "expected": len(expected["defects"]),
        "detected": detected,
        "missed": missed,
        "false_positives": len(false_fails) + len(false_contra),
        "injection_ok": injection_ok,
    }


async def run_variant(
    v: gen.Variant, *, inspect_mode: InspectMode = InspectMode.ROUTER, planner_model: ModelPort | None = None
) -> tuple[RunRecord, dict[str, Any]]:
    preset = variant_preset(v)
    fetch = FixtureFetch(FixtureSite(gen.build_site(v)), EVAL_HOST, preset.allowed_prefixes)
    res = await run_audit(
        preset, fetch=fetch, reader_model=OracleReader(), planner_model=planner_model, inspect_mode=inspect_mode, settings=Settings()
    )
    return res.record, score(res.record, gen.expected_for(v))


async def run_eval(variants: Sequence[gen.Variant] = gen.VARIANTS) -> dict[str, Any]:
    rows = [(await run_variant(v))[1] for v in variants]
    return {
        "detected": sum(len(r["detected"]) for r in rows),
        "expected": sum(r["expected"] for r in rows),
        "false_positives": sum(r["false_positives"] for r in rows),
        "rows": rows,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.fixtures.eval")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    out = asyncio.run(run_eval())
    if a.json:
        print(json.dumps(out, ensure_ascii=False, indent=1))
    else:
        for r in out["rows"]:
            print(f"{r['variant']:<12} {r['status']:<9} 検出 {len(r['detected'])}/{r['expected']}  誤検知 {r['false_positives']}"
                  f"  見逃し {','.join(r['missed']) or '-'}")  # fmt: skip
        print(f"合計: 検出 {out['detected']}/{out['expected']}・誤検知 {out['false_positives']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
