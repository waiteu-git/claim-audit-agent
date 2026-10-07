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
    FunctionCall,
    Kind,
    ModelRequest,
    ModelResponse,
    ObsCode,
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


class RulePlanner:
    """Planner の代わりの規則（ModelPort。LLM ではない）。StateView の JSON だけを見て、決まった手を返す。

    規則: 手順（routes）の残る要件があれば、その手順を実行する（probe が先に要る種類は probe）。検査が「語が無い」で終わった直後に、
    まだ辿っていない案内ページ（役割 docs・スコープ内）があれば辿る（方針変更）。辿った直後は、同じ要件をもう一度検査する。
    それ以外は finish。実際の Planner（Gemini）の代わりではなく、「案内ページを辿る Planner」を決定論で再現するための道具で、
    表では model が rule-planner と出る。実モデルの結果は --live の行（app/fixtures/measure.py）。
    """

    def __init__(self, model_id: str = "rule-planner", *, follow_docs: bool = True) -> None:
        self._model_id = model_id
        self._follow = follow_docs
        self.calls = 0

    @property
    def model_id(self) -> str:
        return self._model_id

    def _decide(self, view: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        allowed = set(view["allowed_tools"])
        last = view.get("last_observation")
        if self._follow and last == "TERMS_ABSENT" and "fetch_link" in allowed:
            for lk in view["links"]:
                if lk["role"] == "docs" and lk["in_scope"] and not lk["fetched"]:
                    return "fetch_link", {"link_id": lk["link_id"], "reason": "案内ページを辿る"}
        for r in view["requirements"]:
            if r["state"] != "open" or not r["routes"]:
                continue
            if r["calls_used"] >= 1 and last != "OK":
                continue  # 検査済みで、新しい材料（辿ったページ）が無い
            kind, _, name = r["routes"][0].partition(":")
            if kind == "http_probe":
                return "http_probe", {"target": "SUBMISSION_URL", "reason": "提出URLの到達検査"}
            return "run_check", {"checker": name, "req_id": r["req_id"]}
        return "finish", {}

    async def generate(self, request: ModelRequest) -> ModelResponse:
        self.calls += 1
        name, args = self._decide(json.loads(request.contents))
        return ModelResponse(
            model=self._model_id,
            function_calls=(FunctionCall(name=name, args=args),),
            usage=Usage(prompt_tokens=estimate_tokens(request.system + request.contents), candidates_tokens=estimate_tokens(name + json.dumps(args))),
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
    for g in expected.get("guards", ()):  # 欠陥ではない要件。期待の判定（案内ページに案内が在る＝推定適合）にならなければ見逃し扱い
        r = by_quote.get(g["quote"])
        v = verdicts.get(r.req_id) if r is not None else None
        if v is None or v.label.value != g["label"]:
            missed.append(g["id"])
    false_fails = [v.req_id for v in record.verdicts if v.label is VerdictLabel.FAIL and v.req_id not in expected_fail_reqs]
    false_contra = [i for i in range(len(record.contradictions)) if i not in matched_contradictions]
    # 誤った absent: 正解表に無い不適合のうち、根拠が「求められた語が本文に無い」（contains_terms の TERMS_ABSENT）だったもの。
    # 辿るべき案内ページを辿らずに「無い」と言った時に出る
    obs = {o.obs_id: o for o in record.observations}
    false_absent = [
        v.req_id for v in record.verdicts
        if v.label is VerdictLabel.FAIL and v.req_id not in expected_fail_reqs
        and any(obs.get(e.obs_id) is not None and obs[e.obs_id].code is ObsCode.TERMS_ABSENT for e in v.evidence)
    ]  # fmt: skip
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
        "false_absent": len(false_absent),
        "unverifiable": sum(1 for v in record.verdicts if v.label is VerdictLabel.UNVERIFIABLE),
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
    ap.add_argument("--live", action="store_true", help="実モデル（Vertex。認証は ADC）で測る。既定はオフライン（モデルを呼ばない）")
    ap.add_argument("--max-calls", type=int, default=None, help="--live のモデル呼び出し回数の上限（既定 40・最大 120。再試行も数える）")
    ap.add_argument("--only", default=None, help="測る変種の名前（カンマ区切り。例 g1found,g2missing）")
    fmt = ap.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="JSON だけを出す")
    fmt.add_argument("--md", action="store_true", help="Markdown の表だけを出す")
    a = ap.parse_args(argv)
    from app.errors import AppError
    from app.fixtures import measure

    only = [x for x in (a.only or "").split(",") if x] or None
    if only is not None and not set(only) <= {v.name for v in measure.all_variants()}:
        ap.error("--only に知らない変種があります: " + ",".join(sorted(set(only) - {v.name for v in measure.all_variants()})))
    if a.max_calls is not None and not a.live:
        ap.error("--max-calls は --live の時だけ使います")
    try:
        table = measure.run(a.live, max_calls=a.max_calls or measure.MAX_LIVE_CALLS_DEFAULT, only=only)
    except (AppError, ValueError) as e:
        print(f"測定できませんでした: {getattr(e, 'detail', '') or e}", file=sys.stderr)
        return 2
    if not a.json:
        print(measure.to_markdown(table))
    if not a.md:
        if not a.json:
            print()
        print(measure.to_json(table))
    return 0


if __name__ == "__main__":
    sys.exit(main())
