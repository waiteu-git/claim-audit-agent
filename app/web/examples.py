"""プリセットの「読める要項・提出物」と「仕込んだ場所 → 見つけた結果」の対応（公開面 S2 の /api/status に載せるデータ）。

純粋な関数だけ（起動時に1度組み立てる）。判定は作らない: 同梱の記録（app/web/replay/<id>.json）から**引くだけ**で、
正解表（app/fixtures/expected.json）と記録が食い違えば ExamplesError で起動を止める（ずれたまま公開しない）。
架空の注記は、フィクスチャのページを変えない（字数・位置情報・要件の再現性を保つ）ため、ここに固定文で持つ。
入力欄・任意URLは作らない（閉世界）。①の href は Preset の spec_seed_urls・submission_url をそのまま通す。
"""
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from app.config import PRESET_LP_SELF, PRESET_SAMPLE_DEFECT, PRESET_SAMPLE_INJECTION
from app.contracts import Preset, RunRecord
from app.fixtures.gen import EXPECTED_PATH
from app.fixtures.site import FixtureSite
from app.web.replay import REPLAY_DIR, load_bundle

FICTIONAL_NOTE = "この要項と提出物は、検査のために作った架空のものです。実在の主催者・参加者・製品とは関係ありません。"

# links の role と、②③の実ページ（FixtureSite が 200 で返すもの）。app/ は転送なので載せない
_FX_LINKS: dict[str, tuple[tuple[str, str, str], ...]] = {
    PRESET_SAMPLE_DEFECT: (
        ("spec", "要項（架空）", "/fx/defect/spec/"),
        ("faq", "よくある質問（架空）", "/fx/defect/faq/"),
        ("submission", "提出物の説明ページ（架空）", "/fx/defect/submission/"),
        ("guide", "操作ガイド（架空）", "/fx/defect/guide/"),
        ("login", "提出物のURLの先（ログインが要る画面・架空）", "/fx/defect/login/"),
    ),
    PRESET_SAMPLE_INJECTION: (
        ("spec", "要項（架空）", "/fx/inject/spec/"),
        ("faq", "よくある質問（架空）", "/fx/inject/faq/"),
        ("submission", "提出物の説明ページ（架空）", "/fx/inject/submission/"),
        ("login", "提出物のURLの先（ログインが要る画面・架空）", "/fx/inject/login/"),
    ),
}
LABEL_OFFICIAL = "募集ページ（外部サイトが開きます）"
LABEL_SELF = "提出物（このサービス自身）"

# 仕込んだ項目の固定文: id → (summary_ja, where_ja)
PLANTED_TEXT: dict[str, tuple[str, str]] = {
    "D1": ("公開説明文が800字を超えている", "提出物の説明ページ"),
    "D2": ("提出物のURLを開くとログインが求められる", "提出物のURLの先（ログインが要る画面）"),
    "D3": ("公開説明文に連絡先のメールアドレスと内部URLが書かれている", "提出物の説明ページ"),
    "D4": ("提出の締切が、要項と質問ページで食い違っている", "要項と、よくある質問のページ"),
    "G1": ("ログインが要る提出物なのに、案内がページの本文に無い（操作ガイドを辿ると見つかる）", "要項の条件と、操作ガイドのページ"),
    "INJ_VISIBLE": ("検査する側のAIに向けた偽の命令が、画面に見える形で書かれている", "要項と提出物の説明ページの本文"),
    "INJ_HIDDEN": ("同じ偽の命令が、画面に見えない形でも隠されている", "提出物の説明ページの見えない部分"),
}


class ExamplesError(RuntimeError):
    """正解表と同梱の記録が合わない（起動時に落とす）。"""


def _links(preset: Preset) -> list[dict[str, str]]:
    fx = _FX_LINKS.get(preset.preset_id)
    if fx is not None:
        return [{"role": role, "label_ja": label, "href": href} for role, label, href in fx]
    out = [{"role": "official", "label_ja": LABEL_OFFICIAL, "href": u} for u in preset.spec_seed_urls]
    if preset.submission_url:
        out.append({"role": "submission", "label_ja": LABEL_SELF, "href": preset.submission_url})
    return out


def check_fixture_links(links: list[dict[str, str]], site: FixtureSite) -> None:
    for ln in links:
        if site.resolve(ln["href"]).status != 200:
            raise ExamplesError("架空ページへのリンクが 200 を返しません")


def _req_by_quote(rec: RunRecord, quote: str) -> str:
    ids = [r.req_id for r in rec.requirements if r.span is not None and r.span.original_span == quote]
    if len(ids) != 1:
        raise ExamplesError("正解表の引用に対応する要件が、記録にちょうど1件ありません")
    return ids[0]


def _verdict_found(rec: RunRecord, quote: str, label: str) -> dict[str, Any]:
    req_id = _req_by_quote(rec, quote)
    got = [v.label.value for v in rec.verdicts if v.req_id == req_id]
    if got != [label]:
        raise ExamplesError("記録の判定ラベルが正解表と一致しません")
    return {"kind": "verdict", "req_id": req_id, "label": label}


def _planted(preset_id: str, expected: Mapping[str, Any], rec: RunRecord) -> list[dict[str, Any]]:
    exp = expected["presets"][preset_id]
    rows: list[tuple[str, dict[str, Any]]] = []
    for d in exp["defects"]:
        if d["type"] == "verdict":
            rows.append((d["id"], _verdict_found(rec, d["quote"], d["label"])))
        elif d["type"] == "contradiction":
            hit = [c for c in rec.contradictions if c.slot.value == d["slot"] and list(c.tokens) == d["tokens"]]
            if len(hit) != 1:
                raise ExamplesError("正解表の矛盾に対応する矛盾が、記録にちょうど1件ありません")
            rows.append((d["id"], {"kind": "contradiction", "slot": d["slot"], "req_ids": list(hit[0].req_ids)}))
        else:
            raise ExamplesError("正解表の欠陥の種類が未知です")
    for g in exp.get("guards") or ():
        rows.append((g["id"], _verdict_found(rec, g["quote"], g["label"])))
    inj = exp.get("injection")
    if inj:
        vis = sum(1 for s in rec.injection_signals if s.visible)
        hid = len(rec.injection_signals) - vis
        if vis < inj["visible_min"] or hid < inj["hidden_min"]:
            raise ExamplesError("記録の偽の命令の検知数が正解表に足りません")
        rows.append(("INJ_VISIBLE", {"kind": "signals", "count": vis}))
        rows.append(("INJ_HIDDEN", {"kind": "signals", "count": hid}))
    out = []
    for pid, found in rows:
        if pid not in PLANTED_TEXT:
            raise ExamplesError("仕込んだ項目の固定文がありません")
        summary, where = PLANTED_TEXT[pid]
        out.append({"id": pid, "summary_ja": summary, "where_ja": where, "found": found})
    return out


def build_examples(
    presets: Mapping[str, Preset],
    *,
    expected: Mapping[str, Any] | None = None,
    replay_dir: Path = REPLAY_DIR,
    site: FixtureSite | None = None,
) -> dict[str, dict[str, Any]]:
    """プリセットID → {fictional, fictional_note, links, planted}。記録と正解表が合わなければ ExamplesError。"""
    exp = expected if expected is not None else json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))
    fx_site = site or FixtureSite.load()
    out: dict[str, dict[str, Any]] = {}
    for pid, preset in presets.items():
        links = _links(preset)
        fictional = pid in _FX_LINKS
        planted: list[dict[str, Any]] = []
        if fictional:
            check_fixture_links(links, fx_site)
            try:
                rec = load_bundle(replay_dir / f"{pid}.json").record
            except Exception as e:  # noqa: BLE001  壊れた・無い記録で公開しない
                raise ExamplesError("同梱の記録を読めません") from e
            planted = _planted(pid, exp, rec)
        out[pid] = {
            "fictional": fictional,
            "fictional_note": FICTIONAL_NOTE if fictional else None,
            "links": links,
            "planted": planted,
        }
    return out
