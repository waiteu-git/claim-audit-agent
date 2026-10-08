"""プリセットの「読める要項・提出物」と「仕込んだ場所 → 見つけた結果」の対応（公開面 S2 の /api/status に載せるデータ）。

純粋な関数だけ（起動時に1度組み立てる）。判定は作らない: 渡された同梱の記録（app/web/replay/<id>.json を読んだ RunRecord）から
**引くだけ**で、正解表（app/fixtures/expected.json）と記録が食い違えば ExamplesError で止める（ずれたまま公開しない）。
ファイルを読むのは app.web.replay.load_fixture_records（記録）と、ここの正解表・フィクスチャだけ。replay からは import しない
（replay の CLI がこの検査を呼ぶので、向きは replay → examples の一方向）。
架空の注記は、フィクスチャのページを変えない（字数・位置情報・要件の再現性を保つ）ため、ここに固定文で持つ。
入力欄・任意URLは作らない（閉世界）。①の href は Preset の spec_seed_urls・submission_url をそのまま通す。

planted[].found の値の由来（各行の basis）:
  すべて**同梱の記録（保存済みの実行）の値**で、basis="bundled_replay" と明示する。req_id・req_ids は、その記録での要件の通し番号
  （Reader が出力順に採番する）なので、②③をライブで実行すると同じ番号が別の要件を指しうる。画面は番号で結ばず、表示する実行の記録と
  突き合わせて、found.quote（要項の逐語。同梱の記録の要件の引用そのもので80字以内）や矛盾の slot・tokens が合う時だけ対応を言う。
  偽の命令の count は同梱の記録の検知数（コードの検知で、Reader の採番には依らない）。
エラーの文言は固定の識別子だけ（理由コード・プリセットID・項目ID）。記録や正解表の中身は出さない。
"""
import json
import re
from collections.abc import Mapping
from enum import StrEnum
from typing import Any

from app.config import PRESET_SAMPLE_DEFECT, PRESET_SAMPLE_INJECTION
from app.contracts import Preset, RunRecord
from app.fixtures.gen import EXPECTED_PATH
from app.fixtures.site import FixtureSite

FICTIONAL_NOTE = "この要項と提出物は、検査のために作った架空のものです。実在の主催者・参加者・製品とは関係ありません。"
BASIS_BUNDLED_REPLAY = "bundled_replay"  # planted[].basis。found の値は同梱の記録（保存済みの実行）のもの
FOUND_QUOTE_MAX_CHARS = 80  # found.quote（要項の逐語の断片）は80字まで

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

# 仕込んだ項目の固定文: id → (summary_ja, where_ja)。画面に出る語なので「本文」「内部の呼び名」は使わない
PLANTED_TEXT: dict[str, tuple[str, str]] = {
    "D1": ("公開説明文が800字を超えている", "提出物の説明ページ"),
    "D2": ("提出物のURLを開くとログインが求められる", "提出物のURLの先（ログインが要る画面）"),
    "D3": ("公開説明文に連絡先のメールアドレスと内部URLが書かれている", "提出物の説明ページ"),
    "D4": ("提出の締切が、要項とよくある質問のページで食い違っている", "要項と、よくある質問のページ"),
    "G1": ("テスト用アカウントの案内が、提出物のページには無く、操作ガイドのページにある", "提出物のページからたどれる操作ガイドのページ"),
    "INJ_VISIBLE": ("検査する側のAIに向けたプロンプトインジェクションが、画面に見える形で書かれている", "要項のページと提出物のページ"),
    "INJ_HIDDEN": ("同じプロンプトインジェクションが、画面に見えない形でも隠されている", "提出物のページの見えない部分"),
}


class ExamplesCode(StrEnum):
    """ExamplesError の理由コード（固定の識別子）。"""

    RECORD_MISSING = "record_missing"  # 同梱の記録が無い
    RECORD_UNREADABLE = "record_unreadable"  # 同梱の記録を契約として読めない
    EXPECTED_MISSING = "expected_missing"  # 正解表にこのプリセットが無い
    EXPECTED_MALFORMED = "expected_malformed"  # 正解表の形が想定と違う
    DEFECT_TYPE_UNKNOWN = "defect_type_unknown"  # 正解表の欠陥の種類が未知
    QUOTE_TOO_LONG = "quote_too_long"  # 正解表の引用が80字を超える
    QUOTE_NOT_IN_RECORD = "quote_not_in_record"  # 正解表の引用を持つ要件が記録に無い
    QUOTE_AMBIGUOUS = "quote_ambiguous"  # 同じ引用を持つ要件が記録に2件以上ある
    LABEL_MISMATCH = "label_mismatch"  # 記録の判定ラベルが正解表と違う
    CONTRADICTION_MISMATCH = "contradiction_mismatch"  # 正解表の矛盾に当たる矛盾が記録にちょうど1件ではない
    SIGNALS_SHORT_VISIBLE = "signals_short_visible"  # 記録の「見える偽の命令」の検知数が正解表に足りない
    SIGNALS_SHORT_HIDDEN = "signals_short_hidden"  # 記録の「隠れた偽の命令」の検知数が正解表に足りない
    TEXT_MISSING = "text_missing"  # 固定文の表（PLANTED_TEXT）に項目が無い
    LINK_NOT_200 = "link_not_200"  # 架空ページへのリンクが 200 を返さない


_IDENT = re.compile(r"[A-Za-z0-9_]{1,32}")


def _ident(value: object) -> str:
    """エラーの文言に載せてよいのは短い英数字の識別子だけ（それ以外は "?"）。"""
    return value if isinstance(value, str) and _IDENT.fullmatch(value) else "?"


class ExamplesError(RuntimeError):
    """正解表と同梱の記録が合わない（起動時・取り込み時に止める）。文言は `理由コード preset=… item=…` の固定の識別子だけ。"""

    def __init__(self, code: ExamplesCode, preset_id: str, item_id: str | None = None) -> None:
        self.code = code
        self.preset_id = _ident(preset_id)
        self.item_id = None if item_id is None else _ident(item_id)
        super().__init__(f"{code.value} preset={self.preset_id} item={self.item_id or '-'}")


def _links(preset: Preset) -> list[dict[str, str]]:
    fx = _FX_LINKS.get(preset.preset_id)
    if fx is not None:
        return [{"role": role, "label_ja": label, "href": href} for role, label, href in fx]
    out = [{"role": "official", "label_ja": LABEL_OFFICIAL, "href": u} for u in preset.spec_seed_urls]
    if preset.submission_url:
        out.append({"role": "submission", "label_ja": LABEL_SELF, "href": preset.submission_url})
    return out


def check_fixture_links(preset_id: str, links: list[dict[str, str]], site: FixtureSite) -> None:
    for ln in links:
        if site.resolve(ln["href"]).status != 200:
            raise ExamplesError(ExamplesCode.LINK_NOT_200, preset_id, f"link_{ln['role']}")


def _req_by_quote(preset_id: str, item_id: str, rec: RunRecord, quote: str) -> str:
    if len(quote) > FOUND_QUOTE_MAX_CHARS:
        raise ExamplesError(ExamplesCode.QUOTE_TOO_LONG, preset_id, item_id)
    ids = [r.req_id for r in rec.requirements if r.span is not None and r.span.original_span == quote]
    if not ids:
        raise ExamplesError(ExamplesCode.QUOTE_NOT_IN_RECORD, preset_id, item_id)
    if len(ids) > 1:
        raise ExamplesError(ExamplesCode.QUOTE_AMBIGUOUS, preset_id, item_id)
    return ids[0]


def _verdict_found(preset_id: str, item_id: str, rec: RunRecord, quote: str, label: str) -> dict[str, Any]:
    req_id = _req_by_quote(preset_id, item_id, rec, quote)
    got = [v.label.value for v in rec.verdicts if v.req_id == req_id]
    if got != [label]:
        raise ExamplesError(ExamplesCode.LABEL_MISMATCH, preset_id, item_id)
    return {"kind": "verdict", "req_id": req_id, "label": label, "quote": quote}


def _planted(preset_id: str, expected: Mapping[str, Any], rec: RunRecord) -> list[dict[str, Any]]:
    try:
        exp = expected["presets"][preset_id]
    except (KeyError, TypeError):
        raise ExamplesError(ExamplesCode.EXPECTED_MISSING, preset_id) from None
    rows: list[tuple[str, dict[str, Any]]] = []
    try:
        for d in exp["defects"]:
            item = d["id"]
            if d["type"] == "verdict":
                rows.append((item, _verdict_found(preset_id, item, rec, d["quote"], d["label"])))
            elif d["type"] == "contradiction":
                hit = [c for c in rec.contradictions if c.slot.value == d["slot"] and list(c.tokens) == list(d["tokens"])]
                if len(hit) != 1:
                    raise ExamplesError(ExamplesCode.CONTRADICTION_MISMATCH, preset_id, item)
                found = {"kind": "contradiction", "slot": d["slot"], "tokens": list(d["tokens"]), "req_ids": list(hit[0].req_ids)}
                rows.append((item, found))
            else:
                raise ExamplesError(ExamplesCode.DEFECT_TYPE_UNKNOWN, preset_id, item)
        for g in exp.get("guards") or ():
            rows.append((g["id"], _verdict_found(preset_id, g["id"], rec, g["quote"], g["label"])))
        inj = exp.get("injection")
        if inj:
            vis = sum(1 for s in rec.injection_signals if s.visible)
            hid = len(rec.injection_signals) - vis
            if vis < inj["visible_min"]:
                raise ExamplesError(ExamplesCode.SIGNALS_SHORT_VISIBLE, preset_id, "INJ_VISIBLE")
            if hid < inj["hidden_min"]:
                raise ExamplesError(ExamplesCode.SIGNALS_SHORT_HIDDEN, preset_id, "INJ_HIDDEN")
            rows.append(("INJ_VISIBLE", {"kind": "signals", "count": vis}))
            rows.append(("INJ_HIDDEN", {"kind": "signals", "count": hid}))
    except (KeyError, TypeError):
        raise ExamplesError(ExamplesCode.EXPECTED_MALFORMED, preset_id) from None
    out = []
    for item, found in rows:
        if item not in PLANTED_TEXT:
            raise ExamplesError(ExamplesCode.TEXT_MISSING, preset_id, item)
        summary, where = PLANTED_TEXT[item]
        out.append({"id": item, "summary_ja": summary, "where_ja": where, "found": found, "basis": BASIS_BUNDLED_REPLAY})
    return out


def build_examples(
    presets: Mapping[str, Preset],
    records: Mapping[str, RunRecord],
    *,
    expected: Mapping[str, Any] | None = None,
    site: FixtureSite | None = None,
) -> dict[str, dict[str, Any]]:
    """プリセットID → {fictional, fictional_note, links, planted}。

    records は同梱の記録（②③の分）。正解表と合わない・記録が無い・リンクが 200 でないなら ExamplesError。
    """
    exp = expected if expected is not None else json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))
    fx_site = site or FixtureSite.load()
    out: dict[str, dict[str, Any]] = {}
    for pid, preset in presets.items():
        links = _links(preset)
        fictional = pid in _FX_LINKS
        planted: list[dict[str, Any]] = []
        if fictional:
            check_fixture_links(pid, links, fx_site)
            rec = records.get(pid)
            if rec is None:
                raise ExamplesError(ExamplesCode.RECORD_MISSING, pid)
            planted = _planted(pid, exp, rec)
        out[pid] = {
            "fictional": fictional,
            "fictional_note": FICTIONAL_NOTE if fictional else None,
            "links": links,
            "planted": planted,
        }
    return out
