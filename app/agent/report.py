"""最小の出力: RunRecord → JSON と、素の HTML 表（設計 §8 の本UI［SSE・ゲージ等］は作らない）。

JSON は契約の serialize_report が唯一の入口（VerifiedRequirement 以外が混ざると例外）。HTML は表だけ（スクリプト・外部読み込み無し）。
画面に出る文字列はすべて契約の「表示用に安全な型」（ゼロ幅・bidi・制御文字を含められない）から取り、さらに html.escape を通す。
判定・理由・証拠のラベルは Verdict（adjudicate.py が作ったもの）をそのまま写すだけで、ここで判定を作らない。
"""
from html import escape

from app.contracts import (
    CHIP_LABEL_JA,
    REASON_LABEL_JA,
    RunRecord,
    RunStatus,
    VerdictLabel,
    serialize_report,
)


def report_json(record: RunRecord) -> str:
    return serialize_report(record)


_STATUS_NOTE = {
    RunStatus.DONE: "",
    RunStatus.DEGRADED: "上限などにより部分結果です。未検査の要件は理由つきの確認不能で表示しています。",
    RunStatus.ABORTED: "実行を中止しました。判定は出していません。",
}


def report_html(record: RunRecord) -> str:
    docs = {d.doc_id: d for d in record.docs}
    verdicts = {v.req_id: v for v in record.verdicts}
    s = record.summary
    counts = "・".join(f"{lab.value} {n}" for lab, n in s.verdict_counts.items()) or "判定なし"
    reason = record.degraded_reason or record.aborted_reason
    head = [
        "<!doctype html>",
        '<html lang="ja"><head><meta charset="utf-8"><title>要項監査レポート</title></head><body>',
        "<h1>要項監査レポート</h1>",
        f"<p>状態: {escape(record.status.value)}{f'（{escape(reason.value)}）' if reason else ''}"
        f" ／ プリセット: {escape(record.preset_id)} ／ 検査: {escape(record.planner_model)}</p>",
    ]
    note = _STATUS_NOTE[record.status]
    if note:
        head.append(f"<p>{escape(note)}</p>")
    head += [
        f"<p>要件 {s.requirements_total} 件（必須・禁止 {s.obligatory_total} 件{'・件数上限で打切り' if s.capped else ''}）。"
        f"引用検証 {s.quotes_checked} 件中 {s.quotes_verbatim} 件が逐語一致・{s.demoted_to_speculative} 件を推測へ降格。</p>",
        f"<p>判定: {escape(counts)} ／ 矛盾 {s.contradictions} 件 ／ 注入疑い 可視 {s.injection_visible}・隠し {s.injection_hidden}"
        f" ／ Governor の拒否 {s.denied} 件</p>",
        '<table border="1"><thead><tr><th>ID</th><th>種別</th><th>要件（要項の引用）</th><th>出典</th><th>判定</th><th>理由</th><th>証拠</th></tr></thead><tbody>',
    ]
    rows = []
    for r in record.requirements:
        if r.span is not None:
            quote = escape(r.display_quote(80))
            src = docs.get(r.span.doc_id)
            source = escape(f"{r.span.doc_id} {src.label if src else ''}".strip())
            if not r.reverified:
                quote += "（再検証前）"
        else:
            quote = f"（要項に引用できない推測）{escape(r.gist)}" if r.gist else "（要項に引用できない推測）"
            source = "—"
        kind = escape(r.kind.value) + "".join(f"［{escape(CHIP_LABEL_JA[c])}］" for c in r.chips)
        if r.declared_kind is not r.kind:
            kind += f"（申告: {escape(r.declared_kind.value)}）"  # コードが降格した要件は、モデルの申告も並べて見せる
        v = verdicts.get(r.req_id)
        if v is None:
            label, why, ev = "—", "", ""
        else:
            label = escape(v.label.value)
            why = escape(v.reason)
            if v.reason_code is not None:
                why = escape(REASON_LABEL_JA[v.reason_code]) + ("：" + why if why else "")
            ev = escape("、".join(e.label for e in v.evidence))
            if v.label is VerdictLabel.REFERENCE:
                ev = ""
        rows.append(
            f"<tr><td>{escape(r.req_id)}</td><td>{kind}</td><td>{quote}</td><td>{source}</td><td>{label}</td><td>{why}</td><td>{ev}</td></tr>"
        )
    return "\n".join([*head, *rows, "</tbody></table>", "</body></html>"]) + "\n"
