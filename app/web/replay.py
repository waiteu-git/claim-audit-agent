"""REPLAY: 同梱した実行記録（app/web/replay/<preset_id>.json）の読み込みと生成。Vertex・Firestore に依存しない。

同梱の②③は、架空フィクスチャを OracleReader（台本の Reader。実 LLM ではない）＋RulePlanner でオフライン実行して作った記録で、
記録の reader_model に "oracle-reader"、planner_model に "rule-planner"（決定論の規則 RulePlanner。LLM ではない）と残る
（画面にも出る＝実モデルの実行と偽らない）。②は案内ページを辿る方針変更（trace の replan）を含む。実 Gemini の実行記録で置き換える時は
`python -m app.cli <preset> --format json --out rec.json` の出力を `--import` で取り込む（漏洩の走査と契約の検証を通ったものだけ）。
取り込み時は第三者の原文を縮める（引用・言い換え・トレースの引用は1件80字まで、要件は40件まで。clip_for_bundle）。

  python -m app.web.replay --write            # ②③の記録を作り直す（決定論: run_id・時刻・時計を固定）
  python -m app.web.replay --check            # 同梱の記録が生成物と一致するか（tests も確かめる）
  python -m app.web.replay --import rec.json --preset lp_self   # 実行記録を REPLAY として取り込む
  python -m app.web.replay --rejudge          # 同梱の全記録の判定を、記録の要件・観測から今のコードで再判定して書き直す（オフライン。実モデルは呼ばない）

②③の記録は、公開面が /api/status に載せる「仕込んだ場所 → 見つけた結果」の対応表（app/web/examples.py）の元になる。--write・--check・--import は
この対応表を組み立てられること（正解表 expected.json と記録が合うこと）も確かめ、合わない記録は書かない・差分として出す
（起動で初めて落ちる、にしない）。メッセージは固定の識別子だけ（理由コード・プリセットID・項目ID）。
"""
import argparse
import asyncio
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.adjudicate import adjudicate
from app.agent.planner import InspectMode
from app.agent.run import run_audit
from app.checks.leak_scan import scan_text
from app.config import PRESET_IDS, PRESET_SAMPLE_DEFECT, PRESET_SAMPLE_INJECTION, PRESETS, Settings
from app.contracts import (
    CHECK_CLASS_CHECKER,
    AdjudicationInput,
    Kind,
    RunMode,
    RunRecord,
    RunStatus,
    ToolName,
    TraceType,
    UnverifiableReason,
    serialize_report,
)
from app.fixtures.eval import OracleReader, RulePlanner
from app.fixtures.site import FixtureFetch, FixtureSite
from app.quotes.replay import restore_saved_record
from app.web.examples import ExamplesCode, ExamplesError, build_examples

REPLAY_QUOTE_MAX_CHARS = 80  # 同梱する第三者の原文の断片は1件80字まで
REPLAY_REQUIREMENTS_MAX = 40  # 同梱する要件は40件まで（超過分は RunRecord.omitted_requirements に件数だけ残す）
REPLAY_DIR = Path(__file__).resolve().parent / "replay"
FIXTURE_REPLAYS = (PRESET_SAMPLE_DEFECT, PRESET_SAMPLE_INJECTION)
REPLAY_STARTED_AT = datetime(2026, 10, 1, 0, 0, tzinfo=UTC)


@dataclass(frozen=True)
class ReplayBundle:
    preset_id: str
    record: RunRecord
    record_json: str  # serialize_report の出力（再生の result に使う）
    event_jsons: tuple[str, ...]  # 1イベント1行の JSON（None を省く）


def _as_replay(record: RunRecord) -> RunRecord:
    # 契約の検証を通し直す（model_copy は検証しないので、mode・public の書き換えの後に再構成する）
    return record.model_copy(update={"mode": RunMode.REPLAY, "public": True})


def _clip(text: str) -> str:
    return text if len(text) <= REPLAY_QUOTE_MAX_CHARS else text[: REPLAY_QUOTE_MAX_CHARS - 1] + "…"


def clip_for_bundle(saved: str | bytes | RunRecord) -> RunRecord:
    """実行記録を同梱用に縮める（第三者＝主催者の文章を持ち込みすぎない）。取り込み（--import）が必ず通す。

      * 原文の断片を持つ欄（要件の引用 span.original_span・推測の言い換え gist・トレースの棄却された引用 model_quote）は
        80字まで。切り詰めた引用には末尾「…」と span.quote_clipped=true を付ける（位置 start/end は元のまま）。
      * 要件は先頭40件まで。省いた要件の判定・観測・矛盾・イベントも落とし、件数は omitted_requirements に残す。
    切り詰めた後に契約の検証を通し直す（restore_saved_record）。同梱の記録は原文を持たないので、再生時に引用を再検証しない。
    """
    # 契約の検証より前に、保存済みの JSON の段階で縮める（長い原文の記録も受け取れるように）
    d = json.loads(serialize_report(saved) if isinstance(saved, RunRecord) else saved)
    reqs = d["requirements"]
    dropped = {r["req_id"] for r in reqs[REPLAY_REQUIREMENTS_MAX:]}
    d["requirements"] = reqs = reqs[:REPLAY_REQUIREMENTS_MAX]
    for r in reqs:
        sp = r.get("span")
        if sp and len(sp["original_span"]) > REPLAY_QUOTE_MAX_CHARS:
            sp["original_span"] = _clip(sp["original_span"])
            sp["quote_clipped"] = True
        if r.get("gist"):
            r["gist"] = _clip(r["gist"])
    d["verdicts"] = [v for v in d["verdicts"] if v["req_id"] not in dropped]
    d["observations"] = [o for o in d["observations"] if o.get("req_id") not in dropped]
    d["contradictions"] = [c for c in d["contradictions"] if not dropped.intersection(c["req_ids"])]
    events = [e for e in d["events"] if e.get("req_id") not in dropped]
    for e in events:
        for st in e.get("quote_steps") or ():
            if st.get("model_quote"):
                st["model_quote"] = _clip(st["model_quote"])
    d["omitted_events"] = d["omitted_events"] + len(d["events"]) - len(events)
    d["events"] = events
    d["omitted_requirements"] = d.get("omitted_requirements", 0) + len(dropped)
    return restore_saved_record(json.dumps(d, ensure_ascii=False))


def check_bundle_limits(record: RunRecord) -> None:
    """同梱の実行記録（フィクスチャ以外）が、原文の長さと件数の上限を守っているか。守っていない記録は読み込まない。"""
    if len(record.requirements) > REPLAY_REQUIREMENTS_MAX:
        raise ValueError("同梱の記録の要件が上限を超えています")
    for r in record.requirements:
        if r.span is not None and len(r.span.original_span) > REPLAY_QUOTE_MAX_CHARS:
            raise ValueError("同梱の記録の引用が上限を超えています")
        if len(r.gist) > REPLAY_QUOTE_MAX_CHARS:
            raise ValueError("同梱の記録の言い換えが上限を超えています")
    for e in record.events:
        if any(len(st.model_quote or "") > REPLAY_QUOTE_MAX_CHARS for st in e.quote_steps):
            raise ValueError("同梱の記録のトレースの引用が上限を超えています")


def bundle_text(record: RunRecord) -> str:
    return json.dumps(json.loads(serialize_report(_as_replay(record))), ensure_ascii=False, indent=1, sort_keys=True) + "\n"


def leak_findings(text: str) -> dict[str, int]:
    """記録に、公開してはいけない文字列（鍵・メール・内部URL）が無いか。同梱の前に必ず空であること。"""
    return scan_text(text)


def _step_clock(step: float = 0.04):  # noqa: ANN202
    t = [1000.0]

    def clock() -> float:
        t[0] += step
        return t[0]

    return clock


async def build_fixture_record(preset_id: str) -> RunRecord:
    """②③の記録をオフラインで作る（FixtureFetch＋OracleReader＋RulePlanner。run_id・開始時刻・時計を固定して決定論にする）。"""
    preset = PRESETS[preset_id]
    host = preset.allowed_prefixes[0].host
    fetch = FixtureFetch(FixtureSite.load(), host, preset.allowed_prefixes)
    res = await run_audit(
        preset,
        fetch=fetch,
        reader_model=OracleReader(),
        planner_model=RulePlanner(),
        inspect_mode=InspectMode.PLANNER,
        settings=Settings(),
        run_id=f"replay_{preset_id}",
        clock=_step_clock(),
        started_at=REPLAY_STARTED_AT,
    )
    return res.record


def load_bundle(path: Path) -> ReplayBundle:
    text = path.read_text(encoding="utf-8")
    record = restore_saved_record(text)
    if record.mode is not RunMode.REPLAY or record.preset_id != path.stem:
        raise ValueError("REPLAY の記録ではない、またはプリセットIDがファイル名と合いません")
    if record.preset_id not in FIXTURE_REPLAYS:  # 実LPなど第三者の文章を含みうる記録は、縮めてあることを読み込みの条件にする
        check_bundle_limits(record)
    return ReplayBundle(
        preset_id=record.preset_id,
        record=record,
        record_json=serialize_report(record),
        event_jsons=tuple(e.model_dump_json(exclude_none=True) for e in record.events),
    )


def load_replays(root: Path = REPLAY_DIR) -> dict[str, ReplayBundle]:
    """同梱の記録を全部読む。壊れた記録は載せない（そのプリセットは「保存済みの実行なし」になる）。"""
    out: dict[str, ReplayBundle] = {}
    for p in sorted(root.glob("*.json")) if root.is_dir() else ():
        if p.stem not in PRESET_IDS:
            continue
        try:
            out[p.stem] = load_bundle(p)
        except Exception:  # noqa: BLE001  壊れた同梱物で起動を止めない（再生しないだけ）
            continue
    return out


def load_fixture_records(root: Path = REPLAY_DIR) -> dict[str, RunRecord]:
    """②③の同梱の記録を厳密に読む。load_replays と違い、無い・契約として読めないなら ExamplesError（黙って外さない）。
    公開面の対応表（examples.build_examples）の元にするので、起動時にここで止める。例外の文言に記録の中身は出さない。"""
    out: dict[str, RunRecord] = {}
    for pid in FIXTURE_REPLAYS:
        p = root / f"{pid}.json"
        if not p.is_file():
            raise ExamplesError(ExamplesCode.RECORD_MISSING, pid)
        try:
            out[pid] = load_bundle(p).record
        except Exception:  # noqa: BLE001  原因（検証エラーなど）は記録の中身を含みうるので、連鎖させず固定の識別子だけにする
            raise ExamplesError(ExamplesCode.RECORD_UNREADABLE, pid) from None
    return out


def cross_check(records: dict[str, RunRecord]) -> None:
    """記録が正解表と合うか（公開面の対応表を組み立てられるか）。合わなければ ExamplesError。"""
    build_examples({pid: PRESETS[pid] for pid in records}, records)


def _examples_problem(pid: str, record: RunRecord) -> str | None:
    try:
        cross_check({pid: record})
    except ExamplesError as e:
        return str(e)
    return None


ORACLE_READER = "oracle-reader"  # --write が作る台本の記録の reader_model（実モデルの記録と区別する印）


def _imported_record_ok(p: Path, text: str) -> bool:
    """実モデルの実行記録を取り込んだ記録の検査: 契約の読み込み・漏洩の走査・今のコードの再判定との一致。
    再判定との一致は、判定表とトレースの verdict イベントが、今の判定表（理由コード・理由文・語）のまま古びていないことを見る。
    印のある実行の記録（RejudgeUnsupported）は、記録の入力だけでは再判定できないので、この一致は見ない。"""
    try:
        record = load_bundle(p).record
    except Exception:  # noqa: BLE001  壊れた同梱物は差分として出す
        return False
    if leak_findings(text):
        return False
    try:
        again = rejudge(record)
    except RejudgeUnsupported:
        return True
    except RejudgeRefused:
        return False
    return again.verdicts == record.verdicts and again.events == record.events


def check(root: Path = REPLAY_DIR) -> list[str]:
    """同梱の記録を確かめる。台本から作った②③の記録（reader_model=oracle-reader）は、再生成と一致するか。
    実モデルの実行記録を --import で取り込んだもの（reader_model が別。実LP を含む）は再生成できないので、一致ではなく、
    契約の読み込み・漏洩の走査・今のコードの再判定との一致を確かめる（取り込み時にも通した検査と、判定表が古びていないかを、
    同梱後の改変やコードの変更に対して繰り返す）。②③の記録が無いのは差分。実LP の記録が無いのは差分にしない。
    ②③は最後に、正解表との照合（公開面の対応表を組み立てられるか）を通す。合わない時の差分は `ファイル名: 理由コード preset=… item=…`。"""
    diff = []
    for pid in PRESET_IDS:
        p = root / f"{pid}.json"
        if not p.is_file():
            if pid in FIXTURE_REPLAYS:
                diff.append(p.name)
            continue
        have = p.read_text(encoding="utf-8")
        try:
            imported = json.loads(have).get("reader_model") != ORACLE_READER
        except ValueError:
            diff.append(p.name)
            continue
        if imported or pid not in FIXTURE_REPLAYS:
            try:
                record = load_bundle(p).record
            except Exception:  # noqa: BLE001  壊れた同梱物は差分として出す
                diff.append(p.name)
                continue
            if pid in FIXTURE_REPLAYS:
                # 取り込んだ②③の記録は、まず正解表との照合を見る（食い違いは、どの項目かが分かる識別子つきの差分にする）
                problem = _examples_problem(pid, record)
                if problem:
                    diff.append(f"{p.name}: {problem}")
                    continue
            if not _imported_record_ok(p, have):  # 契約・漏洩の走査・今の判定表との一致（古びていないか）
                diff.append(p.name)
            continue
        else:
            record = asyncio.run(build_fixture_record(pid))
            if have != bundle_text(record):
                diff.append(p.name)
                continue
        problem = _examples_problem(pid, record)  # 公開面の対応表（正解表との照合）を組み立てられるか
        if problem:
            diff.append(f"{p.name}: {problem}")
    return diff


class RejudgeRefused(ValueError):
    """記録の入力（要件・文書・観測）から今のコードで再判定すると、記録を黙って別物に書き換えてしまう。書き換えない。"""


class RejudgeUnsupported(RejudgeRefused):
    """記録に残らない入力（Planner の確認不能の印・部分結果の印）が判定に効いた実行の記録。再判定できない。"""


# 関門（checks/unverifiable_reason）が決める確認不能の理由コード。これらの間の変更だけは、関門の改善として許す
_GATE_CODES = frozenset(
    {UnverifiableReason.HUMAN_ONLY, UnverifiableReason.FUTURE, UnverifiableReason.NOT_PUBLIC, UnverifiableReason.OUT_OF_SCOPE}
)


def _decided_by_gate(req) -> bool:  # noqa: ANN001
    return req.span is not None and req.kind is not Kind.SPECULATIVE and CHECK_CLASS_CHECKER[req.check_class] is None


def rejudge(record: RunRecord) -> RunRecord:
    """記録の要件・文書・観測から、判定（理由コード・理由文・根拠チップ）とトレースの verdict イベントを今の判定表で作り直す。

    ラベルは変えない（変わるなら RejudgeRefused）。理由コードが変わってよいのは、関門が決める要件（検査できないクラス）の
    関門の4コードの間だけ。それ以外の変更（印などの入力が足りない記録）は RejudgeRefused にして、黙って書き換えない。
    記録は Planner の印を持たないので、印のある実行（mark_unverifiable の呼び出しがある・部分結果）は RejudgeUnsupported。
    """
    if record.status is not RunStatus.DONE or any(e.name == ToolName.MARK_UNVERIFIABLE.value for e in record.events):
        raise RejudgeUnsupported("印のある実行の記録は、記録の入力だけでは再判定できません")
    new = adjudicate(AdjudicationInput(requirements=record.requirements, docs=record.docs, observations=record.observations))
    old = {v.req_id: v for v in record.verdicts}
    reqs = {r.req_id: r for r in record.requirements}
    if set(old) != {v.req_id for v in new}:
        raise RejudgeRefused("記録の要件と判定が対応しません")
    for v in new:
        was = old[v.req_id]
        if v.label is not was.label:
            raise RejudgeRefused(f"再判定でラベルが変わりました（{v.req_id}）。記録の入力が足りない可能性があります")
        if v.reason_code is not was.reason_code and not (
            _decided_by_gate(reqs[v.req_id]) and {v.reason_code, was.reason_code} <= _GATE_CODES
        ):
            raise RejudgeRefused(f"再判定で、関門の外の理由コードが変わりました（{v.req_id}）。記録の入力が足りない可能性があります")
    code_of = {v.req_id: (v.reason_code.value if v.reason_code else None) for v in new}
    events = tuple(
        e.model_copy(update={"reason_code": code_of[e.req_id]}) if e.type is TraceType.VERDICT and e.req_id in code_of else e
        for e in record.events
    )
    return record.model_copy(update={"verdicts": new, "events": events})


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.web.replay")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--write", action="store_true")
    g.add_argument("--check", action="store_true")
    g.add_argument("--import", dest="import_path", type=Path)
    g.add_argument("--rejudge", action="store_true")
    ap.add_argument("--preset", choices=PRESET_IDS)
    a = ap.parse_args(argv)
    if a.check:
        diff = check()
        for d in diff:
            print(f"差分: {d}")
        return 1 if diff else 0
    if a.rejudge:
        outs: dict[Path, str] = {}
        for pid in PRESET_IDS:  # 全記録を先に作り直し、1つでも再判定できなければ何も書かない
            p = REPLAY_DIR / f"{pid}.json"
            if not p.is_file():
                continue
            try:
                text = bundle_text(rejudge(load_bundle(p).record))
            except RejudgeRefused as e:
                print(f"{pid}: 再判定できません（{e}）", file=sys.stderr)
                return 1
            except Exception as e:  # noqa: BLE001  壊れた記録は、内容を出さずに種類だけ伝えて止める（何も書かない）
                print(f"{pid}: 記録を読めません（{type(e).__name__}）", file=sys.stderr)
                return 1
            if leak_findings(text):
                print(f"{pid}: 記録に公開してはいけない文字列があります", file=sys.stderr)
                return 1
            outs[p] = text
        for p, text in outs.items():
            p.write_text(text, encoding="utf-8")
        return 0
    if a.write:
        records = {pid: asyncio.run(build_fixture_record(pid)) for pid in FIXTURE_REPLAYS}
        texts = {pid: bundle_text(rec) for pid, rec in records.items()}
        for pid, text in texts.items():
            if leak_findings(text):
                print(f"{pid}: 記録に公開してはいけない文字列があります", file=sys.stderr)
                return 1
        try:
            cross_check(records)  # 書く前に。正解表と合わない記録は同梱しない
        except ExamplesError as e:
            print(f"記録が正解表と合いません（{e}）", file=sys.stderr)
            return 1
        REPLAY_DIR.mkdir(parents=True, exist_ok=True)
        for pid, text in texts.items():
            (REPLAY_DIR / f"{pid}.json").write_text(text, encoding="utf-8")
        return 0
    if not a.preset:
        ap.error("--import には --preset が要ります")
    try:
        record = clip_for_bundle(a.import_path.read_text(encoding="utf-8"))
    except (ValueError, KeyError, TypeError) as e:
        print(f"記録を取り込めません（{type(e).__name__}）", file=sys.stderr)
        return 1
    if record.preset_id != a.preset:
        print("記録のプリセットIDが --preset と合いません", file=sys.stderr)
        return 1
    text = bundle_text(record)
    found = leak_findings(text)
    if found:
        print(f"記録に公開してはいけない文字列があります（種類: {', '.join(sorted(found))}）", file=sys.stderr)
        return 1
    if a.preset in FIXTURE_REPLAYS:  # ②③は、公開面の対応表の元になる。正解表と合わない記録は取り込まない（起動で初めて落ちる、にしない）
        try:
            cross_check({a.preset: record})
        except ExamplesError as e:
            print(f"記録が正解表と合いません（{e}）", file=sys.stderr)
            return 1
    (REPLAY_DIR / f"{a.preset}.json").write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
