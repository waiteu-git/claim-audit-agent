"""REPLAY: 同梱した実行記録（app/web/replay/<preset_id>.json）の読み込みと生成。Vertex・Firestore に依存しない。

同梱の②③は、架空フィクスチャを OracleReader（台本の Reader。実 LLM ではない）＋router でオフライン実行して作った記録で、
記録の reader_model に "oracle-reader" と残る（画面にも出る＝実モデルの実行と偽らない）。実 Gemini の実行記録で置き換える時は
`python -m app.cli <preset> --format json --out rec.json` の出力を `--import` で取り込む（漏洩の走査と契約の検証を通ったものだけ）。

  python -m app.web.replay --write            # ②③の記録を作り直す（決定論: run_id・時刻・時計を固定）
  python -m app.web.replay --check            # 同梱の記録が生成物と一致するか（tests も確かめる）
  python -m app.web.replay --import rec.json --preset lp_self   # 実行記録を REPLAY として取り込む
"""
import argparse
import asyncio
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.agent.planner import InspectMode
from app.agent.run import run_audit
from app.checks.leak_scan import scan_text
from app.config import PRESET_IDS, PRESET_SAMPLE_DEFECT, PRESET_SAMPLE_INJECTION, PRESETS, Settings
from app.contracts import RunMode, RunRecord, serialize_report
from app.fixtures.eval import OracleReader
from app.fixtures.site import FixtureFetch, FixtureSite
from app.quotes.replay import restore_saved_record

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
    """②③の記録をオフラインで作る（FixtureFetch＋OracleReader＋router。run_id・開始時刻・時計を固定して決定論にする）。"""
    preset = PRESETS[preset_id]
    host = preset.allowed_prefixes[0].host
    fetch = FixtureFetch(FixtureSite.load(), host, preset.allowed_prefixes)
    res = await run_audit(
        preset,
        fetch=fetch,
        reader_model=OracleReader(),
        inspect_mode=InspectMode.ROUTER,
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


def check(root: Path = REPLAY_DIR) -> list[str]:
    diff = []
    for pid in FIXTURE_REPLAYS:
        want = bundle_text(asyncio.run(build_fixture_record(pid)))
        p = root / f"{pid}.json"
        if not p.is_file() or p.read_text(encoding="utf-8") != want:
            diff.append(p.name)
    return diff


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.web.replay")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--write", action="store_true")
    g.add_argument("--check", action="store_true")
    g.add_argument("--import", dest="import_path", type=Path)
    ap.add_argument("--preset", choices=PRESET_IDS)
    a = ap.parse_args(argv)
    if a.check:
        diff = check()
        for d in diff:
            print(f"差分: {d}")
        return 1 if diff else 0
    if a.write:
        REPLAY_DIR.mkdir(parents=True, exist_ok=True)
        for pid in FIXTURE_REPLAYS:
            text = bundle_text(asyncio.run(build_fixture_record(pid)))
            if leak_findings(text):
                print(f"{pid}: 記録に公開してはいけない文字列があります", file=sys.stderr)
                return 1
            (REPLAY_DIR / f"{pid}.json").write_text(text, encoding="utf-8")
        return 0
    if not a.preset:
        ap.error("--import には --preset が要ります")
    record = restore_saved_record(a.import_path.read_text(encoding="utf-8"))
    if record.preset_id != a.preset:
        print("記録のプリセットIDが --preset と合いません", file=sys.stderr)
        return 1
    text = bundle_text(record)
    found = leak_findings(text)
    if found:
        print(f"記録に公開してはいけない文字列があります（種類: {', '.join(sorted(found))}）", file=sys.stderr)
        return 1
    (REPLAY_DIR / f"{a.preset}.json").write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
