"""依存OSSのライセンス一覧（THIRD_PARTY_NOTICES.md）を、インストール済みのパッケージのメタデータから作る。

規約は、OSS を使う提出物に「ライセンス情報を明記すること」を求める。README の表は直接の依存だけなので、推移的な依存を含む
本番イメージの全パッケージを、この一覧に載せる。ライセンスの表記は **メタデータに書かれていた文字列そのまま**（自分で推測した値ではない。
パッケージによって「Apache 2.0」「Apache-2.0」のように書き方が違うが、揃えない）。メタデータに無いものは「記載なし（要確認）」と出す。

  python -m tools.third_party_notices --write   # THIRD_PARTY_NOTICES.md を作り直す（本番と同じ Python で実行すること）
  python -m tools.third_party_notices --check   # 一覧が requirements.txt とインストール済みの閉包に合っているか（差があれば終了コード1）

閉包は requirements.txt の固定版（`==`）を根に、`Requires-Dist` を辿って作る（環境マーカーは今の Python で評価し、要求された extra も辿る）。
requirements.txt は推移的な依存まで固定してあるので、一覧は本番イメージに入る全パッケージと一致する（`--check` で確かめる）。
"""
import argparse
import re
import sys
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "THIRD_PARTY_NOTICES.md"
MISSING = "記載なし（要確認）"


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def roots(path: Path = ROOT / "requirements.txt") -> list[str]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Za-z0-9_.\-]+)==", line.split("#")[0].strip())
        if m:
            out.append(m.group(1))
    return out


def closure(start: list[str]) -> list[metadata.Distribution]:
    """requirements.txt の固定版を根に、Requires-Dist を辿った全パッケージ（今の Python・環境マーカーで評価。要求された extra も辿る）。"""
    from packaging.requirements import Requirement

    seen: dict[str, metadata.Distribution] = {}
    done: set[tuple[str, str]] = set()

    def visit(name: str, extras: frozenset[str]) -> None:
        key = _norm(name)
        try:
            dist = seen.get(key) or metadata.distribution(name)
        except metadata.PackageNotFoundError:
            return
        seen[key] = dist
        for extra in extras or {""}:
            if (key, extra) in done:
                continue
            done.add((key, extra))
            for raw in dist.requires or []:
                req = Requirement(raw)
                if req.marker is not None and not req.marker.evaluate({"extra": extra}):
                    continue
                visit(req.name, frozenset(req.extras))

    for r in start:
        visit(r, frozenset())
    return sorted(seen.values(), key=lambda d: _norm(d.metadata["Name"]))


def license_text(dist: metadata.Distribution) -> str:
    md = dist.metadata
    expr = md.get("License-Expression")
    if expr:
        return expr.strip()
    lic = md.get("License")
    if lic and len(lic) < 80 and "\n" not in lic:
        return lic.strip()
    classifiers = [c.split("::")[-1].strip() for c in md.get_all("Classifier") or [] if c.startswith("License ::")]
    return " / ".join(classifiers) if classifiers else MISSING


def rows() -> list[tuple[str, str, str]]:
    return [(d.metadata["Name"], d.version, license_text(d)) for d in closure(roots())]


def render() -> str:
    lines = [
        "# 依存OSSのライセンス一覧",
        "",
        "このファイルは `python -m tools.third_party_notices --write` が、本番イメージに入る全パッケージ（`requirements.txt` の固定版。推移的な依存も固定してある）を、",
        "インストール済みパッケージのメタデータから作ります。**ライセンスの表記は、メタデータに書かれていた文字列そのままです**",
        "（自分で推測した値ではありません。「Apache 2.0」と「Apache-2.0」のように書き方が違うものも、揃えていません）。",
        "全文と著作権表示は、各パッケージの配布物で確認してください。テスト専用の依存（`requirements-dev.txt`）は、本番イメージに入れないので、ここには載せていません",
        "（README に一覧があります）。",
        "",
        "| パッケージ | 版 | ライセンス（メタデータの表記） |",
        "|---|---|---|",
    ]
    for name, version, lic in rows():
        lines.append(f"| {name} | {version} | {lic} |")
    lines.append("")
    return "\n".join(lines)


def check() -> list[str]:
    problems = []
    text = OUT.read_text(encoding="utf-8") if OUT.is_file() else ""
    have = {}
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 3 and cells[0] not in ("パッケージ", "---") and not cells[0].startswith("-"):
            have[_norm(cells[0])] = (cells[1], cells[2])
    want = {_norm(n): (v, lic) for n, v, lic in rows()}
    for k in sorted(set(want) | set(have)):
        if k not in have:
            problems.append(f"一覧に無い: {k}")
        elif k not in want:
            problems.append(f"インストールされていない（古い行）: {k}")
        elif have[k] != want[k]:
            problems.append(f"食い違い: {k} 一覧={have[k]} 実際={want[k]}")
    for k, (_, lic) in have.items():
        if lic == MISSING:
            problems.append(f"ライセンスの表記がメタデータに無い: {k}")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m tools.third_party_notices")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--write", action="store_true")
    g.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    if args.write:
        OUT.write_text(render(), encoding="utf-8")
        print(f"wrote {OUT.name}: {len(rows())} packages")
        return 0
    problems = check()
    for p in problems:
        print(p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
