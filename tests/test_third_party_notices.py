"""THIRD_PARTY_NOTICES.md が requirements.txt の固定版と一致していること（規約は、OSS を使う提出物にライセンス情報の明記を求める）。

インストール済みのパッケージとの突き合わせは、ネットワークも環境も要るので `python -m ops.third_party_notices --check` に任せる（本番と同じ Python で実行）。
ここでは、ファイル同士（固定版と一覧）の一致と、「要確認」が残っていないことを確かめる。
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _pins() -> dict[str, str]:
    out = {}
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s#]+)", line.strip())
        if m:
            out[_norm(m.group(1))] = m.group(2)
    return out


def _rows() -> dict[str, tuple[str, str]]:
    out = {}
    for line in (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if line.startswith("|") and len(cells) == 3 and cells[0] != "パッケージ" and not cells[0].startswith("-"):
            out[_norm(cells[0])] = (cells[1], cells[2])
    return out


def test_requirements_pin_every_package_exactly():
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        body = line.strip()
        if body and not body.startswith("#"):
            assert re.fullmatch(r"[A-Za-z0-9_.\-]+==[A-Za-z0-9_.\-+]+", body), f"版を固定していない行: {body}"


def test_every_pinned_package_is_listed_with_the_same_version():
    pins, rows = _pins(), _rows()
    assert pins, "requirements.txt に固定版が無い"
    assert set(pins) == set(rows), f"一覧との差: {sorted(set(pins) ^ set(rows))}"
    assert {k: v[0] for k, v in rows.items()} == pins


def test_no_license_is_left_unconfirmed():
    assert all(lic and "要確認" not in lic for _, lic in _rows().values())


def test_readme_points_to_the_notices_and_has_no_unresolved_marker():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "THIRD_PARTY_NOTICES.md" in readme
    assert "要確認" not in readme
