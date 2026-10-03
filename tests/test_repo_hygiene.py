"""統合担当の試験（その3）: リポジトリ全体の衛生（依存の固定・本番イメージの中身・import の向き・S1 の無傷）。

個々のモジュールの試験では見えない、「並行で作ったものを1つにまとめた時」に崩れやすい性質を固定する:

  * 依存は版を固定し、本番（requirements.txt）にテスト専用のものを入れない。コードが直接 import する外部ライブラリは全て宣言する。
  * 本番イメージは requirements.txt と app/ だけ（Dockerfile）。ローカルの作業物はビルド文脈に入れない（.dockerignore）。
  * app/ の import は一方向（循環・逆流は後続の担当が足したモジュールでも起きない）。外向き通信・Vertex の入口は決まった場所だけ。
  * 既存の S1（app/main.py）は他の app モジュールに依存せず、従来どおり動く。
"""
import ast
import importlib
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STDLIB = set(sys.stdlib_module_names)

# 直接 import される外部パッケージ → それを提供する配布名。未知の import が増えたらここへ足す（宣言漏れを止めるため）。
PROD_IMPORTS = {"fastapi": "fastapi", "google": "google-genai", "httpcore": "httpcore", "pydantic": "pydantic"}
TEST_ONLY_IMPORTS = {"pytest": "pytest", "cryptography": "cryptography", "idna": "idna"}
TEST_ONLY_DISTS = {"pytest", "pytest-asyncio", "cryptography", "idna"}  # 本番に宣言してはいけないもの


def _req_lines(name: str) -> list[str]:
    out = []
    for raw in (ROOT / name).read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def _dist(line: str) -> str:
    return re.split(r"==", line, maxsplit=1)[0].strip().lower().replace("_", "-")


def _third_party_imports(root: str) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for p in (ROOT / root).rglob("*.py"):
        if "__pycache__" in p.parts:
            continue
        src = p.read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(src)):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = [node.module]
            for n in names:
                top = n.split(".")[0]
                if top not in STDLIB and top not in {"app", "tests", "ops"}:
                    found.setdefault(top, set()).add(p.relative_to(ROOT).as_posix())
        for m in re.finditer(r"importorskip\(\s*[\"']([\w.]+)[\"']", src):  # 文字列で import する依存も宣言の対象
            found.setdefault(m.group(1).split(".")[0], set()).add(p.relative_to(ROOT).as_posix())
    return found


# --- 依存 ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["requirements.txt", "requirements-dev.txt"])
def test_every_requirement_is_pinned_to_an_exact_version(name: str):
    for line in _req_lines(name):
        if line.startswith("-r "):
            continue
        assert re.fullmatch(r"[A-Za-z0-9_.\-]+==\d+(?:\.\d+)*(?:[a-z0-9.\-]*)", line), f"{name}: {line}"


def test_production_requirements_do_not_declare_test_only_packages():
    declared = {_dist(line) for line in _req_lines("requirements.txt")}
    assert not (declared & TEST_ONLY_DISTS), declared & TEST_ONLY_DISTS
    assert not any(d.startswith("pytest") for d in declared)


def test_dev_requirements_extend_production_and_add_what_the_tests_import():
    lines = _req_lines("requirements-dev.txt")
    assert lines[0] == "-r requirements.txt"
    assert TEST_ONLY_DISTS <= {_dist(line) for line in lines[1:]}


def test_no_distribution_is_pinned_to_two_versions():
    prod = {_dist(line): line for line in _req_lines("requirements.txt")}
    for line in _req_lines("requirements-dev.txt")[1:]:
        assert _dist(line) not in prod, f"{line} は本番側にもある"


@pytest.mark.parametrize("root", ["app", "ops"])
def test_production_code_imports_only_declared_production_dependencies(root: str):
    declared = {_dist(line) for line in _req_lines("requirements.txt")}
    for top, files in _third_party_imports(root).items():
        assert top in PROD_IMPORTS, f"未知の外部 import {top}（{sorted(files)}）。PROD_IMPORTS と requirements.txt に足す"
        assert PROD_IMPORTS[top] in declared, f"{top} は requirements.txt に宣言が無い"


def test_test_code_imports_only_declared_dependencies():
    declared = {_dist(line) for line in _req_lines("requirements.txt") + _req_lines("requirements-dev.txt")}
    allowed = {**PROD_IMPORTS, **TEST_ONLY_IMPORTS}
    for top, files in _third_party_imports("tests").items():
        assert top in allowed, f"未知の外部 import {top}（{sorted(files)}）"
        assert allowed[top] in declared, f"{top} は requirements*.txt に宣言が無い"


@pytest.mark.parametrize("name", ["idna", "cryptography", "pytest_asyncio"])
def test_test_only_dependencies_are_installed_so_no_test_is_silently_skipped(name: str):
    """importorskip は無いと黙ってスキップする。宣言した依存が実際に入っていることを確かめる。"""
    importlib.import_module(name)


# --- 本番イメージ ----------------------------------------------------------------------------------------
def test_dockerfile_installs_only_production_requirements_and_copies_only_app():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^FROM python:3\.13", text, re.M)  # デプロイは 3.13
    installs = re.findall(r"pip install\s+(.*)", text)
    assert installs and all(i.strip() == "-r requirements.txt" for i in installs), installs
    assert "requirements-dev" not in text and "pytest" not in text
    copies = [ln.split()[1:] for ln in text.splitlines() if ln.startswith("COPY ")]
    assert copies == [["requirements.txt", "."], ["app", "./app"]], copies


def test_dockerignore_keeps_local_work_out_of_the_build_context():
    entries = {ln.strip() for ln in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")}
    assert {".git", ".venv", "tests", ".claude", "**/__pycache__", ".env"} <= entries


def test_gitignore_covers_environments_caches_credentials_and_third_party_skill_text():
    entries = {ln.strip() for ln in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")}
    must = {".venv/", "__pycache__/", "*.pyc", ".pytest_cache/", ".env", ".env.*", "*.pem", "*.key", ".DS_Store",
            ".claude/skills/gc-hackathon-vol5/", "tests/cassettes/local/"}  # fmt: skip
    assert must <= entries, must - entries


# --- import の向き・出口 ---------------------------------------------------------------------------------
def _unit(path: Path) -> str:
    parts = path.relative_to(ROOT).with_suffix("").parts  # ('app', 'net', 'safefetch') / ('app', 'config')
    return parts[1]


def _app_edges() -> dict[str, set[str]]:
    edges: dict[str, set[str]] = {}
    for p in (ROOT / "app").rglob("*.py"):
        if "__pycache__" in p.parts or p.name == "__init__.py" and p.parent == ROOT / "app":
            continue
        u = _unit(p)
        for node in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
            mods: list[str] = []
            if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                mods = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
            elif isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            for m in mods:
                parts = m.split(".")
                if parts[0] == "app" and len(parts) > 1 and parts[1] != u:
                    edges.setdefault(u, set()).add(parts[1])
    return edges


# 既知の単位だけを縛る（後から足されるモジュール＝agent・quota・egress_guard などは、下の「他から import されない」だけ守る）
ALLOWED_EDGES: dict[str, set[str]] = {
    "textsafe": set(),
    "errors": set(),
    "contracts": {"errors", "textsafe"},
    "config": {"contracts"},
    "jsonlog": {"contracts", "errors"},
    "net": {"config", "contracts", "jsonlog", "textsafe"},
    "model": {"config", "contracts", "errors"},
    "quotes": {"contracts", "textsafe"},
    "ingest": {"contracts", "net", "textsafe"},
    "checks": {"config", "contracts", "errors", "ingest"},
    "adjudicate": {"checks", "contracts"},
    "main": set(),  # S1 は他の app モジュールに依存しない
}
TOP_LEVEL_ONLY = {"agent", "main"}  # 他の単位から import されない


def test_app_modules_import_in_one_direction_only():
    edges = _app_edges()
    for unit, allowed in ALLOWED_EDGES.items():
        extra = edges.get(unit, set()) - allowed
        assert not extra, f"app.{unit} が依存してはいけない {sorted(extra)}（app/__init__.py の import の向きを参照）"


def test_nothing_imports_the_top_level_only_units():
    edges = _app_edges()
    for unit, deps in edges.items():
        assert not (deps & TOP_LEVEL_ONLY), f"app.{unit} が {sorted(deps & TOP_LEVEL_ONLY)} を import している"


def test_ingest_uses_the_net_package_only_for_the_pure_url_check():
    """ingest が使ってよい net は、標準ライブラリだけの urlcheck（リンク表のスコープ判定の共通定義）だけ。"""
    for p in (ROOT / "app" / "ingest").rglob("*.py"):
        for node in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("app.net"):
                assert node.module == "app.net.urlcheck", f"{p.name}: {node.module}"
            elif isinstance(node, ast.Import):
                assert not any(a.name.startswith("app.net") for a in node.names), p.name


def test_the_vertex_sdk_is_imported_only_by_the_model_port_and_the_s1_service():
    allowed = {"app/model/gemini.py", "app/main.py"}
    offenders = sorted(f for f in _third_party_imports("app").get("google", set()) if f not in allowed)
    assert offenders == []


def test_production_code_never_imports_tests_ops_or_pytest():
    for p in (ROOT / "app").rglob("*.py"):
        for node in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else ([node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
            for n in names:
                assert n.split(".")[0] not in {"tests", "ops", "pytest", "_pytest"}, f"{p.relative_to(ROOT)}: {n}"


# --- S1（疎通確認サービス）が従来どおり ------------------------------------------------------------------
@pytest.fixture
def s1(monkeypatch):
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "placeholder-project")  # 実在しない値（S1 は import 時に必須の環境変数として読む）
    monkeypatch.delenv("KILL_SWITCH", raising=False)
    monkeypatch.setenv("MAX_LLM_CALLS_PER_HOUR", "0")  # 万一 /probe が上限の手前まで進んでも、モデルは呼ばれない
    sys.modules.pop("app.main", None)
    mod = importlib.import_module("app.main")
    yield mod
    sys.modules.pop("app.main", None)


def test_s1_service_still_imports_and_registers_its_two_routes(s1):
    routes = {(r.path, tuple(sorted(r.methods))) for r in s1.app.routes if r.path in ("/health", "/probe")}
    assert routes == {("/health", ("GET",)), ("/probe", ("POST",))}


def test_s1_health_reports_the_kill_switch_state(s1, monkeypatch):
    assert s1.health() == {"ok": True, "killed": False, "model": s1.MODEL}
    monkeypatch.setenv("KILL_SWITCH", "1")
    assert s1.health()["killed"] is True


def test_s1_probe_is_refused_before_any_model_call_by_the_kill_switch_and_the_hourly_cap(s1, monkeypatch):
    from fastapi import HTTPException

    monkeypatch.setenv("KILL_SWITCH", "1")
    with pytest.raises(HTTPException) as e:
        s1.probe()
    assert e.value.status_code == 503
    monkeypatch.delenv("KILL_SWITCH")
    with pytest.raises(HTTPException) as e:
        s1.probe()  # 毎時の上限が 0 なので、クライアントを作る手前で 429
    assert e.value.status_code == 429
    assert s1._client is None  # Vertex のクライアントは作られていない


def test_s1_does_not_pull_any_other_app_module_into_the_process():
    """S1 の import が app.net・app.model（ScriptedPort など）を巻き込まない＝本番起動時の import 連鎖が増えない。"""
    code = "import sys, app.main; print(sorted(m for m in sys.modules if m.startswith('app.')))"
    env = dict(os.environ, GOOGLE_CLOUD_PROJECT="placeholder-project")
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True, check=True).stdout
    assert out.strip() == "['app.main']", out


# --- 第三者原文・個人情報の持ち込み ----------------------------------------------------------------------
def _norm(s: str) -> str:
    import unicodedata

    return re.sub(r"\s+", "", unicodedata.normalize("NFKC", s))


def test_no_long_verbatim_overlap_with_the_organizer_skill_text_in_code_and_tests():
    """配布スキルの文章（このリポの作業ツリーにだけ在る。git には載せない）を、30字以上そのまま埋め込んでいない。
    スキルが無い環境（新しいクローン）では対象が無いのでスキップする。"""
    skill = ROOT / ".claude" / "skills" / "gc-hackathon-vol5"
    refs = sorted(skill.rglob("*.md")) if skill.is_dir() else []
    if not refs:
        pytest.skip("配布スキルが作業ツリーに無い")
    n = 30
    shingles: set[int] = set()
    for p in refs:
        s = _norm(p.read_text(encoding="utf-8", errors="ignore"))
        shingles.update(hash(s[i : i + n]) for i in range(max(0, len(s) - n + 1)))
    offenders = []
    for root in ("app", "tests", "ops"):
        for p in (ROOT / root).rglob("*.py"):
            if "__pycache__" in p.parts:
                continue
            s = _norm(p.read_text(encoding="utf-8"))
            if any(hash(s[i : i + n]) in shingles for i in range(max(0, len(s) - n + 1))):
                offenders.append(p.relative_to(ROOT).as_posix())
    assert offenders == []


def test_only_placeholder_email_addresses_appear_in_the_repository():
    mail = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})")
    files = [p for r in ("app", "tests", "ops") for p in (ROOT / r).rglob("*.py") if "__pycache__" not in p.parts]
    files += [ROOT / n for n in ("README.md", "deploy.sh", "Dockerfile", "requirements.txt", "requirements-dev.txt")]
    bad = []
    for p in files:
        for m in mail.finditer(p.read_text(encoding="utf-8")):
            if not (m.group(1).endswith(".invalid") or m.group(1) in {"example.com", "example.org", "example.net"}):
                bad.append(f"{p.relative_to(ROOT)}: {m.group(0)}")
    assert bad == []
