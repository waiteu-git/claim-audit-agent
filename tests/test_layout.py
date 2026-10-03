"""構造の規約を grep / AST で固定する（設計 §5-1 型分離・§2 出口の一本化・§8 ⑩）。"""
import ast
from pathlib import Path

APP = Path("app")


def py_files(root: Path = APP):
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def test_verification_seals_are_issued_only_in_quotes_and_contracts():
    """VerifiedRequirement の印を発行できるのは DocIndex（quotes.py）だけ。tests/ と ops/ は組み立て用に許可。"""
    allowed = {"app/contracts.py"}
    offenders = []
    for p in py_files():
        rel = p.as_posix()
        if rel in allowed or rel == "app/quotes.py" or rel.startswith("app/quotes/"):
            continue
        if "VerificationSeal" in p.read_text(encoding="utf-8"):
            offenders.append(rel)
    assert offenders == []


def test_only_the_net_package_may_import_http_clients():
    """出口は fetcher クライアント1か所（app/net）。agent 側から直接 requests/httpx/aiohttp/socket を使わない。"""
    banned = {"requests", "httpx", "aiohttp", "urllib3", "urllib.request", "http.client", "socket", "websockets"}
    offenders = []
    for p in py_files():
        rel = p.as_posix()
        if rel.startswith("app/net/"):
            continue
        for node in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for n in names:
                if n in banned or n.split(".")[0] in {"requests", "httpx", "aiohttp", "urllib3", "websockets"}:
                    offenders.append(f"{rel}: {n}")
    assert offenders == []


def _imported_modules(path: Path) -> set[str]:
    mods: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            mods |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
            mods |= {f"{node.module}.{a.name}" for a in node.names}  # from app.model import scripted
    return mods


def test_production_modules_do_not_import_scripted_or_cassette_ports():
    """ScriptedPort / cassette はテスト専用。本番の import 連鎖に入れない（§8 ⑩）。"""
    test_only = ("app.model.scripted", "app.model.cassette")
    offenders = []
    for p in py_files():
        if p.as_posix() in ("app/model/scripted.py", "app/model/cassette.py"):
            continue
        offenders += [f"{p}: {m}" for m in _imported_modules(p) if m in test_only]
    assert offenders == []


def test_contract_modules_depend_only_on_leaf_modules():
    """contracts / errors / textsafe は他の app モジュールに依存しない（contracts は errors・textsafe だけ）。"""
    allowed = {"app/contracts.py": {"app.errors", "app.textsafe"}, "app/errors.py": set(), "app/textsafe.py": set()}
    for rel, ok in allowed.items():
        imported = set()
        for node in ast.walk(ast.parse(Path(rel).read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("app"):
                imported.add(node.module)
            elif isinstance(node, ast.Import):
                imported |= {a.name for a in node.names if a.name.startswith("app")}
        assert imported <= ok, f"{rel}: {imported - ok}"


def test_package_skeleton_exists_for_later_modules():
    for pkg in ("net", "model", "ingest", "agent", "checks"):
        assert (APP / pkg / "__init__.py").is_file(), pkg


def test_no_third_party_text_or_real_identifiers_in_code_and_tests():
    """本物のプロジェクトID・サービスアカウント・run.app の URL をコード・テストに書かない。"""
    import re

    pat = re.compile(r"\.iam\.gserviceaccount\.com|[a-z0-9-]+\.run\.app|AIza[0-9A-Za-z_-]{20,}|ya29\.|BEGIN [A-Z ]*PRIVATE KEY")
    offenders = []
    for root in (Path("app"), Path("tests"), Path("ops")):
        for p in root.rglob("*.py"):
            for m in pat.finditer(p.read_text(encoding="utf-8")):
                # 検知用の正規表現そのものを書いたテストは許可（このファイルとリーク走査のテスト）
                if p.name != "test_layout.py":
                    offenders.append(f"{p}: {m.group(0)}")
    assert offenders == []
