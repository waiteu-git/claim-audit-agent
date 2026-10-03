"""Python 3.13 でも動くことの機械検査（ローカルは 3.14、デプロイは 3.13）。

3.14 は注釈を遅延評価するため、「まだ定義されていない名前を注釈に書く」誤りが 3.14 では import できて 3.13 では
NameError になる（実際に tests/factories.py で一度起きた）。注釈が参照する名前が、その時点で定義済みかを AST で調べる。
文字列の注釈（"Foo"）は対象外。構文は 3.13 の文法で解釈できることも確かめる。
"""
import ast
import builtins
from pathlib import Path

import pytest

ROOTS = (Path("app"), Path("tests"), Path("ops"))


def _files() -> list[Path]:
    return sorted(p for r in ROOTS for p in r.rglob("*.py") if "__pycache__" not in p.parts)


def _bind_names(node: ast.stmt) -> list[str]:
    if isinstance(node, ast.Import):
        return [(a.asname or a.name.split(".")[0]) for a in node.names]
    if isinstance(node, ast.ImportFrom):
        return [(a.asname or a.name) for a in node.names]
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        return [n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name)]
    return []


def _is_type_checking(test: ast.expr) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def _collect(body: list[ast.stmt], out: dict[str, int]) -> None:
    """スコープ直下（if / try の中を含む）で束縛される名前 → 束縛が完了する行。"""
    for node in body:
        for name in _bind_names(node):
            out.setdefault(name, node.end_lineno or node.lineno)
        if isinstance(node, ast.If):
            if _is_type_checking(node.test):
                continue  # 実行時には束縛されない
            _collect(node.body, out)
            _collect(node.orelse, out)
        elif isinstance(node, ast.Try):
            for part in (node.body, node.orelse, node.finalbody, *[h.body for h in node.handlers]):
                _collect(part, out)
        elif isinstance(node, (ast.With, ast.For, ast.While)):
            _collect(node.body, out)


def _annotation_names(ann: ast.expr | None) -> list[ast.Name]:
    if ann is None:
        return []
    out: list[ast.Name] = []

    def visit(n: ast.AST) -> None:
        if isinstance(n, ast.Constant):  # 文字列の前方参照
            return
        if isinstance(n, ast.Name):
            out.append(n)
        for c in ast.iter_child_nodes(n):
            visit(c)

    visit(ann)
    return out


def _fn_annotations(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.expr | None]:
    a = fn.args
    args = [*a.posonlyargs, *a.args, *a.kwonlyargs, *([a.vararg] if a.vararg else []), *([a.kwarg] if a.kwarg else [])]
    return [x.annotation for x in args] + [fn.returns]


def undefined_annotation_names(source: str) -> list[str]:
    """3.13 で定義時に NameError になる注釈の名前（"名前@行"）を返す。"""
    tree = ast.parse(source, feature_version=(3, 13))
    module_names: dict[str, int] = {}
    _collect(tree.body, module_names)
    problems: list[str] = []

    def check(anns: list[ast.expr | None], when: int, local: dict[str, int]) -> None:
        for ann in anns:
            for n in _annotation_names(ann):
                if hasattr(builtins, n.id):
                    continue
                bound = min(module_names.get(n.id, 10**9), local.get(n.id, 10**9))
                if bound >= when:
                    problems.append(f"{n.id}@{n.lineno}")

    def walk_scope(body: list[ast.stmt], local: dict[str, int]) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                check(_fn_annotations(node), node.lineno, local)  # 定義時に評価される
                # 関数の中は実行時に評価されるのでここでは辿らない
            elif isinstance(node, ast.ClassDef):
                inner: dict[str, int] = {}
                walk_scope(node.body, inner)
            elif isinstance(node, ast.AnnAssign):
                check([node.annotation], node.lineno, local)
            elif isinstance(node, (ast.If, ast.Try, ast.With)):
                for part in (getattr(node, "body", []), getattr(node, "orelse", [])):
                    walk_scope(part, local)

    # クラス本体の中の名前は、そのクラス本体の中でだけ有効（メソッド注釈・フィールド注釈の解決用）
    def walk_class(node: ast.ClassDef) -> None:
        local: dict[str, int] = {}
        for stmt in node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                check(_fn_annotations(stmt), stmt.lineno, local)
            elif isinstance(stmt, ast.AnnAssign):
                check([stmt.annotation], stmt.lineno, local)
            elif isinstance(stmt, ast.ClassDef):
                walk_class(stmt)
            for name in _bind_names(stmt):
                local.setdefault(name, stmt.end_lineno or stmt.lineno)

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            check(_fn_annotations(node), node.lineno, {})
        elif isinstance(node, ast.ClassDef):
            walk_class(node)
        elif isinstance(node, ast.AnnAssign):
            check([node.annotation], node.lineno, {})
    return problems


# --- 検査器そのものの確認 -------------------------------------------------------------
@pytest.mark.parametrize(
    "src,expected",
    [
        ("def f() -> Later: ...\nclass Later: ...\n", ["Later@1"]),  # 後ろで定義される名前
        ("class A:\n    def m(self) -> A: ...\n", ["A@2"]),  # 自分自身を引用符なしで参照
        ("class A:\n    def m(self) -> 'A': ...\n", []),  # 引用符つきは可
        ("from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from x import T\ndef f(a: T): ...\n", ["T@4"]),
        ("from x import T\ndef f(a: T, *b: T, **c: T) -> T: ...\n", []),
        ("import typing as t\ndef f(a: t.Any): ...\n", []),
        ("class A:\n    x: int\n    y: B\nclass B: ...\n", ["B@3"]),
        ("class B: ...\nclass A:\n    y: B\n    def m(self, o: B | None) -> list[B]: ...\n", []),
        ("class A:\n    class Inner: ...\n    def m(self) -> Inner: ...\n", []),  # クラス内の名前は本体の中で解決できる
        ("def f():\n    def g(a: Undefined): ...\n", []),  # 関数の中は実行時評価（ここでは対象外）
        ("X = int\ndef f(a: X): ...\n", []),
        ("try:\n    from a import T\nexcept ImportError:\n    T = None\ndef f(a: T): ...\n", []),
    ],
)
def test_checker_finds_exactly_the_3_13_name_errors(src, expected):
    assert undefined_annotation_names(src) == expected


# --- 実コードへの適用 ---------------------------------------------------------------------
@pytest.mark.parametrize("path", _files(), ids=lambda p: p.as_posix())
def test_no_annotation_depends_on_python_3_14_lazy_evaluation(path):
    assert undefined_annotation_names(path.read_text(encoding="utf-8")) == []


def test_no_python_3_14_only_apis_are_used():
    banned = ("annotationlib", "string.templatelib", "compression.zstd", "concurrent.interpreters", "InterpreterPoolExecutor")
    offenders = [
        f"{p}: {needle}" for p in _files() if p.name != Path(__file__).name for needle in banned if needle in p.read_text(encoding="utf-8")
    ]
    assert offenders == []
