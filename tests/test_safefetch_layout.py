"""外向き通信の出口が app/net の1か所だけであることの構造検査（設計 §2 信頼境界）と、既定の配線の確認。

tests/test_layout.py の同種の検査（requests / httpx / aiohttp など）を、T3 で入る下位の部品（httpcore・h11・h2・ssl・anyio）と
ソケット操作の呼び出しまで広げる。app/net 以外が下位の部品を直接使えば、SafeFetch を通らない外向き通信になる。
"""
import ast
import ssl
from pathlib import Path

import httpcore

from app.net.backend import PinnedBackend
from app.net.resolver import system_resolver
from app.net.safefetch import SafeFetch
from app.net.vectors import VECTOR_PREFIXES

APP = Path("app")
OPS = Path("ops")
# 名前（先頭一致）で禁止: HTTP クライアントとその下位部品・生ソケット・TLS・プロキシ越し・非 HTTP の外向きプロトコル
BANNED_MODULES = (
    "httpx", "httpcore", "aiohttp", "requests", "urllib3", "h11", "h2", "hyper", "websockets", "websocket",
    "socket", "ssl", "anyio.streams.tls", "http.client", "urllib.request", "ftplib", "smtplib", "poplib", "imaplib",
    "telnetlib", "xmlrpc.client", "socks", "paramiko",
)
# 呼び出し（属性名）で禁止: ソケットを開く・名前を引く・URL を開く・プロセス経由の通信
BANNED_CALLS = {
    "urlopen", "open_connection", "create_connection", "sock_connect", "getaddrinfo", "gethostbyname",
    "getnameinfo", "start_tls", "create_datagram_endpoint", "connect_tcp",
}


def _py(root: Path):
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _imports(tree: ast.AST) -> list[str]:
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.append(node.module)
            out += [f"{node.module}.{a.name}" for a in node.names]
    return out


def _is_banned(name: str) -> bool:
    return any(name == b or name.startswith(b + ".") for b in BANNED_MODULES)


def test_only_app_net_may_import_http_clients_sockets_or_tls():
    offenders = []
    for root in (APP, OPS):
        for p in _py(root):
            if p.as_posix().startswith("app/net/"):
                continue
            tree = ast.parse(p.read_text(encoding="utf-8"))
            offenders += [f"{p}: import {n}" for n in _imports(tree) if _is_banned(n)]
    assert offenders == []


def test_only_app_net_may_call_socket_level_functions():
    offenders = []
    for root in (APP, OPS):
        for p in _py(root):
            if p.as_posix().startswith("app/net/"):
                continue
            for node in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Call):
                    f = node.func
                    name = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else None)
                    if name in BANNED_CALLS:
                        offenders.append(f"{p}:{node.lineno}: {name}()")
    assert offenders == []


def test_the_structural_check_would_actually_catch_a_violation():
    """検査自体の陽性対照: 違反を含むソースを渡すと見つかる（検査が何も見ていない状態で緑にならない）。"""
    bad = ast.parse("import httpcore\nfrom h11 import Connection\nimport socket\nsocket.getaddrinfo('x', 1)\n")
    assert [n for n in _imports(bad) if _is_banned(n)] == ["httpcore", "h11", "h11.Connection", "socket"]
    ok = ast.parse("import json\nfrom app.net.safefetch import SafeFetch\nimport httpcorelike\n")
    assert [n for n in _imports(ok) if _is_banned(n)] == []  # 名前の先頭一致の誤爆（httpcorelike）が無い


def test_default_wiring_uses_real_dns_the_real_backend_and_a_verifying_tls_context():
    sf = SafeFetch(VECTOR_PREFIXES)
    assert isinstance(sf._inner, httpcore.AnyIOBackend)
    assert sf._guard._resolver is system_resolver
    ctx = sf._ssl
    assert ctx.check_hostname is True and ctx.verify_mode is ssl.CERT_REQUIRED
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_the_pool_is_built_with_the_pinned_backend_and_no_connection_reuse():
    """配線の確認: 取得ごとの接続プールは PinnedBackend を使い、接続を使い回さず、HTTP/2 も使わない。"""
    src = Path("app/net/safefetch.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "AsyncConnectionPool"]
    assert len(calls) == 1
    kw = {k.arg: k.value for k in calls[0].keywords}
    assert isinstance(kw["network_backend"], ast.Call) and kw["network_backend"].func.id == PinnedBackend.__name__
    assert ast.literal_eval(kw["max_keepalive_connections"]) == 0
    assert ast.literal_eval(kw["http2"]) is False and ast.literal_eval(kw["retries"]) == 0
