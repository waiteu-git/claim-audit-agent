"""ループバックの実 TLS で、接続ピン留め・SNI・証明書検証を確かめる（設計 §5-3「最初の30分の実証」）。

外向き通信はしない。偽の名前解決が「公開 IP」を返し、内側のネットワーク層がその接続先を 127.0.0.1 の試験用 TLS サーバーへ
付け替える。確かめること:
  1. 接続先として内側に渡るのは検査済みの IP（名前ではない）。
  2. それでも SNI と証明書検証は元のホスト名で行われる（IP に接続しても検証を弱めない）。
  3. 証明書が別の名前なら失敗する＝検証が実際に効いている（陰性対照）。
  4. 転送の各ホップが、そのホップの IP とホスト名で接続し直す。
"""
import asyncio
import datetime
import ssl
from dataclasses import dataclass, field
from pathlib import Path

import httpcore
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.contracts import FetchOutcome, FetchRequest
from app.net.safefetch import SafeFetch
from app.net.vectors import PUBLIC_IP, PUBLIC_IP_2, SVC2_HOST, SVC_HOST, VECTOR_PREFIXES
from tests.net_support import FakeResolver


def make_cert(*names: str) -> tuple[bytes, bytes]:
    """names すべてを SAN に持つ自己署名証明書（試験用の信頼の起点を兼ねる）。PEM の (証明書, 秘密鍵)。"""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
    )


@dataclass
class TlsServer:
    port: int
    sni: list[str | None] = field(default_factory=list)  # ClientHello の server_name
    hosts: list[str] = field(default_factory=list)  # リクエストの Host ヘッダ
    paths: list[str] = field(default_factory=list)


class LoopbackBackend(httpcore.AsyncNetworkBackend):
    """接続先を 127.0.0.1 の試験用サーバーへ付け替える。内側（AnyIOBackend）は実際の TCP・TLS を行う。"""

    def __init__(self, port: int) -> None:
        self._port = port
        self._real = httpcore.AnyIOBackend()
        self.requested: list[tuple[str, int]] = []  # SafeFetch が接続先として渡したもの（付け替え前）

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):  # type: ignore[no-untyped-def]  # noqa: ANN001, ANN201
        self.requested.append((host, port))
        return await self._real.connect_tcp("127.0.0.1", self._port, timeout=timeout, local_address=None, socket_options=socket_options)

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):  # type: ignore[no-untyped-def]  # noqa: ANN001, ANN201
        raise AssertionError("UNIX ソケットは使わない")

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


async def _start_server(tmp_path: Path, cert_names: tuple[str, ...]):
    cert_pem, key_pem = make_cert(*cert_names)
    (tmp_path / "c.pem").write_bytes(cert_pem)
    (tmp_path / "k.pem").write_bytes(key_pem)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    server_ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    state = TlsServer(port=0)
    server_ctx.sni_callback = lambda sock, name, ctx: state.sni.append(name)  # noqa: ARG005  None を返す＝続行

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = (await reader.readuntil(b"\r\n\r\n")).decode("latin-1")
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            writer.close()
            return
        lines = head.split("\r\n")
        path = lines[0].split(" ")[1]
        state.paths.append(path)
        state.hosts.append(next(ln.split(":", 1)[1].strip() for ln in lines if ln.lower().startswith("host:")))
        if path == "/fx/redirect":
            raw = f"HTTP/1.1 302 Found\r\nLocation: https://{SVC2_HOST}/fx2/b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode()
        else:
            body = b"<html>tls ok</html>"
            raw = (
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body
            )
        writer.write(raw)
        await writer.drain()
        writer.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=server_ctx)
    state.port = srv.sockets[0].getsockname()[1]
    return srv, state, cert_pem


def _client_ctx(trusted_pem: bytes) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cadata=trusted_pem.decode())  # ホスト名検証は既定のまま有効
    assert ctx.check_hostname and ctx.verify_mode is ssl.CERT_REQUIRED
    return ctx


def _fetcher(state: TlsServer, ctx: ssl.SSLContext) -> tuple[SafeFetch, LoopbackBackend]:
    backend = LoopbackBackend(state.port)
    sf = SafeFetch(VECTOR_PREFIXES, resolver=FakeResolver(), network_backend=backend, ssl_context=ctx)
    return sf, backend


@pytest.fixture
async def tls_env(tmp_path: Path):
    srv, state, cert_pem = await _start_server(tmp_path, (SVC_HOST, SVC2_HOST))
    try:
        yield state, cert_pem
    finally:
        srv.close()
        await srv.wait_closed()


async def test_pins_to_the_checked_ip_while_sni_and_certificate_verification_use_the_hostname(tls_env):
    state, cert_pem = tls_env
    sf, backend = _fetcher(state, _client_ctx(cert_pem))
    r = await sf.fetch(FetchRequest(url=f"https://{SVC_HOST}/fx/a"))
    assert (r.outcome, r.status, r.body) == (FetchOutcome.OK, 200, b"<html>tls ok</html>")
    assert backend.requested == [(PUBLIC_IP, 443)]  # 名前ではなく検査済み IP が渡った
    assert state.sni == [SVC_HOST]  # それでも SNI は元のホスト名
    assert state.hosts == [SVC_HOST]


async def test_certificate_for_a_different_name_is_rejected_even_though_the_ip_was_checked(tmp_path: Path):
    """陰性対照: 証明書の名前が違えば失敗する＝IP へ接続しても、ホスト名の検証は実際に効いている。"""
    srv, state, cert_pem = await _start_server(tmp_path, ("someone-else.example.invalid",))
    try:
        sf, _ = _fetcher(state, _client_ctx(cert_pem))
        d = await sf.fetch_ex(FetchRequest(url=f"https://{SVC_HOST}/fx/a"))
        assert d.result.outcome is FetchOutcome.NETWORK_ERROR and d.result.body == b""
        assert state.paths == []  # 検証に失敗したので、HTTP リクエストは1つも送られていない
    finally:
        srv.close()
        await srv.wait_closed()


async def test_untrusted_certificate_is_rejected(tls_env, tmp_path: Path):
    state, _ = tls_env
    other_pem, _key = make_cert(SVC_HOST, SVC2_HOST)  # 同じ名前だが、信頼していない別の証明書
    sf, _ = _fetcher(state, _client_ctx(other_pem))
    r = await sf.fetch(FetchRequest(url=f"https://{SVC_HOST}/fx/a"))
    assert r.outcome is FetchOutcome.NETWORK_ERROR and state.paths == []


async def test_each_redirect_hop_reconnects_to_its_own_checked_ip_with_its_own_sni(tls_env):
    state, cert_pem = tls_env
    sf, backend = _fetcher(state, _client_ctx(cert_pem))
    r = await sf.fetch(FetchRequest(url=f"https://{SVC_HOST}/fx/redirect"))
    assert (r.outcome, r.status) == (FetchOutcome.OK, 200)
    (hop,) = r.redirects
    assert hop.followed is True and r.final_url == f"https://{SVC2_HOST}/fx2/b"
    # ホップごとに、そのホップの検査済み IP へ接続し直し、そのホップのホスト名で SNI・Host を送る
    assert backend.requested == [(PUBLIC_IP, 443), (PUBLIC_IP_2, 443)]
    assert state.sni == [SVC_HOST, SVC2_HOST] and state.hosts == [SVC_HOST, SVC2_HOST]
    assert state.paths == ["/fx/redirect", "/fx2/b"]
