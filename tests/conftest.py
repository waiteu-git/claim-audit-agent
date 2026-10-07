"""pytest 基盤。全テストを完全オフラインにする（外向き通信を遮断）。

ローカルループバック（127.0.0.1 / ::1 / localhost / Unix ソケット）だけ許可する。
DNS や通信は注入できる形にしてフェイクを使うこと。やむを得ず外す場合だけ @pytest.mark.allow_network。
遮断は例外で止めるが、呑み込まれても分かるよう違反を記録し、テスト終了時に失敗させる。
"""
import ipaddress
import socket

import pytest

from app.config import Settings, load_settings

_LOOPBACK_NAMES = {"localhost", "ip6-localhost"}


class NetworkBlockedError(AssertionError):
    """テスト中に外向き通信を試みた。"""


def _host_is_local(host: object) -> bool:
    if host is None or host == "":
        return True
    if isinstance(host, bytes):
        host = host.decode("ascii", "ignore")
    if not isinstance(host, str):
        return False
    if host.lower() in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host.split("%")[0]).is_loopback
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def _offline_guard(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch):
    if request.node.get_closest_marker("allow_network"):
        yield
        return
    violations: list[str] = []
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_getaddrinfo = socket.getaddrinfo

    def check_addr(kind: str, address: object) -> None:
        host = address[0] if isinstance(address, tuple) and address else address
        if not _host_is_local(host):
            violations.append(f"{kind} {host!r}")
            raise NetworkBlockedError(f"テスト中の外向き通信は禁止です: {kind} {host!r}")

    def guarded_connect(self: socket.socket, address):  # type: ignore[no-untyped-def]
        if self.family in (socket.AF_INET, socket.AF_INET6):
            check_addr("connect", address)
        return real_connect(self, address)

    def guarded_connect_ex(self: socket.socket, address):  # type: ignore[no-untyped-def]
        if self.family in (socket.AF_INET, socket.AF_INET6):
            check_addr("connect_ex", address)
        return real_connect_ex(self, address)

    def guarded_getaddrinfo(host, *args, **kwargs):  # type: ignore[no-untyped-def]
        check_addr("getaddrinfo", host)
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
    yield
    if request.node.get_closest_marker("expect_network_block"):
        assert violations, "遮断が働いていません（外向き通信が通ってしまう）"
        return
    if violations:
        pytest.fail("外向き通信を試みました（例外が呑み込まれた可能性）: " + ", ".join(violations))


_APP_ENV_KEYS = (
    "ROLE ENV FETCH_MODE GOOGLE_CLOUD_PROJECT GEMINI_LOCATION GEMINI_MODEL GEMINI_MODEL_READER GEMINI_MODEL_PLANNER "
    "PROMPT_VERSION KILL_SWITCH LIVE_ENABLED SELF_ORIGIN SUBMISSION_URL FETCHER_URL ALLOWED_PREFIXES LP_SEED_URLS "
    "LOG_LEVEL GOOGLE_APPLICATION_CREDENTIALS GOOGLE_API_KEY PORT STATE_BACKEND JUDGE_CODE_SHA256"
).split()


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """アプリの環境変数を全部外した状態（開発機の環境に左右されないため）。"""
    for k in _APP_ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    return monkeypatch


@pytest.fixture
def settings(clean_env: pytest.MonkeyPatch) -> Settings:
    """既定の Settings（ENV=dev・ライブ無効・キルスイッチ無し）。"""
    return load_settings({})
