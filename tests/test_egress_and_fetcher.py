"""egress_guard（全パス共通の上限）と、fetcher（S3）のサーバー入口・S2 側のクライアント（RemoteFetch）。完全オフライン。

fetcher のサーバーは注入した FetchPort（フェイク）と、本物の SafeFetch（自分の許可リストでやり直す＝スコープ外は BLOCKED）の両方で試す。
クライアントは post を注入し、fetcher のアプリへ TestClient で中継する（ネットワークを使わない）。
"""
import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import FetchBackend, GuardLimits, Settings, parse_prefixes
from app.contracts import FetchMode, FetchOutcome, FetchRequest, FetchResult, PolicyId
from app.egress_guard import EgressGuard
from app.net.fetcher_client import RemoteFetch
from app.net.fetcher_server import create_fetcher_app
from tests.fetch_fakes import FakeFetchPort, make_result

FETCHER = "https://fetcher.example.invalid"
TARGET = "https://svc.example.invalid/fx/defect/spec/"


# ---- egress_guard -------------------------------------------------------------------------------
def guarded(limits: GuardLimits, clock) -> TestClient:  # noqa: ANN001
    app = FastAPI()

    @app.get("/x")
    async def x():
        return {"data": "y" * 100}

    app.add_middleware(EgressGuard, limits=limits, clock=clock)
    return TestClient(app)


def test_requests_over_the_per_minute_cap_get_429_on_every_path_and_the_window_resets():
    t = [0.0]
    c = guarded(GuardLimits(requests_per_min=3), lambda: t[0])
    assert [c.get("/x").status_code for _ in range(3)] == [200, 200, 200]
    assert c.get("/x").status_code == 429 and c.get("/nope").status_code == 429
    t[0] += 61
    assert c.get("/x").status_code == 200


def test_bytes_over_the_per_minute_cap_refuse_new_requests_with_503():
    t = [0.0]
    c = guarded(GuardLimits(egress_bytes_per_min=150), lambda: t[0])
    assert c.get("/x").status_code == 200  # 約110バイト
    assert c.get("/x").status_code == 200  # 流れている応答は止めない（ここで上限を超える）
    r = c.get("/x")
    assert r.status_code == 503 and r.json() == {"ok": False, "code": "RATE_LIMITED"}


# ---- fetcher サーバー ---------------------------------------------------------------------------
def fetcher(fetch=None, verify=lambda tok: tok == "good-token", prefixes="svc.example.invalid/fx/") -> TestClient:  # noqa: ANN001
    s = Settings(allowed_prefixes=parse_prefixes(prefixes))
    return TestClient(create_fetcher_app(s, fetch=fetch, verify_token=verify))


AUTH = {"authorization": "Bearer good-token", "content-type": "application/json"}


def test_fetcher_health_and_no_other_paths():
    c = fetcher(FakeFetchPort(make_result(TARGET)))
    assert c.get("/health").json() == {"ok": True}
    for p in ("/probe", "/", "/api/run", "/docs", "/openapi.json"):
        assert c.get(p).status_code == 404


@pytest.mark.parametrize("headers", [{}, {"authorization": "Bearer bad"}, {"authorization": "Basic good-token"}, {"authorization": "Bearer "}])
def test_fetcher_refuses_without_a_verified_token(headers):
    port = FakeFetchPort(make_result(TARGET))
    r = fetcher(port).post("/fetch", json={"url": TARGET}, headers={"content-type": "application/json", **headers})
    assert r.status_code == 401 and port.calls == []


@pytest.mark.parametrize("body", [{"url": TARGET, "scope": ["evil.invalid"]}, {"url": ""}, {"mode": "page"}, {"url": TARGET, "mode": "delete"}])
def test_fetcher_accepts_only_a_fetch_request(body):
    port = FakeFetchPort(make_result(TARGET))
    assert fetcher(port).post("/fetch", json=body, headers=AUTH).status_code == 400 and port.calls == []


def test_fetcher_refuses_oversized_or_non_json_bodies():
    c = fetcher(FakeFetchPort(make_result(TARGET)))
    assert c.post("/fetch", content=b'{"url":"' + b"a" * 9000 + b'"}', headers=AUTH).status_code == 413
    assert c.post("/fetch", content=b"url=x", headers={"authorization": "Bearer good-token", "content-type": "text/plain"}).status_code == 415


def test_fetcher_returns_the_fetch_result_as_json():
    port = FakeFetchPort(make_result(TARGET, body="<p>架空の要項</p>"))
    r = fetcher(port).post("/fetch", json={"url": TARGET, "mode": "probe"}, headers=AUTH)
    res = FetchResult.model_validate_json(r.content)
    assert res.outcome is FetchOutcome.OK and "架空の要項".encode() in res.body
    assert port.calls == [FetchRequest(url=TARGET, mode=FetchMode.PROBE)]


def test_fetcher_rechecks_scope_with_its_own_safefetch_and_never_reaches_out():
    """S2 から何が来ても、fetcher の SafeFetch が自分の許可リスト（ALLOWED_PREFIXES）でやり直す。DNS の前に URL の段階で拒否される。"""
    c = fetcher(None, prefixes="svc.example.invalid/fx/")
    for url in ("https://evil.example.invalid/", "http://svc.example.invalid/fx/a", "https://svc.example.invalid/api/run",
                "https://169.254.169.254/latest/meta-data/"):  # fmt: skip
        res = FetchResult.model_validate_json(c.post("/fetch", json={"url": url}, headers=AUTH).content)
        assert res.outcome is FetchOutcome.BLOCKED and res.blocked_policy in (PolicyId.SCOPE, PolicyId.SSRF_IP), url


def test_fetcher_with_an_empty_allow_list_fetches_nothing():
    c = fetcher(None, prefixes="")
    res = FetchResult.model_validate_json(c.post("/fetch", json={"url": TARGET}, headers=AUTH).content)
    assert res.outcome is FetchOutcome.BLOCKED


def test_a_crashing_fetch_port_returns_500_without_details():
    class Boom:
        async def fetch(self, request):
            raise RuntimeError("secret /srv/path")

    r = fetcher(Boom()).post("/fetch", json={"url": TARGET}, headers=AUTH)
    assert r.status_code == 500 and r.json() == {"ok": False, "code": "INTERNAL"} and "secret" not in r.text


# ---- クライアント（RemoteFetch）------------------------------------------------------------------
def relay(c: TestClient):  # noqa: ANN201
    sent: list[tuple[str, dict]] = []

    async def post(url: str, body: bytes, headers: dict) -> tuple[int, bytes]:
        sent.append((url, headers))
        r = c.post("/fetch", content=body, headers=headers)
        return r.status_code, r.content

    return post, sent


async def token() -> str:
    return "good-token"


def test_remote_fetch_round_trips_through_the_fetcher_app():
    c = fetcher(FakeFetchPort(make_result(TARGET, body="<p>x</p>")))
    post, sent = relay(c)
    res = asyncio.run(RemoteFetch(FETCHER, token, post=post).fetch(FetchRequest(url=TARGET)))
    assert res.outcome is FetchOutcome.OK and res.body == b"<p>x</p>"
    assert sent[0][0] == FETCHER + "/fetch" and sent[0][1]["authorization"] == "Bearer good-token"


@pytest.mark.parametrize(
    "reply",
    [
        (500, b'{"ok":false}'),
        (401, b""),
        (200, b"not json"),
        (200, b'{"requested_url":"x","outcome":"ok"}'),  # 契約の不変条件違反（ok なのに status が無い）
        (200, FetchResult(requested_url="https://other.example.invalid/", outcome=FetchOutcome.OK, status=200).model_dump_json().encode()),
        (200, b"x" * (3 * 1024 * 1024)),
    ],
)
def test_remote_fetch_turns_bad_replies_into_network_errors_not_exceptions(reply):
    async def post(url, body, headers):  # noqa: ANN001
        return reply

    res = asyncio.run(RemoteFetch(FETCHER, token, post=post).fetch(FetchRequest(url=TARGET)))
    assert res.outcome is FetchOutcome.NETWORK_ERROR and res.body == b""


def test_remote_fetch_survives_token_and_transport_failures():
    async def no_token() -> str:
        raise ConnectionError("metadata down")

    async def post(url, body, headers):  # noqa: ANN001
        raise TimeoutError

    assert asyncio.run(RemoteFetch(FETCHER, no_token, post=post).fetch(FetchRequest(url=TARGET))).outcome is FetchOutcome.NETWORK_ERROR
    assert asyncio.run(RemoteFetch(FETCHER, token, post=post).fetch(FetchRequest(url=TARGET))).outcome is FetchOutcome.NETWORK_ERROR


def test_remote_fetch_requires_https_and_the_mode_switch_is_in_settings():
    with pytest.raises(ValueError):
        RemoteFetch("http://fetcher.example.invalid", token)
    assert Settings.from_environ({"FETCH_MODE": "remote"}).fetch_backend is FetchBackend.REMOTE


def test_the_web_layer_builds_the_remote_client_when_fetch_mode_is_remote():
    from app.config import PRESETS
    from app.web.app import _build_fetch

    s = Settings(fetch_backend=FetchBackend.REMOTE, fetcher_url=FETCHER)
    assert isinstance(_build_fetch(s, PRESETS["sample_defect"]), RemoteFetch)
    with pytest.raises(RuntimeError):
        _build_fetch(Settings(fetch_backend=FetchBackend.REMOTE), PRESETS["sample_defect"])
