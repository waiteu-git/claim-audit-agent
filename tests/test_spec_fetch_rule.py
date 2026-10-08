"""第11弾 3: S3 の取得規則（contracts.OpenPageScope ＋ SafeFetch の open_page ＋ fetcher の窓あたりの上限）。完全オフライン。

求める性質: 規則は既定で無効。有効な S3 は、許可リストの外の公開ページを、正規の形の URL・GET の page・1ページだけ取る。
転送は追わない（3xx は失敗として返す）・200 の text/html と text/plain だけ・本文の上限を超えたら拒否・私的アドレスは名前解決後に拒否。
"""
import pytest

from app.config import FETCH_LIMITS, FetchLimits, load_settings, startup_violations
from app.contracts import ContentKind, FetchMode, FetchOutcome, FetchRequest, OpenPageScope, PolicyId, UrlPrefix
from app.net.vectors import PRIVATE_IP, PUBLIC_IP, Reply
from tests.net_support import make_rig

AT = "@"  # userinfo の形は連結で作る（衛生テストのメール検知に引っかけない）
HOST = "spec-site.example"
URL = f"https://{HOST}/rules/2026"
HTML = (("Content-Type", "text/html; charset=utf-8"),)
DNS = {HOST: ((PUBLIC_IP,),)}
PAGE = Reply(headers=HTML, body="<html><body><p>応募は1人1件までとすること。</p></body></html>".encode())


def rig(routes=None, *, enabled=True, prefixes=(), dns=None, **kw):  # noqa: ANN001, ANN003, ANN201
    routes = {f"{HOST}/rules/2026": PAGE} if routes is None else routes
    return make_rig(routes, dns=dns or DNS, prefixes=prefixes, open_page=OpenPageScope() if enabled else None, **kw)


async def get(r, url=URL, mode=FetchMode.SPEC_PAGE):  # noqa: ANN001, ANN201  既定は要項モードの印つき
    return await r.fetch.fetch_ex(FetchRequest(url=url, mode=mode))


def assert_blocked_before_lookup(r, d):  # noqa: ANN001, ANN202
    assert d.result.outcome is FetchOutcome.BLOCKED and d.result.blocked_policy is PolicyId.SCOPE, d.notes
    assert r.resolver.calls == {} and r.net.connects == [] and r.net.requests == []


# ------------------------------------------------------------------ 既定は無効
async def test_disabled_by_default_nothing_outside_the_allow_list_is_fetched():
    r = rig(enabled=False)
    assert_blocked_before_lookup(r, await get(r))
    r2 = make_rig({f"{HOST}/rules/2026": PAGE}, dns=DNS, prefixes=())
    assert_blocked_before_lookup(r2, await get(r2))


def test_flags_are_off_by_default_and_only_the_literal_1_turns_them_on():
    for name, attr in (("SPEC_FETCH_ENABLED", "spec_fetch_enabled"), ("SPEC_INPUT_ENABLED", "spec_input_enabled")):
        assert getattr(load_settings({}), attr) is False
        for v in ("", "0", "true", "yes", "on", " 2", "TRUE"):
            assert getattr(load_settings({name: v}), attr) is False, (name, v)
        assert getattr(load_settings({name: "1"}), attr) is True


# ------------------------------------------------------------------ 通るもの
async def test_a_public_page_is_fetched_with_one_get_pinned_to_the_checked_ip():
    r = rig()
    d = await get(r)
    assert (d.result.outcome, d.result.status, d.result.content_kind) == (FetchOutcome.OK, 200, ContentKind.HTML)
    (seen,) = r.net.requests
    assert (seen.method, seen.target, seen.ip, seen.tls_hostname) == ("GET", "/rules/2026", PUBLIC_IP, HOST)
    assert not ({"cookie", "authorization", "referer"} & set(seen.headers))
    assert r.net.connects == [(PUBLIC_IP, 443)]


async def test_text_plain_and_a_query_are_accepted():
    routes = {f"{HOST}/rules?lang=ja": Reply(headers=(("Content-Type", "text/plain; charset=utf-8"),), body="応募は1人1件まで。".encode())}
    r = rig(routes)
    d = await get(r, f"https://{HOST}/rules?lang=ja")
    assert d.result.outcome is FetchOutcome.OK and d.result.content_kind is ContentKind.PLAIN


# ------------------------------------------------------------------ 形の拒否（名前解決の前）
BAD = {
    "ipv4": "https://203.0.113.10/rules",
    "ipv4-dec": "https://3405803786/rules",
    "ipv4-hex": "https://0xcb00710a/rules",
    "ipv6": "https://[2001:db8::1]/rules",
    "localhost": "https://localhost/rules",
    "single-label": "https://intranet/rules",
    "dot-local": "https://printer.local/rules",
    "dot-internal": "https://metadata.google.internal/rules",
    "port": f"https://{HOST}:8443/rules/2026",
    "port-443-explicit": f"https://{HOST}:443/rules/2026",  # 正規形でない（S2 は正規形だけを送る）
    "userinfo": "https://user" + AT + f"{HOST}/rules/2026",
    "fragment": f"{URL}#top",
    "upper-host": f"https://{HOST.upper()}/rules/2026",
    "trailing-dot": f"https://{HOST}./rules/2026",
    "dotdot": f"https://{HOST}/x/../rules/2026",
    "http": f"http://{HOST}/rules/2026",
}


@pytest.mark.parametrize("name", sorted(BAD))
async def test_shapes_outside_the_rule_are_blocked_before_any_lookup(name):
    r = rig()
    assert_blocked_before_lookup(r, await get(r, BAD[name]))


async def test_probe_mode_is_not_admitted_by_the_rule():
    r = rig()
    assert_blocked_before_lookup(r, await get(r, mode=FetchMode.PROBE))


# ------------------------------------------------------------------ 私的・予約済みアドレス（名前解決後。既存の検査をそのまま通る）
@pytest.mark.parametrize("ip", [PRIVATE_IP, "127.0.0.1", "169.254.169.254", "::1", "fd12:3456::1"])
async def test_private_addresses_after_resolution_are_refused(ip):
    r = rig(dns={HOST: ((ip,),)})
    d = await get(r)
    assert d.result.outcome is FetchOutcome.BLOCKED and d.result.blocked_policy is PolicyId.SSRF_IP
    assert r.net.connects == []


# ------------------------------------------------------------------ 転送は追わない
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("location", ["https://evil.example/x", f"https://{HOST}/other", "/other", "https://169.254.169.254/"])
async def test_3xx_is_returned_as_a_failure_and_never_followed(status, location):
    routes = {f"{HOST}/rules/2026": Reply(status=status, headers=(("Location", location),)), f"{HOST}/other": PAGE, "evil.example/x": PAGE}
    r = rig(routes)
    d = await get(r)
    assert (d.result.outcome, d.result.status, d.result.body) == (FetchOutcome.OK, status, b"")
    assert d.result.redirects[-1].followed is False and "open_page:no_redirect" in d.notes
    assert len(r.net.requests) == 1 and r.resolver.calls == {HOST: 1}


# ------------------------------------------------------------------ 種別・大きさ
@pytest.mark.parametrize("ctype", ["application/pdf", "application/json", "text/markdown", "application/xhtml+xml", "image/png", None])
async def test_only_html_and_plain_are_accepted(ctype):
    headers = (("Content-Type", ctype),) if ctype else ()
    r = rig({f"{HOST}/rules/2026": Reply(headers=headers, body=b"%PDF-1.7 x")})
    d = await get(r)
    assert d.result.outcome is FetchOutcome.UNSUPPORTED_TYPE and d.result.body == b""


async def test_a_page_over_the_cap_is_refused_not_truncated():
    limits = FetchLimits(spec_max_page_bytes=1000)
    r = rig({f"{HOST}/rules/2026": Reply(headers=HTML, body=b"a" * 1001)}, limits=limits)
    res = (await get(r)).result
    assert (res.outcome, res.body, res.truncated) == (FetchOutcome.TOO_LARGE, b"", False)
    r2 = rig({f"{HOST}/rules/2026": Reply(headers=HTML, body=b"a", content_length=5000)}, limits=limits)
    assert (await get(r2)).result.outcome is FetchOutcome.TOO_LARGE
    r3 = rig({f"{HOST}/rules/2026": Reply(headers=HTML, body=b"a" * 1000)}, limits=limits)
    assert (await get(r3)).result.outcome is FetchOutcome.OK


def test_the_page_cap_is_not_above_the_existing_cap():
    assert FETCH_LIMITS.spec_max_page_bytes <= FETCH_LIMITS.max_decoded_bytes


async def test_a_nul_byte_means_binary():
    r = rig({f"{HOST}/rules/2026": Reply(headers=HTML, body=b"<p>x\x00y</p>")})
    assert (await get(r)).result.outcome is FetchOutcome.UNSUPPORTED_TYPE


async def test_status_other_than_200_returns_the_status_without_a_body():
    r = rig({f"{HOST}/rules/2026": Reply(status=404, headers=HTML, body=b"<p>not here</p>")})
    res = (await get(r)).result
    assert (res.status, res.body) == (404, b"")


# ------------------------------------------------------------------ 許可リストの扱いは変えない
async def test_allow_listed_urls_keep_their_old_behaviour_with_the_rule_on():
    prefixes = (UrlPrefix(host="svc.example.invalid", path_prefix="/fx/"),)
    routes = {
        "svc.example.invalid/fx/a": Reply(status=302, headers=(("Location", "/fx/b"),)),
        "svc.example.invalid/fx/b": Reply(headers=HTML, body=b"followed"),
    }
    r = make_rig(routes, prefixes=prefixes, open_page=OpenPageScope())
    d = await r.fetch.fetch_ex(FetchRequest(url="https://svc.example.invalid/fx/a"))
    assert d.result.body == b"followed" and d.result.redirects[0].followed  # 許可リストは従来どおり 3 ホップまで追う
    assert "open_page:no_redirect" not in d.notes


async def test_a_redirect_from_an_allow_listed_host_to_an_open_page_is_not_followed_by_the_rule():
    prefixes = (UrlPrefix(host="svc.example.invalid", path_prefix="/fx/"),)
    routes = {"svc.example.invalid/fx/a": Reply(status=302, headers=(("Location", URL),)), f"{HOST}/rules/2026": PAGE}
    r = make_rig(routes, prefixes=prefixes, open_page=OpenPageScope(), dns=DNS)
    res = (await r.fetch.fetch_ex(FetchRequest(url="https://svc.example.invalid/fx/a"))).result
    assert res.status == 302 and res.redirects[-1].followed is False
    assert [q.target for q in r.net.requests] == ["/fx/a"]


# ------------------------------------------------------------------ S3 の窓あたりの上限・起動時の検査
def relay_app(*, enabled, limits=None, clock=None, prefixes=""):  # noqa: ANN001, ANN201
    from fastapi.testclient import TestClient

    from app.contracts import FetchResult
    from app.net.fetcher_server import create_fetcher_app

    calls: list[str] = []

    class Port:
        async def fetch(self, request):  # noqa: ANN001, ANN202
            calls.append(request.url)
            return FetchResult(requested_url=request.url, final_url=request.url, outcome=FetchOutcome.OK, status=200, body=b"x" * 1000, content_kind=ContentKind.HTML)

    env = {"ROLE": "fetcher", **({"SPEC_FETCH_ENABLED": "1"} if enabled else {}), **({"ALLOWED_PREFIXES": prefixes} if prefixes else {})}
    kw = {"limits": limits or FetchLimits(), **({"clock": clock} if clock else {})}
    return TestClient(create_fetcher_app(load_settings(env), fetch=Port(), **kw)), calls


def post(client, url, mode="spec_page"):  # noqa: ANN001, ANN201  既定は要項モードの印つき
    return client.post("/fetch", json={"url": url, "mode": mode}, headers={"authorization": "Bearer t"})


def test_s3_caps_open_page_requests_per_window_by_itself():
    n = FETCH_LIMITS.spec_relay_requests_per_min
    client, calls = relay_app(enabled=True, prefixes="svc.example.invalid/fx/")
    codes = [post(client, f"https://site{i}.example/rules").status_code for i in range(n + 4)]
    assert codes == [200] * n + [429] * 4 and len(calls) == n  # 頭打ちの後は取りに行かない
    assert post(client, "https://svc.example.invalid/fx/a", mode="page").status_code == 200  # 印の無い取得は数えない
    assert post(client, "https://raw.githubusercontent.com/o/r/HEAD/README.md", mode="page").status_code == 200  # GitHub の固定ファイルも数えない


def test_s3_cap_resets_with_the_window_and_counts_bytes():
    now = [0.0]
    client, _ = relay_app(enabled=True, limits=FetchLimits(spec_relay_requests_per_min=100, spec_relay_bytes_per_min=2500), clock=lambda: now[0])
    assert [post(client, URL).status_code for _ in range(5)] == [200, 200, 200, 429, 429]
    now[0] = 61.0
    assert post(client, URL).status_code == 200


def test_s3_counts_nothing_when_the_rule_is_off():
    client, calls = relay_app(enabled=False)
    assert all(post(client, URL).status_code == 200 for _ in range(50)) and len(calls) == 50


def test_the_fetcher_enables_the_rule_only_with_the_flag(monkeypatch):  # noqa: ANN001
    import app.net.safefetch as sf
    from app.net.fetcher_server import create_fetcher_app

    seen: list[dict] = []

    class Spy:
        def __init__(self, prefixes, **kw):  # noqa: ANN001, ANN003
            seen.append(kw)

    monkeypatch.setattr(sf, "SafeFetch", Spy)
    create_fetcher_app(load_settings({"ROLE": "fetcher"}))
    create_fetcher_app(load_settings({"ROLE": "fetcher", "SPEC_FETCH_ENABLED": "1"}))
    assert seen[0]["open_page"] is None and isinstance(seen[1]["open_page"], OpenPageScope)


def test_startup_checks_for_both_flags():
    for env in ("public", "staging", "dev"):
        s2 = load_settings({"ROLE": "agent", "ENV": env, "SPEC_FETCH_ENABLED": "1"})
        assert any("SPEC_FETCH_ENABLED" in v for v in startup_violations(s2, {}, {})), env
        s3 = load_settings({"ROLE": "fetcher", "ENV": env, "SPEC_INPUT_ENABLED": "1", "JUDGE_CODE_SHA256": "a" * 64, "FETCHER_URL": "https://f.example.invalid"})
        assert any("SPEC_INPUT_ENABLED は ROLE=agent" in v for v in startup_violations(s3, {}, {})), env
    assert startup_violations(load_settings({"ROLE": "fetcher", "ENV": "public", "SPEC_FETCH_ENABLED": "1"}), {}, {}) == []
    no_code = load_settings({"SPEC_INPUT_ENABLED": "1"})
    assert any("JUDGE_CODE_SHA256" in v for v in startup_violations(no_code, {}, {}))
    pub = {"ROLE": "agent", "ENV": "public", "FETCH_MODE": "remote", "STATE_BACKEND": "firestore", "SELF_ORIGIN": "https://self.example.invalid",
           "SPEC_INPUT_ENABLED": "1", "JUDGE_CODE_SHA256": "a" * 64}  # fmt: skip
    assert any("FETCHER_URL" in v for v in startup_violations(load_settings(pub), {}, {}))
    assert startup_violations(load_settings({**pub, "FETCHER_URL": "https://f.example.invalid"}), {}, {}) == []
    assert startup_violations(load_settings({"SPEC_INPUT_ENABLED": "1", "JUDGE_CODE_SHA256": "a" * 64}), {}, {}) == []  # 開発の既定（inproc）


# ====================================================================================================
# 敵対レビュー（追加指示2）
# ====================================================================================================
# ---- 1. 公開ページの規則は、要項モードの印のある要求だけに当たる
@pytest.mark.parametrize("mode", [FetchMode.PAGE, FetchMode.PROBE])
async def test_requests_without_the_spec_mark_never_use_the_open_page_rule(mode):
    r = rig()  # SPEC_FETCH_ENABLED 相当（規則は有効）
    assert_blocked_before_lookup(r, await get(r, mode=mode))  # 許可リストの外の公開ホスト → 拒否（今までどおり）


async def test_only_the_marked_request_is_fetched_by_the_open_page_rule():
    r = rig()
    assert (await get(r, mode=FetchMode.SPEC_PAGE)).result.status == 200 and len(r.net.requests) == 1


async def test_the_spec_mark_does_not_borrow_the_allow_list_or_the_repo_rule():
    from app.contracts import RepoRawScope

    prefixes = (UrlPrefix(host="svc.example.invalid", path_prefix="/fx/"),)
    routes = {"svc.example.invalid/fx/a": Reply(status=302, headers=(("Location", "/fx/b"),)), "svc.example.invalid/fx/b": PAGE}
    r = make_rig(routes, prefixes=prefixes, open_page=OpenPageScope())
    res = (await r.fetch.fetch_ex(FetchRequest(url="https://svc.example.invalid/fx/a", mode=FetchMode.SPEC_PAGE))).result
    assert res.status == 302 and res.body == b"" and len(r.net.requests) == 1  # 印つきは許可リストの中でも転送を追わない
    off = make_rig(routes, prefixes=prefixes)  # 規則が無効なら、印つきは許可リストの中でも取らない
    assert_blocked_before_lookup(off, await off.fetch.fetch_ex(FetchRequest(url="https://svc.example.invalid/fx/a", mode=FetchMode.SPEC_PAGE)))
    raw = "raw.githubusercontent.com/o/r/HEAD/README.md"
    r2 = make_rig({raw: Reply(headers=(("Content-Type", "text/plain"),), body=b"x")}, dns={"raw.githubusercontent.com": ((PUBLIC_IP,),)},
                  prefixes=(), repo_raw=RepoRawScope())  # fmt: skip
    assert_blocked_before_lookup(r2, await r2.fetch.fetch_ex(FetchRequest(url="https://" + raw, mode=FetchMode.SPEC_PAGE)))


def test_s3_with_the_flag_refuses_unmarked_requests_outside_its_allow_list():
    from fastapi.testclient import TestClient

    from app.net.fetcher_server import create_fetcher_app

    calls: list[str] = []

    class Inner:
        async def fetch(self, request):  # noqa: ANN001, ANN202
            calls.append(request.url)
            return await sf.fetch(request)

    sf = make_rig({f"{HOST}/rules/2026": PAGE}, dns=DNS, prefixes=(), open_page=OpenPageScope()).fetch
    c = TestClient(create_fetcher_app(load_settings({"ROLE": "fetcher", "SPEC_FETCH_ENABLED": "1"}), fetch=Inner()))
    unmarked = c.post("/fetch", json={"url": URL}, headers={"authorization": "Bearer t"}).json()
    marked = c.post("/fetch", json={"url": URL, "mode": "spec_page"}, headers={"authorization": "Bearer t"}).json()
    assert unmarked["outcome"] == "blocked" and marked["outcome"] == "ok" and marked["status"] == 200


def test_only_the_spec_pipeline_puts_the_mark_in_app_code():
    from pathlib import Path

    users = sorted(p.as_posix() for p in Path("app").rglob("*.py") if "SPEC_PAGE" in p.read_text(encoding="utf-8"))
    assert users == ["app/agent/spec_read.py", "app/contracts.py", "app/net/fetcher_server.py", "app/net/safefetch.py"]


# ---- 2. 窓は、ホスト名でなく当てる規則（印の有無）で選ぶ
@pytest.mark.parametrize("github_raw", [False, True])
def test_marked_requests_to_the_raw_host_count_toward_the_spec_window(github_raw):
    from fastapi.testclient import TestClient

    from app.contracts import FetchResult
    from app.net.fetcher_server import create_fetcher_app

    class Port:
        async def fetch(self, request):  # noqa: ANN001, ANN202
            return FetchResult(requested_url=request.url, final_url=request.url, outcome=FetchOutcome.OK, status=200, body=b"x", content_kind=ContentKind.PLAIN)

    env = {"ROLE": "fetcher", "SPEC_FETCH_ENABLED": "1", **({"GITHUB_RAW_ENABLED": "1"} if github_raw else {})}
    c = TestClient(create_fetcher_app(load_settings(env), fetch=Port()))
    n = FETCH_LIMITS.spec_relay_requests_per_min
    codes = [post(c, f"https://raw.githubusercontent.com/o/r/HEAD/notes{i}.md").status_code for i in range(n + 1)]
    assert codes == [200] * n + [429]  # 10回目で 429（固定名でないパスは、印つきなら要項の窓に数える）
    if github_raw:
        fixed = [post(c, "https://raw.githubusercontent.com/o/r/HEAD/README.md", mode="page").status_code for _ in range(3)]
        assert fixed == [200, 200, 200]  # 固定名（印なし）は従来どおり repo の窓（要項の窓が尽きていても通る）


# ---- 4. 窓の値を固定する
def test_the_spec_window_values_are_pinned():
    assert (FETCH_LIMITS.spec_relay_requests_per_min, FETCH_LIMITS.spec_relay_bytes_per_min) == (9, 9 * 1024 * 1024)
    assert FETCH_LIMITS.spec_max_page_bytes == 1024 * 1024


def test_the_open_page_matcher_itself_requires_the_mark():
    """_admit も印を先に見るが、照合の関数そのものも印の無い要求を通さない（二重の守り）。"""
    from app.net.urlcheck import validate_url

    sf = rig().fetch
    n = validate_url(URL)
    assert sf._open_page_match(URL, n, FetchMode.SPEC_PAGE) is True
    assert sf._open_page_match(URL, n, FetchMode.PAGE) is False and sf._open_page_match(URL, n, FetchMode.PROBE) is False
