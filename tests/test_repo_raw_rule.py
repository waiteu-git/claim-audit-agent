"""第7弾の土台 2: S3 の許可規則（contracts.RepoRawScope ＋ SafeFetch の repo_raw）。完全オフライン（偽の DNS・偽のネットワーク層）。

求める性質: 規則が有効な S3 は、ホスト raw.githubusercontent.com・パス `/<owner>/<repo>/HEAD/<固定名>` に完全一致・ポート 443 の
URL だけを取る。リダイレクトは追わない。1ファイル 256KB まで・text/plain だけ・NUL を含む本文は拒否。規則は既定で無効。
"""
import random
import re
import string

import pytest

from app.config import FETCH_LIMITS, Settings, load_settings, startup_violations
from app.contracts import (
    REPO_FILE_NAMES,
    ContentKind,
    FetchLimit,
    FetchOutcome,
    FetchRequest,
    PolicyId,
    RepoRawScope,
    UrlPrefix,
    is_github_owner,
    is_github_repo,
)
from app.github_repo import RepoFileStatus, RepoRef, fetch_repo_files, raw_file_url
from app.net.vectors import PUBLIC_IP, Reply
from tests.net_support import make_rig

RAW = "raw.githubusercontent.com"
AT = "@"  # 実アドレスの混入検知（衛生テスト）に引っかからないよう、userinfo の形は連結で作る
BASE = f"{RAW}/example-owner/example-repo/HEAD"
URL = f"https://{BASE}/README.md"
TEXT = (("Content-Type", "text/plain; charset=utf-8"),)
DNS = {RAW: ((PUBLIC_IP,),)}
SCOPE = RepoRawScope()
REF = RepoRef(owner="example-owner", repo="example-repo")


def rig(routes=None, *, enabled=True, prefixes=(), **kw):  # noqa: ANN001, ANN003, ANN201
    return make_rig({f"{BASE}/README.md": Reply(headers=TEXT, body=b"# hello")} if routes is None else routes, dns=DNS, prefixes=prefixes, repo_raw=SCOPE if enabled else None, **kw)


async def get(r, url=URL):  # noqa: ANN001, ANN201
    return await r.fetch.fetch_ex(FetchRequest(url=url))


def assert_blocked_before_any_lookup(r, d):  # noqa: ANN001, ANN202
    assert d.result.outcome is FetchOutcome.BLOCKED and d.result.blocked_policy is PolicyId.SCOPE, d.notes
    assert r.resolver.calls == {} and r.net.connects == [] and r.net.requests == []  # 名前解決もしない＝スコープ外は名前も漏らさない


# ------------------------------------------------------------------ 規則の型そのもの（正規化済みの host・path を見る）
@pytest.mark.parametrize("name", REPO_FILE_NAMES)
def test_scope_matches_each_fixed_name(name):
    assert SCOPE.matches(RAW, f"/example-owner/example-repo/HEAD/{name}")


@pytest.mark.parametrize(
    "host, path",
    [
        (RAW, "/example-owner/example-repo/HEAD/main.py"),
        (RAW, "/example-owner/example-repo/HEAD/readme.md"),
        (RAW, "/example-owner/example-repo/HEAD/README.md/"),
        (RAW, "/example-owner/example-repo/head/README.md"),
        (RAW, "/example-owner/example-repo/main/README.md"),
        (RAW, "/example-owner/example-repo/HEAD/sub/README.md"),
        (RAW, "/example-owner/example-repo/HEAD"),
        (RAW, "/example-owner/example-repo/HEAD/"),
        (RAW, "/example-owner/example-repo"),
        (RAW, "/example-owner"),
        (RAW, "/"),
        (RAW, ""),
        (RAW, "example-owner/example-repo/HEAD/README.md"),
        (RAW, "//example-owner/example-repo/HEAD/README.md"),
        (RAW, "/example-owner//HEAD/README.md"),
        (RAW, "/-example/example-repo/HEAD/README.md"),
        (RAW, "/example-owner/../HEAD/README.md"),
        (RAW, "/example-owner/./HEAD/README.md"),
        (RAW, "/example-owner/example-repo.git/HEAD/README.md"),
        (RAW, "/example-owner/%2e%2e/HEAD/README.md"),
        (RAW, "/example-owner/example-repo/HEAD/README.md%20"),
        (RAW, "/example-owner/example-repo/HEAD/README.md\n"),
        (RAW, "/" + "o" * 40 + "/example-repo/HEAD/README.md"),
        (RAW, "/example-owner/" + "r" * 101 + "/HEAD/README.md"),
        ("raw.githubusercontent.com.evil.example", "/example-owner/example-repo/HEAD/README.md"),
        ("evil.raw.githubusercontent.com", "/example-owner/example-repo/HEAD/README.md"),
        ("githubusercontent.com", "/example-owner/example-repo/HEAD/README.md"),
        ("github.com", "/example-owner/example-repo/HEAD/README.md"),
        ("RAW.githubusercontent.com", "/example-owner/example-repo/HEAD/README.md"),  # 正規化済みの host は小文字のはず
    ],
)
def test_scope_refuses_everything_outside_the_exact_shape(host, path):
    assert not SCOPE.matches(host, path)


def test_the_scope_is_a_new_type_and_does_not_change_url_prefix_semantics():
    p = UrlPrefix(host=RAW, path_prefix="/example-owner/example-repo/HEAD/")
    assert p.matches(RAW, "/example-owner/example-repo/HEAD/anything/at/all.py")  # 接頭辞は配下を全部通す（だから別の型にした）
    assert not SCOPE.matches(RAW, "/example-owner/example-repo/HEAD/anything/at/all.py")
    assert not hasattr(UrlPrefix, "repo_raw") and set(UrlPrefix.model_fields) == {"host", "port", "path_prefix", "exact"}


# ------------------------------------------------------------------ 既定は無効
async def test_disabled_by_default_nothing_outside_the_allow_list_is_fetched():
    r = rig(enabled=False)
    d = await get(r)
    assert_blocked_before_any_lookup(r, d)


async def test_make_rig_default_has_no_repo_rule():
    r = make_rig({f"{BASE}/README.md": Reply(headers=TEXT, body=b"x")}, dns=DNS, prefixes=())
    assert_blocked_before_any_lookup(r, await get(r))


async def test_disabled_flag_does_not_affect_existing_prefix_scope():
    r = make_rig({f"{BASE}/README.md": Reply(headers=TEXT, body=b"x")}, dns=DNS, prefixes=(UrlPrefix(host=RAW, path_prefix="/"),))
    assert (await get(r)).result.outcome is FetchOutcome.OK


# ------------------------------------------------------------------ 形が合う URL だけ通る
@pytest.mark.parametrize("name", REPO_FILE_NAMES)
async def test_exact_shape_is_fetched_with_a_get_pinned_to_the_checked_ip(name):
    r = rig({f"{BASE}/{name}": Reply(headers=TEXT, body=b"content")})
    d = await get(r, f"https://{BASE}/{name}")
    assert (d.result.outcome, d.result.status, d.result.body, d.result.content_kind) == (FetchOutcome.OK, 200, b"content", ContentKind.PLAIN)
    (seen,) = r.net.requests
    assert (seen.method, seen.target, seen.ip, seen.tls_hostname) == ("GET", f"/example-owner/example-repo/HEAD/{name}", PUBLIC_IP, RAW)
    assert seen.headers["host"] == RAW and not ({"cookie", "authorization", "referer"} & set(seen.headers))
    assert r.net.connects == [(PUBLIC_IP, 443)] and r.net.non_ip_connects == []


async def test_explicit_port_443_is_accepted_and_dropped():
    r = rig()
    d = await get(r, f"https://{RAW}:443/example-owner/example-repo/HEAD/README.md")
    assert d.result.outcome is FetchOutcome.OK and r.net.requests[0].target == "/example-owner/example-repo/HEAD/README.md"


BAD_TARGETS = {
    "dotdot-segment": f"https://{RAW}/example-owner/example-repo/x/../HEAD/README.md",  # 正規化すると形に合う迂回も通さない
    "dotdot-owner": f"https://{RAW}/example-owner/../HEAD/README.md",
    "dotdot-up": f"https://{RAW}/example-owner/example-repo/HEAD/../README.md",
    "dotdot-a-b": f"https://{RAW}/a/b/../HEAD/x",
    "dotdot-a-b-readme": f"https://{RAW}/a/b/../HEAD/README.md",
    "dot-segment": f"https://{RAW}/example-owner/example-repo/./HEAD/README.md",
    "dot-last": f"https://{RAW}/example-owner/example-repo/HEAD/./README.md",
    "dot-repo": f"https://{RAW}/example-owner/./HEAD/README.md",
    "double-slash": f"https://{RAW}/example-owner//example-repo/HEAD/README.md",
    "double-slash-lead": f"https://{RAW}//example-owner/example-repo/HEAD/README.md",
    "double-slash-end": f"https://{RAW}/example-owner/example-repo/HEAD//README.md",
    "pct-dot": f"https://{RAW}/example-owner/example-repo/HEAD/README%2emd",
    "pct-slash": f"https://{RAW}/example-owner/example-repo/HEAD%2fREADME.md",
    "pct-slash-owner": f"https://{RAW}/example-owner%2fexample-repo/HEAD/README.md",
    "pct-letter": f"https://{RAW}/example-owner/example-repo/HEAD/%52EADME.md",
    "pct-owner": f"https://{RAW}/%65xample-owner/example-repo/HEAD/README.md",
    "pct-nul": f"https://{RAW}/example-owner/example-repo/HEAD/README.md%00",
    "pct-space": f"https://{RAW}/example-owner/example-repo/HEAD/README.md%20",
    "pct-dotdot": f"https://{RAW}/example-owner/%2e%2e/HEAD/README.md",
    "case-name": f"https://{RAW}/example-owner/example-repo/HEAD/readme.md",
    "case-name2": f"https://{RAW}/example-owner/example-repo/HEAD/Readme.md",
    "case-license": f"https://{RAW}/example-owner/example-repo/HEAD/license",
    "case-ref": f"https://{RAW}/example-owner/example-repo/head/README.md",
    "case-ref2": f"https://{RAW}/example-owner/example-repo/Head/README.md",
    "trailing-slash": f"https://{RAW}/example-owner/example-repo/HEAD/README.md/",
    "trailing-slash-dir": f"https://{RAW}/example-owner/example-repo/HEAD/",
    "query": f"https://{RAW}/example-owner/example-repo/HEAD/README.md?x=1",
    "query-empty": f"https://{RAW}/example-owner/example-repo/HEAD/README.md?",
    "fragment": f"https://{RAW}/example-owner/example-repo/HEAD/README.md#frag",
    "fragment-empty": f"https://{RAW}/example-owner/example-repo/HEAD/README.md#",
    "semicolon": f"https://{RAW}/example-owner/example-repo/HEAD/README.md;x",
    "backslash": f"https://{RAW}/example-owner/example-repo/HEAD\\README.md",
    "other-name": f"https://{RAW}/example-owner/example-repo/HEAD/main.py",
    "other-name-sub": f"https://{RAW}/example-owner/example-repo/HEAD/docs/README.md",
    "other-ref": f"https://{RAW}/example-owner/example-repo/main/README.md",
    "sha-ref": f"https://{RAW}/example-owner/example-repo/0123456789abcdef0123456789abcdef01234567/README.md",
    "refs-heads": f"https://{RAW}/example-owner/example-repo/refs/heads/main/README.md",
    "short-path": f"https://{RAW}/example-owner/example-repo/README.md",
    "no-path": f"https://{RAW}",
    "root": f"https://{RAW}/",
    "owner-only": f"https://{RAW}/example-owner",
    "dotgit-repo": f"https://{RAW}/example-owner/example-repo.git/HEAD/README.md",
    "bad-owner": f"https://{RAW}/-example/example-repo/HEAD/README.md",
    "long-owner": f"https://{RAW}/{'o' * 40}/example-repo/HEAD/README.md",
    "unicode-owner": f"https://{RAW}/exаmple-owner/example-repo/HEAD/README.md",
    "host-evil-suffix": "https://raw.githubusercontent.com.evil.example/example-owner/example-repo/HEAD/README.md",
    "host-evil-prefix": "https://evil.raw.githubusercontent.com/example-owner/example-repo/HEAD/README.md",
    "host-userinfo": "https://raw.githubusercontent.com" + AT + "evil.invalid/example-owner/example-repo/HEAD/README.md",
    "host-userinfo2": "https://user" + AT + "raw.githubusercontent.com/example-owner/example-repo/HEAD/README.md",
    "host-pct": "https://raw.githubusercontent%2ecom/example-owner/example-repo/HEAD/README.md",
    "host-sub": "https://sub.raw.githubusercontent.com/example-owner/example-repo/HEAD/README.md",
    "host-parent": "https://githubusercontent.com/example-owner/example-repo/HEAD/README.md",
    "host-github": "https://github.com/example-owner/example-repo/HEAD/README.md",
    "host-github-raw-path": "https://github.com/example-owner/example-repo/raw/HEAD/README.md",
    "host-api": "https://api.github.com/repos/example-owner/example-repo/contents/README.md",
    "host-www": "https://www.raw.githubusercontent.com/example-owner/example-repo/HEAD/README.md",
    "host-upper": f"https://RAW.GITHUBUSERCONTENT.COM/example-owner/example-repo/HEAD/README.md",
    "host-mixed": f"https://Raw.GitHubUserContent.com/example-owner/example-repo/HEAD/README.md",
    "host-trailing-dot": f"https://{RAW}./example-owner/example-repo/HEAD/README.md",
    "host-ipv4": "https://185.199.108.133/example-owner/example-repo/HEAD/README.md",
    "host-ipv4-dec": "https://3116856453/example-owner/example-repo/HEAD/README.md",
    "host-ipv4-hex": "https://0xb9c76c85/example-owner/example-repo/HEAD/README.md",
    "host-ipv6": "https://[2606:50c0:8000::154]/example-owner/example-repo/HEAD/README.md",
    "host-ipv6-loop": "https://[::1]/example-owner/example-repo/HEAD/README.md",
    "host-loopback": "https://127.0.0.1/example-owner/example-repo/HEAD/README.md",
    "host-localhost": "https://localhost/example-owner/example-repo/HEAD/README.md",
    "host-metadata": "https://169.254.169.254/example-owner/example-repo/HEAD/README.md",
    "host-fullwidth-dot": "https://raw．githubusercontent．com/example-owner/example-repo/HEAD/README.md",
    "host-cyrillic": "https://raw.githubusercontent.cоm/example-owner/example-repo/HEAD/README.md",
    "port-8443": f"https://{RAW}:8443/example-owner/example-repo/HEAD/README.md",
    "port-80": f"https://{RAW}:80/example-owner/example-repo/HEAD/README.md",
    "port-empty": f"https://{RAW}:/example-owner/example-repo/HEAD/README.md",
    "port-0443": f"https://{RAW}:0443/example-owner/example-repo/HEAD/README.md",
    "http": f"http://{RAW}/example-owner/example-repo/HEAD/README.md",
    "http-port": f"http://{RAW}:443/example-owner/example-repo/HEAD/README.md",
    "scheme-upper": f"HTTPS://{RAW}/example-owner/example-repo/HEAD/README.md",
    "scheme-ftp": f"ftp://{RAW}/example-owner/example-repo/HEAD/README.md",
    "scheme-less": f"//{RAW}/example-owner/example-repo/HEAD/README.md",
    "space": f"https://{RAW}/example-owner/example-repo/HEAD/README.md ",
    "newline": f"https://{RAW}/example-owner/example-repo/HEAD/README.md\n",
    "tab": f"https://{RAW}/example-owner/example-repo/HEAD/README.md\t",
    "nul": f"https://{RAW}/example-owner/example-repo/HEAD/README.md\x00",
}


@pytest.mark.parametrize("name", sorted(BAD_TARGETS))
async def test_every_shape_outside_the_rule_is_blocked_before_any_lookup(name):
    r = rig(prefixes=())
    d = await get(r, BAD_TARGETS[name])
    assert_blocked_before_any_lookup(r, d)


async def test_the_positive_control_so_the_table_above_is_not_green_for_the_wrong_reason():
    r = rig()
    assert (await get(r)).result.status == 200 and len(r.net.requests) == 1


async def test_the_rule_does_not_widen_an_existing_prefix_scope_in_either_direction():
    """規則を有効にしても、許可リストの扱いは変わらない: 許可リスト内の URL は従来どおり（転送も追う）、規則にも許可リストにも合わない URL は拒否。"""
    prefixes = (UrlPrefix(host="svc.example.invalid", path_prefix="/fx/"),)
    routes = {
        "svc.example.invalid/fx/a": Reply(status=302, headers=(("Location", "/fx/b"),)),
        "svc.example.invalid/fx/b": Reply(headers=TEXT, body=b"followed"),
    }
    r = make_rig(routes, prefixes=prefixes, repo_raw=SCOPE)
    d = await r.fetch.fetch_ex(FetchRequest(url="https://svc.example.invalid/fx/a"))
    assert d.result.body == b"followed" and d.result.redirects[0].followed  # 許可リストの取得は 3 ホップまで追う（従来どおり）
    r2 = make_rig(routes, prefixes=prefixes, repo_raw=SCOPE, dns=DNS)
    assert_blocked_before_any_lookup(r2, await get(r2, f"https://{BASE}/main.py"))


# ------------------------------------------------------------------ 正規化の前後で割れない（迂回できない）
async def test_what_is_connected_is_exactly_the_checked_path_for_random_mutations():
    """正規の URL を乱数で崩して多数流す。通ったもの（接続まで行ったもの）は、全部が規則の形に完全一致する URL のはず。"""
    rnd = random.Random(5)
    alphabet = string.ascii_letters + "/.%?#:@\\ ;\x00а．-_~HEAD"
    shape = re.compile(rf"/([A-Za-z0-9-]{{1,39}})/([A-Za-z0-9._-]{{1,100}})/HEAD/({'|'.join(re.escape(n) for n in REPO_FILE_NAMES)})")
    passed = 0
    for i in range(1500):
        base = list(f"https://{BASE}/README.md")
        for _ in range(rnd.randint(1, 3)):
            pos = rnd.randrange(len(base) + 1)
            op = rnd.choice("ids")
            if op == "i":
                base.insert(pos, rnd.choice(alphabet))
            elif op == "d" and base:
                base.pop(min(pos, len(base) - 1))
            elif base:
                base[min(pos, len(base) - 1)] = rnd.choice(alphabet)
        url = "".join(base)
        r = rig({f"{BASE}/{n}": Reply(headers=TEXT, body=b"x") for n in REPO_FILE_NAMES}, prefixes=())
        d = await get(r, url)
        if r.net.requests:
            passed += 1
            (seen,) = r.net.requests
            m = shape.fullmatch(seen.target)
            assert seen.headers["host"] == RAW and m and is_github_owner(m[1]) and is_github_repo(m[2]), (url, seen.target)
            assert seen.target == "/" + url.split("/", 3)[3]  # 送ったパスは、受け取った文字列のパスそのもの（正規化で変わっていない）
        else:
            assert d.result.outcome is FetchOutcome.BLOCKED
    assert passed >= 10  # 対照: 変異が小さくて元と同じになるものは通る（全部拒否だから緑、ではない）


# ------------------------------------------------------------------ リダイレクトは追わない
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize(
    "location",
    [
        "https://evil.example/x",
        f"https://{RAW}/example-owner/example-repo/HEAD/LICENSE",  # 規則に合う同じホストの別ファイルでも追わない
        "/example-owner/example-repo/HEAD/LICENSE",
        "https://github.com/example-owner/example-repo",
        "http://" + RAW + "/example-owner/example-repo/HEAD/LICENSE",
        "https://169.254.169.254/",
    ],
)
async def test_3xx_is_returned_as_a_failure_and_never_followed(status, location):
    routes = {
        f"{BASE}/README.md": Reply(status=status, headers=(("Location", location),)),
        f"{BASE}/LICENSE": Reply(headers=TEXT, body=b"MUST NOT BE FETCHED"),
        "evil.example/x": Reply(headers=TEXT, body=b"MUST NOT BE FETCHED"),
    }
    r = rig(routes)
    d = await get(r)
    res = d.result
    assert (res.outcome, res.status, res.body) == (FetchOutcome.OK, status, b"")
    (hop,) = res.redirects
    assert hop.followed is False and hop.blocked_policy is PolicyId.SCOPE and hop.location
    assert len(r.net.requests) == 1 and r.net.connects == [(PUBLIC_IP, 443)]  # 2回目の接続も名前解決も無い
    assert r.resolver.calls == {RAW: 1}
    assert "repo_raw:no_redirect" in d.notes
    from app.github_repo import classify_result

    assert classify_result(res, URL) is RepoFileStatus.REJECTED


async def test_3xx_without_location_is_also_a_failure():
    r = rig({f"{BASE}/README.md": Reply(status=302)})
    res = (await get(r)).result
    assert res.status == 302 and not res.body and len(r.net.requests) == 1


async def test_a_redirect_from_an_allow_listed_host_into_the_rule_shape_is_not_admitted_by_the_rule():
    """規則は最初の要求だけに使う。許可リストの取得が転送で規則の形の URL へ向かっても、規則では通さない（許可リストの範囲だけを追う）。"""
    prefixes = (UrlPrefix(host="svc.example.invalid", path_prefix="/fx/"),)
    routes = {
        "svc.example.invalid/fx/a": Reply(status=302, headers=(("Location", f"https://{BASE}/README.md"),)),
        f"{BASE}/README.md": Reply(headers=TEXT, body=b"MUST NOT BE FETCHED"),
    }
    r = make_rig(routes, prefixes=prefixes, repo_raw=SCOPE, dns=DNS)
    res = (await r.fetch.fetch_ex(FetchRequest(url="https://svc.example.invalid/fx/a"))).result
    assert res.status == 302 and res.redirects[-1].followed is False and res.redirects[-1].blocked_policy is PolicyId.SCOPE
    assert [q.target for q in r.net.requests] == ["/fx/a"]


# ------------------------------------------------------------------ 上限・種別
MAX = FETCH_LIMITS.repo_max_file_bytes


async def test_a_file_of_exactly_the_cap_is_accepted():
    r = rig({f"{BASE}/README.md": Reply(headers=TEXT, body=b"a" * MAX)})
    res = (await get(r)).result
    assert res.outcome is FetchOutcome.OK and len(res.body) == MAX and not res.truncated


async def test_over_the_cap_by_content_length_is_refused_without_reading():
    r = rig({f"{BASE}/README.md": Reply(headers=TEXT, body=b"a", content_length=MAX + 1)})
    d = await get(r)
    assert (d.result.outcome, d.result.limit_hit, d.result.body) == (FetchOutcome.TOO_LARGE, FetchLimit.CONTENT_LENGTH, b"")
    assert "size.repo_file" in d.notes


async def test_over_the_cap_by_one_byte_is_refused_not_truncated():
    r = rig({f"{BASE}/README.md": Reply(headers=TEXT, body=b"a" * (MAX + 1))})
    res = (await get(r)).result
    assert (res.outcome, res.body, res.truncated) == (FetchOutcome.TOO_LARGE, b"", False)  # 打切りの本文を返さない


async def test_chunked_streams_without_content_length_are_capped_too():
    r = rig({f"{BASE}/README.md": Reply(headers=TEXT, repeat=(b"a" * 1024, 400), chunked=True)})  # 400KB
    res = (await get(r)).result
    assert res.outcome is FetchOutcome.TOO_LARGE and res.body == b""


async def test_a_gzip_bomb_is_refused_at_the_per_file_cap():
    r = rig({f"{BASE}/README.md": Reply(headers=(*TEXT, ("Content-Encoding", "gzip")), repeat=(b"a" * 1024, 2000), gzip=True)})  # 展開後 2MB
    res = (await get(r)).result
    assert res.outcome is FetchOutcome.TOO_LARGE and res.body == b""


async def test_an_endless_stream_is_stopped():
    r = rig({f"{BASE}/README.md": Reply(headers=TEXT, infinite=b"a" * 4096)})
    res = (await get(r)).result
    assert res.outcome in (FetchOutcome.TOO_LARGE, FetchOutcome.TIMEOUT) and res.body == b""


async def test_a_nul_byte_means_binary_and_the_body_is_dropped():
    r = rig({f"{BASE}/README.md": Reply(headers=TEXT, body=b"MZ\x90\x00\x03\x00binary")})
    d = await get(r)
    assert (d.result.outcome, d.result.body) == (FetchOutcome.UNSUPPORTED_TYPE, b"") and "type.binary" in d.notes


@pytest.mark.parametrize(
    "ctype", ["application/octet-stream", "text/html", "text/html; charset=utf-8", "application/json", "text/markdown", "image/png", "application/zip", None]
)
async def test_only_text_plain_is_accepted_for_fixed_files(ctype):
    headers = (("Content-Type", ctype),) if ctype else ()
    r = rig({f"{BASE}/README.md": Reply(headers=headers, body=b"# hello")})
    res = (await get(r)).result
    assert res.outcome is FetchOutcome.UNSUPPORTED_TYPE and res.body == b""


async def test_text_plain_with_charset_and_a_multibyte_body_is_accepted():
    r = rig({f"{BASE}/README.md": Reply(headers=(("Content-Type", "text/plain; charset=UTF-8"),), body="日本語の説明".encode())})
    assert (await get(r)).result.body == "日本語の説明".encode()


async def test_the_rule_cap_does_not_shrink_allow_listed_fetches():
    prefixes = (UrlPrefix(host="svc.example.invalid", path_prefix="/fx/"),)
    routes = {"svc.example.invalid/fx/a": Reply(headers=TEXT, body=b"a" * (MAX + 10))}
    r = make_rig(routes, prefixes=prefixes, repo_raw=SCOPE)
    res = (await r.fetch.fetch_ex(FetchRequest(url="https://svc.example.invalid/fx/a"))).result
    assert res.outcome is FetchOutcome.OK and len(res.body) == MAX + 10


# ------------------------------------------------------------------ 404・429・5xx の区別（S3 → 呼び出し側の分類まで）
async def test_404_429_5xx_and_network_failures_stay_distinct_end_to_end():
    S = RepoFileStatus
    for status, want in [(404, S.NOT_FOUND), (429, S.RATE_LIMITED), (500, S.TRANSIENT), (502, S.TRANSIENT), (503, S.TRANSIENT), (403, S.REJECTED), (410, S.REJECTED)]:
        r = rig({f"{BASE}/README.md": Reply(status=status, headers=TEXT, body=b"")})
        got = await fetch_repo_files(REF, r.fetch, limits=FETCH_LIMITS)
        assert got.readme.status is want, status
    r = rig({}, connect_errors={PUBLIC_IP: OSError("fake")})
    # connect_errors は ConnectError 相当の例外を投げる。ここでは 404（routes 無し）と区別されることだけを見る
    res = (await get(r, URL)).result
    assert res.outcome is FetchOutcome.NETWORK_ERROR and res.status is None  # （注入の仕方は下の専用テストで本物の接続失敗にしている）


# ------------------------------------------------------------------ S3 を通した取得の合計・件数の上限（実際の規則の上で）
async def test_total_cap_over_the_real_rule_makes_the_fourth_file_unusable():
    big = Reply(headers=TEXT, body=b"a" * MAX)
    routes = {f"{BASE}/README.md": big, f"{BASE}/LICENSE": big, f"{BASE}/Dockerfile": big, f"{BASE}/requirements.txt": Reply(headers=TEXT, body=b"x")}
    r = rig(routes)
    got = await fetch_repo_files(REF, r.fetch)
    assert [f.status for f in got.files] == [RepoFileStatus.FOUND] * 3 + [RepoFileStatus.UNUSABLE]
    assert got.bytes_total == FETCH_LIMITS.repo_max_total_bytes == 768 * 1024


async def test_request_count_is_capped_over_the_real_rule():
    from app.config import FetchLimits

    r = rig({})
    got = await fetch_repo_files(REF, r.fetch, limits=FetchLimits(repo_max_files=2))
    assert len(r.net.requests) == 2 and got.requests_made == 2
    r_all = rig({})
    await fetch_repo_files(REF, r_all.fetch)
    assert len(r_all.net.requests) == 7 <= FETCH_LIMITS.repo_max_files
    assert {q.target.rsplit("/", 1)[1] for q in r_all.net.requests} == set(REPO_FILE_NAMES)


async def test_urls_built_by_the_client_are_exactly_what_the_rule_admits():
    r = rig({f"{BASE}/{n}": Reply(headers=TEXT, body=b"x") for n in REPO_FILE_NAMES})
    for n in REPO_FILE_NAMES:
        res = (await get(r, raw_file_url(REF, n))).result
        assert res.status == 200, n


# ------------------------------------------------------------------ 機能フラグ・起動時の検査
def test_flag_is_off_by_default_and_only_the_literal_1_turns_it_on():
    assert load_settings({}).github_raw_enabled is False
    assert Settings().github_raw_enabled is False
    for v in ("", "0", "true", "yes", "on", " 2", "TRUE"):
        assert load_settings({"GITHUB_RAW_ENABLED": v}).github_raw_enabled is False, v
    assert load_settings({"GITHUB_RAW_ENABLED": "1"}).github_raw_enabled is True


def test_s2_with_the_flag_is_refused_at_startup_in_every_environment():
    for env in ("public", "staging", "dev"):
        s = load_settings({"ROLE": "agent", "ENV": env, "GITHUB_RAW_ENABLED": "1"})
        v = startup_violations(s, {"ENV": env}, {})
        assert any("GITHUB_RAW_ENABLED" in x for x in v), env
    s = load_settings({"GITHUB_RAW_ENABLED": "1"})  # ROLE の既定は agent
    assert any("GITHUB_RAW_ENABLED" in x for x in startup_violations(s, {}, {}))


def test_s3_with_the_flag_and_s2_without_it_start_cleanly():
    s3 = load_settings({"ROLE": "fetcher", "ENV": "public", "GITHUB_RAW_ENABLED": "1"})
    assert startup_violations(s3, {"ENV": "public"}, {}) == []
    s2 = load_settings({"ROLE": "agent", "ENV": "public", "FETCH_MODE": "remote", "STATE_BACKEND": "firestore", "SELF_ORIGIN": "https://self.example.invalid"})
    assert startup_violations(s2, {"ENV": "public"}, {}) == []


def test_the_fetcher_app_enables_the_rule_only_when_the_flag_is_set(monkeypatch):  # noqa: ANN001
    import app.net.safefetch as sf
    from app.net.fetcher_server import create_fetcher_app

    seen: list[dict] = []

    class Spy:
        def __init__(self, prefixes, **kw):  # noqa: ANN001, ANN003
            seen.append({"prefixes": tuple(prefixes), **kw})

    monkeypatch.setattr(sf, "SafeFetch", Spy)
    create_fetcher_app(load_settings({"ROLE": "fetcher"}))
    create_fetcher_app(load_settings({"ROLE": "fetcher", "GITHUB_RAW_ENABLED": "1", "ALLOWED_PREFIXES": "svc.example.invalid/fx/"}))
    assert seen[0]["repo_raw"] is None and seen[0]["prefixes"] == ()
    assert isinstance(seen[1]["repo_raw"], RepoRawScope) and len(seen[1]["prefixes"]) == 1


def test_existing_env_clean_list_knows_the_new_variable():
    from tests.conftest import _APP_ENV_KEYS

    assert "GITHUB_RAW_ENABLED" in _APP_ENV_KEYS


# ====================================================================================================
# 取り込み前の敵対レビューの指摘
# ====================================================================================================
async def test_a_real_connection_failure_is_transient_not_not_found():
    """指摘16: 通信の失敗は NETWORK_ERROR → TRANSIENT。404（NOT_FOUND）とは別。"""
    import httpcore

    r = rig({}, connect_errors={PUBLIC_IP: httpcore.ConnectError("fake")})
    d = await get(r)
    assert d.result.outcome is FetchOutcome.NETWORK_ERROR and d.result.status is None
    assert any(n.startswith("net.ConnectError") for n in d.notes)  # 想定外の例外の枝（net.unexpected）ではなく、接続失敗の枝
    got = await fetch_repo_files(REF, r.fetch)
    assert all(f.status is RepoFileStatus.TRANSIENT for f in got.files[:1])
    assert got.readme.status is RepoFileStatus.TRANSIENT and not got.nothing_found


# ---- S3 自身の取りすぎ止め（指摘4）
def relay_app(*, enabled, limits=None, clock=None):  # noqa: ANN001, ANN201
    from fastapi.testclient import TestClient

    from app.config import FetchLimits
    from app.contracts import FetchResult
    from app.net.fetcher_server import create_fetcher_app

    calls: list[str] = []

    class Port:
        async def fetch(self, request):  # noqa: ANN001, ANN202
            calls.append(request.url)
            return FetchResult(requested_url=request.url, final_url=request.url, outcome=FetchOutcome.OK, status=200, body=b"x" * 1000, content_kind=ContentKind.PLAIN)

    s = load_settings({"ROLE": "fetcher", **({"GITHUB_RAW_ENABLED": "1"} if enabled else {})})
    kw = {"limits": limits or FetchLimits(), **({"clock": clock} if clock else {})}
    app = create_fetcher_app(s, fetch=Port(), **kw)
    return TestClient(app), calls


AUTH = {"authorization": "Bearer t"}


def post(client, url):  # noqa: ANN001, ANN201
    return client.post("/fetch", json={"url": url}, headers=AUTH)


def test_s3_stops_a_flood_of_github_requests_by_itself_when_the_rule_is_on():
    """S2 が乗っ取られて任意の owner/repo を繰り返し要求しても、S3 自身が窓あたりの数で頭打ちにする。"""
    from app.config import FetchLimits

    client, calls = relay_app(enabled=True, limits=FetchLimits(repo_relay_requests_per_min=5))
    codes = [post(client, f"https://{BASE.replace('example-owner/example-repo', f'owner{i}/repo')}/README.md").status_code for i in range(12)]
    assert codes == [200] * 5 + [429] * 7
    assert len(calls) == 5  # 頭打ちの後は取りに行かない
    assert post(client, "https://svc.example.invalid/fx/a").status_code == 200  # GitHub 以外の要求は数えない


def test_s3_limit_by_bytes_and_the_window_resets():
    from app.config import FetchLimits

    now = [0.0]
    client, calls = relay_app(enabled=True, limits=FetchLimits(repo_relay_requests_per_min=100, repo_relay_bytes_per_min=2500), clock=lambda: now[0])
    codes = [post(client, URL).status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]  # 1,000 バイトずつ。3 件で 2,500 を超えた後は断る
    now[0] = 61.0
    assert post(client, URL).status_code == 200  # 窓が替われば再び通る


def test_s3_does_not_count_anything_when_the_rule_is_off():
    client, calls = relay_app(enabled=False)
    assert all(post(client, URL).status_code == 200 for _ in range(300))
    assert len(calls) == 300


def test_the_default_relay_limits_leave_room_for_normal_runs():
    # 1実行は最大 8 件・768KB。1分に 10 実行ぶんは通る
    assert FETCH_LIMITS.repo_relay_requests_per_min >= 10 * FETCH_LIMITS.repo_max_files
    assert FETCH_LIMITS.repo_relay_bytes_per_min >= 10 * FETCH_LIMITS.repo_max_total_bytes
