"""第7弾の土台 1: 入口の検証（parse_repo_url）・取得先の組み立て（raw_file_url）・取得の結果の区別（fetch_repo_files）。

owner / repo は全て example-owner / example-repo のような明らかな合成名。完全オフライン（取得はフェイクの FetchPort）。
"""
import itertools
import random
import re
import string

import pytest

from app.config import FETCH_LIMITS, FetchLimits
from app.contracts import (
    REPO_FILE_NAMES,
    ContentKind,
    FetchOutcome,
    FetchRequest,
    FetchResult,
    PolicyId,
    RedirectHop,
)
from app.errors import AppError, ErrorCode
from app.github_repo import (
    MAX_REPO_URL_LENGTH,
    PUBLIC_REPO_ONLY_MESSAGE,
    RepoFileStatus,
    RepoRef,
    classify_result,
    fetch_repo_files,
    parse_repo_url,
    raw_file_url,
    repo_log_id,
)

OK_URL = "https://github.com/example-owner/example-repo"
AT = "@"  # 実アドレスの混入検知（衛生テスト）に引っかからないよう、userinfo の形は連結で作る


def rejected(text):  # noqa: ANN001, ANN201
    with pytest.raises(AppError) as e:
        parse_repo_url(text)
    assert e.value.code is ErrorCode.INVALID_INPUT
    assert e.value.detail == ""  # 入力の文字列を例外にもログにも持ち込まない
    assert e.value.public_message == "入力が正しくありません。"
    return e.value


# ------------------------------------------------------------------ 正例
@pytest.mark.parametrize(
    "text, owner, repo",
    [
        (OK_URL, "example-owner", "example-repo"),
        (OK_URL + "/", "example-owner", "example-repo"),  # 末尾 / は1つまで
        ("https://github.com/a/b", "a", "b"),  # 1字
        ("https://github.com/" + "a" * 39 + "/r", "a" * 39, "r"),  # owner 39字
        ("https://github.com/o/" + "r" * 100, "o", "r" * 100),  # repo 100字
        ("https://github.com/A1-b2/Re.po_x-y", "A1-b2", "Re.po_x-y"),
        ("https://github.com/o/.github", "o", ".github"),  # 先頭ドットは可
        ("https://github.com/o/a.gitx", "o", "a.gitx"),  # .git で「終わる」ものだけ不可
        ("https://github.com/o/...", "o", "..."),  # "." と ".." だけが不可
        ("https://github.com/0/0", "0", "0"),
    ],
)
def test_valid_urls_parse(text, owner, repo):
    ref = parse_repo_url(text)
    assert (ref.owner, ref.repo) == (owner, repo)


# ------------------------------------------------------------------ 拒否リスト
BAD_URLS = {
    "http": "http://github.com/example-owner/example-repo",
    "scheme-upper": "HTTPS://github.com/example-owner/example-repo",
    "no-scheme": "github.com/example-owner/example-repo",
    "scheme-relative": "//github.com/example-owner/example-repo",
    "www": "https://www.github.com/example-owner/example-repo",
    "gist": "https://gist.github.com/example-owner/example-repo",
    "host-upper": "https://GitHub.com/example-owner/example-repo",
    "host-upper2": "https://GITHUB.COM/example-owner/example-repo",
    "trailing-dot": "https://github.com./example-owner/example-repo",
    "subdomain": "https://sub.github.com/example-owner/example-repo",
    "suffix-host": "https://github.com.evil.example/example-owner/example-repo",
    "prefix-host": "https://evilgithub.com/example-owner/example-repo",
    "githubusercontent": "https://githubusercontent.com/example-owner/example-repo",
    "raw-host": "https://raw.githubusercontent.com/example-owner/example-repo",
    "userinfo-at": "https://github.com" + AT + "evil.invalid/example-owner/example-repo",
    "userinfo-user": "https://user" + AT + "github.com/example-owner/example-repo",
    "userinfo-pass": "https://user:pass" + AT + "github.com/example-owner/example-repo",
    "pct-dot-host": "https://github%2eevil/example-owner/example-repo",
    "pct-dot-host2": "https://github.com%2eevil.example/example-owner/example-repo",
    "port": "https://github.com:443/example-owner/example-repo",
    "port-other": "https://github.com:8443/example-owner/example-repo",
    "port-empty": "https://github.com:/example-owner/example-repo",
    "query": "https://github.com/example-owner/example-repo?tab=readme",
    "query-empty": "https://github.com/example-owner/example-repo?",
    "fragment": "https://github.com/example-owner/example-repo#readme",
    "fragment-empty": "https://github.com/example-owner/example-repo#",
    "tree": "https://github.com/example-owner/example-repo/tree/main",
    "blob": "https://github.com/example-owner/example-repo/blob/main/README.md",
    "issues": "https://github.com/example-owner/example-repo/issues",
    "extra-seg": "https://github.com/example-owner/example-repo/x",
    "double-slash-end": "https://github.com/example-owner/example-repo//",
    "double-slash-mid": "https://github.com//example-owner/example-repo",
    "double-slash-between": "https://github.com/example-owner//example-repo",
    "triple-slash": "https:///github.com/example-owner/example-repo",
    "only-owner": "https://github.com/example-owner",
    "only-owner-slash": "https://github.com/example-owner/",
    "no-owner": "https://github.com/",
    "host-only": "https://github.com",
    "space": "https://github.com/example-owner/example repo",
    "space-lead": " https://github.com/example-owner/example-repo",
    "space-trail": "https://github.com/example-owner/example-repo ",
    "newline": "https://github.com/example-owner/example-repo\n",
    "newline-mid": "https://github.com/example-owner/example\nrepo",
    "cr": "https://github.com/example-owner/example-repo\r",
    "tab": "https://github.com/example-owner/example\trepo",
    "nul": "https://github.com/example-owner/example-repo\x00",
    "nul-mid": "https://github.com/example-owner/exa\x00mple-repo",
    "ctrl": "https://github.com/example-owner/example-repo\x1b",
    "del": "https://github.com/example-owner/example-repo\x7f",
    "zero-width": "https://github.com/example-owner/example​-repo",
    "bidi": "https://github.com/example-owner/example‮-repo",
    "nbsp": "https://github.com/example-owner/example repo",
    "fullwidth-slash": "https://github.com／example-owner/example-repo",
    "fullwidth-dot-host": "https://github．com/example-owner/example-repo",
    "fullwidth-dot-repo": "https://github.com/example-owner/example．repo",
    "fullwidth-letters": "https://github.com/ｅxample-owner/example-repo",  # NFKC で別の文字列になる
    "fullwidth-colon": "https：//github.com/example-owner/example-repo",
    "ideographic-dot": "https://github。com/example-owner/example-repo",
    "cyrillic-a-host": "https://github.com/example-owner/example-repo".replace("github", "githуb"),
    "cyrillic-a-owner": "https://github.com/exаmple-owner/example-repo",
    "cyrillic-a-repo": "https://github.com/example-owner/exаmple-repo",
    "greek-omicron": "https://github.com/example-owner/examplο-repo",
    "unicode-digit": "https://github.com/example-owner/١repo",  # アラビア・インド数字
    "kelvin": "https://github.com/example-owner/K-repo",  # K（NFKC で k）
    "pct-dot": "https://github.com/example-owner/%2e%2e",
    "pct-slash": "https://github.com/example-owner%2fexample-repo",
    "pct-slash-repo": "https://github.com/example-owner/example%2frepo",
    "pct-letter": "https://github.com/example-owner/%65xample-repo",
    "pct-bare": "https://github.com/example-owner/example-repo%",
    "pct-nul": "https://github.com/example-owner/example-repo%00",
    "backslash": "https://github.com\\example-owner\\example-repo",
    "backslash-end": "https://github.com/example-owner/example-repo\\",
    "backslash-mid": "https://github.com/example-owner\\example-repo",
    "semicolon": "https://github.com/example-owner/example;repo",
    "dot-repo": "https://github.com/example-owner/.",
    "dotdot-repo": "https://github.com/example-owner/..",
    "dot-owner": "https://github.com/./example-repo",
    "dotdot-owner": "https://github.com/../example-repo",
    "dotgit": "https://github.com/example-owner/example-repo.git",
    "dotgit-upper": "https://github.com/example-owner/example-repo.GIT",
    "dotgit-only": "https://github.com/example-owner/.git",
    "dotgit-slash": "https://github.com/example-owner/example-repo.git/",
    "owner-lead-hyphen": "https://github.com/-example/example-repo",
    "owner-trail-hyphen": "https://github.com/example-/example-repo",
    "owner-hyphen-only": "https://github.com/-/example-repo",
    "owner-40": "https://github.com/" + "a" * 40 + "/r",
    "owner-underscore": "https://github.com/example_owner/example-repo",
    "owner-dot": "https://github.com/example.owner/example-repo",
    "repo-101": "https://github.com/o/" + "r" * 101,
    "repo-plus": "https://github.com/o/a+b",
    "repo-tilde": "https://github.com/o/a~b",
    "repo-at": "https://github.com/o/a@b",
    "repo-colon": "https://github.com/o/a:b",
    "empty": "",
    "scheme-only": "https://",
    "slash-only": "/",
    "too-long": "https://github.com/o/" + "r" * (MAX_REPO_URL_LENGTH),
    "very-long": "https://github.com/o/" + "r" * 1_000_000,
    "js": "javascript:alert(1)//https://github.com/o/r",
    "data": "data:text/plain,https://github.com/o/r",
    "file": "file:///etc/passwd",
    "embedded": "x https://github.com/o/r",
    "two-urls": "https://github.com/o/r https://github.com/o/r",
    "git-ssh": "git" + AT + "github.com:example-owner/example-repo.git",
    "ssh-url": "ssh://git" + AT + "github.com/example-owner/example-repo",
}


@pytest.mark.parametrize("name", sorted(BAD_URLS))
def test_every_forbidden_shape_is_rejected_with_invalid_input(name):
    rejected(BAD_URLS[name])


@pytest.mark.parametrize("value", [None, 123, b"https://github.com/o/r", ["https://github.com/o/r"], object()])
def test_non_string_input_is_rejected(value):
    rejected(value)


def test_the_boundary_lengths_are_exact():
    assert parse_repo_url("https://github.com/" + "a" * 39 + "/r").owner == "a" * 39
    rejected("https://github.com/" + "a" * 40 + "/r")
    assert parse_repo_url("https://github.com/o/" + "r" * 100).repo == "r" * 100
    rejected("https://github.com/o/" + "r" * 101)
    # 2048字を超える入力は、形が正しくても長さで落ちる（正規表現に渡す前）
    rejected("https://github.com/o/" + "r" * MAX_REPO_URL_LENGTH)


def test_the_error_never_carries_the_input_in_any_public_place():
    secret = "https://github.com/example-owner/secret-looking-repo?token=abc"
    e = rejected(secret)
    assert "secret-looking-repo" not in (str(e) + repr(e) + e.detail + e.public_message)


def test_the_error_message_is_the_fixed_invalid_input_text_for_every_rejection():
    msgs = set()
    for text in BAD_URLS.values():
        with pytest.raises(AppError) as e:
            parse_repo_url(text)
        msgs.add((e.value.code, e.value.public_message, e.value.detail))
    assert msgs == {(ErrorCode.INVALID_INPUT, "入力が正しくありません。", "")}


def test_no_accepted_input_changes_under_nfkc_or_has_non_ascii():
    """受理された文字列は ASCII だけ＝NFKC で別の文字列にならない。乱数と変異で多数を流して確かめる。"""
    import unicodedata

    rnd = random.Random(7)
    alphabet = string.ascii_letters + string.digits + "-._/:?#%@\\ а．／K​\x00\n"
    accepted = 0
    for _ in range(20000):
        base = list("https://github.com/example-owner/example-repo")
        for _ in range(rnd.randint(1, 3)):
            i = rnd.randrange(len(base) + 1)
            op = rnd.choice("ids")
            if op == "i":
                base.insert(i, rnd.choice(alphabet))
            elif op == "d" and base:
                base.pop(min(i, len(base) - 1))
            elif base:
                base[min(i, len(base) - 1)] = rnd.choice(alphabet)
        text = "".join(base)
        try:
            ref = parse_repo_url(text)
        except AppError:
            continue
        accepted += 1
        assert text.isascii() and unicodedata.normalize("NFKC", text) == text
        assert re.fullmatch(r"https://github\.com/[A-Za-z0-9-]+/[A-Za-z0-9._-]+/?", text)
        assert text.rstrip("/").endswith(f"{ref.owner}/{ref.repo}")
    assert accepted > 0  # 対照: 何も通らないから緑、ではない


# ------------------------------------------------------------------ RepoRef
def test_repo_ref_validates_even_when_built_by_hand():
    RepoRef(owner="o", repo="r")
    for owner, repo in [("-o", "r"), ("o", ".."), ("o", "r.git"), ("o/x", "r"), ("o", "r/x"), ("", "r"), ("o", ""), ("é", "r")]:
        with pytest.raises(ValueError):
            RepoRef(owner=owner, repo=repo)


def test_repo_ref_is_frozen_and_never_prints_the_repo_name():
    ref = RepoRef(owner="example-owner", repo="example-repo")
    with pytest.raises(ValueError):
        ref.owner = "x"  # type: ignore[misc]
    for text in (repr(ref), str(ref), f"{ref}", f"{ref!r}"):
        assert "example-owner" not in text and "example-repo" not in text
    assert repo_log_id(ref) in repr(ref)
    assert re.fullmatch(r"[0-9a-f]{12}", repo_log_id(ref))
    assert repo_log_id(ref) != repo_log_id(RepoRef(owner="example-owner", repo="example-repo2"))


# ------------------------------------------------------------------ 取得先の組み立て
def test_raw_url_is_built_from_the_ref_and_a_fixed_name_only():
    ref = parse_repo_url(OK_URL)
    assert raw_file_url(ref, "README.md") == "https://raw.githubusercontent.com/example-owner/example-repo/HEAD/README.md"
    assert {raw_file_url(ref, n).rsplit("/", 1)[1] for n in REPO_FILE_NAMES} == set(REPO_FILE_NAMES)


@pytest.mark.parametrize(
    "name", ["", "readme.md", "README.MD", "../README.md", "a/README.md", "README.md/", "README.md?x=1", "README.md#x", "LICENSE ", "main.py", ".env"]
)
def test_raw_url_refuses_any_name_outside_the_fixed_list(name):
    with pytest.raises(ValueError):
        raw_file_url(RepoRef(owner="o", repo="r"), name)


def test_assembled_urls_contain_nothing_but_owner_repo_and_the_fixed_name():
    """多数の入力（乱数）で、受理された ref から組んだ URL が決まった形に完全一致し、利用者の文字列は owner / repo の位置にしか入らない。"""
    rnd = random.Random(11)
    owner_chars = string.ascii_letters + string.digits + "-"
    repo_chars = string.ascii_letters + string.digits + "._-"
    shape = re.compile(r"https://raw\.githubusercontent\.com/([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)/HEAD/([A-Za-z.]+)")
    built = 0
    for _ in range(3000):
        owner = "".join(rnd.choice(owner_chars) for _ in range(rnd.randint(1, 39)))
        repo = "".join(rnd.choice(repo_chars) for _ in range(rnd.randint(1, 100)))
        try:
            ref = parse_repo_url(f"https://github.com/{owner}/{repo}")
        except AppError:
            continue
        for name in REPO_FILE_NAMES:
            url = raw_file_url(ref, name)
            m = shape.fullmatch(url)
            assert m and (m[1], m[2], m[3]) == (owner, repo, name)
            assert url.count("/") == 6 and "?" not in url and "#" not in url and "%" not in url and ".." not in url.split("/")
            built += 1
    assert built > 1000


# ------------------------------------------------------------------ 取得の結果の型
def result(status=200, body=b"hello", *, outcome=FetchOutcome.OK, kind=ContentKind.PLAIN, url="https://x.example.invalid/", **kw):  # noqa: ANN001, ANN003
    fields = dict(requested_url=url, final_url=url, outcome=outcome)
    if outcome is FetchOutcome.OK:
        fields.update(status=status, body=body, content_kind=kind if body else None)
    if outcome is FetchOutcome.BLOCKED:
        fields.pop("final_url")
        fields["blocked_policy"] = PolicyId.SCOPE
    fields.update(kw)
    return FetchResult(**fields)


U = "https://x.example.invalid/"


def test_classify_result_distinguishes_every_state():
    S = RepoFileStatus
    assert classify_result(result(200), U) is S.FOUND
    assert classify_result(result(404, b""), U) is S.NOT_FOUND
    assert classify_result(result(429, b""), U) is S.RATE_LIMITED
    for st in (500, 502, 503, 599):
        assert classify_result(result(st, b""), U) is S.TRANSIENT
    assert classify_result(result(outcome=FetchOutcome.NETWORK_ERROR), U) is S.TRANSIENT
    assert classify_result(result(outcome=FetchOutcome.TIMEOUT, limit_hit="total_timeout"), U) is S.TRANSIENT
    for st in (301, 302, 307, 308, 403, 401, 410, 204, 206):
        assert classify_result(result(st, b""), U) is S.REJECTED, st
    assert classify_result(result(outcome=FetchOutcome.BLOCKED), U) is S.REJECTED
    assert classify_result(result(outcome=FetchOutcome.UNSUPPORTED_TYPE), U) is S.UNUSABLE
    assert classify_result(result(outcome=FetchOutcome.TOO_LARGE, limit_hit="content_length"), U) is S.UNUSABLE


def test_classify_result_does_not_trust_s3_blindly():
    S = RepoFileStatus
    assert classify_result(result(200, b""), U) is S.FOUND  # 空のファイル（LICENSE が空、など）は「有る」。読めるかは検査の側で決める
    assert classify_result(result(200, b"", kind=ContentKind.HTML, content_kind=ContentKind.HTML), U) is S.UNUSABLE
    assert classify_result(result(200, b"a\x00b"), U) is S.UNUSABLE  # NUL
    assert classify_result(result(200, b"x" * (FETCH_LIMITS.repo_max_file_bytes + 1)), U) is S.UNUSABLE
    assert classify_result(result(200, b"x" * FETCH_LIMITS.repo_max_file_bytes), U) is S.FOUND  # ちょうど上限は可
    assert classify_result(result(200, b"<p>x</p>", kind=ContentKind.HTML), U) is S.UNUSABLE
    assert classify_result(result(200, b"x", truncated=True, limit_hit="decoded_size"), U) is S.UNUSABLE
    hop = RedirectHop(url=U, status=302, location="https://y.example.invalid/", followed=True, in_scope=True)
    assert classify_result(result(200, b"x", redirects=(hop,)), U) is S.REJECTED  # 転送を経た応答は使わない
    assert classify_result(result(200, b"x", final_url="https://y.example.invalid/"), U) is S.REJECTED


# ------------------------------------------------------------------ fetch_repo_files（フェイクの FetchPort）
class FakePort:
    def __init__(self, files=None, *, default=404, special=None):  # noqa: ANN001
        self.files = files or {}  # 固定名 → 本文(bytes) または FetchResult を返す関数
        self.default = default
        self.special = special or {}  # 固定名 → FetchResult
        self.requests: list[str] = []

    async def fetch(self, request: FetchRequest) -> FetchResult:
        self.requests.append(request.url)
        name = request.url.rsplit("/", 1)[1]
        if name in self.special:
            sp = self.special[name]
            return sp.model_copy(update={"requested_url": request.url, "final_url": request.url if sp.final_url else None})
        if name in self.files:
            return result(200, self.files[name], url=request.url)
        return result(self.default, b"", url=request.url)


REF = RepoRef(owner="example-owner", repo="example-repo")


async def test_all_four_kinds_are_found_with_the_first_candidate():
    port = FakePort({"README.md": b"# readme", "LICENSE": b"lic", "Dockerfile": b"FROM x", "requirements.txt": b"a==1"})
    r = await fetch_repo_files(REF, port)
    assert [f.status for f in r.files] == [RepoFileStatus.FOUND] * 4
    assert (r.readme.name, r.readme.body, r.license.name, r.dockerfile.body, r.requirements.body) == ("README.md", b"# readme", "LICENSE", b"FROM x", b"a==1")
    assert r.requests_made == 4 and r.bytes_total == len(b"# readme") + 3 + 6 + 4
    assert not r.nothing_found
    assert all(u.startswith("https://raw.githubusercontent.com/example-owner/example-repo/HEAD/") for u in port.requests)


async def test_candidates_fall_through_in_order_and_stop_at_the_first_found():
    port = FakePort({"README": b"plain readme", "LICENSE.txt": b"lic"})
    r = await fetch_repo_files(REF, port)
    assert (r.readme.name, r.readme.status) == ("README", RepoFileStatus.FOUND)
    assert (r.license.name, r.license.status) == ("LICENSE.txt", RepoFileStatus.FOUND)
    assert [u.rsplit("/", 1)[1] for u in port.requests] == ["README.md", "README", "LICENSE", "LICENSE.md", "LICENSE.txt", "Dockerfile", "requirements.txt"]
    assert r.dockerfile.status is r.requirements.status is RepoFileStatus.NOT_FOUND
    assert len(port.requests) == 7 <= FETCH_LIMITS.repo_max_files


async def test_everything_missing_is_one_fixed_state_not_a_private_repo_oracle():
    r = await fetch_repo_files(REF, FakePort())
    assert r.nothing_found and all(f.status is RepoFileStatus.NOT_FOUND for f in r.files)
    assert PUBLIC_REPO_ONLY_MESSAGE == "公開リポジトリのURLだけ対応しています。"
    # 「無い」と「非公開」は区別しない（同じ 404）。結果の型にも、非公開を示す状態は無い
    assert "private" not in " ".join(s.value for s in RepoFileStatus)


async def test_rate_limit_stops_the_remaining_requests_and_is_reported_as_such():
    port = FakePort({"README.md": b"r"}, special={"LICENSE": result(429, b"")})
    r = await fetch_repo_files(REF, port)
    assert r.readme.status is RepoFileStatus.FOUND
    assert r.license.status is RepoFileStatus.RATE_LIMITED
    assert r.dockerfile.status is r.requirements.status is RepoFileStatus.SKIPPED
    assert [u.rsplit("/", 1)[1] for u in port.requests] == ["README.md", "LICENSE"]  # 429 の後は取りに行かない


async def test_404_429_and_5xx_are_kept_apart_per_kind():
    port = FakePort(
        special={
            "README.md": result(404, b""),
            "README": result(503, b""),  # 候補の1つが一時的な失敗なら、種類としては「一時的」（無いと断定しない）
            "Dockerfile": result(302, b""),
        }
    )
    r = await fetch_repo_files(REF, port)
    assert r.readme.status is RepoFileStatus.TRANSIENT
    assert r.license.status is RepoFileStatus.NOT_FOUND
    assert r.dockerfile.status is RepoFileStatus.REJECTED
    assert r.requirements.status is RepoFileStatus.NOT_FOUND
    assert not r.nothing_found


async def test_a_found_candidate_wins_over_an_earlier_failure():
    port = FakePort({"README": b"x"}, special={"README.md": result(503, b"")})
    r = await fetch_repo_files(REF, port)
    assert (r.readme.name, r.readme.status) == ("README", RepoFileStatus.FOUND)


async def test_per_file_cap_total_cap_and_the_file_count_cap():
    big = b"a" * FETCH_LIMITS.repo_max_file_bytes  # ちょうど 256KB
    port = FakePort({"README.md": big, "LICENSE": big, "Dockerfile": big, "requirements.txt": b"x"})
    r = await fetch_repo_files(REF, port)
    assert [f.status for f in r.files] == [RepoFileStatus.FOUND] * 3 + [RepoFileStatus.UNUSABLE]  # 合計 768KB を 1 バイト超える
    assert r.bytes_total == 3 * FETCH_LIMITS.repo_max_file_bytes == FETCH_LIMITS.repo_max_total_bytes
    assert r.requirements.body == b""  # 捨てる

    small = FetchLimits(repo_max_files=3)
    port2 = FakePort()
    r2 = await fetch_repo_files(REF, port2, limits=small)
    assert len(port2.requests) == 3 and r2.requests_made == 3  # 404 も1件に数える
    assert r2.dockerfile.status is r2.requirements.status is RepoFileStatus.SKIPPED
    assert FETCH_LIMITS.repo_max_files == 8 and FETCH_LIMITS.repo_max_file_bytes == 256 * 1024 and FETCH_LIMITS.repo_max_total_bytes == 768 * 1024


async def test_binary_and_oversize_bodies_are_unusable_and_not_counted():
    port = FakePort(
        special={
            "README.md": result(200, b"abc\x00def"),
            "LICENSE": result(outcome=FetchOutcome.TOO_LARGE, limit_hit="content_length"),
            "Dockerfile": result(200, b"<html>", kind=ContentKind.HTML),
        }
    )
    r = await fetch_repo_files(REF, port)
    assert r.readme.status is RepoFileStatus.UNUSABLE  # README.md は NUL。README は 404 だが、強い方（使えない）を採る
    assert r.license.status is RepoFileStatus.UNUSABLE and r.dockerfile.status is RepoFileStatus.UNUSABLE
    assert r.bytes_total == 0 and all(f.body == b"" for f in r.files)


async def test_results_never_reveal_the_body_in_repr_or_logs(caplog):  # noqa: ANN001
    import logging

    caplog.set_level(logging.DEBUG)
    r = await fetch_repo_files(REF, FakePort({"README.md": b"SECRET-BODY-TEXT"}))
    assert "SECRET-BODY-TEXT" not in repr(r) and "SECRET-BODY-TEXT" not in repr(r.readme)
    logged = " ".join(str(getattr(rec, "fields", "")) + rec.getMessage() for rec in caplog.records)
    assert "SECRET-BODY-TEXT" not in logged
    assert "example-owner" not in logged and "example-repo" not in logged
    assert repo_log_id(REF) in logged


async def test_a_port_that_returns_a_redirected_or_wrong_url_answer_is_not_used():
    hop = RedirectHop(url=U, status=302, location="https://y.example.invalid/", followed=True, in_scope=True)

    class Sneaky:
        async def fetch(self, request):  # noqa: ANN001, ANN202
            return result(200, b"evil", url=request.url, redirects=(hop,))

    r = await fetch_repo_files(REF, Sneaky())
    assert all(f.status is RepoFileStatus.REJECTED for f in r.files) and r.bytes_total == 0


def test_the_fixed_names_are_exactly_the_documented_seven():
    assert REPO_FILE_NAMES == ("README.md", "README", "LICENSE", "LICENSE.md", "LICENSE.txt", "Dockerfile", "requirements.txt")
    assert len(REPO_FILE_NAMES) <= FETCH_LIMITS.repo_max_files
    assert all(r"/" not in n and n == n.strip() for n in REPO_FILE_NAMES)
    assert len(list(itertools.chain(REPO_FILE_NAMES))) == len(set(REPO_FILE_NAMES))
