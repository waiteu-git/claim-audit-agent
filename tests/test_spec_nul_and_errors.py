"""第11弾 追加指示3: 本文に紛れた NUL の扱いと、全ページが読めない時の固定文。完全オフライン。

負の対照（バイナリを読んでしまう側に倒れないこと）を必ず入れる: 本物の形式の先頭を持つ合成のバイト列は、text/html と名乗っても読まない。
"""
import gzip

import pytest

from app.contracts import ContentKind, FetchOutcome, FetchRequest, FetchResult, OpenPageScope, PolicyId
from app.errors import PUBLIC_MESSAGES, ErrorCode
from app.net.vectors import PUBLIC_IP, Reply
from app.spec_url import parse_spec_url
from app.textsafe import BINARY_NUL_MAX_RATIO, BINARY_PREFIX_BYTES, looks_binary, strip_nul
from tests.net_support import make_rig
from tests.test_spec_mode import FakePagePort, page, post, reader, spec_deps
from tests.web_support import client, first, parse_sse

HOST = "notice.example"
URL = f"https://{HOST}/call/2026"
HTML_H = (("Content-Type", "text/html; charset=utf-8"),)
Q = "応募は1チーム1作品までとすること。"


def html_with_nul(n: int = 1, *, pad: int = 3000) -> bytes:
    """日本語の HTML。先頭 1KB より後ろ（日付の間）に NUL を n バイト紛れ込ませる。"""
    head = ("<html><body><h1>架空の公募の告知</h1><p>" + "説明の文です。" * (pad // 21) + "</p>").encode()
    return head + "<p>締切は10月".encode() + b"\x00" * n + "31日です。</p>".encode() + f"<p>{Q}</p></body></html>".encode()


def png() -> bytes:
    return b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00\x00\x00\x10" * 2 + b"\x08\x02\x00\x00\x00" + b"x" * 200


def pdf() -> bytes:
    return b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog >>\nendobj\n" + b"text " * 400  # 先頭に NUL を持たない PDF


def zip_() -> bytes:
    return b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"y" * 300


def gz_raw() -> bytes:
    return gzip.compress("<html><body>中身</body></html>".encode() * 50)


BINARIES = {"png": png, "pdf": pdf, "zip": zip_, "gzip-raw": gz_raw}


# ------------------------------------------------------------------ 判定の関数
@pytest.mark.parametrize("name", sorted(BINARIES))
def test_real_format_headers_are_binary(name):
    assert looks_binary(BINARIES[name]())


def test_the_ratio_boundary_is_fixed_exactly_at_one_percent():
    size = 10_000
    body = b"a" * (BINARY_PREFIX_BYTES + 10)
    at = body + b"\x00" * 100 + b"a" * (size - len(body) - 100)  # ちょうど 1%
    over = body + b"\x00" * 101 + b"a" * (size - len(body) - 101)  # 1% を超える
    assert len(at) == len(over) == size and BINARY_NUL_MAX_RATIO == 0.01
    assert looks_binary(at) is False and looks_binary(over) is True
    assert looks_binary(b"a" * (BINARY_PREFIX_BYTES - 1) + b"\x00" + b"a" * 100_000) is True  # 先頭 1KB の中
    assert looks_binary(b"a" * BINARY_PREFIX_BYTES + b"\x00" + b"a" * 100_000) is False  # 1KB のすぐ外
    assert BINARY_PREFIX_BYTES == 1024


def test_strip_nul_removes_every_nul():
    assert strip_nul(html_with_nul(3)).count(b"\x00") == 0


# ------------------------------------------------------------------ S3（SafeFetch の公開ページの規則）
def rig(body: bytes, headers=HTML_H, **kw):  # noqa: ANN001, ANN003, ANN201
    return make_rig({f"{HOST}/call/2026": Reply(headers=headers, body=body, **kw)}, dns={HOST: ((PUBLIC_IP,),)}, prefixes=(), open_page=OpenPageScope())


async def fetch(r):  # noqa: ANN001, ANN201
    from app.contracts import FetchMode

    return await r.fetch.fetch_ex(FetchRequest(url=URL, mode=FetchMode.SPEC_PAGE))


@pytest.mark.parametrize("n", [1, 2, 5])
async def test_html_with_a_few_nul_bytes_is_read_and_the_nuls_are_removed(n):
    d = await fetch(rig(html_with_nul(n)))
    res = d.result
    assert (res.outcome, res.status, res.content_kind) == (FetchOutcome.OK, 200, ContentKind.HTML)
    assert b"\x00" not in res.body and Q.encode() in res.body and "body.nul_stripped" in d.notes


async def test_gzipped_html_with_a_nul_in_the_middle_is_read():
    body = html_with_nul(1, pad=60_000)
    r = make_rig({f"{HOST}/call/2026": Reply(headers=(*HTML_H, ("Content-Encoding", "gzip")), body=body, gzip=True)},
                 dns={HOST: ((PUBLIC_IP,),)}, prefixes=(), open_page=OpenPageScope())  # fmt: skip
    res = (await fetch(r)).result
    assert res.outcome is FetchOutcome.OK and b"\x00" not in res.body and Q.encode() in res.body


@pytest.mark.parametrize("name", sorted(BINARIES))
@pytest.mark.parametrize("ctype", ["text/html; charset=utf-8", "text/plain"])
async def test_negative_control_binaries_named_text_stay_unsupported(name, ctype):
    d = await fetch(rig(BINARIES[name](), headers=(("Content-Type", ctype),)))
    assert d.result.outcome is FetchOutcome.UNSUPPORTED_TYPE and d.result.body == b"", name


async def test_negative_control_nul_over_one_percent_stays_unsupported():
    body = b"<html><body>" + b"a" * 2000 + b"\x00" * 50 + b"</body></html>"
    assert (await fetch(rig(body))).result.outcome is FetchOutcome.UNSUPPORTED_TYPE


async def test_the_github_rule_still_refuses_any_nul():
    from app.contracts import RepoRawScope

    base = "raw.githubusercontent.com/o/r/HEAD/README.md"
    r = make_rig({base: Reply(headers=(("Content-Type", "text/plain"),), body=b"a" * 2000 + b"\x00" + b"a" * 2000)},
                 dns={"raw.githubusercontent.com": ((PUBLIC_IP,),)}, prefixes=(), repo_raw=RepoRawScope())  # fmt: skip
    res = (await r.fetch.fetch_ex(FetchRequest(url="https://" + base))).result
    assert res.outcome is FetchOutcome.UNSUPPORTED_TYPE


# ------------------------------------------------------------------ S2（spec_read の判定・本文に NUL が残らない）
def test_s2_reads_a_page_with_a_stray_nul_and_the_extracted_text_has_none():
    url = parse_spec_url(URL).url
    model = reader(__import__("tests.agent_support", fromlist=["raw"]).raw(Q))
    r = post(client(spec_deps(FakePagePort({url: page(url, html_with_nul(2))}), model)), {"preset_id": "spec_url", "spec_url": URL})
    res = first(parse_sse(r.text), "result")
    assert [q["span"]["original_span"] for q in res["requirements"]] == [Q]
    assert "\x00" not in model.requests[0].contents and "\\u0000" not in r.text


@pytest.mark.parametrize("name", sorted(BINARIES))
def test_s2_negative_control_binaries_are_skipped(name):
    url = parse_spec_url(URL).url
    model = reader()
    r = post(client(spec_deps(FakePagePort({url: page(url, BINARIES[name]())}), model)), {"preset_id": "spec_url", "spec_url": URL})
    assert first(parse_sse(r.text), "error")["code"] == "SPEC_UNSUPPORTED" and model.requests == []


# ------------------------------------------------------------------ 全ページが読めない時の固定文
U = ["https://a1.example/x", "https://b2.example/y", "https://c3.example/z"]
PDF_REFUSED = lambda u: FetchResult(requested_url=u, outcome=FetchOutcome.UNSUPPORTED_TYPE)  # noqa: E731  S3 が PDF を拒否した形
NOT_FOUND = lambda u: page(u, status=404, body=b"")  # noqa: E731


def run(urls, default):  # noqa: ANN001, ANN201
    model = reader()
    r = post(client(spec_deps(FakePagePort(default=default), model)), {"preset_id": "spec_url", "spec_urls": urls})
    return first(parse_sse(r.text), "error"), model


@pytest.mark.parametrize("n", [1, 3])
def test_pdf_only_gives_the_format_sentence(n):
    err, model = run(U[:n], PDF_REFUSED)
    assert err == {"code": "SPEC_UNSUPPORTED", "message": "HTMLとテキスト以外の形式のため、読んでいません。"} and model.requests == []


def test_not_found_only_gives_the_fetch_sentence():
    err, _ = run(U[:2], NOT_FOUND)
    assert err == {"code": "FETCH_FAILED", "message": PUBLIC_MESSAGES[ErrorCode.FETCH_FAILED]}


def test_mixed_reasons_give_the_fetch_sentence():
    results = {parse_spec_url(U[0]).url: PDF_REFUSED(parse_spec_url(U[0]).url), parse_spec_url(U[1]).url: NOT_FOUND(parse_spec_url(U[1]).url)}
    model = reader()
    r = post(client(spec_deps(FakePagePort(results), model)), {"preset_id": "spec_url", "spec_urls": U[:2]})
    assert first(parse_sse(r.text), "error")["code"] == "FETCH_FAILED"


@pytest.mark.parametrize(
    "result, code",
    [
        (lambda u: FetchResult(requested_url=u, outcome=FetchOutcome.TOO_LARGE, limit_hit=__import__("app.contracts", fromlist=["FetchLimit"]).FetchLimit.CONTENT_LENGTH), "SPEC_TOO_LARGE"),
        (lambda u: page(u, body=b""), "SPEC_EMPTY"),
        (lambda u: FetchResult(requested_url=u, outcome=FetchOutcome.BLOCKED, blocked_policy=PolicyId.SCOPE), "SPEC_UNAVAILABLE"),
    ],
)
def test_each_single_reason_has_its_own_fixed_sentence(result, code):
    err, _ = run(U[:2], result)
    assert err == {"code": code, "message": PUBLIC_MESSAGES[ErrorCode(code)]}


def test_the_new_sentences_carry_no_url_or_number():
    for code in (ErrorCode.SPEC_UNSUPPORTED, ErrorCode.SPEC_TOO_LARGE, ErrorCode.SPEC_EMPTY):
        msg = PUBLIC_MESSAGES[code]
        assert msg.endswith("。") and not any(c.isdigit() for c in msg) and "/" not in msg and "http" not in msg.lower()
