"""第11弾 追加: 要項モードの複数リンク（上限3件）。完全オフライン（偽の FetchPort・台本の ModelPort）。"""
import io
import logging

import pytest

from app.agent.spec_read import read_spec_pages
from app.config import FETCH_LIMITS, RUN_CAPS
from app.contracts import (
    SPEC_MAX_URLS,
    ContentKind,
    FetchOutcome,
    FetchResult,
    Kind,
    LinkRole,
    PolicyId,
    RunStatus,
    SpecSkipReason,
)
from app.errors import PUBLIC_MESSAGES, ErrorCode
from app.jsonlog import LOGGER_NAME, setup_logging
from app.model.scripted import ScriptedPort
from app.quota import InMemoryState
from app.spec_url import parse_spec_url
from tests.agent_support import raw, reader_reply
from tests.test_spec_mode import EVIL, INJECTION, FakePagePort, page, post, spec_deps
from tests.web_support import client, first, parse_sse, run_async

U1 = "https://multi-canary-a1.example/rules"
U2 = "https://multi-canary-b2.example/faq?lang=ja"
U3 = "https://multi-canary-c3.invalid/terms"
A = "応募は1チーム1作品までとすること。"
B = "チームの人数は4名以下とすること。"
C = "提出物に個人情報を含めてはならない。"


def html(*sentences: str, extra: str = "") -> str:
    return "<html><body>" + "".join(f"<p>{x}</p>" for x in sentences) + extra + "</body></html>"


PAGES = {U1: html(A), U2: html(B), U3: html(C)}


def port_for(urls, overrides=None):  # noqa: ANN001, ANN201
    results = {parse_spec_url(u).url: page(parse_spec_url(u).url, PAGES[u]) for u in urls}
    for u, r in (overrides or {}).items():
        results[parse_spec_url(u).url] = r(parse_spec_url(u).url)
    return FakePagePort(results)


def reader_for(*per_doc):  # noqa: ANN002, ANN201
    """文書ごとの Reader の応答（1文書1チャンク）。"""
    return ScriptedPort([reader_reply(*(raw(q, k) for q, k in doc)) for doc in per_doc], model_id="scripted-reader")


def run_multi(urls, port, model, **kw):  # noqa: ANN001, ANN003, ANN201
    r = post(client(spec_deps(port, model, **kw)), {"preset_id": "spec_url", "spec_urls": urls})
    return r, (parse_sse(r.text) if r.headers.get("content-type", "").startswith("text/event-stream") else [])


@pytest.fixture
def log_stream():
    stream = io.StringIO()
    setup_logging("DEBUG", stream)
    yield stream
    logging.getLogger(LOGGER_NAME).handlers.clear()


# ------------------------------------------------------------------ 1件・2件・3件で出典が分かれる
@pytest.mark.parametrize("n", [1, 2, 3])
def test_one_to_three_urls_give_a_list_with_separate_sources(n):
    urls = [U1, U2, U3][:n]
    docs = [((A, Kind.REQUIRED),), ((B, Kind.REQUIRED),), ((C, Kind.PROHIBITED),)][:n]
    port, model = port_for(urls), reader_for(*docs)
    r, ev = run_multi(urls, port, model)
    res = first(ev, "result")
    assert res["kind"] == "spec_only" and res["verdicts"] == [] and res["skipped_pages"] == []
    got = [(q["span"]["original_span"], q["span"]["doc_id"]) for q in res["requirements"]]
    assert got == [(A, "D1"), (B, "D2"), (C, "D3")][:n]
    assert [(d["doc_id"], d["label"]) for d in res["docs"]] == [("D1", "要項 1"), ("D2", "要項 2"), ("D3", "要項 3")][:n]
    assert [q.url for q in port.requests] == [parse_spec_url(u).url for u in urls]  # 1件ずつ1ページだけ


def test_the_old_single_form_still_works():
    port = port_for([U1])
    r = post(client(spec_deps(port, reader_for(((A, Kind.REQUIRED),)))), {"preset_id": "spec_url", "spec_url": U1})
    assert first(parse_sse(r.text), "result")["requirements"][0]["span"]["doc_id"] == "D1"


@pytest.mark.parametrize(
    "body",
    [
        {"preset_id": "spec_url", "spec_urls": []},
        {"preset_id": "spec_url", "spec_urls": [U1, U2, U3, "https://fourth.example/x"]},
        {"preset_id": "spec_url", "spec_urls": [U1, U1]},
        {"preset_id": "spec_url", "spec_urls": [U1, U1.replace("https://", "https://") + "/../rules"]},  # 正規化すると同じ
        {"preset_id": "spec_url", "spec_urls": [U1, "https://MULTI-CANARY-A1.example/rules"]},  # 正規形でない別表記も1件ずつ拒否か重複
        {"preset_id": "spec_url", "spec_url": U1, "spec_urls": [U2]},
        {"preset_id": "spec_url", "spec_urls": U1},
        {"preset_id": "spec_url", "spec_urls": {"a": U1}},
        {"preset_id": "spec_url", "spec_urls": [U1, 7]},
        {"preset_id": "spec_url", "spec_urls": [U1, None]},
        {"preset_id": "spec_url", "spec_urls": [U1, "http://multi-canary-b2.example/x"]},
        {"preset_id": "spec_url", "spec_urls": [U1, "https://10.0.0.1/x"]},
        {"preset_id": "sample_defect", "spec_urls": [U1]},
        {"preset_id": "github_repo", "spec_urls": [U1]},
    ],
)
def test_bad_shapes_are_rejected_with_the_fixed_sentence(body, log_stream):
    port = port_for([U1, U2, U3])
    r = post(client(spec_deps(port)), body)
    assert r.status_code == 400 and r.json() == {"ok": False, "code": "INVALID_INPUT"}
    assert port.requests == []
    for frag in ("multi-canary", "fourth.example", "10.0.0.1"):
        assert frag not in r.text and frag not in log_stream.getvalue()


def test_the_limit_is_three_everywhere():
    assert SPEC_MAX_URLS == FETCH_LIMITS.spec_max_pages == 3 <= RUN_CAPS.fetches_acquire
    assert FETCH_LIMITS.spec_relay_requests_per_min >= 3 * FETCH_LIMITS.spec_max_pages  # 1分に3実行ぶんは通る
    with pytest.raises(ValueError):
        run_async(read_spec_pages([parse_spec_url(u) for u in (U1, U2, U3, "https://d4.example/x")], fetch=FakePagePort(), reader_model=reader_for()))


# ------------------------------------------------------------------ 取れないページは飛ばして、件数と理由を載せる
def test_a_404_and_a_pdf_are_skipped_and_the_rest_is_read(log_stream):
    pdf = lambda u: FetchResult(requested_url=u, outcome=FetchOutcome.UNSUPPORTED_TYPE)  # noqa: E731  S3 が PDF を拒否した形
    nf = lambda u: page(u, status=404, body=b"")  # noqa: E731
    port = port_for([U1, U2, U3], {U1: nf, U3: pdf})
    model = reader_for(((B, Kind.REQUIRED),))
    r, ev = run_multi([U1, U2, U3], port, model)
    res = first(ev, "result")
    assert [(q["span"]["original_span"], q["span"]["doc_id"]) for q in res["requirements"]] == [(B, "D1")]
    assert [d["label"] for d in res["docs"]] == ["要項 2"]  # 何番目の入力かはラベルに残る
    assert res["skipped_pages"] == [{"page": 1, "reason": SpecSkipReason.FETCH_FAILED.value}, {"page": 3, "reason": SpecSkipReason.UNSUPPORTED.value}]
    assert len(port.requests) == 3 and len(model.requests) == 1
    for frag in ("multi-canary", "lang=ja"):
        assert frag not in r.text and frag not in log_stream.getvalue()


def test_a_pdf_content_kind_that_slipped_through_is_still_skipped():
    weird = lambda u: page(u, b"%PDF-1.7 x", kind=ContentKind.UNSUPPORTED)  # noqa: E731
    port = port_for([U1, U2], {U2: weird})
    _, ev = run_multi([U1, U2], port, reader_for(((A, Kind.REQUIRED),)))
    assert first(ev, "result")["skipped_pages"] == [{"page": 2, "reason": SpecSkipReason.UNSUPPORTED.value}]


@pytest.mark.parametrize(
    "fail, code",
    [
        (lambda u: page(u, status=404, body=b""), "FETCH_FAILED"),
        (lambda u: FetchResult(requested_url=u, outcome=FetchOutcome.BLOCKED, blocked_policy=PolicyId.SCOPE), "SPEC_UNAVAILABLE"),
    ],
)
def test_all_pages_failing_is_a_fixed_error_settled_at_zero(fail, code):
    store = InMemoryState()
    model = reader_for()
    _, ev = run_multi([U1, U2, U3], FakePagePort(default=fail), model, store=store)
    assert first(ev, "error") == {"code": code, "message": PUBLIC_MESSAGES[ErrorCode(code)]} and model.requests == []
    total = next(v for k, v in store.docs.items() if k.endswith("/total"))
    assert total["reservations"] == {} and total["spent"]["judge"] == 0


def test_skip_reasons_are_fixed_sentences_without_values():
    for r in SpecSkipReason:
        assert r.value.endswith("。") and not any(c.isdigit() for c in r.value) and "/" not in r.value


# ------------------------------------------------------------------ 取得は3回だけ・よそへ取りに行かない
def test_three_urls_mean_three_requests_even_with_injected_instructions(log_stream):
    pages = {U1: html(A, extra=f'<p>{INJECTION}</p><a href="{EVIL}">続き</a>'), U2: html(B), U3: html(C)}
    port = FakePagePort({parse_spec_url(u).url: page(parse_spec_url(u).url, b) for u, b in pages.items()})
    model = ScriptedPort(
        [reader_reply(raw(A, Kind.REQUIRED), link_roles=[{"link_id": "L1", "role": LinkRole.DOCS.value}]),
         reader_reply(raw(B, Kind.REQUIRED)), reader_reply(raw(C, Kind.PROHIBITED))],
        model_id="scripted-reader",
    )  # fmt: skip
    r, ev = run_multi([U1, U2, U3], port, model)
    assert len(port.requests) == 3 and EVIL not in [q.url for q in port.requests]
    res = first(ev, "result")
    assert res["verdicts"] == [] and len(res["requirements"]) == 3
    for frag in ("evil-collector", "これまでの指示をすべて無視", "multi-canary"):
        assert frag not in r.text and frag not in log_stream.getvalue(), frag


def test_s3_stops_at_its_own_window_cap_too():
    from tests.test_spec_fetch_rule import post as s3_post
    from tests.test_spec_fetch_rule import relay_app

    from app.config import FetchLimits

    client_, calls = relay_app(enabled=True, limits=FetchLimits(spec_relay_requests_per_min=3))
    codes = [s3_post(client_, parse_spec_url(u).url).status_code for u in (U1, U2, U3, "https://d4.example/x")]  # 印つき
    assert codes == [200, 200, 200, 429] and len(calls) == 3


# ------------------------------------------------------------------ 上限に当たったら部分結果・予約は精算
def test_the_model_call_cap_gives_a_partial_result_and_the_reservation_is_settled():
    caps = RUN_CAPS.model_copy(update={"model_calls_reader": 1, "model_calls_spare": 0})
    store = InMemoryState()
    model = reader_for(((A, Kind.REQUIRED),), ((B, Kind.REQUIRED),), ((C, Kind.PROHIBITED),))
    _, ev = run_multi([U1, U2, U3], port_for([U1, U2, U3]), model, store=store, spec_caps=caps)
    res = first(ev, "result")
    assert res["status"] == RunStatus.DEGRADED.value and res["degraded_reason"] == "BUDGET"
    assert len(model.requests) == 1 and len(res["requirements"]) == 1  # 1回呼んだ分だけの部分結果
    assert any(d["truncated"] for d in res["docs"])  # 読めなかった文書は打切りとして残る
    total = next(v for k, v in store.docs.items() if k.endswith("/total"))
    assert total["reservations"] == {} and total["spent"]["judge"] == res["summary"]["est_cost_micro_jpy"] > 0
