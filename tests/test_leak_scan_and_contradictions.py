"""leak_scan（提出物の本文の漏洩走査）と、要項間の矛盾（adjudicate.find_contradictions）。正常・境界・攻撃。"""
import pytest

from app import contracts as C
from app.adjudicate import evidence_label, find_contradictions, slot_tokens
from app.checks.leak_scan import check_leak_scan, scan_text
from app.contracts import INJECTION_PLACEHOLDER, CheckClass, DocRole, Kind, ObsCode, ObsOutcome, PageClass, Slot
from app.quotes import DocIndex, QuoteChecker
from tests.agent_support import raw
from tests.factories import make_doc

RUN_APP = "." + "run" + ".app"
LEAK_REQ_TEXT = "公開説明文にメールアドレスを記載してはならない。"


def leak_req():
    spec = make_doc("D1", f"要項\u001e{LEAK_REQ_TEXT}")
    out = QuoteChecker(DocIndex([spec])).begin(raw(LEAK_REQ_TEXT, Kind.PROHIBITED, CheckClass.LEAK), "R1")
    return out.requirement


def sub(text: str, doc_id: str = "D2", **kw):
    return make_doc(doc_id, text, role=DocRole.SUBMISSION, **kw)


# ---- leak_scan ----------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "text,kind",
    [
        ("連絡は team@example.invalid まで", "email"),
        ("連絡は ｔｅａｍ＠ｅｘａｍｐｌｅ．ｉｎｖａｌｉｄ まで", "email"),  # 全角で崩しても NFKC で拾う
        (f"API は https://svc-abc123-an.a{RUN_APP}/v1", "service_url"),
        ("鍵 AIza" + "B" * 35, "google_api_key"),
        ("-----BEGIN " + "PRIVATE KEY-----", "private_key"),  # 連結で組む（ソースに鍵の見出しをそのまま書かない）
        ("サーバーは 192.168.10.20 です", "private_ip"),
        ("サーバーは 172.20.1.1 です", "private_ip"),
        ("sa@proj-x" + ".iam.gserviceaccount" + ".com", "service_account"),
    ],
)
def test_leak_patterns_find_each_kind(text, kind):
    assert kind in scan_text(text)


@pytest.mark.parametrize("text", ["バージョン 1.2.3.4 を使用", "8.8.8.8 は公開DNS", "メールアドレスは載せません", "https://example.invalid/run.apple",
                                  "192.168.1", "価格は10.5万円"])  # fmt: skip
def test_ordinary_text_is_not_a_leak(text):
    assert scan_text(text) == {}


def test_a_leak_is_a_strong_failure_with_kinds_and_counts_but_never_the_string_itself():
    o = check_leak_scan(leak_req(), [sub(f"問い合わせ a@example.invalid と b@example.invalid、https://x-1.a{RUN_APP}/")], "O1")
    assert (o.code, o.outcome, o.strong, o.doc_id) == (ObsCode.LEAK_FOUND, ObsOutcome.FAIL, True, "D2")
    assert o.facts == {"email": 2, "service_url": 1, "count": 3}
    assert "example" not in str(o.model_dump())
    assert evidence_label(o) == "公開してはいけない文字列あり（メール2件・サービスの直URL1件）"


def test_no_leak_is_a_strong_pass_on_complete_content():
    o = check_leak_scan(leak_req(), [sub("架空の作品の説明です。" * 5)], "O1")
    assert (o.code, o.outcome, o.strong, o.doc_id) == (ObsCode.NO_LEAK, ObsOutcome.PASS, True, "D2")


def test_masked_injection_text_prevents_a_no_leak_conclusion_but_not_a_leak_finding():
    masked = sub(f"説明{INJECTION_PLACEHOLDER}です")
    assert check_leak_scan(leak_req(), [masked], "O1").facts == {"reason": "masked_text"}
    leaky = sub(f"説明{INJECTION_PLACEHOLDER} a@example.invalid")
    assert check_leak_scan(leak_req(), [leaky], "O1").code is ObsCode.LEAK_FOUND


def test_only_content_documents_can_prove_absence():
    login = sub("ログイン", page_class=PageClass.LOGIN_WALL)
    assert check_leak_scan(leak_req(), [login], "O1").outcome is ObsOutcome.INCONCLUSIVE
    assert check_leak_scan(leak_req(), [], "O1").facts == {"reason": "no_submission_doc"}
    trunc = sub("説明" * 10, truncated=True)
    o = check_leak_scan(leak_req(), [sub("説明" * 10, "D3"), trunc], "O1")
    assert o.code is ObsCode.NO_LEAK and o.doc_id == "D2"  # 打切りの文書を指す（判定表が TRUNCATED の確認不能にする）


def test_end_to_end_a_truncated_submission_is_not_a_pass():
    from app.adjudicate import adjudicate

    r = leak_req()
    trunc = sub("説明" * 10, truncated=True)
    o = check_leak_scan(r, [trunc], "O1")
    spec = make_doc("D1", f"要項\u001e{LEAK_REQ_TEXT}")
    (v,) = adjudicate(C.AdjudicationInput(requirements=(r,), docs=(spec.meta(), trunc.meta()), observations=(o,)))
    assert v.label is C.VerdictLabel.UNVERIFIABLE and v.reason_code is C.UnverifiableReason.TRUNCATED


# ---- 矛盾 ---------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "slot,text,tokens",
    [
        (Slot.DEADLINE, "作品は10月15日 23:59（日本時間）までに提出すること。", ("10/15 23:59",)),
        (Slot.DEADLINE, "締切は１０／１６（金）１２：００です。", ("10/16 12:00",)),
        (Slot.DEADLINE, "締切は10月16日12時です。", ("10/16 12:00",)),
        (Slot.DEADLINE, "締切は13月40日です。", ()),
        (Slot.CHAR_LIMIT, "説明は1,000文字以内。", ("1000字",)),
        (Slot.TEAM_SIZE, "1チーム4名まで。", ("4名",)),  # 「1チーム」は単位（名・人）でないので数えない
        (Slot.NONE, "10月15日", ()),
    ],
)
def test_slot_tokens(slot, text, tokens):
    assert slot_tokens(slot, text) == tokens


def _reqs(*pairs):
    """(doc_id, 文, slot) の組 → 検証済みの要件（文書ごとに索引を作る）。"""
    docs = {}
    for doc_id, text, _ in pairs:
        docs.setdefault(doc_id, []).append(text)
    built = {d: make_doc(d, "要項\u001e" + "\u001e".join(t)) for d, t in docs.items()}
    qc = QuoteChecker(DocIndex(list(built.values())))
    out = []
    for i, (_, text, slot) in enumerate(pairs, start=1):
        r = qc.begin(raw(text, Kind.REQUIRED, CheckClass.NONE, slot=slot), f"R{i}").requirement
        assert r is not None and r.span is not None
        out.append(r)
    return out


def test_different_deadlines_in_different_documents_are_one_contradiction():
    reqs = _reqs(("D1", "作品は10月15日 23:59までに提出すること。", Slot.DEADLINE),
                 ("D2", "作品は10月16日 12:00までに提出しなければなりません。", Slot.DEADLINE))  # fmt: skip
    (c,) = find_contradictions(reqs)
    assert (c.slot, c.req_ids, c.tokens, c.basis) == (Slot.DEADLINE, ("R1", "R2"), ("10/15 23:59", "10/16 12:00"), C.ContradictionBasis.TOKEN_DIFF)


def test_same_values_same_document_or_no_values_are_not_contradictions():
    same = _reqs(("D1", "作品は10月15日 23:59までに提出すること。", Slot.DEADLINE),
                 ("D2", "作品は10月15日 23:59までに提出しなければなりません。", Slot.DEADLINE))  # fmt: skip
    assert find_contradictions(same) == ()
    one_doc = _reqs(("D1", "作品は10月15日までに提出すること。", Slot.DEADLINE), ("D1", "作品は10月16日までに登録すること。", Slot.DEADLINE))
    assert find_contradictions(one_doc) == ()
    other_slot = _reqs(("D1", "作品は10月15日までに提出すること。", Slot.DEADLINE), ("D2", "説明は800字以内とすること。", Slot.CHAR_LIMIT))
    assert find_contradictions(other_slot) == ()


def test_overlapping_values_are_not_a_contradiction():
    reqs = _reqs(("D1", "作品は10月15日 23:59までに提出すること。", Slot.DEADLINE),
                 ("D2", "作品は10月15日 23:59までに提出し、10月20日に発表すること。", Slot.DEADLINE))  # fmt: skip
    assert find_contradictions(reqs) == ()


def test_the_model_cannot_create_a_contradiction_by_slot_labels_alone():
    """slot は Reader が付けるが、値の相違はコードが引用から取る。値の無い文に締切の slot を付けても矛盾にならない。"""
    reqs = _reqs(("D1", "作品は期日までに提出すること。", Slot.DEADLINE), ("D2", "作品は10月16日までに提出すること。", Slot.DEADLINE))
    assert find_contradictions(reqs) == ()
