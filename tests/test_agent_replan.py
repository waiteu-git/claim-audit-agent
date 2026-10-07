"""「判断が変わる場面」（デモ②の核）を台本で固定する。

欠陥入りの提出物: AUTORUN が提出URLの認証壁（302→ログイン画面）を観測する → Planner が、提出物の説明に「テスト用アカウントの案内」が
あるかを contains_terms で確かめる → 無い（不確定）ので、案内ページへのリンクを fetch_link で辿る（方針変更。コードが replan の印を残す）
→ そこでも contains_terms を実行する → 在れば推定適合、無ければ「無い」を確定して不適合にする。
判定は観測からコード（adjudicate.py）が決める。Planner は手を選ぶだけ。"""
from app import contracts as C
from app.agent.planner import InspectMode
from app.contracts import Phase, TraceType, VerdictLabel
from app.model.scripted import ScriptedPort, reply_calls
from tests.agent_support import GUIDE_PAGE_WITH_ACCOUNT, GUIDE_PAGE_WITHOUT_ACCOUNT, guide_fetch, guide_reader
from tests.test_agent_run import go, verdicts

CHECK_TERMS = reply_calls(("run_check", {"checker": "contains_terms", "req_id": "R3"}))
FOLLOW = reply_calls(("fetch_link", {"link_id": "L1", "reason": "案内ページを辿る"}))
FINISH = reply_calls(("finish", {}))


def planner(*steps) -> ScriptedPort:
    return ScriptedPort(list(steps), model_id="scripted-planner")


def story(res):
    """トレースから、順序の見える要点だけを取り出す（(フェーズ, 種別, 名前, 要件, 符号)）。"""
    keep = (TraceType.TOOL_REQUEST, TraceType.TOOL_RESULT, TraceType.REPLAN)
    out = []
    for e in res.events:
        if e.phase in (Phase.AUTORUN, Phase.INSPECT) and e.type in keep:
            out.append((e.phase.value, e.type.value, e.name, e.req_id, e.reason_code))
    return out


async def run_story(guide_page, steps):
    return await go(InspectMode.PLANNER, planner=planner(*steps), fetch=guide_fetch(guide_page=guide_page), reader=guide_reader())


async def test_the_guide_is_found_on_the_linked_page_so_the_absence_on_the_description_page_is_not_reported():
    res = await run_story(GUIDE_PAGE_WITH_ACCOUNT, [CHECK_TERMS, FOLLOW, CHECK_TERMS, FINISH])
    assert story(res) == [
        ("AUTORUN", "tool_request", "http_probe", None, None),
        ("AUTORUN", "tool_result", "http_probe", None, "AUTH_WALL"),  # ① 提出URLは 302→ログイン画面
        ("AUTORUN", "tool_request", "run_check", "R1", None),
        ("AUTORUN", "tool_result", "run_check", "R1", "OVER_LIMIT"),
        ("AUTORUN", "tool_request", "run_check", "R2", None),
        ("AUTORUN", "tool_result", "run_check", "R2", "AUTH_WALL"),
        ("INSPECT", "tool_request", "run_check", "R3", None),  # ② Planner: 説明に案内があるか
        ("INSPECT", "tool_result", "run_check", "R3", "TERMS_ABSENT"),  # ③ 無い（不確定）
        ("INSPECT", "replan", "fetch_link", "R3", "TERMS_ABSENT"),  # ④ 方針変更: 案内ページを辿る
        ("INSPECT", "tool_request", "fetch_link", None, None),
        ("INSPECT", "tool_result", "fetch_link", None, "OK"),
        ("INSPECT", "tool_request", "run_check", "R3", None),  # ⑤ 辿った先でも確かめる
        ("INSPECT", "tool_result", "run_check", "R3", "TERMS_FOUND"),
        ("INSPECT", "tool_request", "finish", None, None),
        ("INSPECT", "tool_result", "finish", None, None),
    ]
    v = verdicts(res)
    assert v["R1"].label is VerdictLabel.FAIL and v["R2"].label is VerdictLabel.FAIL
    assert v["R2"].evidence[0].label == "302→/fx/defect/login/・password欄あり"  # 「審査員が開けない」の根拠
    assert v["R3"].label is VerdictLabel.PRESUMED_PASS  # 案内ページに在った。語が在ることの証明であって内容の保証ではない
    assert res.record.status is C.RunStatus.DONE and res.record.summary.denied == 0


async def test_when_the_linked_page_has_no_guide_either_the_absence_is_confirmed_and_the_requirement_fails():
    res = await run_story(GUIDE_PAGE_WITHOUT_ACCOUNT, [CHECK_TERMS, FOLLOW, CHECK_TERMS, FINISH])
    assert [s[1:] for s in story(res) if s[1] == "replan"] == [("replan", "fetch_link", "R3", "TERMS_ABSENT")]
    terms = [o for o in res.record.observations if o.req_id == "R3"]
    assert [(o.doc_id, o.code.value) for o in terms] == [("D2", "TERMS_ABSENT"), ("D3", "TERMS_ABSENT")]  # 説明ページと案内ページの両方で「無い」
    v = verdicts(res)
    assert v["R3"].label is VerdictLabel.FAIL and v["R3"].reason == "要項が求める案内（語）が、提出物の本文に見つかりません。"
    assert v["R2"].label is VerdictLabel.FAIL  # 提出URLはログインへ転送される＋案内も無い＝審査員が開けない
    assert {e.obs_id for e in v["R3"].evidence} == {terms[0].obs_id}  # 判定の証拠チップは観測を指す


async def test_the_replan_mark_points_at_the_observation_that_changed_the_plan():
    res = await run_story(GUIDE_PAGE_WITH_ACCOUNT, [CHECK_TERMS, FOLLOW, CHECK_TERMS, FINISH])
    (mark,) = [e for e in res.events if e.type is TraceType.REPLAN]
    absent = next(o for o in res.record.observations if o.code is C.ObsCode.TERMS_ABSENT)
    assert (mark.obs_id, mark.req_id, mark.reason_code, mark.actor) == (absent.obs_id, "R3", "TERMS_ABSENT", C.Actor.GOVERNOR)
    assert mark.attrs == {"after": "run_check", "next": "fetch_link", "checker": "contains_terms"}
    tool_req = next(e for e in res.events if e.type is TraceType.TOOL_REQUEST and e.name == "fetch_link")
    assert mark.seq == tool_req.seq - 1  # 印は、方針を変えた呼び出しの直前に残る


async def test_an_agent_that_never_leaves_the_description_page_reports_a_false_absence_and_the_trace_has_no_replan():
    """測れる差: 案内ページを辿らない Planner（router も同じ）は、案内ページに在る案内を「無い」と報告する。replan の印も出ない。"""
    res = await run_story(GUIDE_PAGE_WITH_ACCOUNT, [CHECK_TERMS, FINISH])
    assert not [e for e in res.events if e.type is TraceType.REPLAN]
    assert verdicts(res)["R3"].label is VerdictLabel.FAIL


async def test_following_a_link_after_a_conclusive_observation_is_not_a_change_of_plan():
    """replan は「検査が不確定だった後に、新しい材料を取りに行った」時だけ。AUTORUN が済ませた確定の観測の後の取得は方針変更ではない。"""
    res = await run_story(GUIDE_PAGE_WITH_ACCOUNT, [FOLLOW, CHECK_TERMS, FINISH])
    assert not [e for e in res.events if e.type is TraceType.REPLAN]
    assert [o.doc_id for o in res.record.observations if o.req_id == "R3"] == ["D2"]  # 文書を選ぶのはコード（取得順に、未検査の1枚）


async def test_contains_terms_checks_each_submission_page_once_and_the_third_call_finds_nothing_new_to_check():
    steps = [CHECK_TERMS, FOLLOW, CHECK_TERMS, CHECK_TERMS, FINISH]
    res = await run_story(GUIDE_PAGE_WITHOUT_ACCOUNT, steps)
    terms = [o for o in res.record.observations if o.req_id == "R3"]
    assert [(o.doc_id, o.code.value) for o in terms[:2]] == [("D2", "TERMS_ABSENT"), ("D3", "TERMS_ABSENT")]
    assert len(terms) <= 3 and all(o.code is not C.ObsCode.TERMS_FOUND for o in terms)
    if len(terms) == 3:
        assert terms[2].facts == {"why": "no_unchecked_doc"} and terms[2].outcome is C.ObsOutcome.INCONCLUSIVE
    assert verdicts(res)["R3"].label is VerdictLabel.FAIL


# ---- 架空フィクスチャ（g1found・g2missing）での同じ場面 ---------------------------------------------------
from app.fixtures import gen  # noqa: E402
from app.fixtures.eval import RulePlanner, run_variant  # noqa: E402

FOLLOW_L3 = reply_calls(("fetch_link", {"link_id": "L3", "reason": "案内ページを辿る"}))  # L1 は要項の「よくある質問」、L2 は提出物のデプロイURL、L3 が案内ページ
CHECK_GUIDE = reply_calls(("run_check", {"checker": "contains_terms", "req_id": "R7"}))


def key_events(record):
    out = []
    for e in record.events:
        if e.phase in (Phase.AUTORUN, Phase.INSPECT) and e.type in (TraceType.TOOL_RESULT, TraceType.REPLAN):
            out.append((e.type.value, e.name, e.req_id, e.reason_code))
    return out


async def test_fixture_demo_the_guide_is_on_the_linked_page():
    record, row = await run_variant(gen.GUIDE_VARIANTS[0], inspect_mode=InspectMode.PLANNER, planner_model=planner(CHECK_GUIDE, FOLLOW_L3, CHECK_GUIDE, FINISH))
    assert key_events(record) == [
        ("tool_result", "http_probe", None, "AUTH_WALL"),
        ("tool_result", "run_check", "R2", "WITHIN_LIMIT"),
        ("tool_result", "run_check", "R3", "AUTH_WALL"),
        ("tool_result", "run_check", "R4", "NO_LEAK"),
        ("tool_result", "run_check", "R7", "TERMS_ABSENT"),
        ("replan", "fetch_link", "R7", "TERMS_ABSENT"),
        ("tool_result", "fetch_link", None, "OK"),
        ("tool_result", "run_check", "R7", "TERMS_FOUND"),
        ("tool_result", "finish", None, None),
    ]
    labels = {r.req_id: v.label for r, v in zip(record.requirements, record.verdicts)}
    assert labels["R3"] is VerdictLabel.FAIL and labels["R7"] is VerdictLabel.PRESUMED_PASS
    assert (row["detected"], row["missed"], row["false_positives"], row["false_absent"]) == (["D2"], [], 0, 0)


async def test_fixture_demo_the_guide_is_missing_on_both_pages():
    record, row = await run_variant(gen.GUIDE_VARIANTS[1], inspect_mode=InspectMode.PLANNER, planner_model=planner(CHECK_GUIDE, FOLLOW_L3, CHECK_GUIDE, FINISH))
    labels = {r.req_id: v.label for r, v in zip(record.requirements, record.verdicts)}
    assert labels["R3"] is VerdictLabel.FAIL and labels["R7"] is VerdictLabel.FAIL  # 辿った先にも無い＝無いことを確定
    assert (row["detected"], row["false_positives"], row["false_absent"]) == (["D2", "D5"], 0, 0)
    assert [(o.doc_id, o.code.value) for o in record.observations if o.req_id == "R7"] == [("D3", "TERMS_ABSENT"), ("D4", "TERMS_ABSENT")]


async def test_the_rule_planner_makes_the_same_move_as_the_script_and_the_router_does_not():
    scripted, _ = await run_variant(gen.GUIDE_VARIANTS[0], inspect_mode=InspectMode.PLANNER, planner_model=planner(CHECK_GUIDE, FOLLOW_L3, CHECK_GUIDE, FINISH))
    rule, rrow = await run_variant(gen.GUIDE_VARIANTS[0], inspect_mode=InspectMode.PLANNER, planner_model=RulePlanner())
    router, orow = await run_variant(gen.GUIDE_VARIANTS[0])
    assert key_events(rule) == key_events(scripted) and [v.label for v in rule.verdicts] == [v.label for v in scripted.verdicts]
    assert (rrow["false_absent"], orow["false_absent"]) == (0, 1)  # 辿る Planner は誤った absent を出さず、辿らない router は出す
    assert not [e for e in router.events if e.type is TraceType.REPLAN]


# ---- 手順（routes）に従うだけの Planner で、方針変更の場面が完走する（10/7 の実測から） -------------------------------------
def route_follower():
    """StateView の routes の先頭だけに従う台本。実 Gemini は、不確定の後に手順が更新されないと同じ run_check を繰り返した
    （重複で3回拒否されて劣化）。手順が「次の1手」を出していれば、モデルの賢さに依らず完走することを固定する。"""
    import json

    def follow(req):
        view = json.loads(req.contents)
        for r in view["requirements"]:
            if r["state"] != "open":
                continue
            for route in r["routes"]:
                tool, _, arg = route.partition(":")
                if tool not in view["allowed_tools"]:
                    continue
                if tool == "fetch_link":
                    return reply_calls(("fetch_link", {"link_id": arg, "reason": "案内ページを辿る"}))
                if tool == "run_check":
                    return reply_calls(("run_check", {"checker": arg, "req_id": r["req_id"]}))
                if tool == "http_probe":
                    return reply_calls(("http_probe", {"target": arg, "reason": "到達検査"}))
        return reply_calls(("finish", {}))

    return follow


async def test_a_route_following_planner_follows_the_guide_page_when_the_first_check_is_inconclusive():
    res = await go(
        InspectMode.PLANNER, planner=ScriptedPort([route_follower()] * 8), fetch=guide_fetch(guide_page=GUIDE_PAGE_WITH_ACCOUNT), reader=guide_reader()
    )
    assert res.record.status is C.RunStatus.DONE and res.record.summary.denied == 0  # 重複の拒否も劣化も無い
    views = [e.state_view for e in res.events if e.type is TraceType.STATE_VIEW]
    r3 = [next(q for q in v.requirements if q.req_id == "R3").routes for v in views]
    assert r3[0] == ("run_check:contains_terms",)  # 最初は検査
    assert r3[1] == ("fetch_link:L1",)  # 不確定（今ある文書は調べ尽くした）→ 次の手は案内ページを辿ること
    assert r3[2] == ("run_check:contains_terms",)  # 辿った先の文書は未検査 → 検査
    assert any(e.type is TraceType.REPLAN for e in res.events)  # 方針変更の印（コードが付ける）
    assert verdicts(res)["R3"].label is VerdictLabel.PRESUMED_PASS  # 案内ページに在った


async def test_a_route_following_planner_confirms_the_absence_when_the_guide_page_has_none_either():
    res = await go(
        InspectMode.PLANNER, planner=ScriptedPort([route_follower()] * 8), fetch=guide_fetch(guide_page=GUIDE_PAGE_WITHOUT_ACCOUNT), reader=guide_reader()
    )
    assert res.record.status is C.RunStatus.DONE and res.record.summary.denied == 0
    assert verdicts(res)["R3"].label is VerdictLabel.FAIL  # 辿った先にも無い → 「無い」を確定して不適合
    # 調べ尽くして辿れるリンクも無い: 手順は空になり、Planner を呼ばずに終える（これ以上の手が無い）
    assert any(e.type is TraceType.AUTORUN and e.name == "planner_skipped" for e in res.events)
