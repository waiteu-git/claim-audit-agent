"""ToolRegistry: Governor が許可した関数呼び出しを実行する（設計 §4。ツールは5本だけ）。

  fetch_link(link_id)         リンク表の通し番号で指したページを取得して洗浄し、文書として加える（URL 文字列は受けない）
  http_probe(target)          提出URL（SUBMISSION_URL）かリンクへの到達検査（ログイン壁の観測など）。本文は観測に載せない
  run_check(checker, req_id)  決定論のチェッカー（ネットワーク・LLM 不使用）。検査の値は検証済み引用から取る
  mark_unverifiable           P-UNVERIF-01 を通った確認不能の印
  finish                      検査の終了

ここは実行だけをする。許可・上限・重複の判断は Governor が済ませている（Admission を受けて動く）。観測（Observation）は
コードが整形し、Planner へ戻るのは ObsCode（1語）だけ。取得物の本文・URL・アンカー文言は Planner へ返さない。
想定内の失敗（拒否・タイムアウト・未実装のチェッカー）は例外でなく、不確定の観測（確認不能の材料）として返す。
"""
import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from app.agent.governor import PLANNER_MARK_CODES, Admission, Governor
from app.agent.state import RunState
from app.agent.trace import digest
from app.checks.http_probe import http_probe
from app.checks.registry import CheckContext, run_checker
from app.contracts import (
    Actor,
    ContentKind,
    DocRole,
    FetchKind,
    FetchOutcome,
    FetchPort,
    FetchRequest,
    FetchResult,
    Observation,
    ObsCode,
    ObsOutcome,
    TOOL_ARG_MODELS,
    ToolDecl,
    ToolName,
    TraceType,
    UnverifiableMark,
    llm_json_schema,
)
from app.errors import AppError, ErrorCode, classify
from app.ingest.sanitize import sanitize


TOOL_DESCRIPTIONS: dict[ToolName, str] = {
    ToolName.FETCH_LINK: "リンク表の link_id で指したページを取得して文書に加える。URL は渡せない。",
    ToolName.HTTP_PROBE: "SUBMISSION_URL か link_id へ到達検査をして、ログイン壁などの観測を得る。",
    ToolName.RUN_CHECK: "要件 req_id に対応する決定論の検査（checker）を実行して観測を得る。値は検証済みの引用から取る。",
    ToolName.MARK_UNVERIFIABLE: (
        "前提が揃った要件を、理由コードつきの確認不能にする。reason_code は列挙された値だけ（NEEDS_AUTH・NEEDS_JS は前提の観測が要る）。"
        "検査できる要件は、検査が不確定だった時だけ。"
    ),
    ToolName.FINISH: "検査を終える。検査できる要件に未着手のものが残る間は拒否される。",
}


@dataclass(frozen=True)
class ToolResult:
    name: ToolName
    code: ObsCode | None = None  # Planner の次の StateView へ載る1語
    observation: Observation | None = None
    mark: UnverifiableMark | None = None
    finished: bool = False


def mark_unverifiable_schema(req_ids: "tuple[str, ...]" = ()) -> dict:
    """mark_unverifiable の引数スキーマ。reason_code を PLANNER_MARK_CODES の列挙に絞る（maxItems は llm_json_schema が除く）。"""
    schema = llm_json_schema(TOOL_ARG_MODELS[ToolName.MARK_UNVERIFIABLE])
    props = schema["properties"]
    props["reason_code"] = {"type": "string", "enum": sorted(c.value for c in PLANNER_MARK_CODES)}
    if req_ids:
        props["req_id"] = {"type": "string", "enum": list(req_ids)}
    return schema


_FETCH_CODE = {
    FetchOutcome.BLOCKED: ObsCode.BLOCKED,
    FetchOutcome.UNSUPPORTED_TYPE: ObsCode.UNSUPPORTED_TYPE,
    FetchOutcome.TOO_LARGE: ObsCode.ERROR,
    FetchOutcome.TIMEOUT: ObsCode.TRANSIENT,
    FetchOutcome.NETWORK_ERROR: ObsCode.TRANSIENT,
    FetchOutcome.TOO_MANY_REDIRECTS: ObsCode.ERROR,
}


class ToolRegistry:
    def __init__(
        self,
        *,
        state: RunState,
        governor: Governor,
        fetch: FetchPort,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._state = state
        self._gov = governor
        self._fetch = fetch
        self._sleep = sleep

    @staticmethod
    def declarations(allowed: "tuple[ToolName, ...]", *, mark_req_ids: "tuple[str, ...]" = ()) -> tuple[ToolDecl, ...]:
        """モデルへ渡す関数宣言。今ターンの許可リストに無い関数は宣言しない。

        mark_unverifiable の reason_code は、Planner が付けてよい理由（PLANNER_MARK_CODES）だけの列挙にする
        （契約の UnverifiableReason は12語あり、そのまま渡すとコード専用の理由（NO_EVIDENCE・BUDGET 等）を選べてしまい、
        Governor の CODE_ONLY で拒否され続ける＝10/7 のライブ実行で DEGRADED になった原因）。mark_req_ids を渡すと、
        req_id も印を付けられる要件（Governor.markable_reqs）の列挙に絞る。最終の判断は常に Governor がする。
        """
        out = []
        for n in allowed:
            if n is ToolName.MARK_UNVERIFIABLE:
                out.append(ToolDecl(name=n, description=TOOL_DESCRIPTIONS[n], parameters=mark_unverifiable_schema(mark_req_ids)))
            else:
                out.append(ToolDecl.for_tool(n, TOOL_DESCRIPTIONS[n]))
        return tuple(out)

    # ---- 実行 ----------------------------------------------------------------------------------
    async def execute(self, adm: Admission) -> ToolResult:
        if adm.call is None:
            raise ValueError("許可されていない呼び出しは実行できません")
        call = adm.call
        a = call.args
        if call.name is ToolName.FINISH:
            self._emit_result(call.name, None, None)
            return ToolResult(call.name, finished=True)
        if call.name is ToolName.MARK_UNVERIFIABLE:
            mark = UnverifiableMark(
                req_id=a.req_id, reason_code=a.reason_code, premise_obs_id=adm.premise_obs_id, by_planner=True  # type: ignore[union-attr]
            )
            self._state.marks[mark.req_id] = mark
            self._emit_result(call.name, None, mark.req_id, code=mark.reason_code.value)
            return ToolResult(call.name, mark=mark)
        if call.name is ToolName.RUN_CHECK:
            obs = self._run_check(a.checker, a.req_id)  # type: ignore[union-attr]
        elif call.name is ToolName.HTTP_PROBE:
            obs = await self._http_probe(a.target)  # type: ignore[union-attr]
        else:
            obs = await self._fetch_link(a.link_id)  # type: ignore[union-attr]
        ev = self._emit_result(call.name, obs, obs.req_id)
        obs = obs.model_copy(update={"event_seq": ev.seq})
        self._state.observations.append(obs)
        self._state.last_observation = obs.code
        return ToolResult(call.name, code=obs.code, observation=obs)

    def _emit_result(self, name: ToolName, obs: Observation | None, req_id: str | None, *, code: str | None = None):  # noqa: ANN202
        return self._gov.trace.emit(
            self._gov.phase,
            Actor.TOOL,
            TraceType.TOOL_RESULT,
            name=name.value,
            req_id=req_id,
            obs_id=obs.obs_id if obs else None,
            reason_code=(obs.code.value if obs else code),
            result_digest=digest(obs.model_dump(mode="json")) if obs else None,
        )

    # ---- run_check -----------------------------------------------------------------------------
    def _run_check(self, checker, req_id: str) -> Observation:  # noqa: ANN001
        st = self._state
        req = st.req(req_id)
        assert req is not None  # Governor が存在を確かめている
        obs_id = st.next_obs_id()
        ctx = CheckContext(docs=dict(st.docs), probes=st.probes(), target_doc_id=st.submission_doc_id)
        try:
            return run_checker(checker, req, ctx, obs_id)
        except NotImplementedError:
            why = "not_implemented"  # G3 の差し込み口（leak_scan・contains_terms）。確認不能の材料にする
        except Exception:  # noqa: BLE001  チェッカーの不具合で実行全体を落とさない（例外の中身は観測に載せない）
            why = "checker_error"
        return Observation(
            obs_id=obs_id,
            tool=ToolName.RUN_CHECK,
            checker=checker,
            req_id=req_id,
            code=ObsCode.ERROR,
            outcome=ObsOutcome.INCONCLUSIVE,
            facts={"why": why},
        )

    # ---- http_probe ----------------------------------------------------------------------------
    async def _http_probe(self, target: str) -> Observation:
        st = self._state
        href = st.preset.submission_url if target == "SUBMISSION_URL" else st.links[target].entry.href
        assert href is not None
        obs_id = st.next_obs_id()
        st.probed_targets.add(target)
        attempts = 1
        try:
            res = await http_probe(self._fetch, href, obs_id=obs_id, target=target, sleep=self._sleep)
            attempts = res.attempts
            return res.observation
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001  取得層の想定外は不確定の観測にする（classify の ErrorCode だけを残す）
            return Observation(
                obs_id=obs_id,
                tool=ToolName.HTTP_PROBE,
                code=ObsCode.ERROR,
                outcome=ObsOutcome.INCONCLUSIVE,
                facts={"target": target, "error": classify(e).value.lower()},
            )
        finally:
            self._gov.charge_fetches(FetchKind.HTTP_PROBE, attempts, href)

    # ---- fetch_link ----------------------------------------------------------------------------
    async def _fetch_link(self, link_id: str) -> Observation:
        st = self._state
        ref = st.links[link_id]
        href = ref.entry.href
        obs_id = st.next_obs_id()
        st.fetched_links.add(link_id)
        facts: dict[str, bool | int | str] = {"link": link_id}
        try:
            result: FetchResult = await self._fetch.fetch(FetchRequest(url=href))
        except asyncio.CancelledError:
            raise
        except AppError as e:
            code = ObsCode.BLOCKED if e.code is ErrorCode.FETCH_BLOCKED else ObsCode.TRANSIENT
            facts["error"] = e.code.value.lower()
            return self._obs(obs_id, code, facts)
        except Exception as e:  # noqa: BLE001
            facts["error"] = classify(e).value.lower()
            return self._obs(obs_id, ObsCode.ERROR, facts)
        finally:
            self._gov.charge_fetches(FetchKind.FETCH_LINK, 1, href)
        facts["outcome"] = result.outcome.value
        if result.status is not None:
            facts["status"] = result.status
        if result.outcome is not FetchOutcome.OK:
            return self._obs(obs_id, _FETCH_CODE.get(result.outcome, ObsCode.ERROR), facts)
        if result.content_kind is ContentKind.UNSUPPORTED:
            return self._obs(obs_id, ObsCode.UNSUPPORTED_TYPE, facts)
        parent_role = st.docs[ref.doc_id].role
        try:
            doc = sanitize(
                result,
                doc_id=st.next_doc_id(),
                role=DocRole.SUBMISSION if parent_role is DocRole.SUBMISSION else DocRole.SPEC,
                label=f"リンク先 {link_id}",
                scope=st.preset.allowed_prefixes,
            )
        except ValueError:
            return self._obs(obs_id, ObsCode.UNSUPPORTED_TYPE, facts)
        st.add_doc(doc)
        facts["doc"] = doc.doc_id
        facts["page_class"] = doc.page_class.value
        return self._obs(obs_id, ObsCode.OK, facts, passed=True)

    @staticmethod
    def _obs(obs_id: str, code: ObsCode, facts: dict[str, bool | int | str], *, passed: bool = False) -> Observation:
        return Observation(
            obs_id=obs_id,
            tool=ToolName.FETCH_LINK,
            code=code,
            outcome=ObsOutcome.PASS if passed else ObsOutcome.INCONCLUSIVE,
            facts=facts,
        )
