"""RunState: 1実行の作業状態（文書・リンク表・要件・観測・確認不能の印）。Governor・ToolRegistry・Planner・Reader が共有する。

ここにあるのは事実の入れ物と、事実からの導出（要件の状態・検査できるか）だけ。許可・拒否は governor.py、取得や検査の実行は tools.py。

リンク表: SanitizedDoc ごとに L1… が振られているので、文書をまたぐと衝突する。実行の作業状態では全文書を通した通し番号
（L1…。LinkId は L999 まで）に振り直し、どの文書のどのリンクかを LinkRef で持つ。fetch_link(link_id) は通し番号だけを受ける。
"""
from dataclasses import dataclass, field

from app.checks.class_screen import quote_supports_class
from app.contracts import (
    CHECK_CLASS_CHECKER,
    CheckClass,
    DocMeta,
    DocRole,
    Kind,
    LinkEntry,
    Observation,
    ObsCode,
    ObsOutcome,
    Preset,
    ReqState,
    SanitizedDoc,
    ToolName,
    UnverifiableMark,
    VerifiedRequirement,
)

MAX_GLOBAL_LINKS = 200


@dataclass(frozen=True)
class LinkRef:
    entry: LinkEntry  # link_id は実行を通した通し番号
    doc_id: str  # このリンクを載せていた文書
    origin_link_id: str  # 文書内の元の番号


@dataclass
class RunState:
    preset: Preset
    docs: dict[str, SanitizedDoc] = field(default_factory=dict)
    links: dict[str, LinkRef] = field(default_factory=dict)
    requirements: list[VerifiedRequirement] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    marks: dict[str, UnverifiableMark] = field(default_factory=dict)
    fetched_links: set[str] = field(default_factory=set)
    probed_targets: set[str] = field(default_factory=set)
    req_calls: dict[str, int] = field(default_factory=dict)
    last_observation: ObsCode | None = None
    submission_doc_id: str | None = None
    unread_doc_ids: set[str] = field(default_factory=set)  # Reader が読み切れなかった spec 文書
    capped: bool = False  # 要件の件数上限で落としたものがある
    _obs_n: int = 0
    _doc_n: int = 0

    # ---- 採番 ---------------------------------------------------------------------------------
    def next_obs_id(self) -> str:
        self._obs_n += 1
        return f"O{self._obs_n}"

    def next_doc_id(self) -> str:
        """未使用の doc_id（外から add_doc された文書と衝突しない。衝突すると既存の文書を黙って上書きしてしまう）。"""
        self._doc_n += 1
        while f"D{self._doc_n}" in self.docs:
            self._doc_n += 1
        return f"D{self._doc_n}"

    # ---- 文書・リンク -------------------------------------------------------------------------
    def add_doc(self, doc: SanitizedDoc) -> None:
        self.docs[doc.doc_id] = doc
        if doc.role is DocRole.SUBMISSION and self.submission_doc_id is None:
            self.submission_doc_id = doc.doc_id
        for lk in doc.links:
            if len(self.links) >= MAX_GLOBAL_LINKS:
                break
            gid = f"L{len(self.links) + 1}"
            self.links[gid] = LinkRef(lk.model_copy(update={"link_id": gid}), doc.doc_id, lk.link_id)

    def links_of(self, doc_id: str) -> list[LinkRef]:
        return [r for r in self.links.values() if r.doc_id == doc_id]

    def doc_metas(self) -> tuple[DocMeta, ...]:
        """本文を持たない文書のメタ。Reader が読み切れなかった spec 文書は truncated にする（判定表が打切りとして扱う）。"""
        out = []
        for d in self.docs.values():
            m = d.meta()
            if d.doc_id in self.unread_doc_ids and not m.truncated:
                m = m.model_copy(update={"truncated": True})
            out.append(m)
        return tuple(out)

    # ---- 要件 ---------------------------------------------------------------------------------
    def req(self, req_id: str) -> VerifiedRequirement | None:
        for r in self.requirements:
            if r.req_id == req_id:
                return r
        return None

    def probes(self) -> tuple[Observation, ...]:
        return tuple(o for o in self.observations if o.tool is ToolName.HTTP_PROBE)

    def check_observations(self, req_id: str) -> list[Observation]:
        return [o for o in self.observations if o.req_id == req_id and o.tool is ToolName.RUN_CHECK]

    def req_state(self, req: VerifiedRequirement) -> ReqState:
        """推測は検査しないので done。印がある・結論つきの検査の観測がある要件も、これ以上の呼び出しは要らない。"""
        if req.kind is Kind.SPECULATIVE:
            return ReqState.DONE
        if req.req_id in self.marks:
            return ReqState.UNVERIFIABLE
        if any(o.outcome is not ObsOutcome.INCONCLUSIVE for o in self.check_observations(req.req_id)):
            return ReqState.DONE
        return ReqState.OPEN

    def is_checkable(self, req: VerifiedRequirement) -> bool:
        """検査の種類があり、引用がその話題に触れている（判定表の関門と同じ関数）。推測・引用なしは検査できない。"""
        if req.kind is Kind.SPECULATIVE or req.span is None:
            return False
        if CHECK_CLASS_CHECKER[req.check_class] is None:
            return False
        return quote_supports_class(req.check_class, req.span.original_span)

    def can_run_check(self, req: VerifiedRequirement) -> bool:
        """今この実行で run_check が意味のある観測を返せるか。検査できる要件でも、材料（提出URL・提出物の文書）が無ければ
        チェッカーは ERROR を返すだけなので、Planner には手順として出さない（10/7 のライブ実行: ERROR の run_check）。"""
        if not self.is_checkable(req):
            return False
        if req.check_class in (CheckClass.AUTH_WALL, CheckClass.RUNTIME_SIGNATURE):
            return bool(self.preset.submission_url)
        return self.submission_doc_id is not None

    def calls_used(self, req_id: str) -> int:
        return self.req_calls.get(req_id, 0)
