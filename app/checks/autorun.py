"""AUTORUN: 前提がコード判定で揃う検査を、Planner の呼び出しと無関係に必ず実行する（設計 §3。LLM 無し・費用 0）。

G3（T9 後半）で実装する。ここは差し込み口だけ。実装時の取り決め:
  * 提出URLの http_probe を1回、続けて text_length・auth_wall・leak_scan・cloud_run_signature・contains_terms を
    要件の check_class に応じて走らせる（registry.run_checker を使う）。観測は req_id 付きで返す。
  * 「検査を減らす」方向の Reader の出力（page_class=login_wall 等・必須→任意・role=login）は、コード裏取りと一致した時だけ採用する。
  * Planner の inspect_mode=router（T8）が同じ関数を共用する。
"""
from collections.abc import Callable, Sequence

from app.checks.registry import CheckContext
from app.contracts import FetchPort, Observation, VerifiedRequirement


async def autorun(
    requirements: Sequence[VerifiedRequirement],
    ctx: CheckContext,
    fetch: FetchPort,
    *,
    submission_url: str,
    next_obs_id: Callable[[], str],
) -> tuple[Observation, ...]:
    raise NotImplementedError("AUTORUN は G3（T9 後半）で実装する")
