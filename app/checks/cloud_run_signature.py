"""cloud_run_signature: 提出物が Cloud Run で動いているかを、http_probe の観測から読む（設計 §3 runtime_signature・§9 デモ①）。

署名 = Cloud Run の既定ドメイン（run.app 系）で応答していて、応答ヘッダが Google Frontend を示すこと。
http_probe が真偽の印だけを facts に残している（ホスト名そのものは残さない。設計 §7 の漏洩防止）ので、ここでは再取得しない。

  * 両方ある（かつ応答が 2xx/3xx）    → SIGNATURE_PRESENT（適合・強）
      4xx/5xx は対象外: 存在しないサービスの 404 や IAM の 403 も Google Frontend が返すので、「動いている」の証拠にならない。
  * 片方だけ／どちらも無い            → SIGNATURE_ABSENT（不確定）。署名が無いことは Cloud Run でない証明ではない
      （独自ドメインや CDN の背後の Cloud Run は、どちらも見えない）ので、不適合にはしない。
  * 取得できていない（一時失敗・拒否・種別）→ その観測のコードを引き継ぐ（不確定）。
  * 結論つきの観測どうしで署名の材料が食い違う（1回目は run.app で 200、2回目は 403 など）→ 不確定（reason=probe_conflict）。

限界: 署名は「応答したホストが Cloud Run の既定ドメインで、Google Frontend の応答だった」ことだけを示す。他人の Cloud Run サービス
（提出物は別の場所で動いていて、run.app 側は転送だけ）でも立つ。提出物そのものが Cloud Run で動くことの証明ではない。
"""
from collections.abc import Sequence

from app.checks.probe_facts import TARGET_SUBMISSION, fact_bool, select_probe, signature_flips
from app.contracts import Checker, Observation, ObsCode, ObsOutcome, ToolName, VerifiedRequirement

# 署名の判断に使えない（応答が無い）観測。コードを引き継いで不確定にする
_NO_RESPONSE_CODES = frozenset({ObsCode.TRANSIENT, ObsCode.BLOCKED, ObsCode.UNSUPPORTED_TYPE})


def _obs(
    req: VerifiedRequirement,
    obs_id: str,
    code: ObsCode,
    outcome: ObsOutcome,
    facts: dict[str, bool | int | str],
    *,
    strong: bool = False,
) -> Observation:
    return Observation(
        obs_id=obs_id,
        tool=ToolName.RUN_CHECK,
        checker=Checker.CLOUD_RUN_SIGNATURE,
        req_id=req.req_id,
        code=code,
        outcome=outcome,
        strong=strong,
        facts=facts,
    )


def check_cloud_run_signature(
    req: VerifiedRequirement,
    probes: Sequence[Observation],
    obs_id: str,
    *,
    target: str = TARGET_SUBMISSION,
) -> Observation:
    probe = select_probe(probes, target)
    if probe is None:
        return _obs(req, obs_id, ObsCode.ERROR, ObsOutcome.INCONCLUSIVE, {"target": target, "reason": "no_probe"})
    if signature_flips(probes, target):  # 署名の材料が観測ごとに違う。最新の観測だけで「署名あり」と言わない
        return _obs(req, obs_id, ObsCode.ERROR, ObsOutcome.INCONCLUSIVE, {"target": target, "reason": "probe_conflict"})
    if probe.code in _NO_RESPONSE_CODES:
        return _obs(req, obs_id, probe.code, ObsOutcome.INCONCLUSIVE, {"target": target, "reason": "no_response"})
    host_sig = fact_bool(probe, "run_app_host")
    gfe = fact_bool(probe, "gfe")
    facts: dict[str, bool | int | str] = {"target": target, "run_app_host": host_sig, "gfe": gfe}
    status = probe.facts.get("status")
    served = False
    if isinstance(status, int) and not isinstance(status, bool):
        facts["status"] = status
        served = 200 <= status < 400
    if host_sig and gfe and served:
        return _obs(req, obs_id, ObsCode.SIGNATURE_PRESENT, ObsOutcome.PASS, facts, strong=True)
    return _obs(req, obs_id, ObsCode.SIGNATURE_ABSENT, ObsOutcome.INCONCLUSIVE, facts)
