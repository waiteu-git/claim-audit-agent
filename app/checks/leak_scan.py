"""leak_scan: 提出物の可視テキストに、公開してはいけない文字列（鍵形式・メール・内部ホスト等）が混入していないかを走査する（設計 §4）。

G3（T9 後半）で実装する。ここは差し込み口だけ（呼び出し側が import できる関数シグネチャ）。実装時の取り決め:
  * 走査対象と正規表現の集合は、設計 §7 の egress_filter と「同じ集合」を1か所に定義して共有する（契約監査の指摘）。
  * 観測は checker=LEAK_SCAN・code=LEAK_FOUND（不適合・強）／NO_LEAK（適合・強）。見つけた文字列そのものは facts に載せない
    （種類と件数だけ）。判定表（adjudicate）は、文書が打切り・非 content の時の「漏洩なし」を適合にしない。
  * 本文に INJECTION_PLACEHOLDER（注入疑いの置換記号）がある文書では NO_LEAK を結論にしない（置換した区間に鍵やメールを
    隠せる）。不確定（code=ERROR・outcome=INCONCLUSIVE・facts reason=masked_text）で返す。LEAK_FOUND は置換の外で見つかれば有効。
"""
from collections.abc import Sequence

from app.contracts import Observation, SanitizedDoc, VerifiedRequirement


def check_leak_scan(req: VerifiedRequirement, docs: Sequence[SanitizedDoc], obs_id: str) -> Observation:
    raise NotImplementedError("leak_scan は G3（T9 後半）で実装する")
