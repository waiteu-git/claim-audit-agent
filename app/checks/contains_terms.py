"""contains_terms: 提出物の可視テキストに、要件が求める語（テストアカウントの案内・動画URL など）があるかを調べる（設計 §3・§4）。

G3（T9 後半）で実装する。ここは差し込み口だけ。実装時の取り決め（判定表 adjudicate.py が前提にしている形）:
  * 語は check_class（guidance_present／url_present）ごとの固定辞書（コード定数）。LLM もリクエストも語を決めない。
  * 見つかった時: checker=CONTAINS_TERMS・code=TERMS_FOUND・outcome=PASS・strong=False（語が在る証明であって内容の保証ではない）。
  * 無い時: code=TERMS_ABSENT・outcome=INCONCLUSIVE。不適合にするかは判定表が、文書の完全性
    （truncated=false・page_class=content）と要件の kind（必須）で決める。チェッカーは決めない。
  * doc_id は必ず付ける（判定表が文書の完全性を引く）。
  * 本文に INJECTION_PLACEHOLDER（注入疑いの置換記号）がある文書では TERMS_ABSENT を結論にしない（置換した区間に語があったかもしれない）。
    不確定（code=ERROR・outcome=INCONCLUSIVE・facts reason=masked_text）で返す。TERMS_FOUND は置換の外で見つかれば有効。
  * 判定表は、提出物（role=submission）の文書の観測だけを採り、「禁止」の要件にはこの検査を当てない（向きが逆）。
"""
from app.contracts import Observation, SanitizedDoc, VerifiedRequirement


def check_contains_terms(req: VerifiedRequirement, doc: SanitizedDoc, obs_id: str) -> Observation:
    raise NotImplementedError("contains_terms は G3（T9 後半）で実装する")
