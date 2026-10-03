"""引用検証器（設計 §5-1。差別化の核）。モデルが返した原文引用を、コードが逐語で照合する。

VerificationSeal を発行できるのはこのパッケージだけ（tests/test_layout.py が固定）。
  - normalize: 正規化と原文オフセットの復元表
  - index: DocIndex（照合・長さ規則・省略記号・ambiguous・crosses_block・注入区間）
  - sentence: snap_to_sentence
  - semantics: 否定・例外語と kind のコード側クロスチェック
  - checker: QuoteChecker（昇格・降格・最終再検証）

敵対レビュー（tests/test_quotes_adversarial.py）で、「検証済みなのに意味が逆」になる入力（否定された義務語・疑問文・
仮定・条件・導入文だけの要件・文書をまたぐ例外）と、最終再検証のすり抜けを見つけて塞いである。語彙は vocab.py の1か所。
"""
from app.quotes.checker import (
    PendingRequote,
    QuoteChecker,
    QuoteOutcome,
    ReverifyFailure,
    ReverifyIssue,
    ReverifyResult,
)
from app.quotes.index import DocHits, DocIndex, Rejected, Verified
from app.quotes.sentence import next_sentence_head, snap_to_sentence

__all__ = [
    "DocHits",
    "DocIndex",
    "PendingRequote",
    "QuoteChecker",
    "QuoteOutcome",
    "Rejected",
    "ReverifyFailure",
    "ReverifyIssue",
    "ReverifyResult",
    "Verified",
    "next_sentence_head",
    "snap_to_sentence",
]
