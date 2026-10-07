"""保存済みの実行記録（REPLAY）の復元。RunRecord.restore は VerificationSeal を要るので、印を発行できるこのパッケージに置く。

使い道は公開面の REPLAY（同梱した実行記録の再生）だけ。復元できるのは、記録した時点で REPORT の最終再検証
（QuoteChecker.reverify）を通った要件だけ: span のある要件は reverified=True でなければ拒否する
（原文は保存しないので、ここで再検証はできない。記録の時点の検証を条件にする）。
"""
from app.contracts import RunRecord, VerificationSeal

_REPLAY_SEAL = VerificationSeal.issue("app.quotes.replay")


class ReplayRecordError(ValueError):
    """保存済みの記録が再生の条件を満たさない。"""


def restore_saved_record(text: str | bytes) -> RunRecord:
    """JSON → RunRecord。契約の検証（RunRecord の不変条件）に加え、引用つきの要件が最終再検証済みであることを求める。"""
    record = RunRecord.restore_json(text, seal=_REPLAY_SEAL)
    for r in record.requirements:
        if r.span is not None and not r.reverified:
            raise ReplayRecordError("最終再検証を通っていない引用を含む記録は再生しません")
    return record
