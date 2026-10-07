"""StatePort の本番実装（Firestore）。quota.py の枠・予約・キルスイッチの保存先。

実接続はテストしない（オフライン）。コードだけ用意してある: クライアントは注入でき、既定の作り方（from_project）だけが
google-cloud-firestore を import する（requirements.txt に版を固定してある）。鍵ファイルは使わない（Cloud Run のサービスアカウント＝ADC）。

文書の鍵 `{env}/day/2026-10-15` は、Firestore のコレクション `claim_audit_state` の文書 ID（`/` は `__` に置き換える）にする。
transaction は Firestore のトランザクション（読み→書き。競合時は SDK が再試行）。同期の SDK を asyncio.to_thread で呼ぶ。
"""
import asyncio
from collections.abc import Callable, Sequence
from typing import Any

from app.quota import Docs

COLLECTION = "claim_audit_state"


def _doc_id(key: str) -> str:
    return key.replace("/", "__")


class FirestoreState:
    def __init__(self, client: Any, transactional: Callable[[Callable[..., Any]], Callable[..., Any]]) -> None:
        """client は google.cloud.firestore.Client、transactional は google.cloud.firestore.transactional（テストでは差し替え可能）。"""
        self._client = client
        self._transactional = transactional

    @classmethod
    def from_project(cls, project: str | None) -> "FirestoreState":  # pragma: no cover - 実接続（オフラインのテストでは呼ばない）
        from google.cloud import firestore

        return cls(firestore.Client(project=project), firestore.transactional)

    def _ref(self, key: str) -> Any:
        return self._client.collection(COLLECTION).document(_doc_id(key))

    def _transaction_sync(self, keys: Sequence[str], fn: Callable[[Docs], Docs]) -> Docs:
        refs = {k: self._ref(k) for k in keys}

        def body(tx: Any) -> Docs:
            current: Docs = {}
            for k, ref in refs.items():
                snap = ref.get(transaction=tx)
                current[k] = snap.to_dict() if snap.exists else None
            new = fn(current)
            for k, v in new.items():
                if k not in refs:
                    raise KeyError("transaction は読んだ文書にだけ書けます")
                if v is None:
                    tx.delete(refs[k])
                else:
                    tx.set(refs[k], v)
            return new

        return self._transactional(body)(self._client.transaction())

    async def transaction(self, keys: Sequence[str], fn: Callable[[Docs], Docs]) -> Docs:
        return await asyncio.to_thread(self._transaction_sync, list(keys), fn)

    async def get(self, key: str) -> dict[str, Any] | None:
        def read() -> dict[str, Any] | None:
            snap = self._ref(key).get()
            return snap.to_dict() if snap.exists else None

        return await asyncio.to_thread(read)
