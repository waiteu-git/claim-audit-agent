"""cassette: ModelPort の記録・再生（テスト・評価用）。

record: 内側の ModelPort を呼んで応答を JSON へ保存する。replay: 要求の request_digest で保存済みの応答を返す。
保存するのは request_digest（要求の sha256）と応答だけで、プロンプト本文は保存しない。
ただし応答には第三者文書の引用が入りうるので、実文書で録った cassette はコミットしない（.gitignore の対象）。
"""
import json
import os
import tempfile
from pathlib import Path
from typing import Literal

from app.contracts import ModelRequest, ModelResponse
from app.model.port import ModelPort

CASSETTE_VERSION = 1


class CassetteMiss(AssertionError):
    """再生で、同じ要求の記録が無い（または使い切った）。プロンプトを変えたら録り直す。"""


class CassettePort:
    def __init__(
        self,
        path: Path | str,
        *,
        mode: Literal["record", "replay"],
        inner: ModelPort | None = None,
        model_id: str = "cassette-model",
    ) -> None:
        if mode == "record" and inner is None:
            raise ValueError("record には inner の ModelPort が要ります")
        self._path = Path(path)
        self._mode = mode
        self._inner = inner
        self._model_id = inner.model_id if inner is not None else model_id
        self._entries: list[dict[str, object]] = []
        self._used: dict[str, int] = {}
        if mode == "replay":
            data = json.loads(self._path.read_text(encoding="utf-8"))
            if data.get("version") != CASSETTE_VERSION:
                raise ValueError("cassette の版が違います")
            self._entries = list(data["entries"])

    @property
    def model_id(self) -> str:
        return self._model_id

    async def generate(self, request: ModelRequest) -> ModelResponse:
        key = request.request_digest()
        if self._mode == "replay":
            matches = [e for e in self._entries if e["key"] == key]
            i = self._used.get(key, 0)
            if i >= len(matches):
                raise CassetteMiss(f"記録なし: purpose={request.purpose.value} digest={key[:12]}")
            self._used[key] = i + 1
            return ModelResponse.model_validate(matches[i]["response"])
        assert self._inner is not None
        resp = await self._inner.generate(request)
        self._entries.append({"key": key, "purpose": request.purpose.value, "response": resp.model_dump(mode="json")})
        self._save()
        return resp

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self._path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"version": CASSETTE_VERSION, "entries": self._entries}, f, ensure_ascii=False, indent=1)
            os.replace(tmp, self._path)  # 書きかけを残さない
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
