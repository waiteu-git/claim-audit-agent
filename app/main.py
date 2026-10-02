"""疎通確認用の最小サービス。呼び出し上限とキルスイッチを最初から入れてある。"""
import os
import threading
import time
from collections import deque

from fastapi import FastAPI, HTTPException
from google import genai
from google.genai import types

PROJECT = os.environ["GOOGLE_CLOUD_PROJECT"]
LOCATION = os.environ.get("GEMINI_LOCATION", "global")
MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.7-flash")
MAX_CALLS_PER_HOUR = int(os.environ.get("MAX_LLM_CALLS_PER_HOUR", "60"))  # インスタンス単位
MAX_OUTPUT_TOKENS = int(os.environ.get("MAX_OUTPUT_TOKENS", "64"))

app = FastAPI(title="claim-audit-agent")
_calls: deque[float] = deque()
_lock = threading.Lock()
_client: genai.Client | None = None


def killed() -> bool:
    # 環境変数 KILL_SWITCH=1 で全モデル呼び出しを止める（`gcloud run services update --update-env-vars`）。
    return os.environ.get("KILL_SWITCH") == "1"


def take_slot() -> bool:
    now = time.monotonic()
    with _lock:
        while _calls and now - _calls[0] > 3600:
            _calls.popleft()
        if len(_calls) >= MAX_CALLS_PER_HOUR:
            return False
        _calls.append(now)
        return True


@app.get("/health")  # Cloud Run は /healthz を予約している（前段が404を返す）
def health():
    return {"ok": True, "killed": killed(), "model": MODEL}


@app.post("/probe")
def probe():
    global _client
    if killed():
        raise HTTPException(503, "kill switch is on")
    if not take_slot():
        raise HTTPException(429, "hourly call cap reached on this instance")
    if _client is None:
        _client = genai.Client(vertexai=True, project=PROJECT, location=LOCATION)
    r = _client.models.generate_content(
        model=MODEL,
        contents="「疎通OK」とだけ返してください。",
        config=types.GenerateContentConfig(max_output_tokens=MAX_OUTPUT_TOKENS),
    )
    u = r.usage_metadata
    return {"text": r.text, "model": MODEL, "tokens_in": u.prompt_token_count, "tokens_out": u.candidates_token_count}
