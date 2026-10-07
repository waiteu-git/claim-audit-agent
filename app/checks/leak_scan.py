"""leak_scan: 提出物の可視テキストに、公開してはいけない文字列（鍵形式・メール・内部ホスト等）が混入していないかを走査する（設計 §4）。

走査対象の正規表現の集合（LEAK_PATTERNS）はここ1か所に置く。公開面の漏洩 CI（tests/test_public_surface.py ほか）も同じ集合を使い、
UI・フィクスチャ・同梱のリプレイに鍵・メール・内部URLが載っていないことを確かめる（設計 §7 の egress_filter と同じ集合）。

観測の形（判定表 adjudicate.py が前提にしている）:
  * 見つかった: checker=LEAK_SCAN・code=LEAK_FOUND・outcome=FAIL・strong=True。facts は種類ごとの件数だけ
    （見つけた文字列そのものは載せない）。doc_id は最初に見つかった文書。
  * 見つからない: code=NO_LEAK・outcome=PASS・strong=True。doc_id は検査した本文の文書（判定表が打切り・非 content を確認不能にする）。
  * 本文に INJECTION_PLACEHOLDER（注入疑いの置換記号）がある文書があれば NO_LEAK を結論にしない（置換した区間に鍵やメールを
    隠せる）。不確定（code=ERROR・outcome=INCONCLUSIVE・facts reason=masked_text）。LEAK_FOUND は置換の外で見つかれば有効。
  * 検査する本文は page_class=content の提出物の文書（リンク先のログイン画面などは「無い」の根拠にしない。見つかれば不適合には採る）。
走査は NFKC に畳んでから行う（全角の＠・英数で形を崩してすり抜けさせない）。
"""
import re
import unicodedata
from collections.abc import Sequence

from app.contracts import (
    INJECTION_PLACEHOLDER,
    Checker,
    Observation,
    ObsCode,
    ObsOutcome,
    PageClass,
    SanitizedDoc,
    ToolName,
    VerifiedRequirement,
)

_I = re.IGNORECASE
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"

# 種類 → 正規表現。種類名は facts のキー（^[a-z][a-z0-9_]{0,31}$）にそのまま使う。
LEAK_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}"),
    # サーバーレス実行環境のサービスの直URL（公開説明文に載せると、フロントを経ない入口・内部の構成が出る）
    "service_url": re.compile(r"\b[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)*\.run" + r"\.app\b", _I),
    "service_account": re.compile(r"\.iam\.gserviceaccount\.com\b", _I),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "oauth_token": re.compile(r"\bya29\.[0-9A-Za-z_\-]{20,}"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}"),
    "aws_key_id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # 非公開のIPアドレス（10/8・172.16/12・192.168/16・100.64/10）
    "private_ip": re.compile(
        r"(?<![\d.])(?:10\." + _OCTET + r"|172\.(?:1[6-9]|2\d|3[01])|192\.168|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7]))"
        r"\." + _OCTET + r"\." + _OCTET + r"(?![\d.])"
    ),
}


def scan_text(text: str) -> dict[str, int]:
    """文字列 → 種類ごとの件数（0件の種類は含めない）。公開面の漏洩 CI もこれを使う。"""
    flat = unicodedata.normalize("NFKC", text)
    out: dict[str, int] = {}
    for name, pat in LEAK_PATTERNS.items():
        n = len(pat.findall(flat))
        if n:
            out[name] = n
    return out


def _obs(req: VerifiedRequirement, obs_id: str, code: ObsCode, outcome: ObsOutcome, *, doc_id: str | None = None,
         strong: bool = False, facts: dict | None = None) -> Observation:  # fmt: skip
    return Observation(
        obs_id=obs_id,
        tool=ToolName.RUN_CHECK,
        checker=Checker.LEAK_SCAN,
        req_id=req.req_id,
        doc_id=doc_id,
        code=code,
        outcome=outcome,
        strong=strong,
        facts=facts or {},
    )


def check_leak_scan(req: VerifiedRequirement, docs: Sequence[SanitizedDoc], obs_id: str) -> Observation:
    if not docs:
        return _obs(req, obs_id, ObsCode.ERROR, ObsOutcome.INCONCLUSIVE, facts={"reason": "no_submission_doc"})
    total: dict[str, int] = {}
    first_hit: str | None = None
    for d in docs:
        hits = scan_text(d.visible_text)
        if hits and first_hit is None:
            first_hit = d.doc_id
        for k, n in hits.items():
            total[k] = total.get(k, 0) + n
    if first_hit is not None:
        facts: dict = {k: min(n, 99) for k, n in sorted(total.items())}
        facts["count"] = min(sum(total.values()), 999)
        return _obs(req, obs_id, ObsCode.LEAK_FOUND, ObsOutcome.FAIL, doc_id=first_hit, strong=True, facts=facts)
    if any(INJECTION_PLACEHOLDER in d.visible_text for d in docs):
        return _obs(req, obs_id, ObsCode.ERROR, ObsOutcome.INCONCLUSIVE, facts={"reason": "masked_text"})
    body = [d for d in docs if d.page_class is PageClass.CONTENT]
    if not body:
        return _obs(req, obs_id, ObsCode.ERROR, ObsOutcome.INCONCLUSIVE, doc_id=docs[0].doc_id, facts={"reason": "no_content_doc"})
    truncated = next((d for d in body if d.truncated), None)
    target = truncated or body[0]  # 打切りの文書があればそれを指す（判定表が TRUNCATED の確認不能にする）
    return _obs(req, obs_id, ObsCode.NO_LEAK, ObsOutcome.PASS, doc_id=target.doc_id, strong=True, facts={"docs": len(body)})
