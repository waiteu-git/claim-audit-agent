"""リポジトリの基本点検（第10弾）: 固定ファイルを取り、事実を取り出し、固定3項目をコードが判定する。

  audit_repo(ref, port) -> RepoAuditOutcome   結果（RepoAuditResult）か、結果にならない失敗の ErrorCode のどちらか

流れ: github_repo.fetch_repo_files（固定名だけ）→ repo_inspect（事実だけ。README などの中身を読むのはこのコードだけ）→ adjudicate.adjudicate_repo。
モデルは呼ばない・渡さない（このモジュールは model を import しない）。リポの文面・URL は結果にもログにも持ち込まない（種類と件数だけ）。
Planner がファイルを選ぶ形・要項の要件への結びつけは、ここにはない（今後）。
"""
from dataclasses import dataclass

from app.adjudicate import RepoFacts, adjudicate_repo
from app.checks.repo_inspect import decode_repo_text, detect_license, scan_readme, tech_traces
from app.contracts import FetchPort, RepoAuditResult
from app.errors import ErrorCode
from app.github_repo import RepoFile, RepoFileStatus, RepoFetchResult, RepoRef, fetch_repo_files

_NAMES = ("README", "LICENSE", "Dockerfile", "requirements.txt")


@dataclass(frozen=True)
class RepoAuditOutcome:
    result: RepoAuditResult | None = None
    error: ErrorCode | None = None  # result が無い時の理由（固定文は errors.PUBLIC_MESSAGES）


def _text(f: RepoFile) -> str | None:
    return decode_repo_text(f.body) if f.status is RepoFileStatus.FOUND else None


def failure_code(fetched: RepoFetchResult) -> ErrorCode | None:
    """1つも取れなかった時の、画面に出す固定文の種類。1つでも取れていれば None（項目ごとの確認不能で示す）。

    非公開・存在しない・空のリポは 404 で区別できないので、同じ REPO_PUBLIC_ONLY にする。
    """
    sts = {f.status for f in fetched.files}
    if RepoFileStatus.FOUND in sts:
        return None
    if sts == {RepoFileStatus.NOT_FOUND}:
        return ErrorCode.REPO_PUBLIC_ONLY
    if RepoFileStatus.RATE_LIMITED in sts:
        return ErrorCode.REPO_RATE_LIMITED
    if RepoFileStatus.REJECTED in sts:
        return ErrorCode.REPO_UNAVAILABLE  # S3 が規則を持たない（GITHUB_RAW_ENABLED なし）・許可外
    if RepoFileStatus.TRANSIENT in sts:
        return ErrorCode.FETCH_FAILED
    return None  # 大きすぎる・テキストでない・取得しなかった: 取れていないことを項目ごとの確認不能で示す


async def audit_repo(ref: RepoRef, port: FetchPort) -> RepoAuditOutcome:
    fetched = await fetch_repo_files(ref, port)
    code = failure_code(fetched)
    if code is not None:
        return RepoAuditOutcome(error=code)
    readme, lic, docker, reqs = (_text(f) for f in fetched.files)
    statuses = {name: f.status.value for name, f in zip(_NAMES, fetched.files, strict=True)}
    facts = RepoFacts(
        statuses=statuses,
        license=detect_license(lic) if statuses["LICENSE"] in ("found", "not_found") else None,
        readme=scan_readme(readme) if readme is not None else None,
        tech=tech_traces(docker, reqs),
    )
    return RepoAuditOutcome(result=adjudicate_repo(facts))
