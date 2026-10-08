"""GitHub 公開リポジトリの入口の検証と、固定ファイルの取得（第7弾の土台。配線・判定・画面は含まない）。

  parse_repo_url(text) -> RepoRef   受けるのは `https://github.com/<owner>/<repo>`（末尾 `/` 1つまで）だけ。失敗は INVALID_INPUT。
  raw_file_url(ref, name) -> str    取得先 `https://raw.githubusercontent.com/<owner>/<repo>/HEAD/<固定名>` を、検証済みの RepoRef と
                                    固定名（contracts.REPO_FILE_NAMES）から**私たちが組み立てる**（利用者の文字列を直接使わない）。
  fetch_repo_files(ref, port)       固定ファイルを FetchPort（S2 では S3 へのクライアント）で取る。結果は取得できた／無い（404）／
                                    回数制限（429）／一時的な失敗／許可外／使えない（大きさ・種別・バイナリ）を区別して持つ。

owner / repo の形と固定名は contracts に1つだけ定義がある（S3 の許可規則 RepoRawScope.matches も同じ関数を使う＝入口と S3 で割れない）。
S3 は S2 から来た要求を信用せず、自分で形を検査し直す。ここ（呼び出し側）でも、結果が契約どおりか（転送を経ていない・大きさ・NUL）を
もう一度確かめる。トークンは受け取らない・預からない（未認証で取れる公開リポジトリだけ。非公開は 404 になり、存在しないのと区別できない）。

ログにはリポ名を出さない（`owner/repo` の sha256 の先頭12桁だけ）。取得した中身は保存しない・ログに出さない（repr にも出さない）。
取得した本文はバイト列のまま返す。文字コードの読みは ingest.sanitize.decode_body が唯一の定義なので、文字列にするのは checks 側
（repo_inspect.decode_repo_text）で行う。
"""
import hashlib
import re
from dataclasses import dataclass, field
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator

from app.config import FETCH_LIMITS, FetchLimits
from app.contracts import (
    GITHUB_RAW_HOST,
    GITHUB_RAW_REF,
    REPO_FILE_NAMES,
    ContentKind,
    FetchOutcome,
    FetchPort,
    FetchRequest,
    FetchResult,
    is_github_owner,
    is_github_repo,
)
from app.errors import AppError, ErrorCode
from app.jsonlog import log_event

MAX_REPO_URL_LENGTH = 2048
# 非公開のリポジトリは未認証だと 404（存在しないのと区別できない）。区別せず、この固定文だけを画面に出す。
PUBLIC_REPO_ONLY_MESSAGE = "公開リポジトリのURLだけ対応しています。"

# 先頭から末尾まで ASCII の許可文字だけ。全角・互換文字・キリル文字などは、この文字クラスに入らないので NFKC の前に落ちる。
# fullmatch なので末尾の改行も通らない（`$` の落とし穴を避ける）。この正規表現は「どこまでが owner と repo か」を切り出すだけで、
# 形の定義は contracts.is_github_owner / is_github_repo が唯一（RepoRef の検証と S3 の規則が同じ関数を使う）。
_REPO_URL = re.compile(
    r"https://github\.com/(?P<owner>[A-Za-z0-9][A-Za-z0-9-]*)/(?P<repo>[A-Za-z0-9._-]+)/?",
)


def _invalid() -> AppError:
    return AppError(ErrorCode.INVALID_INPUT)  # 自由文は作らない（detail も空。入力の文字列をログにも残さない）


class RepoRef(BaseModel):
    """検証済みの owner / repo。作れた時点で contracts の定義に合っている（手で作っても同じ検査を通る）。"""

    model_config = ConfigDict(frozen=True, extra="forbid")

    owner: str
    repo: str

    @field_validator("owner")
    @classmethod
    def _owner(cls, v: str) -> str:
        if not is_github_owner(v):
            raise ValueError("owner の形ではありません")
        return v

    @field_validator("repo")
    @classmethod
    def _repo(cls, v: str) -> str:
        if not is_github_repo(v):
            raise ValueError("repo の形ではありません")
        return v

    def __repr__(self) -> str:  # 例外・ログにリポ名を出さない
        return f"RepoRef(<{repo_log_id(self)}>)"

    __str__ = __repr__


def repo_log_id(ref: RepoRef) -> str:
    """ログ用の識別子: `owner/repo` の sha256 の先頭12桁（リポ名そのものはログに出さない）。"""
    return hashlib.sha256(f"{ref.owner}/{ref.repo}".encode()).hexdigest()[:12]


def parse_repo_url(text: str) -> RepoRef:
    """`https://github.com/<owner>/<repo>`（末尾 `/` 1つまで）だけを受ける。それ以外は AppError(INVALID_INPUT)。"""
    if not isinstance(text, str) or not text or len(text) > MAX_REPO_URL_LENGTH:
        raise _invalid()
    m = _REPO_URL.fullmatch(text)
    if m is None:
        raise _invalid()
    try:
        return RepoRef(owner=m["owner"], repo=m["repo"])
    except ValueError as e:  # 長さ・末尾ハイフン・"." ".." ".git" 終わり
        raise _invalid() from e


def raw_file_url(ref: RepoRef, name: str) -> str:
    """取得先 URL。owner / repo は検証済みの RepoRef、name は固定名のどれかだけ（それ以外は ValueError）。"""
    if name not in REPO_FILE_NAMES:
        raise ValueError("固定名ではありません")
    return f"https://{GITHUB_RAW_HOST}/{ref.owner}/{ref.repo}/{GITHUB_RAW_REF}/{name}"


# ---------------------------------------------------------------------------
# 取得
# ---------------------------------------------------------------------------
class RepoFileStatus(StrEnum):
    FOUND = "found"  # 取得できた（本文あり）
    NOT_FOUND = "not_found"  # 404（無い。非公開のリポも同じになる）
    RATE_LIMITED = "rate_limited"  # 429（GitHub の回数制限）
    TRANSIENT = "transient"  # 5xx・通信の失敗・タイムアウト（一時的）
    REJECTED = "rejected"  # 許可外（3xx・403 などの想定外の状態・S3 の拒否・転送を経た応答）
    UNUSABLE = "unusable"  # 取れたが使えない（1ファイル・合計の上限超・text/plain でない・NUL を含む）
    SKIPPED = "skipped"  # 取得しなかった（回数制限の後・件数の上限）


# 状態の強さ。同じ種類の候補（README.md と README など）の結果を1つにまとめる時、強い方を採る（FOUND は別扱いで最優先）。
_SEVERITY = {
    RepoFileStatus.NOT_FOUND: 0,
    RepoFileStatus.SKIPPED: 1,
    RepoFileStatus.UNUSABLE: 2,
    RepoFileStatus.REJECTED: 3,
    RepoFileStatus.TRANSIENT: 4,
    RepoFileStatus.RATE_LIMITED: 5,
}


@dataclass(frozen=True)
class RepoFile:
    """固定名1つの結果。本文はバイト列のまま（repr に出さない）。"""

    name: str
    status: RepoFileStatus
    body: bytes = field(default=b"", repr=False)


@dataclass(frozen=True)
class RepoFetchResult:
    """README・LICENSE・Dockerfile・requirements.txt それぞれの結果（種類ごとに1つ）。取れなかった種類も状態を持つ。"""

    readme: RepoFile
    license: RepoFile
    dockerfile: RepoFile
    requirements: RepoFile
    requests_made: int = 0
    bytes_total: int = 0

    @property
    def files(self) -> tuple[RepoFile, ...]:
        return (self.readme, self.license, self.dockerfile, self.requirements)

    @property
    def nothing_found(self) -> bool:
        """4種類すべてが「無い（404）」。非公開のリポ・存在しないリポ・空のリポは区別できないので、固定文 1つで返す。"""
        return all(f.status is RepoFileStatus.NOT_FOUND for f in self.files)


def classify_result(result: FetchResult, url: str, limits: FetchLimits = FETCH_LIMITS) -> RepoFileStatus:
    """FetchResult → 状態。S3 を信用しすぎず、転送を経た応答・上限超・NUL・種別も呼び出し側で確かめる。"""
    o = result.outcome
    if o is FetchOutcome.OK:
        if result.redirects or (result.final_url is not None and result.final_url != url):
            return RepoFileStatus.REJECTED  # 転送は追わない規則。3xx と、転送を経た応答は使わない
        status = result.status or 0
        if status == 404:
            return RepoFileStatus.NOT_FOUND
        if status == 429:
            return RepoFileStatus.RATE_LIMITED
        if status >= 500:
            return RepoFileStatus.TRANSIENT
        if status != 200:
            return RepoFileStatus.REJECTED  # 3xx・403・その他の 4xx・204 など
        if (
            result.truncated
            or (result.content_kind is not ContentKind.PLAIN and (result.body or result.content_kind is not None))  # 空の本文は種別なしでよい
            or len(result.body) > limits.repo_max_file_bytes
            or b"\x00" in result.body
        ):
            return RepoFileStatus.UNUSABLE
        return RepoFileStatus.FOUND
    if o in (FetchOutcome.TIMEOUT, FetchOutcome.NETWORK_ERROR):
        return RepoFileStatus.TRANSIENT
    if o in (FetchOutcome.TOO_LARGE, FetchOutcome.UNSUPPORTED_TYPE):
        return RepoFileStatus.UNUSABLE
    return RepoFileStatus.REJECTED  # blocked・too_many_redirects


class _Budget:
    """1実行の件数と合計バイト数。取得の要求ごとに数える（404 も 1件）。"""

    def __init__(self, limits: FetchLimits) -> None:
        self._limits = limits
        self.requests = 0
        self.bytes = 0

    def may_request(self) -> bool:
        return self.requests < self._limits.repo_max_files

    def count_request(self) -> None:
        self.requests += 1

    def try_add(self, size: int) -> bool:
        if self.bytes + size > self._limits.repo_max_total_bytes:
            return False
        self.bytes += size
        return True


# 種類 → 候補の名前（先に見つかったものを使う）
_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("readme", ("README.md", "README")),
    ("license", ("LICENSE", "LICENSE.md", "LICENSE.txt")),
    ("dockerfile", ("Dockerfile",)),
    ("requirements", ("requirements.txt",)),
)


async def fetch_repo_files(ref: RepoRef, port: FetchPort, *, limits: FetchLimits = FETCH_LIMITS) -> RepoFetchResult:
    """固定ファイルを順に取る（直列。ツリーの一覧・github.com の画面・REST API は使わない）。

    429 を受けたら残りは取らない（SKIPPED）。件数（repo_max_files）に達したら残りは取らない。合計（repo_max_total_bytes）を
    超える本文は UNUSABLE にして捨てる。例外は出さない（想定内の失敗は RepoFileStatus）。
    """
    budget = _Budget(limits)
    chosen: dict[str, RepoFile] = {}
    stop = False
    for kind, names in _GROUPS:
        best: RepoFile | None = None
        for name in names:
            if stop or not budget.may_request():
                cand = RepoFile(name, RepoFileStatus.SKIPPED)
            else:
                url = raw_file_url(ref, name)
                budget.count_request()
                result = await port.fetch(FetchRequest(url=url))
                st = classify_result(result, url, limits)
                if st is RepoFileStatus.FOUND and not budget.try_add(len(result.body)):
                    st = RepoFileStatus.UNUSABLE  # 合計の上限超
                if st is RepoFileStatus.RATE_LIMITED:
                    stop = True
                cand = RepoFile(name, st, result.body if st is RepoFileStatus.FOUND else b"")
            if cand.status is RepoFileStatus.FOUND:
                best = cand
                break
            if best is None or _SEVERITY[cand.status] > _SEVERITY[best.status]:
                best = cand
        assert best is not None
        chosen[kind] = best
    out = RepoFetchResult(**chosen, requests_made=budget.requests, bytes_total=budget.bytes)
    log_event(
        "github_repo.fetched",
        repo=repo_log_id(ref),
        requests=budget.requests,
        bytes=budget.bytes,
        statuses={f.name: f.status.value for f in out.files},
    )
    return out
