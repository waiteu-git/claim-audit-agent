"""要項モード（第11弾）の入口の検証: 利用者が入れた公開ページの URL を受けるかどうか（取得・読み取りはしない）。

  parse_spec_url(text) -> SpecRef   受けるのは `https://` の公開ホスト名の URL だけ。失敗は AppError(INVALID_INPUT)（固定文）。

受けないもの: http・ポートの指定（:443 も含む）・userinfo・IP アドレスの直書き（v4 の10進・16進・8進・短縮形、v6 の角括弧）・
localhost・単一ラベルのホスト・.local／.internal／.localhost／.localdomain／.home.arpa・フラグメント（`#`）・空白や制御文字・
2048字超。クエリは受ける（ログには出さない）。

ホスト・パスの形の検査は net.urlcheck.validate_url が唯一の定義（S3 の SafeFetch も同じ関数で検査し直す＝入口と S3 で割れない）。
ここで足すのは「入口ではポートの指定も受けない」「フラグメントを黙って捨てずに拒否する」だけ。受けた URL は正規化した形
（SpecRef.url）だけを先へ渡す。S3 の規則（contracts.OpenPageScope）は、この正規形の文字列だけを通す。

入力の文字列は、応答・ログ・例外の原因連鎖に入れない（github_repo.parse_repo_url と同じ注意。例外は except の外で、原因を付けずに投げる）。
ログに出すのは正規化した URL の sha256 の先頭12桁だけ（spec_log_id）。
"""
import hashlib

from app.errors import AppError, ErrorCode
from app.net.urlcheck import UrlRejected, validate_url

MAX_SPEC_URL_LENGTH = 2048


class SpecRef:
    """検証済みの URL（正規化した形）。repr・str に URL を出さない。"""

    __slots__ = ("_url",)

    def __init__(self, url: str) -> None:
        self._url = url

    @property
    def url(self) -> str:
        return self._url

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SpecRef) and other._url == self._url

    def __hash__(self) -> int:
        return hash(self._url)

    def __repr__(self) -> str:
        return f"SpecRef(<{spec_log_id(self)}>)"

    __str__ = __repr__


def spec_log_id(ref: SpecRef) -> str:
    """ログ用の識別子: 正規化した URL の sha256 の先頭12桁（URL そのものはログに出さない）。"""
    return hashlib.sha256(ref.url.encode("utf-8")).hexdigest()[:12]


def _invalid() -> AppError:
    return AppError(ErrorCode.INVALID_INPUT)  # 自由文は作らない（detail も空）


def _shape_ok(text: object) -> str | None:
    """受けてよければ正規化した URL、だめなら None。例外は外へ出さない（原因連鎖に入力を残さない）。"""
    if not isinstance(text, str) or not text or len(text) > MAX_SPEC_URL_LENGTH:
        return None
    if not text.startswith("https://") or "#" in text:
        return None
    authority = text[len("https://") :].split("/", 1)[0].split("?", 1)[0]
    if ":" in authority or "@" in authority or "[" in authority:  # ポートの指定・userinfo・IPv6 の直書き
        return None
    try:
        normalized = validate_url(text, max_length=MAX_SPEC_URL_LENGTH)
    except UrlRejected:
        return None
    return normalized.url


def parse_spec_url(text: object) -> SpecRef:
    """公開ホスト名の https URL だけを受ける。それ以外は AppError(INVALID_INPUT)。"""
    url = _shape_ok(text)
    if url is None:
        raise _invalid()
    return SpecRef(url)
