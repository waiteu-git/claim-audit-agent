"""T4（入口の洗浄）のテスト用の組み立て。合成 HTML → FetchResult → SanitizedDoc。"""
from collections.abc import Sequence

from app.contracts import ContentKind, DocRole, FetchOutcome, FetchResult, RedirectHop, SanitizedDoc, UrlPrefix
from app.ingest.sanitize import sanitize
from app.textsafe import BLOCK_SEP

HOST = "svc.example.invalid"
URL = f"https://{HOST}/page"
SCOPE: tuple[UrlPrefix, ...] = (UrlPrefix(host=HOST, path_prefix="/"),)


def fetch_result(
    body: str | bytes,
    *,
    status: int = 200,
    content_type: str = "text/html; charset=utf-8",
    kind: ContentKind | None = ContentKind.HTML,
    url: str = URL,
    final_url: str | None = None,
    redirects: Sequence[RedirectHop] = (),
    outcome: FetchOutcome = FetchOutcome.OK,
    truncated: bool = False,
) -> FetchResult:
    data = body.encode("utf-8") if isinstance(body, str) else body
    kw: dict = {}
    if truncated:
        from app.contracts import FetchLimit

        kw["limit_hit"] = FetchLimit.DECODED_SIZE
    return FetchResult(
        requested_url=url,
        final_url=final_url or url,
        redirects=tuple(redirects),
        outcome=outcome,
        status=status,
        headers={"content-type": content_type} if content_type else {},
        body=data,
        content_kind=kind,
        truncated=truncated,
        **kw,
    )


def san(html: str | bytes, *, role: DocRole = DocRole.SPEC, doc_id: str = "D1", label: str = "架空のページ", scope=SCOPE, **kw) -> SanitizedDoc:
    """HTML 文字列を直接 sanitize する（取得結果は 200・text/html）。status などは fetch_result を直接使う。"""
    return sanitize(fetch_result(html), doc_id=doc_id, role=role, label=label, scope=scope, **kw)


def blocks(doc: SanitizedDoc) -> list[str]:
    return doc.visible_text.split(BLOCK_SEP) if doc.visible_text else []


def kinds(doc: SanitizedDoc) -> set[str]:
    return {h.kind.value for h in doc.hidden}
