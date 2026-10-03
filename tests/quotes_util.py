"""引用検証器のテスト用の組み立て関数。文章はすべて合成した架空のもの。"""
from app.contracts import InjectionSignal, Kind, RawRequirement, SanitizedDoc
from app.quotes import DocIndex, QuoteChecker
from app.textsafe import BLOCK_SEP as SEP
from tests.factories import make_doc


def blocks(*bs: str) -> str:
    """ブロックを境界 U+001E でつないだ可視テキスト（sanitize の出力の形）。"""
    return SEP.join(bs)


def doc(*bs: str, doc_id: str = "D1", **kw) -> SanitizedDoc:
    return make_doc(doc_id, blocks(*bs), **kw)


def index(*docs: SanitizedDoc) -> DocIndex:
    return DocIndex(docs)


def checker(*docs: SanitizedDoc) -> QuoteChecker:
    return QuoteChecker(DocIndex(docs))


def raw(quote: str, kind: Kind = Kind.REQUIRED, **kw) -> RawRequirement:
    return RawRequirement(quote=quote, kind=kind, **kw)


def injection(doc_id: str, start: int, end: int, pattern_id: str = "inj.test") -> InjectionSignal:
    return InjectionSignal(pattern_id=pattern_id, doc_id=doc_id, visible=True, start=start, end=end)
