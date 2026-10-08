"""repo_inspect: GitHub 公開リポジトリの固定ファイルから、事実だけを取り出す純関数（第7弾の土台）。

  detect_license(text | None) -> LicenseFact     LICENSE の有無と種類（SPDX の短い識別子。標準文の特徴的な語句で判定。迷ったら UNKNOWN）
  scan_readme(text | None) -> ReadmeFact         README の漏洩走査（leak_scan.scan_text をそのまま使う。種類ごとの件数だけ）と偽の命令の疑いの件数
  tech_traces(dockerfile, requirements)          Google Cloud の AI 関連の技術の痕跡が、どのファイルにあるか（固定の辞書）
  count_injection_suspicions(text | None) -> int ingest.inject_scan の定義で数えた偽の命令の疑いの件数（件数のみ。後で警告に使う）
  decode_repo_text(body) -> str                  取得したバイト列の読み（文字コードは ingest.sanitize.decode_body が唯一の定義）

**判定（適合・不適合）は書かない**。判定を書けるのは adjudicate.py だけで、ここは「何がどう在ったか」の事実を frozen な型で返す。
モデルは呼ばない・渡さない。README などの文面を読むのはこのコードだけで、見つけた文字列は結果に持たない（種類と件数だけ）。
外へ出る通信も保存もしない。入力の大きさは取得側が 256KB に抑えるが、ここでも走査は先頭 MAX_ANALYZE_CHARS 字までにする。
"""
import re
import unicodedata
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from app.checks.leak_scan import scan_text
from app.ingest.inject_scan import scan as scan_injection
from app.ingest.sanitize import decode_body

MAX_ANALYZE_CHARS = 300_000  # これを超える分は読まない（取得の上限 256KB より大きい。巨大な入力でも走査の時間を抑える）
MIN_LICENSE_CHARS = 20  # 正規化後（英数字の語だけ）でこれ未満は、読めるライセンス文ではない


class _Fact(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


def decode_repo_text(body: bytes) -> str:
    """取得したバイト列 → 文字列（BOM・charset の読みは decode_body に任せる。壊れた列は置換文字）。"""
    return decode_body(body[: MAX_ANALYZE_CHARS * 4], "text/plain")[:MAX_ANALYZE_CHARS]


# ---------------------------------------------------------------------------
# LICENSE
# ---------------------------------------------------------------------------
class LicenseKind(StrEnum):
    ABSENT = "ABSENT"  # ファイルが無い
    UNREADABLE = "UNREADABLE"  # 有るが、空・極端に短い
    UNKNOWN = "UNKNOWN"  # 有るが、種類を判定できない（迷った時もここ）
    MIT = "MIT"
    APACHE_2_0 = "Apache-2.0"
    BSD_2_CLAUSE = "BSD-2-Clause"
    BSD_3_CLAUSE = "BSD-3-Clause"
    GPL_2_0 = "GPL-2.0"
    GPL_3_0 = "GPL-3.0"
    LGPL_3_0 = "LGPL-3.0"
    AGPL_3_0 = "AGPL-3.0"
    MPL_2_0 = "MPL-2.0"
    ISC = "ISC"
    UNLICENSE = "Unlicense"


class LicenseFact(_Fact):
    present: bool
    kind: LicenseKind

    @property
    def identified(self) -> bool:
        """SPDX の識別子まで判定できた（ABSENT・UNREADABLE・UNKNOWN 以外）。"""
        return self.kind not in (LicenseKind.ABSENT, LicenseKind.UNREADABLE, LicenseKind.UNKNOWN)


def _words(text: str) -> str:
    """英数字の語だけを小文字・空白1個で連ねた形（引用符・改行・記号・全角の違いに左右されない）。"""
    flat = unicodedata.normalize("NFKC", text[:MAX_ANALYZE_CHARS]).casefold()
    return " ".join(re.findall(r"[a-z0-9]+", flat))


def _w(phrase: str) -> str:
    return _words(phrase)


# 各ライセンスの標準文の特徴的な語句（短い。全文は持たない）。ライセンスごとに「全部が在る」時だけ候補にする。
_MIT = tuple(
    _w(p)
    for p in (
        "Permission is hereby granted, free of charge, to any person obtaining a copy",
        "without restriction, including without limitation the rights",
        "The above copyright notice and this permission notice shall be included",
        "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND",
    )
)
_ISC = (
    _w("Permission to use, copy, modify, and/or distribute this software"),
    _w("with or without fee is hereby granted, provided that the above"),
)
_BSD_BASE = (
    _w("Redistribution and use in source and binary forms, with or without modification"),
    _w("are permitted provided that the following conditions are met"),
    _w("Redistributions of source code must retain the above copyright notice"),
    _w("Redistributions in binary form must reproduce the above copyright notice"),
)
_BSD3_EXTRA = _w("may be used to endorse or promote products derived from this software")
_BSD_ADVERTISING = _w("All advertising materials mentioning features")  # BSD-4: 3条項とは別物。見たら UNKNOWN
_APACHE = (
    _w("Apache License"),
    _w("Version 2.0, January 2004"),
    _w("TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION"),
)
_UNLICENSE = (
    _w("This is free and unencumbered software released into the public domain"),
    _w("Anyone is free to copy, modify, publish, use, compile, sell"),
)
_MPL = (
    _w("Mozilla Public License Version 2.0"),
    _w("Covered Software"),
    _w("means the form of the work preferred for making modifications"),
)
# GNU 系は表題（先頭付近）で族と版を決め、本文の特徴で確かめる。LGPL・AGPL の本文には GPL の名前が出るので、表題で分ける。
_GNU_HEAD_CHARS = 600
_GNU_TITLE = re.compile(r"gnu (affero |lesser |library )?general public license version (\d(?: \d)?)")
_GPL3_BODY = _w("is a free, copyleft license for software and other kinds of works")
_GPL2_BODY = _w("most software are designed to take away your freedom to share and change it")
_LGPL3_BODY = _w("incorporates the terms and conditions of version 3 of the")
_AGPL3_BODY = _w("Affero General Public License is a free, copyleft license")


def _has_all(words: str, phrases: tuple[str, ...]) -> bool:
    return all(p in words for p in phrases)


def _gnu_candidate(words: str) -> LicenseKind | None:
    head = words[:_GNU_HEAD_CHARS]
    m = _GNU_TITLE.search(head)
    if m is None:
        return None
    family, ver = (m.group(1) or "").strip(), m.group(2)
    if family == "" and ver.startswith("3") and _GPL3_BODY in words:
        return LicenseKind.GPL_3_0
    if family == "" and ver.startswith("2") and not ver.startswith("2 1") and _GPL2_BODY in words:
        return LicenseKind.GPL_2_0
    if family == "lesser" and ver.startswith("3") and _LGPL3_BODY in words:
        return LicenseKind.LGPL_3_0
    if family == "affero" and ver.startswith("3") and _AGPL3_BODY in words:
        return LicenseKind.AGPL_3_0
    return None


def detect_license(text: str | None) -> LicenseFact:
    """LICENSE の本文 → 有無と種類。部分一致の甘い判定はしない: 候補がちょうど1つに絞れない時、判定できない時は UNKNOWN。"""
    if text is None:
        return LicenseFact(present=False, kind=LicenseKind.ABSENT)
    words = _words(text)
    if len(words) < MIN_LICENSE_CHARS:
        return LicenseFact(present=True, kind=LicenseKind.UNREADABLE)
    found: list[LicenseKind] = []
    if _has_all(words, _MIT):
        found.append(LicenseKind.MIT)
    if _has_all(words, _ISC):
        found.append(LicenseKind.ISC)
    if _has_all(words, _BSD_BASE) and _BSD_ADVERTISING not in words:
        found.append(LicenseKind.BSD_3_CLAUSE if _BSD3_EXTRA in words else LicenseKind.BSD_2_CLAUSE)
    if _has_all(words, _APACHE):
        found.append(LicenseKind.APACHE_2_0)
    if _has_all(words, _UNLICENSE):
        found.append(LicenseKind.UNLICENSE)
    if _has_all(words, _MPL):
        found.append(LicenseKind.MPL_2_0)
    gnu = _gnu_candidate(words)
    if gnu is not None:
        found.append(gnu)
    kind = found[0] if len(found) == 1 else LicenseKind.UNKNOWN  # 0 件も 2 件以上（二重ライセンス・引用）も UNKNOWN
    return LicenseFact(present=True, kind=kind)


# ---------------------------------------------------------------------------
# README
# ---------------------------------------------------------------------------
class ReadmeFact(_Fact):
    present: bool
    leak_counts: tuple[tuple[str, int], ...] = ()  # (leak_scan.LEAK_PATTERNS の種類名, 件数)。名前順。見つけた文字列は持たない
    injection_suspicions: int = 0  # ingest.inject_scan の定義で数えた偽の命令の疑い（件数のみ）

    @property
    def leak_total(self) -> int:
        return sum(n for _, n in self.leak_counts)


_LEAK_CHUNK_CHARS = 1024  # leak_scan の email・service_url の正規表現は、区切りの無い長い連なりで入力長の2乗かかる（20,000字で数秒）


def _leak_chunks(text: str):  # noqa: ANN202
    """走査の塊。行（改行）単位でまとめ、長い行は空白で、空白の無い長い語は固定長で切る。漏洩の1件（メール・URL・鍵の見出し）は
    数百字以内なので、通常の README では塊の境目をまたがない。2乗の時間を、塊の長さの2乗 × 塊の数に抑える。"""
    buf: list[str] = []
    size = 0
    for line in text.split("\n"):
        if len(line) > _LEAK_CHUNK_CHARS:
            if buf:
                yield "\n".join(buf)
                buf, size = [], 0
            piece = ""
            for token in re.split(r"(\s+)", line):
                while len(token) > _LEAK_CHUNK_CHARS:  # 空白の無い長い語は固定長で切る（境目をまたぐ1件は拾えない＝既知の限界）
                    if piece:
                        yield piece
                        piece = ""
                    yield token[:_LEAK_CHUNK_CHARS]
                    token = token[_LEAK_CHUNK_CHARS:]
                if len(piece) + len(token) > _LEAK_CHUNK_CHARS and piece:
                    yield piece
                    piece = ""
                piece += token
            if piece:
                yield piece
            continue
        if size + len(line) + 1 > _LEAK_CHUNK_CHARS and buf:
            yield "\n".join(buf)
            buf, size = [], 0
        buf.append(line)
        size += len(line) + 1
    if buf:
        yield "\n".join(buf)


def _leak_counts(text: str) -> dict[str, int]:
    """leak_scan.scan_text（定義はそのまま）を塊ごとに呼んで足す。"""
    total: dict[str, int] = {}
    for chunk in _leak_chunks(text):
        for kind, n in scan_text(chunk).items():
            total[kind] = total.get(kind, 0) + n
    return total


def count_injection_suspicions(text: str | None) -> int:
    """偽の命令の疑いの件数（ingest.inject_scan.scan の検知の数。近接する一致は1件）。文面は書き換えない・返さない。"""
    if not text:
        return 0
    return len(scan_injection(text[:MAX_ANALYZE_CHARS]))


def scan_readme(text: str | None) -> ReadmeFact:
    if text is None:
        return ReadmeFact(present=False)
    body = text[:MAX_ANALYZE_CHARS]
    counts = _leak_counts(body)
    return ReadmeFact(
        present=True,
        leak_counts=tuple(sorted(counts.items())),
        injection_suspicions=count_injection_suspicions(body),
    )


# ---------------------------------------------------------------------------
# 技術の痕跡（Google Cloud の AI 関連）
# ---------------------------------------------------------------------------
# PEP 503 で正規化したパッケージ名（小文字・. _ - の連なりは - 1個）の固定辞書。小さく保守的に: 別名や関連しそうな名前は足さない。
TECH_PACKAGES: frozenset[str] = frozenset(
    {
        "google-genai",
        "google-generativeai",
        "google-cloud-aiplatform",
        "vertexai",
        "google-adk",
    }
)
REQUIREMENTS_FILE = "requirements.txt"
DOCKERFILE = "Dockerfile"

_REQ_NAME = re.compile(r"([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)")
# 要件名の直後に来てよい文字。URL（"https:" の ":"）・パスの "/"・"+"（git+https）・名前に続く "." などは含めない＝名前でない行は拾わない。
_REQ_AFTER = frozenset(" \t[=<>!~;@,")


def _canon(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirement_name(spec: str) -> str | None:
    """1つの要件指定（"google-genai[x]>=1 ; marker" など）の行頭の名前。名前の形でない・URL・オプションは None。"""
    spec = spec.strip().strip("\"'")
    if not spec or spec.startswith(("-", "#", ".", "/", "~")):
        return None
    m = _REQ_NAME.match(spec)
    if m is None:
        return None
    if m.end() < len(spec) and spec[m.end()] not in _REQ_AFTER:
        return None  # "https://…"・"git+https://…"・"google-genai/x" など。名前の直後が要件の書式でない
    return _canon(m.group(1))


def _requirement_hits(text: str | None) -> frozenset[str]:
    if not text:
        return frozenset()
    hits: set[str] = set()
    for raw in text[:MAX_ANALYZE_CHARS].splitlines():
        line = re.split(r"(?:^|\s)#", raw, maxsplit=1)[0].strip()  # 行頭または空白の後ろの # 以降はコメント（URL の #egg= は空白が無いので残る）
        name = _requirement_name(line)
        if name in TECH_PACKAGES:
            hits.add(name)
    return frozenset(hits)


_PIP_INSTALL = re.compile(r"(?:^|[\s;&|(])(?:python[\d.]*\s+-m\s+)?(?:uv\s+)?pip[\d.]*\s+install\b", re.I)
_SHELL_SPLIT = re.compile(r"&&|\|\||[;|]")


def _dockerfile_run_lines(text: str) -> list[str]:
    """継続行（行末の \\）をつないだ上で、RUN 命令の本体を返す（コメント行は読まない）。"""
    logical: list[str] = []
    buf = ""
    for raw in text[:MAX_ANALYZE_CHARS].splitlines():
        stripped = raw.strip()
        if not buf and stripped.startswith("#"):
            continue
        if buf and stripped.startswith("#"):
            continue  # 継続行の途中のコメント行（Dockerfile では無視される）
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        logical.append(buf + stripped)
        buf = ""
    if buf:
        logical.append(buf)
    out = []
    for ln in logical:
        m = re.match(r"RUN\s+(.*)", ln, re.I | re.S)
        if m:
            out.append(m.group(1))
    return out


def _dockerfile_hits(text: str | None) -> frozenset[str]:
    if not text:
        return frozenset()
    hits: set[str] = set()
    for body in _dockerfile_run_lines(text):
        for part in _SHELL_SPLIT.split(body):
            m = _PIP_INSTALL.search(part)
            if m is None:
                continue
            for token in part[m.end() :].split():
                name = _requirement_name(token)
                if name in TECH_PACKAGES:
                    hits.add(name)
    return frozenset(hits)


class TechTraceFact(_Fact):
    """技術の痕跡が在ったパッケージ名（辞書の正規化名）を、見つかったファイルごとに持つ。"""

    in_requirements: tuple[str, ...] = ()
    in_dockerfile: tuple[str, ...] = ()

    @property
    def packages(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.in_requirements) | set(self.in_dockerfile)))

    @property
    def files_by_package(self) -> dict[str, tuple[str, ...]]:
        out: dict[str, tuple[str, ...]] = {}
        for pkg in self.packages:
            files = tuple(f for f, names in ((DOCKERFILE, self.in_dockerfile), (REQUIREMENTS_FILE, self.in_requirements)) if pkg in names)
            out[pkg] = files
        return out


def tech_traces(dockerfile: str | None, requirements: str | None) -> TechTraceFact:
    return TechTraceFact(
        in_requirements=tuple(sorted(_requirement_hits(requirements))),
        in_dockerfile=tuple(sorted(_dockerfile_hits(dockerfile))),
    )
