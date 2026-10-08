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
import json
import re
import unicodedata
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.checks.leak_scan import LEAK_PATTERNS, scan_text
from app.ingest.inject_scan import scan as scan_injection
from app.ingest.sanitize import decode_body

MAX_ANALYZE_CHARS = 300_000  # これを超える分は読まない（取得の上限 256KB より大きい。巨大な入力でも走査の時間を抑える）
MIN_LICENSE_CHARS = 20  # 正規化後（英数字の語だけ）でこれ未満は、読めるライセンス文ではない


class _Fact(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


def decode_repo_text(body: bytes) -> str:
    """取得したバイト列 → 文字列。壊れた列は置換文字。

    これらのファイルは HTML ではなく、持ち主が自由に書ける。Content-Type に charset を付けて渡し、本文の `<meta charset=…>` を読ませない
    （charset 無しだと decode_body は先頭 1,024 バイトの meta を読み、`replacement` 系の宣言1行で本文全体が U+FFFD 1文字になる＝
    漏洩・偽の命令・技術の痕跡・ライセンスの事実を持ち主が1行で空にできる）。BOM（UTF-8・UTF-16）だけは decode_body が先に読む。
    """
    return decode_body(body[: MAX_ANALYZE_CHARS * 4], "text/plain; charset=utf-8")[:MAX_ANALYZE_CHARS]


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

    @model_validator(mode="after")
    def _consistent(self) -> "LicenseFact":
        if self.present == (self.kind is LicenseKind.ABSENT):
            raise ValueError("ABSENT は present=False の時だけ")
        return self

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


# 各ライセンスの標準文の特徴的な語句（80字未満の短い断片。全文は持たない）。「全部が在る」ことが候補の条件で、さらに次の3つを全部満たした時だけ
# 確定する（迷ったら UNKNOWN。持ち主が標準文に1行足す・標準文を引用しただけの別文書を、標準ライセンスと言い切らないため）:
#   1. 標準文の本体（先頭の語句から末尾まで）の語数が、実在の標準文の最大の語数に少しの余裕を足した上限以内（足された条件・追記を弾く）
#   2. 本体の前に在るのは、題名と著作権行ぐらいの短い文だけ（長い前置き・「以下は参考」型の文を弾く）
#   3. 短い許諾型（MIT・ISC・BSD・Unlicense）では、追加条件・適用範囲の限定を示す語（_FOREIGN）が無い
# 上限は実在の LICENSE（MIT 163 語・BSD-2 184〜186 語・BSD-3 213〜230 語・Apache 1,426〜1,608 語・MPL 2,426 語・GPL-2 2,989 語・
# GPL-3 5,700 語・LGPL-3 1,241 語。いずれも英数字の語の数）に基づく。ISC（約105語）・Unlicense（約120語）・AGPL-3.0 は実文が手元に無いので、
# 記憶に基づく概算で置いた（実文で確かめるまで、変種は UNKNOWN 側に倒れうる。AGPL-3.0 は GPL-3 より緩い）。
_MIT = tuple(
    _w(p)
    for p in (
        "Permission is hereby granted, free of charge, to any person obtaining a copy",
        "without restriction, including without limitation the rights",
        "The above copyright notice and this permission notice shall be included",
        "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND",
    )
)
_ISC_PERMISSION = _w("Permission to use, copy, modify")
_ISC = (
    _w("Permission to use, copy, modify"),
    _w("distribute this software for any purpose"),
    _w("with or without fee is hereby granted, provided that the above"),
)
_BSD_BASE = (
    _w("Redistribution and use in source and binary forms, with or without modification"),
    _w("are permitted provided that the following conditions are met"),
    _w("Redistributions of source code must retain the above copyright notice"),
    _w("Redistributions in binary form must reproduce the above copyright notice"),
)
_BSD3_CLAUSE = (
    _w("Neither the name of"),
    _w("nor the names of its contributors may be used to endorse or promote products"),
    _w("derived from this software without specific prior written permission"),
)
# 3条項目の別の書き方・特許条項・宣伝条項など。BSD-2 と言い切れなくなる語（これらが在れば BSD-2-Clause とは言わない）
_BSD2_FORBIDDEN = re.compile(r"\b(?:endorse|promote|neither|nor the names?|advertis\w*|patents?|trademarks?)\b")
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
# 短い許諾型が「追加条件・限定つき」であることを示す語。標準の MIT・ISC・BSD・Unlicense の本文には現れない。
_FOREIGN = re.compile(
    r"\b(?:not licensed|reference|only|applies|apply|except|exceptions?|either|dual|at your option|additional|commons clause|"
    r"you may not|may not|must not|not be used|prohibit\w*|forbidden|may not sell|evil|patents?|trademarks?|third party|bundled|dependenc\w*|proprietary|commercial)\b"
)

# GNU 系は表題（題名＋版＋日付）で族と版を決め、本文の特徴で確かめる。表題は本文の**どこに在っても**数える（先頭だけを見ると、
# 後ろに GPL の全文を付けた二重ライセンスの文書を単独の別ライセンスと言ってしまう）。LGPL・AGPL の本文には GPL の名前が出るが、
# 日付つきの表題は出ないので、表題で分けられる。表題が在るのに対応表に無い版（LGPL-2.1・GPL-1 など）は、UNKNOWN にする。
_GNU_TITLES = {
    _w("GNU General Public License Version 3, 29 June 2007"): (LicenseKind.GPL_3_0, _w("is a free, copyleft license for software and other kinds of works")),
    _w("GNU General Public License Version 2, June 1991"): (LicenseKind.GPL_2_0, _w("most software are designed to take away your freedom to share and change it")),
    _w("GNU Lesser General Public License Version 3, 29 June 2007"): (LicenseKind.LGPL_3_0, _w("incorporates the terms and conditions of version 3 of the")),
    _w("GNU Affero General Public License Version 3, 19 November 2007"): (LicenseKind.AGPL_3_0, _w("Affero General Public License is a free, copyleft license")),
}  # fmt: skip
_MONTHS = "january|february|march|april|may|june|july|august|september|october|november|december"
# 日付つき＝表題。MPL などが「GNU General Public License, Version 2.0」と版名を参照しているだけの文は、日付が付かないので表題に数えない
_GNU_ANY_TITLE = re.compile(rf"\bgnu (?:affero |lesser |library )?general public license version \d(?: \d)? (?:\d{{1,2}} )?(?:{_MONTHS}) \d{{4}}")
_PREFIX_MAX_WORDS = 45  # 本体の前に許す語数（題名・著作権行）。実在の最大は 43
_PREFIX_TITLE_WORDS = 8  # 題名だけなら、著作権行が無くてよい

# 種類 → (本体の先頭の語句, 本体の語数の上限, 短い許諾型か)。上限 = 実在の最大 + 少しの余裕
_BODY_LIMITS = {
    LicenseKind.MIT: 168,
    LicenseKind.ISC: 115,
    LicenseKind.BSD_2_CLAUSE: 192,
    LicenseKind.BSD_3_CLAUSE: 220,
    LicenseKind.UNLICENSE: 125,
    LicenseKind.APACHE_2_0: 1_650,
    LicenseKind.MPL_2_0: 2_480,
    LicenseKind.GPL_2_0: 3_040,
    LicenseKind.GPL_3_0: 5_780,
    LicenseKind.LGPL_3_0: 1_290,
    LicenseKind.AGPL_3_0: 6_000,
}
_SHORT_PERMISSIVE = frozenset({LicenseKind.MIT, LicenseKind.ISC, LicenseKind.BSD_2_CLAUSE, LicenseKind.BSD_3_CLAUSE, LicenseKind.UNLICENSE})


def _has_all(words: str, phrases: tuple[str, ...]) -> bool:
    return all(p in words for p in phrases)


def _isc_text(words: str) -> bool:
    # 原文には "and/or distribute" と "and distribute" の両方の書き方がある
    return _has_all(words, _ISC) and ("modify and or distribute" in words or "modify and distribute" in words)


def _confirmed(words: str, kind: LicenseKind, anchor: str) -> bool:
    """候補の種類を、本体の語数・前置き・追加条件の語で確かめる（3つとも満たした時だけ True）。"""
    i = words.find(anchor)
    if i < 0:
        return False
    prefix = words[:i].split()
    body = words[i:].split()
    if len(body) > _BODY_LIMITS[kind] or len(prefix) > _PREFIX_MAX_WORDS:
        return False
    if len(prefix) > _PREFIX_TITLE_WORDS and "copyright" not in prefix:
        return False
    return not (kind in _SHORT_PERMISSIVE and _FOREIGN.search(words))


def detect_license(text: str | None) -> LicenseFact:
    """LICENSE の本文 → 有無と種類。確信できる時だけ確定の識別子を返す。候補がちょうど1つに絞れない・確かめを満たさない時は UNKNOWN。"""
    if text is None:
        return LicenseFact(present=False, kind=LicenseKind.ABSENT)
    words = _words(text)
    if len(words) < MIN_LICENSE_CHARS:
        return LicenseFact(present=True, kind=LicenseKind.UNREADABLE)
    found: list[LicenseKind] = []  # 標準文の語句が揃った候補（確かめの結果に依らない）
    sure: list[LicenseKind] = []  # そのうち確かめを満たしたもの
    candidates: list[tuple[LicenseKind, str]] = []
    if _has_all(words, _MIT):
        candidates.append((LicenseKind.MIT, _MIT[0]))
    if _isc_text(words):
        candidates.append((LicenseKind.ISC, _ISC_PERMISSION))
    if _has_all(words, _BSD_BASE):
        if _has_all(words, _BSD_BASE + _BSD3_CLAUSE) and not re.search(r"\b(?:advertis\w*|patents?|trademarks?)\b", words):
            candidates.append((LicenseKind.BSD_3_CLAUSE, _BSD_BASE[0]))
        elif not _BSD2_FORBIDDEN.search(words):
            candidates.append((LicenseKind.BSD_2_CLAUSE, _BSD_BASE[0]))
        else:
            found.append(LicenseKind.UNKNOWN)  # BSD の変種（宣伝条項・別の3条項目・特許条項）。BSD-2/3 と言い切らない
    if _has_all(words, _APACHE):
        candidates.append((LicenseKind.APACHE_2_0, _APACHE[0]))
    if _has_all(words, _UNLICENSE):
        candidates.append((LicenseKind.UNLICENSE, _UNLICENSE[0]))
    if _has_all(words, _MPL):
        candidates.append((LicenseKind.MPL_2_0, _MPL[0]))
    titles = 0
    for title, (kind, body_marker) in _GNU_TITLES.items():
        n = words.count(title)
        titles += n
        if n and body_marker in words:
            candidates.append((kind, title))
        elif n:
            found.append(LicenseKind.UNKNOWN)  # 表題だけで本文の特徴が無い
    if len(_GNU_ANY_TITLE.findall(words)) > titles:
        found.append(LicenseKind.UNKNOWN)  # 対応表に無い GNU の版（LGPL-2.1・GPL-1 など）の表題が在る
    for kind, anchor in candidates:
        found.append(kind)
        if _confirmed(words, kind, anchor):
            sure.append(kind)
    kind = sure[0] if len(found) == 1 and len(sure) == 1 else LicenseKind.UNKNOWN  # 0 件・2 件以上・確かめ不成立は UNKNOWN
    return LicenseFact(present=True, kind=kind)


# ---------------------------------------------------------------------------
# README
# ---------------------------------------------------------------------------
class ReadmeFact(_Fact):
    present: bool
    leak_counts: tuple[tuple[str, Annotated[int, Field(ge=1)]], ...] = ()  # (leak_scan.LEAK_PATTERNS の種類名, 件数)。名前順。見つけた文字列は持たない
    injection_suspicions: int = Field(default=0, ge=0)  # ingest.inject_scan の定義で数えた偽の命令の疑い（件数のみ）

    @model_validator(mode="after")
    def _kinds(self) -> "ReadmeFact":
        # 持てるのは辞書にある種類名と数だけ（リポの文面が型に入り込む経路を作らない）
        names = [k for k, _ in self.leak_counts]
        if any(k not in LEAK_PATTERNS for k in names) or len(set(names)) != len(names):
            raise ValueError("leak_counts の種類名は LEAK_PATTERNS のものを1度ずつ")
        if not self.present and (self.leak_counts or self.injection_suspicions):
            raise ValueError("README が無いのに件数は持てません")
        return self

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
    """leak_scan.scan_text（定義はそのまま）を塊ごとに呼んで足す。

    private_key の見出しだけは空白を含み、塊の境目で切れうる。この正規表現は線形なので、全体に掛けて数える
    （パターンは leak_scan.LEAK_PATTERNS のもの。NFKC に畳むのも scan_text と同じ）。他の種類は空白を含まないので塊に分けてよい。
    """
    total: dict[str, int] = {}
    for chunk in _leak_chunks(text):
        for kind, n in scan_text(chunk).items():
            if kind != "private_key":
                total[kind] = total.get(kind, 0) + n
    n_key = len(LEAK_PATTERNS["private_key"].findall(unicodedata.normalize("NFKC", text)))
    if n_key:
        total["private_key"] = n_key
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


# 命令の先頭が pip install（python -m pip・uv pip・sudo 付きも）か uv add のときだけ、引数を要件として読む。
# `echo pip install x`・`apt-get install x`・`pip download x` は読まない（先頭の語で決める）。
_PIP_START = re.compile(r"\s*(?:sudo\s+)?(?:(?:python[\d.]*|py)\s+-m\s+)?(?:(?:uv\s+)?pip[\d.]*\s+install|uv\s+add)\b", re.I)
_SHELL_SPLIT = re.compile(r"&&|\|\||[;|&]")
# 値を1つ取るオプション（その値を要件として読まない: `--target vertexai` の vertexai はディレクトリ名）
_PIP_VALUE_OPTIONS = frozenset({
    "-r", "--requirement", "-c", "--constraint", "-t", "--target", "--prefix", "--root", "-i", "--index-url", "--extra-index-url",
    "-f", "--find-links", "--platform", "--python-version", "--implementation", "--abi", "--cache-dir", "--src", "--upgrade-strategy",
    "--only-binary", "--no-binary", "-e", "--editable", "--python", "-p", "--config-settings", "-C",
})  # fmt: skip


def _strip_shell_comment(line: str) -> str:
    """引用符の外で、行頭または空白の直後の # から後ろを捨てる（シェルのコメント）。"""
    quote = ""
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i]
    return line


def _dockerfile_run_lines(text: str) -> list[str]:
    """継続行（行末の \\）をつないだ上で、RUN 命令（ONBUILD RUN も）の本体を返す。コメント行は読まない。

    読まないもの（既知の限界。「痕跡なし」は「無い」と同じではない）: ヒアドキュメントの RUN・変数経由の指定・COPY した別ファイルの中身。
    """
    logical: list[str] = []
    buf = ""
    for raw in text[:MAX_ANALYZE_CHARS].splitlines():
        stripped = raw.strip()
        if stripped.startswith("#"):
            continue  # コメント行（継続行の途中でも Dockerfile は無視する。行末の \\ も継続にしない）
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        logical.append(buf + stripped)
        buf = ""
    if buf:
        logical.append(buf)
    out = []
    for ln in logical:
        m = re.match(r"(?:ONBUILD\s+)?RUN\s+(.*)", ln, re.I | re.S)
        if not m:
            continue
        body = m.group(1).strip()
        if body.startswith("["):  # exec 形式 RUN ["pip", "install", "x"]
            try:
                parts = json.loads(body)
            except ValueError:
                continue
            if not isinstance(parts, list) or not all(isinstance(x, str) for x in parts):
                continue
            body = " ".join(parts)
        while body.startswith("--"):  # RUN --mount=… などのフラグ
            body = body.partition(" ")[2].lstrip()
        out.append(body)
    return out


def _dockerfile_hits(text: str | None) -> frozenset[str]:
    if not text:
        return frozenset()
    hits: set[str] = set()
    for body in _dockerfile_run_lines(text):
        for part in _SHELL_SPLIT.split(_strip_shell_comment(body)):
            m = _PIP_START.match(part)
            if m is None:
                continue
            skip = False
            for token in part[m.end() :].split():
                if skip:
                    skip = False
                    continue
                if token in _PIP_VALUE_OPTIONS:
                    skip = True
                    continue
                name = _requirement_name(token)
                if name in TECH_PACKAGES:
                    hits.add(name)
    return frozenset(hits)


class TechTraceFact(_Fact):
    """技術の痕跡が在ったパッケージ名（辞書の正規化名）を、見つかったファイルごとに持つ。"""

    in_requirements: tuple[str, ...] = ()
    in_dockerfile: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _only_dictionary_names(self) -> "TechTraceFact":
        for names in (self.in_requirements, self.in_dockerfile):
            if any(n not in TECH_PACKAGES for n in names) or len(set(names)) != len(names):
                raise ValueError("痕跡のパッケージ名は TECH_PACKAGES の正規化名を1度ずつ")
        return self

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
