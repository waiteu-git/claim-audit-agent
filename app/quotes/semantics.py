"""「検証済みなのに意味が逆」を防ぐ判定（設計 §5-1 否定・例外語／kind のコード側クロスチェック）。

逐語一致は「その文が原文に実在する」証明であって、解釈の保証ではない。引用が文の途中（否定語・「ただし」・
「〜を除く」の手前）で切れていれば、一致していても意味は逆になる。ここで文脈を見て、怪しければ推測へ落とす。
落とす側に倒す（検証済みの表示を出さない）。

否定・例外語の走査（設計の規則を、引用と文の位置関係で書き直した形）:
  (A) 拡張後の1文の中で、引用の外にある否定・例外・条件の語がある  → 引用が文を切り取っている
  (B) 直後の文の先頭40字に例外語（ただし・除く・以外…）がある      → 例外が次の文で続く
  (C) 引用に否定・例外語が1つも無く、直後の文の先頭40字に否定語がある  → 設計書の字面どおりの規則
設計書の字面は「引用に否定語が無く、文にある場合」だけで、引用が「ません」を含めば例外が続いても通ってしまう。
(A)(B) はその穴（引用の外の語を見る）を塞ぐ。禁止文が連続する箇所では、各引用が自分の「ません」を含むので
(C) が働かず、連鎖して降格しない。「しなければならない」の「ない」は二重否定で否定として働かないので、(A)(C) では数えない
（引用が義務の言い回しの手前で終わっていても、文全体が義務を述べていれば kind は文で判断する）。

文全体を引用しても通ってしまう意味の反転（引用の外に語が無いので (A) は働かない）は、文そのものを見て塞ぐ
（敵対レビュー W1・W4・W5・W8）:
  - 義務語が否定されている（必須としません・義務はありません・禁止していません・No ... is required）
  - 断定でない文（疑問・仮定・予定・推量・誤解の紹介・旧規約・定義）
  - 箇条書きの手前で終わる導入の文（条件は次のブロックにある）／対象を絞る見出し（「海外在住の方」）の下の文
  - 別の節で義務語が否定された節と肯定された節が混ざる文（「必須ではありませんが、字幕は必須です」）
どれも引用がどこで切れているかに依らない（拡張後の文だけで決まる）ので、最終再検証の再計算と必ず一致する。

kind の判定（拡張後の1文だけを見る。モデルの引用ではなく）:
  必須・禁止と申告された要件に、文の中の義務語が無い                       → 推測（no_obligation_word）
  義務語が否定されている（必須ではありません）                               → 推測＋否定チップ
  義務語が無く、依頼語（お願い・ご遠慮・推奨…）だけ                           → 任意＋依頼チップ
  必須と申告されたが、明示の禁止語（禁止・してはならない）しか無い／その逆      → 推測（no_obligation_word）
  任意・依頼と申告されたが、文に否定されていない強い義務語がある              → 推測＋否定チップ
  必須・禁止と申告されたが、強い義務語が無く（指示の言い回しだけ）、同じ文に「任意」があるか、直前の見出しが任意・推奨 → 任意＋依頼チップ
語彙は vocab.py の1か所。設計書の列挙より広い（Gate2 の再現率採点で調整する前提）。
"""
import re
from bisect import bisect_left
from dataclasses import dataclass
from typing import Literal

from app.contracts import QUOTE_SPAN_MAX_CHARS, Chip, DemotionReason, Kind
from app.quotes import vocab
from app.quotes.normalize import normalize
from app.quotes.sentence import (
    CLOSERS,
    Barrier,
    block_follows,
    ends_with_terminator,
    next_sentence_head,
    previous_block,
    snap_to_sentence,
)

# N 否定 / E 例外・限定 / L 緩い例外（対象外・無効。(A) だけ）/ C 条件（場合・とき・if。(A) だけ）
WordClass = Literal["N", "E", "L", "C"]

_CLAUSE_END = re.compile(r"[、，,。．；;！？!?]")
_EN_CLAUSE_END = re.compile(r"[,;:.!?]")
_TRAILING = frozenset(CLOSERS) | frozenset("。．. ")
_EN_TOKEN = re.compile(r"[a-z'’]+")


@dataclass(frozen=True, slots=True)
class WordHit:
    cls: WordClass
    start: int  # 領域内の原文位置
    end: int
    double_negation: bool = False  # 「しなければならない」の「ない」。否定として働かない


def _find(pattern, norm_text: str, starts, ends, offset: int = 0) -> list[tuple[int, int]]:
    """正規化文字列上の一致を原文の区間 [start, end) へ戻す。"""
    return [(offset + starts[m.start()], offset + ends[m.end() - 1]) for m in pattern.finditer(norm_text)]


def find_words(region: str) -> list[WordHit]:
    """領域（原文の部分文字列）にある否定語（N）・例外・限定語（E）・緩い例外（L）・条件（C）。位置は領域内の原文位置。"""
    flat = normalize(region)
    spaced = normalize(region, spaced=True)
    hits: list[WordHit] = []
    musts = _find(vocab.JP_DOUBLE_NEGATION, flat.text, flat.starts, flat.ends)
    for pat, cls in ((vocab.JP_NEGATION, "N"), (vocab.JP_EXCEPTION, "E"), (vocab.JP_LOOSE_EXCEPTION, "L"), (vocab.JP_CONDITION, "C")):
        for a, b in _find(pat, flat.text, flat.starts, flat.ends):
            hits.append(WordHit(cls, a, b, cls == "N" and any(ma <= a and b <= mb for ma, mb in musts)))
    for pat, cls in ((vocab.EN_NEGATION, "N"), (vocab.EN_EXCEPTION, "E"), (vocab.EN_CONDITION, "C")):
        hits += [WordHit(cls, a, b) for a, b in _find(pat, spaced.text, spaced.starts, spaced.ends)]
    return hits


def _refers_back(head: str) -> bool:
    """直後の文が前の文を受けている（「この定めは…」）。この場合、例外・否定は先頭40字より後ろにも来る。"""
    return bool(
        vocab.JP_ANAPHORA.match(normalize(head).text) or vocab.EN_ANAPHORA.match(normalize(head, spaced=True).text)
    )


def has_cutoff_risk(
    text: str, s: int, e: int, v0: int, v1: int, barriers: tuple[Barrier, ...] = ()
) -> bool:
    """引用 [v0, v1)・文 [s, e) の組が、否定・例外・条件の手前で切れているおそれ（(A)(B)(C)）。"""
    inside = False
    for w in find_words(text[s:e]):
        a, b = s + w.start, s + w.end
        if v0 <= a and b <= v1:
            inside = inside or w.cls in ("N", "E")  # 引用の中にある否定・例外は、見えている
        elif not w.double_negation:
            return True  # (A)
    head = next_sentence_head(text, e, barriers)
    if head is None:
        return False
    if _refers_back(text[head[0] : head[1]]):
        head = next_sentence_head(text, e, barriers, limit=QUOTE_SPAN_MAX_CHARS) or head
    for w in find_words(text[head[0] : head[1]]):
        if w.cls == "E":
            return True  # (B)
        if w.cls == "N" and not inside and not w.double_negation:
            return True  # (C)
    return False


# ---- 断定でない文・箇条書きの導入・見出し ------------------------------------------------------------
def is_question(sentence: str) -> bool:
    """疑問文（FAQ の Q）。疑問符で終わる／「〜ですか」で終わる／「Q.」の見出し付き。"""
    flat = normalize(sentence).text
    core = flat.rstrip("".join(_TRAILING))
    if core.endswith("?") or vocab.JP_QUESTION_END.search(core):
        return True
    return bool(vocab.JP_QUESTION_LABEL.search(flat))


def _hedged_obligation(flat_text: str) -> bool:
    """推量・予定・可能性・過去の語が、義務語・依頼語と同じ節にある（「必須とする予定です」）。別の節（理由）なら断定を弱めない。"""
    for clause in _CLAUSE_END.split(flat_text):
        if vocab.JP_HEDGE.search(clause) and any(
            p.search(clause)
            for p in (
                vocab.JP_REQUIRED,
                vocab.JP_PROHIBITED,
                vocab.JP_BOTH,
                vocab.JP_REQUIRED_INSTRUCTION,
                vocab.JP_PROHIBITED_INSTRUCTION,
                vocab.JP_REQUEST,
                vocab.JP_OPTIONAL,
            )
        ):
            return True
    return False


def is_non_assertion(sentence: str) -> bool:
    """義務語を含んでいても何も義務づけていない文: 疑問・仮定・予定・推量・誤解の紹介・旧規約・定義。"""
    if is_question(sentence):
        return True
    flat = normalize(sentence)
    spaced = normalize(sentence, spaced=True)
    return bool(
        vocab.JP_NON_ASSERTION.search(flat.text)
        or _hedged_obligation(flat.text)
        or vocab.EN_NON_ASSERTION.search(spaced.text)
    )


def dangling_list_intro(text: str, s: int, e: int) -> bool:
    """文が句点で終わらずに次のブロックへ続き、「次の・以下の」か末尾のコロンで箇条書きを導いている。

    条件（何が・誰が）は箇条書きの中にあるので、導入の文だけを要件として確定させると条件が落ちる。
    句点で終わる文は、導入でも対象にしない（「次のとおり提出すること。」＋日付のブロック、のような普通の文を降格しない）。
    """
    if ends_with_terminator(text, s, e) or not block_follows(text, e):
        return False
    sentence = text[s:e]
    flat = normalize(sentence).text
    if flat.rstrip().endswith(":"):  # NFKC で「：」は「:」
        return True
    spaced = normalize(sentence, spaced=True).text
    return bool(vocab.JP_LIST_INTRO.search(flat) or vocab.EN_LIST_INTRO.search(spaced))


def heading_above(text: str, s: int) -> tuple[str, str] | None:
    """文の直前のブロックが見出し（短く、句点で終わらず、文の形でない）なら、その (flat, spaced) 正規化。文がブロックの途中から始まる・見出しでなければ None。"""
    pb = previous_block(text, s)
    if pb is None:
        return None
    heading = text[pb[0] : pb[1]]
    flat = normalize(heading).text.rstrip()
    if not flat or len(flat) > vocab.HEADING_MAX_CHARS:
        return None
    if flat[-1] in "。.!?" or vocab.HEADING_FINITE_END.search(flat):
        return None
    return flat, normalize(heading, spaced=True).text


def weak_heading_above(text: str, s: int) -> bool:
    """直前の見出しが、任意・推奨と言っている（「【任意提出物】」）。"""
    h = heading_above(text, s)
    return h is not None and bool(vocab.HEADING_WEAK_JP.search(h[0]) or vocab.HEADING_WEAK_EN.search(h[1]))


def restricting_heading_above(text: str, s: int) -> bool:
    """直前の見出しが、後ろの文の対象を絞っている（「海外在住の方」「法人向け」「学生限定」）。条件が見出しにあって、文には無い。"""
    h = heading_above(text, s)
    return h is not None and bool(vocab.HEADING_RESTRICT.search(h[0]))


# ---- 義務語とその否定 -------------------------------------------------------------------------------
def _jp_negated(flat_text: str, end: int) -> bool:
    """義務語（flat_text の end で終わる）が、同じ節の中で否定されている（「必須としません」「義務はありません」）。"""
    seg = flat_text[end : end + 4 * vocab.NEGATION_SCOPE_CHARS]
    m = _CLAUSE_END.search(seg)
    clause = seg[: m.start()] if m else seg
    clause = vocab.JP_DOUBLE_NEGATION.sub("", clause)
    clause = vocab.JP_PROHIBITION_BUILD.sub("", clause)
    window = clause[: vocab.NEGATION_SCOPE_CHARS]
    if vocab.JP_COND_NEG.search(window):
        return False  # 「なければ…できません」は要求の言い方（条件の否定＋禁止）
    return bool(vocab.JP_NEG_MARK.search(window))


def _en_negated(spaced_text: str, start: int) -> bool:
    """義務語（spaced_text の start から）の直前の数語に否定がある（"not required"・"no longer required"・"No X is required"）。"""
    head = spaced_text[max(0, start - 60) : start]
    for sep in ",;:.":
        head = head[head.rfind(sep) + 1 :]
    toks = _EN_TOKEN.findall(head)[-vocab.EN_NEGATION_LOOKBACK :]
    return any(t in vocab.EN_NEGATION_TOKENS or t.endswith(("n't", "n’t")) for t in toks)


@dataclass(frozen=True, slots=True)
class Support:
    """文にある義務語の数。negated は否定されて義務を支えない義務語。

    required / prohibited は強い義務語、instr_* は指示の言い回し（〜すること・〜ください）。
    pure_* は向きが明らかな語だけ（必須・必ず・義務／禁止・してはならない・must not）。「できません」「不可」
    「〜しないこと」は禁止の形で要求を言うことがあるので、向きの取り違えの判定には入れない。
    """

    required: int = 0
    prohibited: int = 0
    instr_required: int = 0
    instr_prohibited: int = 0
    negated: int = 0
    request: int = 0
    optional: int = 0
    pure_required: int = 0
    pure_prohibited: int = 0
    mixed: bool = False  # 別の節で、義務語が否定されている節と、否定されていない節が両方ある

    @property
    def r_evidence(self) -> int:
        """必須側の根拠。指示の言い回しは、依頼語（お願い・ご遠慮…）が同じ文にあるときは義務に数えない。"""
        return self.required + (0 if self.request else self.instr_required)

    @property
    def p_evidence(self) -> int:
        return self.prohibited + (0 if self.request else self.instr_prohibited)

    @property
    def has_obligation(self) -> bool:
        """義務を支える語があるか。設計書の列挙は必須側・禁止側を分けない（「必須」も「禁止」も義務語）。"""
        return bool(self.r_evidence or self.p_evidence)

    @property
    def strong(self) -> int:
        return self.required + self.prohibited


def _clause_bounds(text: str, pattern=_CLAUSE_END) -> list[int]:
    return [m.start() for m in pattern.finditer(text)]


def kind_support(sentence: str) -> Support:
    flat = normalize(sentence)
    spaced = normalize(sentence, spaced=True)
    counts = {"R": 0, "P": 0, "IR": 0, "IP": 0, "PR": 0, "PP": 0}
    negated = 0
    # 義務語ごとの (節の番号, 否定されているか)。節をまたいで否定と肯定が混ざる文（「必須ではありませんが、字幕は必須です」）を見つける
    flat_bounds = _clause_bounds(flat.text)
    spaced_bounds = _clause_bounds(spaced.text, _EN_CLAUSE_END)
    seen: list[tuple[int, bool]] = []

    def jp(pat, which: tuple[str, ...]) -> None:
        nonlocal negated
        for m in pat.finditer(flat.text):
            neg = _jp_negated(flat.text, m.end())
            seen.append((bisect_left(flat_bounds, m.start()), neg))
            if neg:
                negated += 1
            else:
                for w in which:
                    counts[w] += 1

    def en(pat, which: tuple[str, ...], check_head: bool) -> None:
        nonlocal negated
        for m in pat.finditer(spaced.text):
            neg = check_head and _en_negated(spaced.text, m.start())
            seen.append((1000 + bisect_left(spaced_bounds, m.start()), neg))
            if neg:
                negated += 1
            else:
                for w in which:
                    counts[w] += 1

    jp(vocab.JP_REQUIRED, ("R",))
    jp(vocab.JP_PURE_REQUIRED, ("PR",))
    jp(vocab.JP_PROHIBITED, ("P",))
    jp(vocab.JP_PURE_PROHIBITION, ("PP",))
    jp(vocab.JP_BOTH, ("R", "P"))
    for _ in vocab.JP_COND_PROHIBITION.finditer(flat.text):
        counts["R"] += 1  # 「18歳以上でなければ応募できません」は、禁止の形の要求
    for pat, which in ((vocab.JP_REQUIRED_INSTRUCTION, "IR"), (vocab.JP_PROHIBITED_INSTRUCTION, "IP")):
        counts[which] += len(pat.findall(flat.text))
    en(vocab.EN_REQUIRED, ("R", "PR"), True)
    en(vocab.EN_PROHIBITED_PHRASE, ("P", "PP"), False)
    en(vocab.EN_PROHIBITED_WORD, ("P", "PP"), True)
    request = len(vocab.JP_REQUEST.findall(flat.text)) + len(vocab.EN_REQUEST.findall(spaced.text))
    optional = len(vocab.JP_OPTIONAL.findall(flat.text)) + len(vocab.EN_OPTIONAL.findall(spaced.text))
    # 否定された義務語だけの節と、否定されていない義務語のある節が両方ある（同じ節に両方あるのは、否定が別の語にかかる誤検出の
    # 可能性が高い。「必須項目を入力しない場合は失格とする」）
    neg_only = {c for c, n in seen if n and not any(c2 == c and not n2 for c2, n2 in seen)}
    pos = {c for c, n in seen if not n}
    mixed = bool(neg_only) and bool(pos - neg_only)
    return Support(
        counts["R"], counts["P"], counts["IR"], counts["IP"], negated, request, optional, counts["PR"], counts["PP"], mixed
    )


@dataclass(frozen=True, slots=True)
class Decision:
    """1つの出現についての判定。span は画面に出す原文の区間（拡張後の1文、または拡張前の引用）。"""

    kind: Kind
    demotion: DemotionReason | None
    chips: tuple[Chip, ...]
    span: tuple[int, int]

    @property
    def severity(self) -> int:
        """複数の出現のうち、最も慎重な判定を選ぶための順位。"""
        return _SEVERITY[self.demotion]


_SEVERITY: dict[DemotionReason | None, int] = {
    None: 0,
    DemotionReason.REQUEST_WORDING: 1,
    DemotionReason.SENTENCE_TOO_LONG: 2,
    DemotionReason.NO_OBLIGATION_WORD: 3,
    DemotionReason.NEGATION_OR_EXCEPTION: 4,
    DemotionReason.QUOTE_UNVERIFIED: 5,
}


def _caution(span: tuple[int, int]) -> Decision:
    """否定・例外・条件・断定でない文: 推測へ落とし、否定・例外のチップを付ける。"""
    return Decision(Kind.SPECULATIVE, DemotionReason.NEGATION_OR_EXCEPTION, (Chip.NEGATION_OR_EXCEPTION,), span)


def decide(
    text: str, v0: int, v1: int, declared: Kind, barriers: tuple[Barrier, ...] = ()
) -> Decision:
    """検証済みの引用 [v0, v1) を文へ広げ、否定・例外と kind を見て最終 kind を決める。"""
    s, e = snap_to_sentence(text, v0, v1, barriers)
    too_long = e - s > QUOTE_SPAN_MAX_CHARS
    if declared is Kind.SPECULATIVE:
        # 推測と申告された要件は、降格しようがない。表示は文があれば文、長すぎれば引用の区間。
        return Decision(Kind.SPECULATIVE, None, (), (v0, v1) if too_long else (s, e))
    if too_long:
        # 160字を超える文は読点で切らず推測へ（引用の区間 v0..v1 は160字以内なので表示に使える）
        return Decision(Kind.SPECULATIVE, DemotionReason.SENTENCE_TOO_LONG, (), (v0, v1))
    sentence = text[s:e]
    if (
        has_cutoff_risk(text, s, e, v0, v1, barriers)
        or is_non_assertion(sentence)
        or dangling_list_intro(text, s, e)
        or restricting_heading_above(text, s)
    ):
        return _caution((s, e))
    sup = kind_support(sentence)
    if sup.mixed:
        # 「動画は必須ではありませんが、字幕は必須です」: 引用がどちらの節でも、文の kind は決められない
        return _caution((s, e))
    if declared in (Kind.REQUIRED, Kind.PROHIBITED):
        if not sup.has_obligation:
            if sup.negated:
                # 「必須ではありません」のように、義務語が否定されている
                return _caution((s, e))
            if sup.request and not (sup.required or sup.prohibited):  # 依頼語だけ（強い義務語が無い）
                return Decision(Kind.OPTIONAL, DemotionReason.REQUEST_WORDING, (Chip.REQUEST_WORDING,), (s, e))
            return Decision(Kind.SPECULATIVE, DemotionReason.NO_OBLIGATION_WORD, (), (s, e))
        if _polarity_swapped(sentence, sup, declared):
            return Decision(Kind.SPECULATIVE, DemotionReason.NO_OBLIGATION_WORD, (), (s, e))
        if not sup.strong and not sup.request and (sup.optional or weak_heading_above(text, s)):
            # 「〜してください」「〜すること」だけで、同じ文に「任意」がある（見出しと本文が1ブロックのプレーンテキスト）か、
            # 直前の見出しが任意・推奨＝任意の項目の指示文
            return Decision(Kind.OPTIONAL, DemotionReason.REQUEST_WORDING, (Chip.REQUEST_WORDING,), (s, e))
    elif declared in (Kind.OPTIONAL, Kind.REQUEST) and sup.strong:
        # 任意・依頼と申告されたが、文に否定されていない強い義務語がある（必須・禁止の文を弱めて、違反を見逃させる向きの反転）
        return _caution((s, e))
    return Decision(declared, None, (), (s, e))


def _polarity_swapped(sentence: str, sup: Support, declared: Kind) -> bool:
    """必須と申告されたが明示の禁止語しか無い（してはならない）／禁止と申告されたが明示の必須語しか無い（必ず…しなければならない）。

    判定は明示の語だけ。「できません」「不可」「〜しないこと」は、禁止の形で要求を言うことが多く（人が必須と付けた文にも
    多い）、向きを決められない。禁止と申告されて、文に否定語が1つでもあれば（「侵害しないものとします」）、
    必須の語は禁止の内容を修飾しているので取り違えとみなさない。
    """
    if declared is Kind.REQUIRED:
        return sup.r_evidence == 0 and sup.pure_prohibited > 0
    if sup.p_evidence or not sup.pure_required:
        return False
    return not any(w.cls == "N" and not w.double_negation for w in find_words(sentence))
