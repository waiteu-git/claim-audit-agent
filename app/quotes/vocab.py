"""引用の意味を逆にしうる語と、義務・依頼・任意の語彙（設計 §5-1「否定・例外語」「kind のコード側クロスチェック」）。

設計書の列挙を出発点にし、活用形（除く→除き、しなければならない→しなければなりません）と、敵対レビュー
（tests/test_quotes_adversarial.py）で意味の反転・条件の欠落が見つかった語を足している:
否定の言い方（おらず・無し・no longer）、例外・撤回の語（もっとも・例外・免除・廃止）、条件（場合・とき・if・when）、
断定でない文（疑問・仮定・予定・推量・誤解の紹介・旧規約・定義）。語彙を広げると誤降格（再現率の低下）が増えるので、
手元の台帳（リポ外）の件数で毎回確かめている。

日本語の語は空白を除いた正規化（flat）に、英語の語は空白を畳んだ小文字（spaced）にかける
（英語は空白を除くと語の切れ目が消えて "note" に "not" が一致するため）。
"""
import re

# --- 否定語（N）・例外・限定語（E）・緩い例外（L）・条件（C）-----------------------------------
# N・E は引用の外にあれば引用を切り取りとみなす（A）。E は直後の文の先頭にあっても同じ（B）。
# L・C は (A) だけ（直後の文に「対象外」「場合」があっても、前の文の意味は変わらない＝誤降格を避ける）。
# 「ない」は「しなければならない」にも入る。それでよい（義務表現の「ない」を引用が含むかどうかを見ている）。
# 「不可欠」「不可避」は否定でない（義務の強い言い方）。
JP_NEGATION = re.compile(r"ない|ません|不要|不可(?!欠|避|分|逆|侵)|ではなく|でなく|無い|無し|なし(?!得)|おらず|おりません")
JP_EXCEPTION = re.compile(
    r"除く|除き|除いて|除外|以外|ただし|但し|なお|のみ|限り|限る|限って|限定"
    r"|もっとも|ただ[、,]|例外|特例|免除|適用除外|不問|廃止|撤廃|撤回|取りやめ|取り止め|取止め|取消|この限りで"
)
JP_LOOSE_EXCEPTION = re.compile(r"対象外|適用外|不適用|無効|失効")
# 条件。引用が文の途中から始まると、前に付いた条件が落ちる（「海外在住の場合は、…が必須です」）。
JP_CONDITION = re.compile(
    r"場合|とき(?=は|に|、|も)|(?<![実国交間])際(?=は|に|し|の|、)|なら(?![ないずざべれびで])|ならば|であれば|すれば|したら|もし(?!くは)|仮に|たとえ|にあたり|に当たり|に応じ|に該当"
    r"|の(?:方|者|人|チーム|参加者|応募者|ユーザー)(?:は|が|へ|に)"  # 対象を絞る主語（「海外在住の方は、…が必須です」）
)
EN_NEGATION = re.compile(
    r"(?<![a-z0-9])(?:not|cannot|never|neither|nor|none|nobody|nothing|without)(?![a-z0-9])|n['’]t(?![a-z])"
    r"|(?<![a-z0-9])no(?![a-z0-9])(?!\s+(?:later|more|less|fewer|earlier|greater|larger|smaller|higher|lower|longer\s+than|shorter\s+than))"
)
EN_EXCEPTION = re.compile(
    r"(?<![a-z0-9])(?:unless|except|only|excluding|exempt(?:ed|ion|ions)?|exceptions?|waive[ds]?|waiver"
    r"|aside\s+from|apart\s+from|other\s+than|save\s+for|besides)(?![a-z0-9])"
)
EN_CONDITION = re.compile(
    r"(?<![a-z0-9])(?:if|when|whenever|provided\s+that|as\s+long\s+as|in\s+case|in\s+the\s+event)(?![a-z0-9])"
)

# 直後の文が前の文を受けている（「この定めは…」「前項の規定は…」）。例外や否定が先頭40字より後ろに来ることがあるので、
# この場合だけ直後の文を最後まで（160字まで）見る。
JP_ANAPHORA = re.compile(r"^(?:この|その|当該|前項|前条|前段|上記|同項|同条|本項|本条|前述|前記|これらの|それらの|以上の)")
EN_ANAPHORA = re.compile(r"^(?:this|these|that|such|the above|the preceding|the foregoing)(?![a-z0-9])")

# --- 義務語 ----------------------------------------------------------------------------------
# 二重否定の義務表現。「ない」を含むが、否定として働かない（引用の外にあっても、引用の意味を逆にしない）。
JP_DOUBLE_NEGATION = re.compile(r"なければ(?:ならない|ならず|なりません|いけない|いけません)|ねばならな")

# 強い義務語（設計書の列挙＋活用形）。これがあれば、依頼語があっても義務と読む。
# 必須側。「必ずしも」は「必ずしも〜ない」の否定の前触れなので義務語に数えない。「不必要」は含めない。
JP_REQUIRED = re.compile(
    r"(?<![非不無])必須|不可欠|必ず(?!しも)|" + JP_DOUBLE_NEGATION.pattern + r"|(?<![非不無])義務"
    r"|(?<!不)必要(?:が|は)?(?:あります|ある|です|となります|となる|とします|とする|である|とされ)|ものとします|要します"
    r"|に限(?:ります|る)"
)
# 禁止側。「できません」は実際の規約文で最も多い禁止の言い方（「参加できません」）。
JP_PROHIBITED = re.compile(
    r"禁止|禁じ|てはならな|てはなりません|てはいけな|てはいけません|不可(?!欠|避|分|逆|侵)|認められません|認めません|できません"
)
# どちらにも数える（失格は「しなければ失格」にも「すれば失格」にも使う）。
JP_BOTH = re.compile(r"失格")
# 指示の言い回し（〜すること／〜してください）。依頼語（お願い・ご遠慮…）が同じ文にあるときは義務に数えない
# （「ご遠慮ください」は依頼）。設計書の列挙には無いが、実際の規約文の必須・禁止の大半がこの形（Gate2 の調整用に
# 分けてある。無効にするなら INSTRUCTION を空にする）。
JP_REQUIRED_INSTRUCTION = re.compile(
    r"(?<!ない)こと(?=$|[。．（(、，,」』）)])"
    r"|(?<!ないで)(?<!避けて)(?<!控え)(?<!遠慮)(?:ください|下さい)"
)
JP_PROHIBITED_INSTRUCTION = re.compile(r"ない(?:で)?(?:こと|ください|下さい)|避けて(?:ください|下さい)|(?<![おご])控える")
EN_REQUIRED = re.compile(r"(?<![a-z0-9])(?:must(?! not)|required|mandatory)(?![a-z0-9])")
# 英語の禁止は、語そのものが否定を含む言い方（must not）と、前に否定が付きうる語（prohibited）を分ける。
# 後者だけ「is not prohibited」「no longer prohibited」の否定を見る。
EN_PROHIBITED_PHRASE = re.compile(r"(?<![a-z0-9])(?:must not|may not|shall not|not allowed)(?![a-z0-9])")
EN_PROHIBITED_WORD = re.compile(r"(?<![a-z0-9])(?:prohibited|forbidden)(?![a-z0-9])")
EN_PROHIBITED = re.compile(EN_PROHIBITED_PHRASE.pattern + "|" + EN_PROHIBITED_WORD.pattern)

# --- 義務語が否定されているか -------------------------------------------------------------------
# 義務語の直後に、同じ節（読点まで・最大 NEGATION_SCOPE_CHARS 字）の中で否定が続く
# （「必須としません」「義務はありません」「禁止していません」「失格にはなりません」）。この義務語は義務を支えない。
# 直後でなくてもよい（「必須とは言えない」「必須とはしていません」の間に助詞・動詞が挟まる）。
# 禁止を作る「ないこと」「てはならない」と、二重否定「なければならない」は否定として数えない。
# 「なければ…できません」（条件の否定＋禁止）は要求の言い方なので、その節は否定とみなさない。
NEGATION_SCOPE_CHARS = 24
JP_NEG_MARK = re.compile(r"ない(?!し)|なく|なかっ|ません|おらず|おりません|不要")
JP_COND_NEG = re.compile(r"なければ|ないと|でないと|ない限り|ないかぎり|なくては|なくして|でなければ")
JP_PROHIBITION_BUILD = re.compile(r"てはならな[いか]|てはなりません|てはいけな[いか]|てはいけません|ないこと|ないで|ないよう")
# 「18歳以上でなければ応募できません」: 条件の否定の後に禁止の言い方が続く＝実際は「18歳以上であること」という要求。
JP_COND_PROHIBITION = re.compile(
    r"(?:なければ|ないと|でないと|ない限り|ないかぎり|なくては|でなければ)[^、，,。．]{0,25}?"
    r"(?:できません|認められません|認めません|不可|失格|受け付けません|受理されません|対象外|無効|なりません|いけません)"
)
EN_NEGATION_TOKENS = frozenset(
    {"no", "not", "never", "none", "nobody", "nothing", "neither", "nor", "cannot", "without"}
)
EN_NEGATION_LOOKBACK = 4  # 義務語の前の何語まで見るか（"No demo video is required" で no は4語前）

# --- 必須と禁止の取り違え（明示の語だけ）---------------------------------------------------------
# 「できません」「不可」「〜しないこと」は、禁止の形で要求を言う（「ローカルのみは不可」「権利を侵害しないこと」）。
# 人が必須と付ける文にも多いので、向きの判定には使わない。向きが明らかに反対の語だけで取り違えを見る。
JP_PURE_PROHIBITION = re.compile(r"禁止|禁じ|てはならな|てはなりません|てはいけな|てはいけません")
JP_PURE_REQUIRED = re.compile(r"(?<![非不無])必須|不可欠|必ず(?!しも)|" + JP_DOUBLE_NEGATION.pattern + r"|(?<![非不無])義務")
EN_PURE_PROHIBITION = re.compile(r"(?<![a-z0-9])(?:must not|may not|shall not|prohibited|forbidden)(?![a-z0-9])")

# --- 断定でない文 ------------------------------------------------------------------------------
# 疑問・仮定・予定・推量・誤解の紹介・旧規約・定義は、義務語を含んでいても何も義務づけていない。
# 質問文（FAQ の Q）は答えが「いいえ」かもしれない。文末（句点・閉じ括弧を除く）にかける。
JP_QUESTION_END = re.compile(r"(?:です|ます|ません|でしょう|ない|いい|よい|良い|だろう|の)か$")
JP_QUESTION_LABEL = re.compile(r"^(?:[qQ]\d{0,3}[.:)]|質問\d{0,3}[.:：])")
# 文のどこにあっても断定を打ち消す語（仮定・例示・誤解の紹介・旧規約・撤回・定義）。
# 「誤り」「間違い」は「誤りがないこと」のような要求にも出るので、否定の言い切り（誤りです）だけ。
JP_NON_ASSERTION = re.compile(
    r"仮に|たとえ|例えば|[(（]例[)）]|例[:：]|かどうか|か否か"
    r"|誤解|勘違い|誤認|(?:誤り|間違い)(?:です|でした|である|だ)"
    r"|という(?:声|意見|指摘|質問|記載|表記|説明|噂)|との(?:声|意見|指摘|質問)|と言われ|といわれ|と書かれ"
    r"|旧(?:版|規約|ルール|要項)|従来は|以前は|かつて|当初は|廃止|撤廃|撤回|取りやめ|取り止め|取止め"
    r"|(?:必須|義務|禁止|必要|不可|失格)とは"
)
# 義務語と同じ節にあるときだけ断定を弱める語（推量・予定・可能性・過去）。別の節（理由・補足）にあっても要件は変わらない
# （例:「混雑する場合があるため、早めの提出をおすすめします」の「場合がある」は理由の節）。
JP_HEDGE = re.compile(
    r"かもしれ|でしょう|だろう|と思われ|と考えられ|予定|見込み|可能性|検討|未定|場合があ|ことがあ"
    r"|でした|だった|であった|としていた|とされていた|ていました"
)
EN_NON_ASSERTION = re.compile(
    r"(?<![a-z0-9])(?:misconception|myth|mistaken|mistakenly|incorrect|incorrectly|untrue|wrong|might|could|possibly|perhaps|probably|tbd)(?![a-z0-9])"
    r"|(?<![a-z0-9])may(?! not)(?![a-z0-9])"
    r"|in the future|under consideration|to be determined|for example|for instance|e\.g\.|planned|plan to"
)
# 箇条書きの導入（次の・以下の・下記…）。導入の文が句点で終わらずに次のブロックへ続くと、条件は箇条書きの中にある。
JP_LIST_INTRO = re.compile(r"以下の|以下に|以下を|以下、|次の|次に|(?:下記|左記)[のにを]|上記の")
EN_LIST_INTRO = re.compile(r"(?<![a-z0-9])(?:following|as follows|below|these)(?![a-z0-9])")
# 直前のブロックが見出しで、任意・推奨と言っている（「【任意提出物】」の下の「〜してください」）。
HEADING_WEAK_JP = re.compile(r"任意|オプション|推奨|お願い|望まし|参考|おすすめ|お勧め|できれば")
HEADING_WEAK_EN = re.compile(r"(?<![a-z0-9])(?:optional|recommended|suggested|bonus|nice to have)(?![a-z0-9])")
# 直前の見出しが、後ろの文の対象を絞る（「海外在住の方」「法人向け」「チームで参加する場合」「学生限定」）。
HEADING_RESTRICT = re.compile(r"(?:の方|の者|の人|向け|場合|のとき|限定|のみ)[へは]?[】」』）)\]]?$")
HEADING_FINITE_END = re.compile(r"(?:こと|です|ます|ください|する|ある|いる|ない|だ|い|る|た)$")
HEADING_MAX_CHARS = 40

# --- 依頼語・任意語 --------------------------------------------------------------------------
JP_REQUEST = re.compile(r"お願い|ご遠慮|お控え|推奨|望まし|お勧め|おすすめ")
EN_REQUEST = re.compile(r"(?<![a-z0-9])(?:recommended|encouraged|preferred|please)(?![a-z0-9])")
JP_OPTIONAL = re.compile(r"任意|できます|構いません|かまいません|差し支えありません|問いません")
EN_OPTIONAL = re.compile(r"(?<![a-z0-9])optional(?![a-z0-9])")

# --- 6〜11字の短い引用を通すための語（必須・禁止・任意・数値/単位語）-----------------------
_UNIT = (
    r"%|分|秒|時間|日|月|年|字|文字|語|人|名|件|枚|回|個|点|円|歳|才|ページ|頁|行|章|条|項"
    r"|mb|kb|gb|tb|px|min|sec|chars?|words?|pages?|hours?|days?|years?"
)
NUMBER_UNIT = re.compile(rf"\d+(?:[.,]\d+)*(?:{_UNIT})", re.IGNORECASE)

# --- 省略記号 ---------------------------------------------------------------------------------
# NFKC の後の文字列にかける（… は ... になる。全角の．．．も ... になる）。
ELLIPSIS_AFTER_NFKC = re.compile(
    r"\.(?:\s*\.){2,}|・{3,}|[\[(（【〔]\s*(?:中略|以下略|後略|前略|省略|略)\s*[\])）】〕]"
)
# NFKC で別の文字列になって見えなくなる省略記号。NFKC の前の文字列にかける。
ELLIPSIS_RAW = re.compile("[…⋯‥]")


def has_short_quote_word(flat_text: str, spaced_text: str) -> bool:
    """6〜11字の引用が「必須・禁止・任意・数値/単位語」を含むか。日本語は flat、英語は spaced（語の切れ目が要る）。"""
    if any(p.search(flat_text) for p in (JP_REQUIRED, JP_PROHIBITED, JP_BOTH, JP_OPTIONAL, NUMBER_UNIT)):
        return True
    return any(p.search(spaced_text) for p in (EN_REQUIRED, EN_PROHIBITED, EN_OPTIONAL))
