"""静的 UI（app/web/static）と同梱物の検査: innerHTML 等の不在・外部 URL の不在・インラインの script/style の不在・入力欄の不在・
判定の3重表記・ライト/ダーク・狭い幅、および UI・フィクスチャ・同梱リプレイの漏洩走査（実URL・プロジェクトID・メール・鍵）。

漏洩の正規表現は app/checks/leak_scan.py の LEAK_PATTERNS（提出物の検査と同じ集合）に、リポジトリ固有の形を足して使う。
"""
import json
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

from app.checks.leak_scan import scan_text
from app.fixtures import gen
from app.fixtures.site import CLOUD_RUN_PLACEHOLDER, SITE_DIR

STATIC = Path("app/web/static")
REPLAY = Path("app/web/replay")
JS = (STATIC / "app.js").read_text(encoding="utf-8")
CSS = (STATIC / "app.css").read_text(encoding="utf-8")
HTML = (STATIC / "index.html").read_text(encoding="utf-8")
UI_FILES = {"index.html": HTML, "app.js": JS, "app.css": CSS}


# ---- 危険な描画・外部読み込みの不在 ---------------------------------------------------------------
@pytest.mark.parametrize(
    "pattern",
    [r"\binnerHTML\b", r"\bouterHTML\b", r"insertAdjacentHTML", r"document\.write", r"\beval\s*\(", r"new\s+Function\s*\(",
     r"setTimeout\s*\(\s*['\"]", r"createContextualFragment", r"\.srcdoc\b", r"DOMParser"],
)  # fmt: skip
def test_the_script_never_writes_html_strings(pattern):
    assert not re.search(pattern, JS), pattern


def test_text_is_rendered_only_through_text_nodes():
    assert "textContent" in JS and "createTextNode" in JS and "createElement" in JS


@pytest.mark.parametrize("name", list(UI_FILES))
def test_no_external_url_or_cdn_in_ui_files(name):
    text = UI_FILES[name]
    assert not re.search(r"https?://", text), name
    assert "//cdn" not in text and "@import" not in text


def test_the_script_talks_only_to_its_own_api():
    urls = re.findall(r"fetch\(\s*\"([^\"]+)\"", JS)
    assert urls and all(u.startswith("/api/") for u in urls)
    assert "XMLHttpRequest" not in JS and "WebSocket" not in JS and "sendBeacon" not in JS


class _Tags(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict]] = []
        self.script_text = ""
        self._in_script = False

    def handle_starttag(self, tag, attrs):  # noqa: ANN001
        self.tags.append((tag, dict(attrs)))
        self._in_script = tag == "script"

    def handle_endtag(self, tag):  # noqa: ANN001
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):  # noqa: ANN001
        if self._in_script:
            self.script_text += data


def _parsed() -> _Tags:
    p = _Tags()
    p.feed(HTML)
    return p


def test_no_inline_script_style_or_event_handler_in_the_page():
    p = _parsed()
    assert p.script_text.strip() == ""
    scripts = [a for t, a in p.tags if t == "script"]
    assert scripts == [{"src": "/app.js", "defer": None}]
    assert not any(t == "style" for t, _ in p.tags)
    for tag, attrs in p.tags:
        assert "style" not in attrs, tag
        assert not any(k.startswith("on") for k in attrs), (tag, attrs)
    links = [a for t, a in p.tags if t == "link"]
    assert links == [{"rel": "stylesheet", "href": "/app.css"}]


def test_the_only_input_field_is_the_github_repo_one_and_the_rest_is_preset_cards_and_one_run_button():
    """入力欄は、審査員コード用の GitHub のリポジトリ欄（`repo-url`）の1つだけ。最初は隠れていて、そのカードを選んだ時だけ出る。
    textarea・select・form は無い。値の使い道は `repoUrl()` だけ（保存・URL・表示に出さない）で、POST の本文にだけ入れる。"""
    p = _parsed()
    inputs = [a for t, a in p.tags if t == "input"]
    assert len(inputs) == 1 and inputs[0]["id"] == "repo-url" and inputs[0]["type"] == "text"
    assert not any(t in ("textarea", "select", "form") for t, _ in p.tags)
    assert re.search(r'<div id="repo-input"[^>]*\bhidden\b', HTML)
    assert JS.count('($("repo-url").value || "")') == 1 and "body.repo_url = url" in JS  # 値を読むのは urlInput() の1か所だけ
    for bad in ("localStorage", "sessionStorage", "document.cookie", "sendBeacon", "history.pushState"):
        assert bad not in JS, bad
    cards = JS.split("function renderPresets")[1].split("function select")[0]
    assert "URL_PRESETS[p.id] && !state.judge" in cards  # 審査員コードが無い時は、GitHub・要項モードのカードを出さない
    assert ("button", {"id": "run", "type": "button", "class": "primary", "disabled": None}) in p.tags
    assert ">監査を実行<" in HTML


def test_the_page_is_japanese_and_responsive_in_both_colour_schemes():
    assert '<html lang="ja">' in HTML and 'name="viewport"' in HTML
    assert "@media (prefers-color-scheme: dark)" in CSS
    assert re.search(r"@media \(max-width: 799px\)", CSS)  # 幅 800px 未満で縦積み
    narrow = CSS.split("@media (max-width: 799px)")[1]
    assert "grid-template-columns: 1fr" in narrow and "display: block" in narrow  # 表もカード状に縦積み（横スクロール無し）
    assert "overflow-x" not in CSS


def test_verdicts_are_shown_with_colour_symbol_and_text():
    block = JS.split("const VERDICT = {")[1].split("};")[0]
    for label in ("適合", "推定適合", "不適合", "確認不能", "参考"):
        m = re.search(rf'"{label}": \["(v-[a-z]+)", "(.)"\]', block)
        assert m, label
        assert f".{m.group(1)} " in CSS or f".{m.group(1)}{{" in CSS.replace(" {", "{")  # 色（クラス）がある
    assert "document.createTextNode(v.label)" in JS  # 文字


def test_the_ui_has_the_required_regions():
    for rid in ("presets", "run", "summary", "reqs", "source", "budget-box", "trace-box", "mode", "warning"):
        assert f'id="{rid}"' in HTML, rid
    assert "<details" in HTML and "<meter" not in HTML  # ゲージは JS が meter で描く（インラインの幅指定を使わない）
    assert '"meter"' in JS


def test_the_judge_code_is_read_from_the_fragment_and_removed_from_the_address_bar():
    assert "location.hash" in JS and "history.replaceState" in JS and '"X-Judge"' in JS
    assert "localStorage" not in JS  # 審査員コードを端末に残さない


# ---- 漏洩の走査（UI・フィクスチャ・同梱リプレイ）--------------------------------------------------
# リポジトリ固有の形（leak_scan の集合に足す）: GCP のプロジェクトID らしき文字列・実在のクラウドのホスト
_REPO_EXTRA = re.compile(r"projects/[a-z][a-z0-9-]{4,28}[a-z0-9]|\.(?:appspot\.com|cloudfunctions\.net|a\.run" + r"\.app)\b|"
                         r"\b(?:zenn\.dev|googleapis\.com/v1/projects)\b")  # fmt: skip
ALLOWED_FIXTURE_EMAIL = "mirai-team@example.invalid"  # D3 の欠陥として仕込んだ架空のメール（予約ドメイン）


def _bundle_files() -> list[Path]:
    files = [*STATIC.glob("*"), *REPLAY.glob("*.json"), *SITE_DIR.rglob("*"), Path("app/fixtures/expected.json")]
    return [p for p in files if p.is_file()]


@pytest.mark.parametrize("path", _bundle_files(), ids=lambda p: p.as_posix())
def test_no_real_url_project_id_email_or_key_in_shipped_files(path):
    text = path.read_text(encoding="utf-8")
    found = scan_text(text)
    if path.is_relative_to(SITE_DIR) and path.parent.name == "submission":
        # D3: 説明文に架空のメールを仕込んである（サービスの直URLはプレースホルダで、配信時に組み立てる）
        assert set(found) <= {"email"} and re.findall(r"[\w.+-]+@[\w.-]+", text) == [ALLOWED_FIXTURE_EMAIL]
        assert CLOUD_RUN_PLACEHOLDER in text
    else:
        assert found == {}, (path, found)
    assert not _REPO_EXTRA.search(text), path
    assert ".run" + ".app" not in text  # ファイルには run.app 系のホストを書かない


def test_the_bundled_replays_carry_no_page_text_beyond_the_verified_quotes():
    for p in REPLAY.glob("*.json"):
        rec = json.loads(p.read_text(encoding="utf-8"))
        assert rec["mode"] == "REPLAY"
        if p.stem in ("sample_defect", "sample_injection"):
            # 架空サンプルは、台本の Reader で作った記録（oracle-reader）か、実モデルの実行記録を取り込んだもの（モデル名が記録に残る）
            assert rec["reader_model"] == "oracle-reader" or rec["reader_model"].startswith("gemini-")
        else:  # 実LPの記録: 取り込みの上限（引用80字・要件40件）を守り、URL・メール・鍵を持たない
            reqs = rec["requirements"]
            assert len(reqs) <= 40 and rec["omitted_requirements"] >= 0
            assert all(len(r["span"]["original_span"]) <= 80 for r in reqs if r.get("span"))
            assert all(len(r.get("gist") or "") <= 80 for r in reqs)
            assert not scan_text(p.read_text(encoding="utf-8"))
        text = p.read_text(encoding="utf-8")
        assert "まちの落とし物マップ" not in text  # 提出物の本文（説明文）は記録に無い
        assert gen.INJECTION_TEXT not in text  # 偽の命令の本文も無い（スニペットはエスケープした60字まで）


def test_the_leak_patterns_are_live_positive_controls():
    """漏洩 CI が実際に検出できること（何も見ていない検査で緑にならない）。"""
    host = "x" + "." + "a.run" + ".app"
    hits = scan_text(f"連絡先 someone@example.invalid と https://svc-{host}/ と AIza{'A' * 35} と 10.1.2.3")
    assert {"email", "service_url", "google_api_key", "private_ip"} <= set(hits)


# ---- 第5弾: 結果画面の2つの帯（コードが検証した引用・判断が変わった場面）----------------------------------
def test_the_result_has_a_quote_band_and_a_replan_band_that_start_hidden():
    p = _parsed()
    by_id = {a.get("id"): a for t, a in p.tags if a.get("id")}
    for rid in ("trust-band", "trust-who", "trust-quote", "trust-example", "trust-flow", "replan-band", "replan-steps", "replan-end"):
        assert rid in by_id, rid
    assert "hidden" in by_id["trust-band"] and "hidden" in by_id["replan-band"]  # 材料の無い実行では出さない
    assert "hidden" in by_id["trust-quote"] and "hidden" in by_id["trust-example"]
    assert "判定の根拠" in HTML and "調べ方を変えた場面" in HTML


def test_the_quote_band_summary_and_examples_follow_the_agreed_wording_and_limits():
    assert "AIの引用は、コードが要項と照合しました。" in JS
    assert "一度受け付けず、引用し直させました" in JS  # 「棄却」でなく「受け付けず」（本人の裁定 S09 B）。「引き直し」でなく「引用し直し」（10/8 夜）
    assert "引き直" not in JS and "AIが引いた" not in JS and 'step("AIが引用した文"' in JS
    assert "examples.length < 1" in JS  # 照合の例は1つだけ（成功の流れ。赤い✕の並びにしない）
    assert JS.count("clip(ex.model, 54)") == 1 and JS.count("clip(ex.original, 54)") == 1  # 例の引用は短く切る
    assert "clip(r.span.original_span, 80)" in JS  # 要件の引用は80字まで


def test_the_bands_do_not_break_when_the_record_lacks_the_fields_they_need():
    # 必要なフィールドが無い記録では帯を出さない（描かずに戻る）。ブラウザでの確認は、欠けた・壊れた記録で例外が出ないことを手元で見た
    assert 'typeof s.quotes_checked !== "number"' in JS and "s.quotes_checked <= 0" in JS
    assert "Array.isArray(rec.events)" in JS and "Array.isArray(ev.quote_steps)" in JS
    assert "if (!mark) return;" in JS and "if (!trigger) return;" in JS


def test_the_replan_band_shows_two_or_three_steps_each_jumping_to_the_trace():
    block = JS.split("function renderReplanBand")[1].split("function renderContradictions")[0] if "function renderReplanBand" in JS else JS.split("function renderReplanBand")[1]
    assert block.count("stepNode(") == 3 and "jumpTo(seq)" in JS


def test_the_ui_explains_that_the_code_decides_and_names_no_other_product_or_distributed_skill():
    assert "判定は、確かめた結果からコードが決めます。AIは判定を書けません。" in HTML
    assert "判定はすべて、コードが出しました。" in JS
    for name, text in UI_FILES.items():
        for word in ("スキル", "他社", "競合", "比較して"):
            assert word not in text, (name, word)


# ---- 第6弾: ②の同梱REPLAYの方針変更・「誰が決めたか」の帯 ------------------------------------------------
def _replay(pid):
    return json.loads((REPLAY / f"{pid}.json").read_text(encoding="utf-8"))


def test_the_bundled_preset_2_replay_contains_a_replan_and_the_guide_page_it_followed():
    rec = _replay("sample_defect")
    # 台本の記録（oracle-reader＋rule-planner）か、実モデルの実行記録（モデル名が残る）か。どちらでも記録のモデル名は実際のもの
    scripted = (rec["reader_model"], rec["planner_model"]) == ("oracle-reader", "rule-planner")
    live = rec["reader_model"].startswith("gemini-") and rec["planner_model"].startswith("gemini-")
    assert scripted or live
    ev = rec["events"]
    mark = next(e for e in ev if e["type"] == "replan")
    trigger = next(e for e in ev if e["type"] == "tool_result" and e["obs_id"] == mark["obs_id"])
    after = [e for e in ev if e["type"] == "tool_result" and e["seq"] > mark["seq"]]
    again = next(e for e in after[1:] if e["name"] == trigger["name"] and e["req_id"] == mark["req_id"])
    assert (trigger["reason_code"], mark["name"], again["reason_code"]) == ("TERMS_ABSENT", "fetch_link", "TERMS_FOUND")
    assert "リンク先" in " ".join(d["label"] for d in rec["docs"])  # 辿った案内ページの文書
    assert rec["summary"]["verdict_counts"]["不適合"] == 3 and rec["summary"]["contradictions"] == 1  # D1〜D4 は変わらない


def test_the_bundled_preset_3_replay_has_no_replan_and_records_that_the_planner_was_skipped():
    rec = _replay("sample_injection")
    assert not any(e["type"] == "replan" for e in rec["events"])
    assert any(e["type"] == "autorun" and e["name"] == "planner_skipped" for e in rec["events"])
    assert not any(e["type"] == "model_call" and e["purpose"] == "planner" for e in rec["events"])


def test_the_run_breakdown_is_computed_from_the_record_and_left_out_when_it_cannot_be():
    # 「誰が決めたか」の内訳は、実行の詳細の中の事実の行になった（AUTORUN・Planner・Governor などの内部の呼び名は画面に出さない）
    assert 'id="facts"' in HTML and 'id="run-box"' in HTML
    block = JS.split("function renderFacts")[1].split("document.addEventListener")[0]
    for text in ("自動の検査 ", "AIが選んだ検査 ", "AIの呼び出し", "方針の変更", "見積もり費用", "実行の制限による拒否"):
        assert text in block, text
    assert 'e.phase === "AUTORUN"' in block and "if (checks && " in block  # AUTORUN の無い古い記録では内訳を言えない
    for word in ("Planner（", "AUTORUN（", "Governor", "REPLAY（", "スキル", "他社", "競合", "比較して"):
        assert word not in JS, word


def test_the_unverifiable_rows_are_split_by_reason_code_into_self_check_and_not_checked():
    # 確認不能の判定ラベルは変えず、理由コード（HUMAN_ONLY・FUTURE）の行だけ「ご自身で確認」と呼ぶ。色・記号・文字の3重表記
    assert 'const HUMAN_VERDICT = ["v-human", "☑", "ご自身で確認"]' in JS
    assert 'const HUMAN_CODES = ["HUMAN_ONLY", "FUTURE"]' in JS
    assert ".v-human " in CSS and ".v-unk " in CSS
    assert "ご自身で確認" in JS and "確認不能" in JS


def test_a_run_that_switched_from_live_to_the_saved_run_resets_the_screen_and_says_why():
    block = JS.split("function onMode")[1].split("function onError")[0]
    assert "m.switched" in block and "resetResult()" in block
    assert "混み合っていて時間内に終わらなかったため、保存済みの結果を表示しています。" in JS  # 本人が承認した文面（統合ハブ案B）
    assert ".run-mode.switched" in CSS  # 目立たせる（通常の状態の行と同じ見た目にしない）


def test_the_result_shows_few_things_at_once_groups_are_closed_except_the_things_to_fix():
    """本人の指摘「認知負荷が高め」: 最初に開くのは「直す点」だけ。ご自身で確認・通過・確認不能・参考は件数だけ見せて畳む。
    カードは札と1行の見出しだけで、根拠の一文・確かめた結果は開いた時だけ。絞り込みの操作・「ほかに」の行・補足の重複は無い。"""
    assert "open: { fail: true }" in JS  # 最初に開く組は「直す点」だけ
    block = JS.split("function renderList")[1].split("function verdictNode")[0]
    assert 'el("details", { cls: "group c-" + tone' in block and "g.open = !!v.open[tone]" in block
    assert 'if (tone !== "fail") body.appendChild(el("p", { cls: "group-sub"' in block  # 「直す点」の組には補足の文を付けない（説明は1画面に1つ）
    row = JS.split("function rowNode")[1].split("function factsNode")[0]
    assert 'el("details", { cls: "rc" }' in row and 'cls: "rhead"' in row  # カードは開閉。札と1行の見出し
    assert "p.quote" not in row.split('cls: "rhead"')[1].split("const body")[0]  # 見出しの行に、引用の長文を置かない
    for gone in ("renderFilters", "FILTERS", "COMPACT_LIMIT", "hero-others", "showmore"):
        assert gone not in JS and gone not in HTML, gone
    assert 'id="filters"' not in HTML
    assert 'id="trust-band"' in HTML and re.search(r'<details id="trust-band"[^>]*\bhidden\b', HTML)  # 根拠・調べ方・仕込み・詳細は畳んだ開閉の部品


def test_the_headline_numbers_open_their_group_and_the_names_follow_the_ruling():
    block = JS.split("function renderHero")[1].split("function renderWarning")[0]
    assert 'openGroup(tone, true)' in block and '"ご自身で確認"' in block and '"通過"' in block
    assert "ほかに " not in JS and '"ほかに' not in JS  # 補足の行（「ほかに N 件」）は置かない（件数は組の見出しに出る）。要件一覧の説明文の「判定のほかに、…」は別
    assert "受け付けず" in JS  # 「棄却」でなく「受け付けず」


def test_the_zero_fix_headline_does_not_repeat_the_zero_count_and_the_attack_is_called_by_its_common_name():
    """本人の指摘: 直す点が0の時、見出し「直す点は見つかりませんでした」と数の「直す点 0」は同じことの繰り返し。
    見出しは「確かめた範囲では、問題なく通過しました。」（確かめていない項目まで通ったとは言わない）。
    「偽の命令」は分かりにくいので、画面・説明では「プロンプトインジェクション」と呼ぶ。"""
    block = JS.split("function renderHero")[1].split("function renderWarning")[0]
    assert '"確かめた範囲では、問題なく通過しました。"' in block
    assert "直す点は見つかりませんでした" not in JS
    for name, text in UI_FILES.items():
        assert "偽の命令" not in text, name
    assert "プロンプトインジェクション" in JS and "プロンプトインジェクション" in HTML


def test_the_requirement_list_is_a_closed_band_built_from_the_record_and_copying_is_only_for_the_fictional_examples():
    """本人の裁定（10/8 夜）: 結果に「要件一覧（N件）」の開閉の帯を足す（最初は閉じる・サーバーと Reader は触らない）。
    保存済みの実行では「最大40件・引用は80字まで」を必ず出す。Markdown の一括コピーは架空の例（②③）だけ（実在の主催者の要項の①には出さない）。"""
    assert re.search(r'<details id="reqlist-band"[^>]*\bhidden\b', HTML) and 'id="reqlist-summary"' in HTML and 'id="reqlist-copy"' in HTML
    assert re.search(r'<div id="reqlist-actions"[^>]*\bhidden\b', HTML)  # コピーのボタンの置き場は、既定で隠れている
    block = JS.split("function renderReqList")[1].split("function mdCell")[0]
    assert '"要件一覧（" + fmt(rows.length) + "件）"' in block and "要項の要件一覧" not in JS  # 見出しに「要項の」は付けない
    assert "保存済みの実行のため、最大40件・引用は80字までです。" in block and "!state.live" in block
    assert "p.fictional === true" in block and "$(\"reqlist-actions\").hidden = !canCopy" in block  # コピーは架空の例だけ
    assert "band.open = specOnly" in block  # 最初は閉じる（要項モードだけは一覧が結果そのものなので開く）
    assert "navigator.clipboard" in JS and "コピーできませんでした" in JS  # 失敗した時は、できなかったと言う
    assert '"reqlist-band"' in JS.split("function resetResult")[1].split("function onMode")[0]  # 新しい実行では帯を隠す


def test_the_github_result_is_drawn_from_fixed_sentences_labels_and_counts_only_and_the_run_box_comes_back():
    """GitHub の基本点検の結果（kind=repo_audit）は、固定文・ラベル・件数・取得の状態だけを描く。要項の要件・引用・一覧の部品は使わない。
    押せない数（クリックで一覧を開く先が無い）。実行の記録が無いので隠し、次の実行で戻す。エラーの固定文は、コードから引く。"""
    assert 'rec.kind === "repo_audit"' in JS.split("function renderResult")[1].split("function renderHero")[0]
    block = JS.split("function renderRepoAudit")[1].split("function renderWarning")[0]
    assert "it.title_ja" in block and "it.reason_ja" in block and "renderHero(rec, rows, true)" in block
    for gone in ("original_span", "quote", "rec.requirements", "rec.verdicts", "readme", "README の中身"):
        assert gone not in block, gone
    assert "AIは使っていません" in block and "AIには渡していません" in block
    assert '$("run-box").hidden = true' in block and '$("run-box").hidden = false' in JS.split("function resetResult")[1].split("function onMode")[0]
    for code in ("JUDGE_REQUIRED", "INVALID_INPUT", "QUOTA"):
        assert code + ":" in JS.split("const ERROR_JA")[1].split("};")[0], code
    assert "async function errorCode" in JS and "ERROR_JA[code]" in JS


def test_the_spec_only_mode_shows_just_the_requirement_list_opened_with_copy_and_no_verdicts():
    """要項モード（本人の裁定 A-min）: 審査員コード用の⑤カード。URL 欄は GitHub と同じ1つを使い回す（入れる物が変わる時は空にする）。
    結果は要件の一覧だけ（開いた状態・Markdown のコピー付き）。直す点・判定の数・根拠の帯は出さない。"""
    assert set(re.findall(r"^    (\w+): \[", JS.split("const URL_PRESETS")[1].split("};")[0], re.M)) == {"github_repo", "spec_url"}
    assert 'rec.kind === "spec_only"' in JS.split("function renderResult")[1].split("function renderHero")[0]
    block = JS.split("function renderSpecOnly")[1].split("function renderWarning")[0]
    assert "renderReqList(rec, rows)" in block and "clear($(\"summary\"))" in block and "判定はしていません" in block
    for gone in ("renderHero", "renderTrust", "renderPlanted", "renderList()"):
        assert gone not in block, gone
    rl = JS.split("function renderReqList")[1].split("function mdCell")[0]
    assert "p.fictional === true || specOnly" in rl and "band.open = specOnly" in rl
    assert "body.spec_urls = urls" in JS and 'state.selected === SPEC_PRESET && !specUrls()' in JS
    assert "rec.skipped_pages" in block and "max_urls" in JS  # 読めなかったページは何番目かと理由の固定文だけ。件数の上限はサーバーの値
    assert 'if (state.urlFor !== id) $("repo-url").value = ""' in JS


def test_a_saved_run_does_not_draw_the_time_gauge_because_its_cap_may_differ_from_todays():
    block = JS.split("function renderBudget")[1].split("function jumpTo")[0]
    assert "withTime" in block and 'key === "wall_ms_left" && !withTime' in block


def test_an_aborted_result_says_no_verdict_was_made_instead_of_claiming_nothing_to_fix():
    block = JS.split("function renderHero")[1].split("function renderWarning")[0]
    assert 'rec.status === "ABORTED"' in block and "実行を中止したため、判定は出していません。" in block


def test_the_replan_and_who_bands_use_only_text_nodes_and_the_replay_has_no_hidden_text():
    # 帯の描画は textContent／createTextNode だけ（innerHTML 等は上のテストが全体で禁じる）。同梱の記録に、見えない文字（Cf・制御文字）が無い
    for pid in ("sample_defect", "sample_injection"):
        text = (REPLAY / f"{pid}.json").read_text(encoding="utf-8")
        assert not re.search(r"[​-‏‪-‮⁠-⁤﻿]", text), pid


def test_the_live_progress_line_is_replaced_when_the_result_arrives():
    """本番の実行で見つかった表示の残り: 結果が出た後も「ライブ実行中です」のままだった。"""
    block = JS.split("function renderResult")[1].split("function renderHero")[0]
    assert 'state.live) $("run-mode").textContent = "ライブ実行の結果です。"' in block
    assert "保存済みの実行を再生しています" not in JS  # 終わった後に「再生しています」と言わない


def test_the_spec_sentence_can_be_opened_on_the_original_page_with_a_text_fragment():
    # 確かめていない行（ご自身で確認・確認不能）は、要項の元のページの、その一文の場所を別のタブで開ける。
    # URL は例の既知のリンク（presets[].links）だけから作り、記録の文字列から URL を作らない
    block = JS.split("function specPageHref")[1].split("function showSource")[0]
    assert "state.presets[state.view.rec.preset_id]" in block and '#:~:text=' in block
    assert '"official", "spec", "faq"' in block and 'd.role !== "spec"' in block
    assert 'rel: "noopener noreferrer"' in block and 'target: "_blank"' in block
    assert 'replace(/-/g, "%2D")' in block  # テキストフラグメントの区切り文字を本文の中で使わせない


def test_the_human_rows_can_be_ticked_without_storing_anything():
    row = JS.split("function rowNode")[1].split("function factsNode")[0]
    assert 'x.tone === "human"' in row and 'type: "checkbox"' in row and "e.stopPropagation()" in row
    assert 'checked[x.r.req_id] ? "☑ " : "□ "' in JS  # コピーするチェックリストにも印が載る
    for bad in ("localStorage", "sessionStorage", "document.cookie"):
        assert bad not in JS
