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


def test_there_is_no_input_field_only_preset_cards_and_one_run_button():
    p = _parsed()
    assert not any(t in ("input", "textarea", "select", "form") for t, _ in p.tags)
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
        assert rec["mode"] == "REPLAY" and rec["reader_model"] == "oracle-reader"  # 台本の Reader で作ったと分かる
        text = p.read_text(encoding="utf-8")
        assert "まちの落とし物マップ" not in text  # 提出物の本文（説明文）は記録に無い
        assert gen.INJECTION_TEXT not in text  # 偽の命令の本文も無い（スニペットはエスケープした60字まで）


def test_the_leak_patterns_are_live_positive_controls():
    """漏洩 CI が実際に検出できること（何も見ていない検査で緑にならない）。"""
    host = "x" + "." + "a.run" + ".app"
    hits = scan_text(f"連絡先 someone@example.invalid と https://svc-{host}/ と AIza{'A' * 35} と 10.1.2.3")
    assert {"email", "service_url", "google_api_key", "private_ip"} <= set(hits)
