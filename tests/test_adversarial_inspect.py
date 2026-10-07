"""敵対レビュー: 検査（http_probe・認証壁・字数・署名・窓口）を疑う。

各テストは「弱点の再現」で、修正前は落ちていた（番号は報告の通し番号）。
  A1  「Googleでログイン」だけの画面（password 欄もフォームも無い）を「ログイン不要で開ける」と判定していた
  A2  Flutter / Angular など描画先の印が無い JS 描画の殻を「開ける」と判定していた
  A3  <meta refresh> の行き先（非ログインのパス・外部 IdP）を見ずに「開ける」と判定していた
  A4  先頭 64KB で打ち切られた短い本文を「開ける」と判定していた
  A5  UTF-16（BOM・charset 宣言）のログイン画面を読めず「開ける」と判定していた
  A6  同じ属性の重複（type="password" type="text"）で password 欄を隠せた（ブラウザは先頭の属性を採る）
  A7  パーサの食い違い（<![CDATA[>…、<!-->…）で password 欄を隠せた
  A8  403（取得元IPを弾くWAFと区別できない）を「不適合」にしていた
  A9  同じURLの観測が食い違っても（1回目は壁・2回目は開く）、最新の観測だけで「適合」にしていた
  A10 転送先のパスにある UUID・APIキー・メールの断片が facts（保存・再生される記録）に残っていた
  A11 タイトル・名称・コメントの字数上限を、提出物の本文全体の上限として使い「不適合」にしていた
  A12 「（英語は400語以内）」のような別の単位の上限を無視していた
  A13 「全角800字」を半角1字=1字で数えて「不適合」にしていた
  A14 要項側の文書を字数の測定対象に選べてしまった（窓口）
  A15 全角英字の「Ｓｉｇｎ ｉｎ」でログインの語をすり抜けられる／逆に「ログイン不要」を壁と取り違える（防御を足した側の誤判定）
  A16 文字が見えない画面・iframe だけの画面（画像・別サービスの埋め込み）を「開ける」と判定していた
  A17 取得結果の組み合わせを乱数で作っても、観測の組み立てが落ちない（facts は16件まで・URL を載せない）
  A20 HTTP 200 で返る「アクセスできません」「見つかりません」の短い画面（ソフト403・ソフト404）を「開ける」と判定していた
"""
import pytest

import app.contracts as C
from app.adjudicate import adjudicate
from app.checks.auth_wall import check_auth_wall, path_fact
from app.checks.cloud_run_signature import check_cloud_run_signature
from app.checks.html_signals import analyze_html, decode_body
from app.checks.http_probe import http_probe, observe_probe
from app.checks.registry import CheckContext, run_checker
from app.checks.text_length import check_text_length, count_chars, extract_limit, measure
from app.textsafe import BLOCK_SEP
from tests.factories import make_doc, make_verified
from tests.fetch_fakes import (
    CLOUD_RUN_URL,
    FakeFetchPort,
    SleepRecorder,
    make_result,
    redirect,
)

L = C.VerdictLabel
U = C.UnverifiableReason
LONG = "<p>" + "あ" * 600 + "</p>"
PW_FORM = '<h1>ログイン</h1><form action="/session" method="post"><input type="password" name="p"></form>'
GFE = {"content-type": "text/html", "server": "Google Frontend"}


def obs_of(result, **kw):
    return observe_probe(result, obs_id="O1", **kw)


def shape(o):
    return (o.code, o.outcome, o.strong, o.facts["access"])


def inconclusive(o):
    return o.outcome is C.ObsOutcome.INCONCLUSIVE and not o.strong


def verdict_of_probe(result, *, req_class=C.CheckClass.AUTH_WALL):
    """取得結果 → 観測 → run_check → 判定表。「適合」と言われたら負け、の確認に使う。"""
    spec = make_doc("D1", "提出URLは審査員がログインなしで開けること。")
    req = make_verified("R2", doc=spec, needle="提出URLは審査員がログインなしで開けること。", check_class=req_class)
    probe = obs_of(result)
    ctx = CheckContext(docs={}, probes=(probe,))
    checker = C.CHECK_CLASS_CHECKER[req_class]
    obs = run_checker(checker, req, ctx, "O2")
    (v,) = adjudicate(C.AdjudicationInput(requirements=(req,), docs=(spec.meta(),), observations=(probe, obs)))
    return v


# ---------------------------------------------------------------------------
# A1: ログインを促すだけの画面
# ---------------------------------------------------------------------------
SSO_ONLY = [
    "<html><head><title>Sign in</title></head><body><a href='/auth/google'>Sign in with Google</a></body></html>",
    "<html><head><title>ログイン</title></head><body><button onclick=\"go()\">Googleでログイン</button></body></html>",
    "<body><h1>Welcome</h1><p>Please sign in to continue.</p><a href='/start'>Continue</a></body>",
]


@pytest.mark.parametrize("body", SSO_ONLY)
def test_a1_a_page_that_only_asks_to_sign_in_is_not_called_open(body):
    o = obs_of(make_result(body=body))
    assert (o.code, o.outcome, o.strong) == (C.ObsCode.AUTH_WALL, C.ObsOutcome.INCONCLUSIVE, False)
    assert o.facts["access"] == "login_prompt"
    v = verdict_of_probe(make_result(body=body))
    assert v.label is L.UNVERIFIABLE and v.reason_code is U.NEEDS_AUTH


@pytest.mark.parametrize(
    "body",
    [
        f"<header><nav><a href='/login'>ログイン</a></nav></header>{LONG}",  # 内容のあるページの見出しにあるログイン導線
        "<html><head><title>ようこそ</title></head><body>" + "<p>" + "この作品はテキストを要約します。" * 20 + "</p><a href='/login'>ログイン</a></body></html>",
        "<title>ログインのしかた</title>" + LONG,  # 題名にログインがあっても、長い説明ページは壁ではない
        "<body><h1>ログイン不要で試せます</h1><p>今すぐ始める</p></body>",  # 短い画面でも、ログインを求めていない言い回しは壁の印ではない
        "<body><p>No sign in required. Just try it.</p><a href='/start'>Start</a></body>",
        "<body><p>Use it without logging in.</p><a href='/start'>Start</a></body>",
    ],
)
def test_a1_positive_control_a_content_page_with_a_login_link_is_still_open(body):
    assert obs_of(make_result(body=body)).code is C.ObsCode.NO_AUTH_WALL


# ---------------------------------------------------------------------------
# A2: 描画先の印が無い JS 描画の殻
# ---------------------------------------------------------------------------
SHELLS = [
    '<html><body><script src="flutter_bootstrap.js" async></script></body></html>',  # Flutter
    '<html><body><app-root></app-root><script src="main.js" type="module"></script></body></html>',  # Angular
    '<html><body><script type="module" src="/assets/index.js"></script></body></html>',  # Svelte / Vite（描画先 id 無し）
    '<body><my-app></my-app><script src="/a.js"></script></body>',  # Web Components
    "<body><app-root>読み込み中...</app-root><script src='main.js'></script></body>",  # 読み込み中の文言だけある（描画先の印はカスタム要素）
]


@pytest.mark.parametrize("body", SHELLS)
def test_a2_a_script_only_shell_without_a_mount_id_is_spa_shell(body):
    o = obs_of(make_result(body=body))
    assert shape(o) == (C.ObsCode.SPA_SHELL, C.ObsOutcome.INCONCLUSIVE, False, "spa_shell")
    v = verdict_of_probe(make_result(body=body))
    assert v.label is L.UNVERIFIABLE and v.reason_code is U.NEEDS_JS


@pytest.mark.parametrize(
    "body",
    [
        "<body><p>準備中です</p><script>ga('send')</script></body>",  # 短い静的ページ＋解析用の script
        f"<body><app-root>{'あ' * 300}</app-root><script src='/a.js'></script></body>",  # 本文のあるサーバー描画
        "<body><p>こんにちは</p></body>",  # script の無い短い静的ページ
    ],
)
def test_a2_positive_control_static_and_server_rendered_pages_are_open(body):
    assert obs_of(make_result(body=body)).code is C.ObsCode.NO_AUTH_WALL


# ---------------------------------------------------------------------------
# A3: <meta refresh> の行き先
# ---------------------------------------------------------------------------
def test_a3_meta_refresh_to_an_ordinary_path_hides_the_real_destination():
    o = obs_of(make_result(body='<html><head><meta http-equiv="refresh" content="0; url=/app/"></head><body></body></html>'))
    assert shape(o) == (C.ObsCode.BLOCKED, C.ObsOutcome.INCONCLUSIVE, False, "unknown_redirect")
    assert o.facts["unfollowed"] is True
    v = verdict_of_probe(make_result(body='<meta http-equiv="refresh" content="0; url=/app/">'))
    assert v.label is L.UNVERIFIABLE and v.reason_code is U.OUT_OF_SCOPE


@pytest.mark.parametrize(
    "url",
    ["https://tenant.auth0.com/", "https://acme.okta.com/app/x", "https://sso.example.invalid/saml", "https://other.example.invalid/x?client_id=abc&response_type=code"],
)
def test_a3_meta_refresh_to_an_identity_provider_is_a_wall_whatever_the_path(url):
    o = obs_of(make_result(body=f'<meta http-equiv="refresh" content="0; url={url}">'))
    assert shape(o) == (C.ObsCode.AUTH_WALL, C.ObsOutcome.FAIL, True, "idp_redirect")
    assert o.facts["redirect_status"] == 0
    dumped = o.model_dump_json()
    assert "auth0" not in dumped and "okta" not in dumped and "client_id" not in dumped


@pytest.mark.parametrize(
    "markup",
    [
        '<meta http-equiv="refresh" content="300">',  # 再読み込みだけ（転送ではない）
        '<meta http-equiv="refresh" content="5; url=/fx/defect/submission/">',  # 自分自身へ
        '<meta http-equiv="refresh" content="600; url=/app/">',  # 十分に長い待ち時間（内容が先に見える）
        '<meta name="refresh" content="0; url=/app/">',  # http-equiv ではない
    ],
)
def test_a3_positive_control_reloading_the_same_page_is_not_a_redirect(markup):
    assert obs_of(make_result(body=f"{markup}{LONG}")).code is C.ObsCode.NO_AUTH_WALL


def test_a3_a_slow_refresh_to_a_login_path_does_not_hide_the_content_that_is_shown_first():
    """10分後にログインへ飛ぶ（セッション切れの案内など）だけなら、内容が先に見える。待ちが短い転送だけを壁とする。"""
    markup = '<meta http-equiv="refresh" content="600; url=/login">'
    assert obs_of(make_result(body=f"{markup}{LONG}")).code is C.ObsCode.NO_AUTH_WALL


# ---------------------------------------------------------------------------
# A4: 先頭 64KB での打切り
# ---------------------------------------------------------------------------
def _truncated(body: str, **kw):
    return make_result(body=body, truncated=True, limit_hit=C.FetchLimit.PROBE_PREFIX, **kw)


def test_a4_a_probe_cut_at_64kb_with_little_text_so_far_cannot_say_nobody_has_to_log_in():
    body = "<html><head><style>" + "a{b:c}" * 9000 + "</style></head><body><p>hello</p>"
    o = obs_of(_truncated(body))
    assert shape(o) == (C.ObsCode.ERROR, C.ObsOutcome.INCONCLUSIVE, False, "probe_partial")
    v = verdict_of_probe(_truncated(body))
    assert v.label is L.UNVERIFIABLE and v.reason_code is U.TRUNCATED


def test_a4_positive_control_a_cut_page_with_plenty_of_text_is_still_open():
    o = obs_of(_truncated(LONG * 4))  # 2,400字を読めた。ログイン画面ではない
    assert o.code is C.ObsCode.NO_AUTH_WALL


def test_a4_a_cut_page_that_already_shows_a_login_form_is_still_a_wall():
    o = obs_of(_truncated(PW_FORM))
    assert o.code is C.ObsCode.AUTH_WALL and o.outcome is C.ObsOutcome.FAIL


# ---------------------------------------------------------------------------
# A5: 文字コード
# ---------------------------------------------------------------------------
PW_PAGE = '<html><body><h1>login</h1><form action="/s"><input type="password" name="p"></form></body></html>'


@pytest.mark.parametrize(
    ("raw", "ctype"),
    [
        (PW_PAGE.encode("utf-16"), "text/html"),  # BOM 付き（宣言なし）
        (PW_PAGE.encode("utf-16-le"), "text/html; charset=utf-16"),
        (PW_PAGE.encode("utf-16-le"), "text/html; charset=UTF-16LE"),
        (PW_PAGE.encode("utf-16-be"), "text/html; charset=utf-16be"),
        (b"\xef\xbb\xbf" + PW_PAGE.encode("utf-8"), "text/html"),  # UTF-8 の BOM
        (b"\xef\xbb\xbf" + PW_PAGE.encode("utf-8"), "text/html; charset=shift_jis"),  # BOM は宣言に勝つ（ブラウザと同じ）
    ],
)
def test_a5_login_pages_in_other_encodings_are_still_login_pages(raw, ctype):
    assert analyze_html(raw, ctype).has_password_input is True
    o = obs_of(make_result(body=raw, headers={"content-type": ctype}))
    assert shape(o) == (C.ObsCode.AUTH_WALL, C.ObsOutcome.FAIL, True, "login_form")


def test_a5_a_bom_beats_the_declared_charset_like_a_browser():
    assert decode_body(b"\xef\xbb\xbf" + "ログイン".encode(), "text/html; charset=shift_jis") == "ログイン"
    assert decode_body("ログイン".encode("utf-16"), "text/html; charset=shift_jis") == "ログイン"


def test_a5_decode_body_still_refuses_non_text_codecs():
    assert decode_body("あ".encode("utf-8"), "text/html; charset=rot13") == "あ"
    assert decode_body(b"abc", "text/html; charset=utf-16") != "abc"  # 奇数長・不正でも例外にしない


# ---------------------------------------------------------------------------
# A6・A7: パーサの食い違いで password 欄を隠す
# ---------------------------------------------------------------------------
DUP_ATTRS = [
    '<h1>Login</h1><form action="/s"><input type="password" type="text" name="p"></form>',  # 先頭の type が有効
    '<h1>Login</h1><form action="/s"><input style="" style="display:none" type="password" name="p"></form>',  # 先頭の style が有効
    '<h1>Login</h1><form action="/s"><input type="password" hidden="" name="p"></form>',  # これは本当に隠れている（対照）
]


def test_a6_the_first_attribute_wins_like_a_browser():
    assert analyze_html(DUP_ATTRS[0].encode(), "text/html").has_password_input is True
    assert analyze_html(DUP_ATTRS[1].encode(), "text/html").has_password_input is True
    assert analyze_html(DUP_ATTRS[2].encode(), "text/html").has_password_input is False  # hidden は隠れている
    assert analyze_html(b'<input type="text" type="password">', "text/html").has_password_input is False  # 逆向きは password ではない
    o = obs_of(make_result(body=DUP_ATTRS[0]))
    assert shape(o) == (C.ObsCode.AUTH_WALL, C.ObsOutcome.FAIL, True, "login_form")


HEAD = "<h1>Account</h1><p>please enter your details below to continue</p>"  # ログインの語を含まない（語の判定に助けられないように）
PARSER_TRICKS = [
    HEAD + '<form action="/s"><![CDATA[><input type=password name=p>]]></form>',  # ブラウザは壊れたコメント扱い（> で終わる）
    HEAD + "<!--><input type=password name=p>--><p>x</p>",  # <!--> は空のコメント
    HEAD + "<!---><input type=password name=p>--><p>x</p>",
    HEAD + '<form action="/s"><!-- x --!><input type=password name=p></form>',  # --!> でコメントが閉じる
    HEAD + "<textarea/><input type=password name=p>",  # <textarea/> は自己終了にならない（ブラウザでは入力欄が続きの文字になる）
    HEAD + "<textarea><script></textarea><input type=password name=p><script></script>",  # script と見えて、実は textarea の中身
    HEAD + "<title><style></title><input type=password name=p><style></style>",
    HEAD + "<![CDATA[><input type=p&#x61;ssword name=p>]]>",  # 文字参照と CDATA の併用
]


@pytest.mark.parametrize("body", PARSER_TRICKS)
def test_a7_a_password_field_the_parser_cannot_see_is_never_reported_as_open(body):
    o = obs_of(make_result(body=body))
    assert o.code is not C.ObsCode.NO_AUTH_WALL, o
    # ログインの語に助けられず、password 欄として数えられた（強い壁）か、生の記述の照合で見つけた（不確定）かのどちらか。
    # どちらになるかは html.parser の版による（3.12 と 3.14 で、コメントの閉じ方などの解釈が違う）。「開ける」にだけはならない。
    assert o.facts["access"] in ("login_form", "form_unconfirmed"), o
    assert o.outcome is not C.ObsOutcome.PASS
    v = verdict_of_probe(make_result(body=body))
    assert v.label in (L.UNVERIFIABLE, L.FAIL), v


def test_a7_the_raw_hint_is_unconfirmed_so_it_never_makes_a_strong_wall():
    # <template> の中は、パーサがどの版でも入力欄と数えない（コメントの解釈のような版差が無い）。生の記述だけが残る
    o = obs_of(make_result(body=HEAD + "<template><input type=password name=p></template>"))
    assert o.outcome is C.ObsOutcome.INCONCLUSIVE and o.strong is False and o.facts["access"] == "form_unconfirmed"
    assert o.facts["has_password_input"] is False


@pytest.mark.parametrize(
    "body",
    [
        f"{LONG}<style>/* input[type=password] */</style>",  # 入力欄の記述ではない（CSS のセレクタ）
        f"<h1>パスワードの付け方</h1><p>input type=password という書き方は…</p>{LONG}",  # 文章としての言及
        f"<h1>書き方</h1><p>&lt;input type=&quot;password&quot;&gt; と書きます。</p>{LONG}",  # コード例を文章で見せている
        f'{LONG}<input type="text" data-type="password" placeholder="暗証番号">',  # 属性名の途中（data-type）は type ではない
    ],
)
def test_a7_positive_control_mentions_of_a_password_input_in_prose_are_not_hints(body):
    o = obs_of(make_result(body=body))
    assert o.code is C.ObsCode.NO_AUTH_WALL and o.facts["has_password_input"] is False


def test_a7_a_login_form_assembled_in_a_script_string_is_unconfirmed_not_open():
    """許容する損失: script の文字列に入力欄の HTML があるページは、囲まれている文脈を問わず不確定にする。"""
    o = obs_of(make_result(body=f"{LONG}<script>var t = '<input type=\"password\">';</script>"))
    assert o.outcome is C.ObsOutcome.INCONCLUSIVE and o.facts["access"] == "form_unconfirmed"


def test_a7_the_hint_scan_stays_linear_on_hostile_input():
    import time

    hostile = ("<input " * 9000 + "<script " * 100).encode()  # 先頭 64KB 内で閉じない開始タグが並ぶ
    t0 = time.perf_counter()
    analyze_html(hostile, "text/html")
    analyze_html(("<script>" + "<input type=" * 5000).encode(), "text/html")
    assert time.perf_counter() - t0 < 2.0


# ---------------------------------------------------------------------------
# A8: 403
# ---------------------------------------------------------------------------
def test_a8_403_from_an_ordinary_host_cannot_be_told_from_a_firewall_so_it_is_left_to_a_human():
    o = obs_of(make_result(status=403, body=b"", headers={"content-type": "text/html", "server": "cloudflare"}))
    assert (o.code, o.outcome, o.strong, o.facts["access"]) == (C.ObsCode.AUTH_WALL, C.ObsOutcome.INCONCLUSIVE, False, "http_403")
    v = verdict_of_probe(make_result(status=403, body=b"", headers={"content-type": "text/html"}))
    assert (v.label, v.reason_code) == (L.UNVERIFIABLE, U.HUMAN_ONLY)


def test_a8_403_from_a_cloud_run_default_domain_is_the_iam_wall_and_stays_a_fail():
    r = make_result(CLOUD_RUN_URL, status=403, body=b"", headers=GFE)
    o = obs_of(r)
    assert (o.code, o.outcome, o.strong, o.facts["access"]) == (C.ObsCode.AUTH_WALL, C.ObsOutcome.FAIL, True, "http_403")
    assert verdict_of_probe(r).label is L.FAIL


def test_a8_403_from_a_cloud_run_domain_without_the_google_frontend_marker_is_not_trusted():
    r = make_result(CLOUD_RUN_URL, status=403, body=b"", headers={"content-type": "text/html", "server": "nginx"})
    assert obs_of(r).outcome is C.ObsOutcome.INCONCLUSIVE


# ---------------------------------------------------------------------------
# 試して欠陥が無かった偽装（回帰の固定）: Cloud Run 署名はホストの細工では立たない
# ---------------------------------------------------------------------------
_RUN = "." + "run" + ".app"  # ソースに run.app 系ホストを書かない規約（test_layout）のため連結
_SPOOFS = {
    "userinfo": ("https://x" + _RUN + "@evil.example.invalid/", GFE),
    "path": ("https://evil.example.invalid/x" + _RUN + "/", GFE),
    "suffix": ("https://x" + _RUN + ".evil.example.invalid/", GFE),
    "trailing_dot": ("https://x" + _RUN + "./", GFE),
    "gfe_header_on_other_host": ("https://svc.example.invalid/fx/defect/submission/", GFE),
    "404_page": ("https://x" + _RUN + "/", GFE),
}


@pytest.mark.parametrize("name", list(_SPOOFS))
def test_cloud_run_signature_is_not_spoofed_by_host_tricks(name):
    url, headers = _SPOOFS[name]
    status = 404 if name == "404_page" else 200
    probe = observe_probe(make_result(url, status=status, body=LONG if status == 200 else b"", headers=headers), obs_id="O1")
    o = check_cloud_run_signature(make_verified("R4", check_class=C.CheckClass.RUNTIME_SIGNATURE), [probe], "O2")
    assert (o.code, o.outcome, o.strong) == (C.ObsCode.SIGNATURE_ABSENT, C.ObsOutcome.INCONCLUSIVE, False)


def test_cloud_run_signature_is_not_claimed_when_the_run_app_host_only_redirects_away():
    x = "https://x" + _RUN + "/"
    hop = redirect(frm=x, location="https://evil.example.invalid/", followed=False, blocked_policy=C.PolicyId.SCOPE)
    probe = observe_probe(make_result(x, status=302, body=b"", redirects=(hop,), final_url=x, headers=GFE), obs_id="O1")
    o = check_cloud_run_signature(make_verified("R4", check_class=C.CheckClass.RUNTIME_SIGNATURE), [probe], "O2")
    assert o.code is C.ObsCode.BLOCKED and o.outcome is C.ObsOutcome.INCONCLUSIVE  # 転送の行き先は提出物の本体かもしれない


# ---------------------------------------------------------------------------
# A9: 同じURLの観測が食い違う（先に壁・後に開く／逆）
# ---------------------------------------------------------------------------
def _open(obs_id="O2"):
    return observe_probe(make_result(body=LONG), obs_id=obs_id)


def _req():
    return make_verified("R2", check_class=C.CheckClass.AUTH_WALL)


@pytest.mark.parametrize("order", ["wall_then_open", "open_then_wall"])
def test_a9_a_flapping_submission_is_not_judged_by_the_latest_probe_alone(order):
    wall = observe_probe(make_result(redirects=(redirect(),), body=PW_FORM), obs_id="O1")
    opened = _open("O2")
    probes = [wall, opened] if order == "wall_then_open" else [opened, wall]
    o = check_auth_wall(_req(), probes, "O9")
    assert (o.code, o.outcome, o.strong) == (C.ObsCode.ERROR, C.ObsOutcome.INCONCLUSIVE, False)
    assert o.facts["reason"] == "probe_conflict"


def test_a9_a_signature_that_flips_between_probes_is_not_a_signature():
    served = observe_probe(make_result(CLOUD_RUN_URL, body=LONG, headers=GFE), obs_id="O1")  # 1回目: run.app・200
    iam = observe_probe(make_result(CLOUD_RUN_URL, status=403, body=b"", headers=GFE), obs_id="O2")  # 2回目: 403 に変わった
    req = make_verified("R4", check_class=C.CheckClass.RUNTIME_SIGNATURE)
    for probes in ([served, iam], [iam, served]):
        o = check_cloud_run_signature(req, probes, "O8")
        assert (o.outcome, o.strong) == (C.ObsOutcome.INCONCLUSIVE, False) and o.facts["reason"] == "probe_conflict"
    again = observe_probe(make_result(CLOUD_RUN_URL, body=LONG, headers=GFE), obs_id="O3")
    assert check_cloud_run_signature(req, [served, again], "O9").code is C.ObsCode.SIGNATURE_PRESENT  # 一致していれば従来どおり


def test_a9_end_to_end_a_flapping_probe_gives_unverifiable_not_a_pass():
    wall = observe_probe(make_result(redirects=(redirect(),), body=PW_FORM), obs_id="O1")
    opened = _open("O2")
    spec = make_doc("D1", "提出URLは審査員がログインなしで開けること。")
    req = make_verified("R2", doc=spec, needle="提出URLは審査員がログインなしで開けること。", check_class=C.CheckClass.AUTH_WALL)
    o = check_auth_wall(req, [wall, opened], "O3")
    (v,) = adjudicate(C.AdjudicationInput(requirements=(req,), docs=(spec.meta(),), observations=(wall, opened, o)))
    assert v.label is L.UNVERIFIABLE and "食い違" in v.reason


def test_a9_a_transient_failure_followed_by_a_clean_probe_is_still_a_clean_probe():
    transient = observe_probe(make_result(status=503, headers={}, body=b""), obs_id="O1")
    o = check_auth_wall(_req(), [transient, _open("O2")], "O9")
    assert o.code is C.ObsCode.NO_AUTH_WALL


_SUSPECT_ONLY = (C.ObsOutcome.INCONCLUSIVE,)
# html.parser の版で割れる: 古い版は「<!-->」の中の入力欄が見えず不確定（疑い）、3.13 のセキュリティ更新以降は
# 空のコメントとして読み、入力欄を見つけて強い壁（FAIL）にする（10/7 に本番と同じ 3.13.16 で実測）。どちらでも「開ける」にはならない
_SUSPECT_OR_WALL = (C.ObsOutcome.INCONCLUSIVE, C.ObsOutcome.FAIL)


@pytest.mark.parametrize(
    ("suspicious", "allowed_outcomes"),
    [
        (make_result(status=403, body=b"", headers={"content-type": "text/html"}), _SUSPECT_ONLY),  # 取得元を弾く（認証か WAF か不明）
        (make_result(body="<title>Sign in</title><a href='/a'>Sign in with Google</a>"), _SUSPECT_ONLY),  # ログインを促す画面
        (make_result(body="<h1>Login</h1><!--><input type=password>-->"), _SUSPECT_OR_WALL),  # パーサに見えるかが版で割れる記述
    ],
    ids=["403", "login_prompt", "form_unconfirmed"],
)
def test_a9_an_open_probe_next_to_a_wall_suspecting_probe_is_not_a_clean_pass(suspicious, allowed_outcomes):
    """合格の観測と、壁の疑い（不確定）の観測が同居したら、合格を採らない（応答が揺れている）。"""
    wall_like = observe_probe(suspicious, obs_id="O1")
    assert wall_like.code is C.ObsCode.AUTH_WALL and wall_like.outcome in allowed_outcomes
    for probes in ([wall_like, _open("O2")], [_open("O2"), wall_like]):
        o = check_auth_wall(_req(), probes, "O9")
        assert o.facts["reason"] == "probe_conflict" and o.outcome is C.ObsOutcome.INCONCLUSIVE


def test_a9_wall_suspecting_probes_alone_or_with_a_transient_failure_are_not_a_conflict():
    s403 = observe_probe(make_result(status=403, body=b"", headers={"content-type": "text/html"}), obs_id="O1")
    transient = observe_probe(make_result(status=503, headers={}, body=b""), obs_id="O2")
    assert check_auth_wall(_req(), [s403, transient], "O9").facts.get("reason") != "probe_conflict"  # 合格が無いので割れではない
    assert check_auth_wall(_req(), [transient, _open("O3")], "O9").code is C.ObsCode.NO_AUTH_WALL


def test_a9_two_agreeing_probes_are_not_a_conflict():
    o = check_auth_wall(_req(), [_open("O1"), _open("O2")], "O9")
    assert o.code is C.ObsCode.NO_AUTH_WALL


# ---------------------------------------------------------------------------
# A10: 転送先のパスから、秘密やIDを facts に残さない
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("path", "leaked"),
    [
        ("/login/550e8400-e29b-41d4-a716-446655440000", "550e8400"),
        ("/signin/" + "AI" + "zaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY", "9tSrke72"),  # APIキーの形（ソースに鍵の形を書かない規約のため連結）
        ("/login/john.doe@example.com", "john"),
        ("/auth/sessions/4f9c2d7a1b3e", "4f9c2d7a"),
        ("/login/Zm9vYmFyYmF6cXV4", "Zm9v"),
        ("/login/this-submission-is-fully-compliant-ok", "compliant"),  # 提出物の側が決められる文が、そのまま証拠チップに出ない
    ],
)
def test_a10_paths_in_facts_keep_the_login_shape_but_not_identifiers(path, leaked):
    p = path_fact(path)
    assert leaked not in p and p.startswith("/")
    o = obs_of(make_result(status=302, redirects=(redirect(location=path, followed=False, blocked_policy=C.PolicyId.SCOPE),), final_url="https://svc.example.invalid/fx/defect/submission/", body=b""))
    assert o.code is C.ObsCode.AUTH_WALL and leaked not in o.model_dump_json()


@pytest.mark.parametrize("path", ["/login", "/fx/defect/login/", "/users/sign_in", "/wp-login.php", "/oauth2/authorize", "/saml2/idp", "/.well-known/openid-configuration", "/en/auth"])
def test_a10_positive_control_ordinary_login_paths_stay_readable(path):
    assert path_fact(path) == path


# ---------------------------------------------------------------------------
# A19: 転送先の読み方をブラウザに揃える（読み方が割れると IdP への転送を見落とす）
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "location",
    [
        "\\\\accounts.google.com\\o\\oauth2\\v2",  # \\host\path はブラウザでは //host/path
        "https://%61ccounts.google.com/o/oauth2/auth",  # ホストの % 符号化
        "HTTPS://ACCOUNTS.GOOGLE.COM/",
        " \thttps://login.example.invalid/x\n",  # 前後の空白・制御文字
    ],
)
def test_a19_odd_spellings_of_an_identity_provider_redirect_are_still_a_wall(location):
    hop = redirect(location=location, followed=False, blocked_policy=C.PolicyId.SCOPE)
    o = obs_of(make_result(status=302, redirects=(hop,), final_url="https://svc.example.invalid/fx/defect/submission/", body=b""))
    assert shape(o) == (C.ObsCode.AUTH_WALL, C.ObsOutcome.FAIL, True, "idp_redirect"), location


# ---------------------------------------------------------------------------
# A11・A12・A13: 字数の上限の読み取り
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "quote",
    [
        "タイトルは50字以内とする。",
        "作品名は30文字以内で入力してください。",
        "コメントは140文字以内。",
        "プロジェクト名：最大40字",
        "キャッチコピーは30字以内で記載すること。",
        "The title must be within 60 characters.",
        "Tagline: up to 80 characters.",
    ],
)
def test_a11_a_limit_for_a_short_field_is_not_a_limit_for_the_whole_page(quote):
    spec = extract_limit(quote)
    assert spec.limit is None and spec.reason == "other_subject"


@pytest.mark.parametrize(
    ("quote", "limit"),
    [
        ("説明は800字以内とする。", 800),
        ("プロジェクトの概要を800字以内で記載してください。", 800),
        ("タイトルを含め、概要は800字以内。", 800),  # 題名の語があっても、説明が対象
        ("Describe the project in 500 characters or fewer.", 500),
        ("800字以内で記載すること。", 800),  # 対象を言っていない（従来どおり説明とみなす）
    ],
)
def test_a11_positive_control_description_limits_are_still_read(quote, limit):
    assert extract_limit(quote).limit == limit


@pytest.mark.parametrize(
    "quote",
    [
        "説明は800字以内（英語の場合は400語以内）。",
        "説明は800字以内、英文の場合は300 words以内とする。",
        "Description: up to 800 characters, or up to 200 words for English text.",
        "説明は800字以内、または100行以内。",
    ],
)
def test_a12_a_limit_in_another_unit_makes_the_character_limit_ambiguous(quote):
    spec = extract_limit(quote)
    assert spec.limit is None and spec.reason == "other_unit"


def test_a12_positive_control_words_in_a_different_sense_do_not_hide_the_limit():
    assert extract_limit("日本語または英語で、説明は800字以内とする。").limit == 800


def test_a13_full_width_basis_counts_half_width_characters_as_half():
    text = "Cloud Run" * 90 + "あ" * 400  # 空白除き 1,120 字（半角 720 + 全角 400）。全角換算では約 760
    counts = count_chars(text)
    assert counts.chars_no_ws > 800
    spec = extract_limit("全角800字以内とする。")
    assert spec.basis == "fullwidth" and spec.limit == 800
    code, outcome, strong = measure(counts, spec.limit, spec.basis)
    assert code is C.ObsCode.LIMIT_UNDECIDABLE and not strong  # 全角換算では上限内だが、全部1字と数える流儀では超える


def test_a13_full_width_basis_still_fails_a_clearly_over_long_text():
    text = "あ" * 900 + "Cloud Run" * 5
    spec = extract_limit("全角800字以内とする。")
    assert measure(count_chars(text), spec.limit, spec.basis)[0] is C.ObsCode.OVER_LIMIT


def test_a13_full_width_basis_passes_a_text_that_fits_even_when_every_character_counts_as_one():
    spec = extract_limit("全角800字以内とする。")
    assert measure(count_chars("あ" * 500 + "abc" * 100), spec.limit, spec.basis)[0] is C.ObsCode.WITHIN_LIMIT


def test_a13_half_width_basis_counts_full_width_characters_as_two():
    spec = extract_limit("半角1,000文字以内とする。")
    assert spec.basis == "halfwidth" and spec.limit == 1000
    assert measure(count_chars("あ" * 600), spec.limit, spec.basis)[0] is C.ObsCode.LIMIT_UNDECIDABLE  # 600 字だが半角換算 1,200
    assert measure(count_chars("a" * 1001), spec.limit, spec.basis)[0] is C.ObsCode.OVER_LIMIT
    assert measure(count_chars("a" * 900), spec.limit, spec.basis)[0] is C.ObsCode.WITHIN_LIMIT
    assert measure(count_chars("あ" * 400), spec.limit, spec.basis)[0] is C.ObsCode.WITHIN_LIMIT  # 800


def test_a13_both_widths_in_the_quote_stay_undecidable_unless_the_quote_says_it_does_not_matter():
    assert extract_limit("全角800字（半角1600字）以内").reason == "width_dependent"
    assert extract_limit("全角・半角を問わず800字以内とする。").limit == 800
    assert extract_limit("全角半角の区別なく800字以内").limit == 800


def test_a13_the_basis_is_recorded_in_the_observation():
    spec = make_doc("D1", f"応募要項{BLOCK_SEP}全角800字以内とする。")
    req = make_verified("R1", doc=spec, needle="全角800字以内とする。", check_class=C.CheckClass.LENGTH_LIMIT)
    sub = make_doc("D3", "あ" * 100, role=C.DocRole.SUBMISSION, url="https://svc.example.invalid/x/")
    o = check_text_length(req, sub, "O1")
    assert o.facts["basis"] == "fullwidth" and o.code is C.ObsCode.WITHIN_LIMIT


def test_a13_counting_does_not_raise_on_stray_surrogates_or_odd_input():
    """文書の型は孤立サロゲートを受けないが、数える関数が単体で呼ばれても落ちない（1単位と数える）。"""
    assert count_chars("ab\ud800cd").units_max == 5
    assert count_chars("").chars_with_ws == 0 and count_chars(BLOCK_SEP * 5).chars_no_ws == 0
    # 半角10字は全角換算で5字。上限5字ちょうどなので不適合にはせず、全部1字と数える流儀では超えるので割れる
    assert measure(count_chars("a" * 10), 5, "fullwidth")[0] is C.ObsCode.LIMIT_UNDECIDABLE
    assert measure(count_chars("a" * 11), 5, "fullwidth")[0] is C.ObsCode.OVER_LIMIT


# ---------------------------------------------------------------------------
# A14: 窓口は要項側の文書を、提出物として測らない
# ---------------------------------------------------------------------------
def test_a14_the_registry_refuses_a_target_document_that_is_not_a_submission():
    spec = make_doc("D1", f"応募要項{BLOCK_SEP}提出物の説明は800字以内とする。")
    sub = make_doc("D3", "あ" * 100, role=C.DocRole.SUBMISSION, url="https://svc.example.invalid/x/")
    req = make_verified("R1", doc=spec, needle="提出物の説明は800字以内とする。", check_class=C.CheckClass.LENGTH_LIMIT)
    ctx = CheckContext(docs={"D1": spec, "D3": sub}, target_doc_id="D1")
    o = run_checker(C.Checker.TEXT_LENGTH, req, ctx, "O1")
    assert (o.code, o.outcome, o.facts["why"]) == (C.ObsCode.ERROR, C.ObsOutcome.INCONCLUSIVE, "not_submission_doc")
    ok = run_checker(C.Checker.TEXT_LENGTH, req, CheckContext(docs={"D1": spec, "D3": sub}, target_doc_id="D3"), "O2")
    assert ok.code is C.ObsCode.WITHIN_LIMIT


# ---------------------------------------------------------------------------
# A18: 注入疑いの置換で縮んだ本文を「上限以内」と言わない
# ---------------------------------------------------------------------------
def test_a18_a_body_shrunk_by_injection_placeholders_is_never_within_the_limit():
    """長い説明を注入文の連続に見せかけて置換記号に縮めても、字数制限をすり抜けられない（置換前の長さは分からない）。"""
    from app.contracts import INJECTION_PLACEHOLDER

    spec = make_doc("D1", f"応募要項{BLOCK_SEP}提出物の説明は800字以内とする。")
    req = make_verified("R1", doc=spec, needle="提出物の説明は800字以内とする。", check_class=C.CheckClass.LENGTH_LIMIT)
    shrunk = make_doc("D3", "あ" * 300 + INJECTION_PLACEHOLDER * 20, role=C.DocRole.SUBMISSION, url="https://svc.example.invalid/x/")
    o = check_text_length(req, shrunk, "O1")
    assert (o.code, o.outcome, o.strong) == (C.ObsCode.LIMIT_UNDECIDABLE, C.ObsOutcome.INCONCLUSIVE, False) and o.facts["masked"] is True
    plain = make_doc("D3", "あ" * 420, role=C.DocRole.SUBMISSION, url="https://svc.example.invalid/x/")
    assert check_text_length(req, plain, "O2").code is C.ObsCode.WITHIN_LIMIT  # 置換が無ければ従来どおり
    over = make_doc("D3", "あ" * 900 + INJECTION_PLACEHOLDER, role=C.DocRole.SUBMISSION, url="https://svc.example.invalid/x/")
    assert check_text_length(req, over, "O3").code is C.ObsCode.OVER_LIMIT  # 縮んでも超えているなら、超過は言える


# ---------------------------------------------------------------------------
# 通し: 回避用のページは、どれも「適合」にならない（取得 → 観測 → 窓口 → 判定表）
# ---------------------------------------------------------------------------
EVASIONS = [
    *SSO_ONLY,
    *SHELLS,
    '<meta http-equiv="refresh" content="0; url=/app/">',
    '<meta http-equiv="refresh" content="0; url=https://tenant.auth0.com/">',
    *DUP_ATTRS[:2],
    *PARSER_TRICKS,
]


@pytest.mark.parametrize("body", EVASIONS)
async def test_every_evasion_page_ends_without_a_machine_verified_pass(body):
    fetch = FakeFetchPort(make_result(body=body))
    res = await http_probe(fetch, "https://svc.example.invalid/fx/defect/submission/", obs_id="O1", sleep=SleepRecorder())
    spec = make_doc("D1", "提出URLは審査員がログインなしで開けること。")
    req = make_verified("R2", doc=spec, needle="提出URLは審査員がログインなしで開けること。", check_class=C.CheckClass.AUTH_WALL)
    o = run_checker(C.Checker.AUTH_WALL, req, CheckContext(docs={}, probes=(res.observation,)), "O2")
    (v,) = adjudicate(C.AdjudicationInput(requirements=(req,), docs=(spec.meta(),), observations=(res.observation, o)))
    assert v.label in (L.UNVERIFIABLE, L.FAIL), (body, v)


# ---------------------------------------------------------------------------
# A15: ログインを促す語の判定（全角でのすり抜け・否定の取り違え）
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "body",
    [
        "<title>Ｓｉｇｎ ｉｎ</title><a href='/a'>Ｇｏｏｇｌｅ</a>",  # 全角英字
        "<body><p>ＬＯＧ ＩＮ to continue</p><a href='/a'>go</a></body>",
        "<body><p>サインイン してください</p><a href='/a'>進む</a></body>",
    ],
)
def test_a15_full_width_letters_do_not_hide_a_login_prompt(body):
    o = obs_of(make_result(body=body))
    assert o.code is C.ObsCode.AUTH_WALL and o.facts["access"] == "login_prompt"


# ---------------------------------------------------------------------------
# A16: 文字が見えない画面・埋め込みだけの画面
# ---------------------------------------------------------------------------
EMPTY_PAGES = [
    "<html><head><title>x</title></head><body></body></html>",  # 空白の画面
    '<html><body><img src="/login-with-google.png"></body></html>',  # 画像だけ（ログインを促す画像かもしれない）
    '<html><body><iframe src="https://other.example.invalid/app"></iframe></body></html>',  # 別サービスの埋め込みだけ
    '<html><body><p>読み込み中</p><iframe src="https://other.example.invalid/app"></iframe></body></html>',
    '<html><body><canvas id="c"></canvas></body></html>',
]


@pytest.mark.parametrize("body", EMPTY_PAGES)
def test_a16_a_page_with_nothing_to_read_is_not_called_open(body):
    o = obs_of(make_result(body=body))
    assert shape(o) == (C.ObsCode.ERROR, C.ObsOutcome.INCONCLUSIVE, False, "empty_page")
    v = verdict_of_probe(make_result(body=body))
    assert v.label is L.UNVERIFIABLE and v.reason_code is U.NO_EVIDENCE and "判断できません" in v.reason


@pytest.mark.parametrize(
    "body",
    [
        f'<body>{LONG}<iframe src="https://other.example.invalid/video"></iframe></body>',  # 本文が十分にあり、動画などを埋め込んだだけ
        "<body><p>こんにちは</p></body>",
    ],
)
def test_a16_positive_control_a_page_with_text_is_still_open(body):
    assert obs_of(make_result(body=body)).code is C.ObsCode.NO_AUTH_WALL


def test_a16_an_empty_response_body_is_still_a_plain_no_content_response():
    assert obs_of(make_result(status=204, body=b"", headers={})).code is C.ObsCode.NO_AUTH_WALL


# ---------------------------------------------------------------------------
# A20: ステータスが 200 でも、中身が拒否・エラーの画面
# ---------------------------------------------------------------------------
SOFT_ERRORS = [
    "<html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1></body></html>",
    "<h1>Access Denied</h1><p>You don't have permission to view this page.</p>",
    "<h1>404 Not Found</h1><p>The page you requested does not exist.</p>",
    "<title>エラー</title><p>ページが見つかりません</p>",
    "<p>アクセスが拒否されました。</p>",
    "<title>403 Forbidden</title><p>" + "申し訳ありません。しばらくしてからもう一度お試しいただくか、サイトの管理者までお問い合わせください。" + "</p>",  # 題名だけ（本文は中立）
    "<p>このページを閲覧する権限がありません。</p>",
    "<p>Ｕｎａｕｔｈｏｒｉｚｅｄ</p>",  # 全角英字
]


@pytest.mark.parametrize("body", SOFT_ERRORS)
def test_a20_a_short_screen_that_says_denied_or_not_found_is_not_called_open(body):
    o = obs_of(make_result(body=body))
    assert (o.code, o.outcome, o.strong, o.facts["access"]) == (C.ObsCode.AUTH_WALL, C.ObsOutcome.INCONCLUSIVE, False, "error_page")
    v = verdict_of_probe(make_result(body=body))
    assert (v.label, v.reason_code) == (L.UNVERIFIABLE, U.HUMAN_ONLY) and "200" in v.reason


@pytest.mark.parametrize(
    "body",
    [
        f"<title>Forbidden Planet</title>{LONG}",  # 題名の語が偶然でも、本文が十分にある
        f"<h1>お探しのページはこちら</h1>{LONG}",
        "<body><h1>ようこそ</h1><p>" + "この作品は、あなたの暮らしを少し楽にします。" * 10 + "</p></body>",
        "<body><p>見つかりました！</p></body>",  # 「見つかりません」ではない
        "<body><p>利用者 1,404 人・導入 400 社</p><a href='/start'>はじめる</a></body>",  # 数の一部の 404・400
    ],
)
def test_a20_positive_control_pages_with_content_or_ordinary_words_stay_open(body):
    assert obs_of(make_result(body=body)).code is C.ObsCode.NO_AUTH_WALL


# ---------------------------------------------------------------------------
# A17: 乱数で作った取得結果でも、観測の組み立てが落ちない
# ---------------------------------------------------------------------------
_FRAGMENTS = [
    '<input type="password">', '<input type=password name=p>', "<!--", "-->", "<![CDATA[", "]]>", "<template>", "</template>",
    "<noscript>", "</noscript>", "<textarea>", "<script>", "</script>", "<style>", '<meta http-equiv="refresh" content="0; url=/login">',
    '<meta http-equiv="refresh" content="3;url=https://x.example.invalid/a?b=c">', "<iframe src=x>", "<app-root>", "<title>ログイン</title>",
    "<form action=/login>", "</form>", "<p>" + "あ" * 50 + "</p>", "Sign in", "ログイン不要", "\x00", "&#x70;assword", "<", ">", '"', "'",
]  # fmt: skip


def _random_result(rng):
    kind = rng.choice(["ok", "ok", "ok", "timeout", "blocked", "too_large", "unsupported"])
    url = rng.choice([SUB_URL_FOR_FUZZ, CLOUD_RUN_URL])
    hops = ()
    if rng.random() < 0.4:
        loc = rng.choice(["/login", "/a", "https://sso.example.invalid/x", "https://www.example.invalid/", "/x" * 40, "//e.example.invalid/l", "/ログイン", ""])
        hops = (redirect(frm=url, location=loc, followed=True),)
    body = "".join(rng.choice(_FRAGMENTS) for _ in range(rng.randint(0, 12)))
    raw = body.encode(rng.choice(["utf-8", "utf-8", "utf-16", "utf-16-le", "shift_jis"]), errors="replace")
    if kind == "timeout":
        return make_result(url, outcome=C.FetchOutcome.TIMEOUT, limit_hit=C.FetchLimit.TOTAL_TIMEOUT, content_kind=None, headers={})
    if kind == "blocked":
        return make_result(url, outcome=C.FetchOutcome.BLOCKED, blocked_policy=C.PolicyId.SCOPE, content_kind=None, headers={})
    if kind == "too_large":
        return make_result(url, outcome=C.FetchOutcome.TOO_LARGE, limit_hit=C.FetchLimit.CONTENT_LENGTH, content_kind=None)
    if kind == "unsupported":
        return make_result(url, outcome=C.FetchOutcome.UNSUPPORTED_TYPE, status=200, content_kind=C.ContentKind.UNSUPPORTED)
    extra = {"truncated": True, "limit_hit": C.FetchLimit.PROBE_PREFIX} if rng.random() < 0.3 else {}
    headers = rng.choice([
        {"content-type": "text/html"}, {"content-type": "text/html; charset=utf-16"}, {"content-type": "text/html; charset=shift_jis", "server": "Google Frontend"},
        {"content-type": "application/json"}, {"content-type": "text/html", "x-audit-app": "1"}, {},
    ])  # fmt: skip
    status = rng.choice([200, 200, 200, 204, 301, 302, 401, 403, 404, 429, 500, 502, 503])
    return make_result(url, status=status, body=raw, headers=headers, redirects=hops, **extra)


SUB_URL_FOR_FUZZ = "https://svc.example.invalid/fx/defect/submission/"


def test_a17_observation_building_never_raises_and_keeps_facts_safe():
    import random

    for seed in range(1500):
        rng = random.Random(seed)
        result = _random_result(rng)
        o = obs_of(result)
        assert len(o.facts) <= 16
        assert o.strong is False or o.outcome is not C.ObsOutcome.INCONCLUSIVE
        for k, v in o.facts.items():
            if isinstance(v, str):
                assert len(v) <= 64 and "//" not in v and "://" not in v and "?" not in v, (seed, k, v)
        # 取得結果が何であっても、「適合」と言える観測（強い合格）は、壁・殻・空・埋め込み・転送先未確認の印が無い時だけ
        if o.code is C.ObsCode.NO_AUTH_WALL:
            assert not o.facts.get("spa_shell") and "unfollowed" not in o.facts, (seed, o)


def test_a17_the_probe_loop_survives_random_exceptions_and_results():
    import asyncio
    import random

    async def go():
        for seed in range(150):
            rng = random.Random(seed)
            script = [_random_result(rng) for _ in range(3)]
            res = await http_probe(FakeFetchPort(*script), SUB_URL_FOR_FUZZ, obs_id="O1", sleep=SleepRecorder())
            assert 1 <= res.attempts <= 2
            assert res.observation.facts["attempts"] == res.attempts or res.observation.facts.get("attempts") is None

    asyncio.run(go())


def test_a17_any_password_input_written_in_the_markup_is_never_reported_as_open():
    """断片をでたらめに繋いだ HTML の中に password 欄の記述（コメント・CDATA・template の中も含む）が1つでもあれば、「開ける」と言わない。

    パーサの解釈（コメントの閉じ方・生テキスト要素・属性の重複）に依らず成り立つ、回避への備えの総合的な性質。
    """
    import random
    import re

    hint = re.compile(r"<\s*input\b[^>]{0,1000}?(?<![\w-])type\s*=\s*[\"']?\s*password\b", re.IGNORECASE)
    checked = 0
    for seed in range(3000):
        rng = random.Random(seed)
        body = "".join(rng.choice(_FRAGMENTS) for _ in range(rng.randint(1, 14)))
        o = obs_of(make_result(body=body))
        if hint.search(body):
            checked += 1
            assert o.code is not C.ObsCode.NO_AUTH_WALL, (seed, body, o)
    assert checked > 300  # この性質が実際に試されている（空振りの対策）


def test_a17_a_login_hop_in_the_redirect_chain_is_a_strong_wall_whatever_else_was_returned():
    """転送の連なりにログイン用パスがあれば、最終応答が何でも（時間切れ・500・空・SPA・どんな本文でも）強い壁。"""
    import random

    walls = 0
    for seed in range(1500):
        rng = random.Random(seed)
        r = _random_result(rng)
        if r.outcome is C.FetchOutcome.BLOCKED or r.redirects:  # 最初の拒否は転送を持てない（契約）
            continue
        hops = (redirect(frm=r.requested_url, location=rng.choice(["/login", "/users/sign_in", "/signin?next=/"]), followed=True),)
        o = obs_of(r.model_copy(update={"redirects": hops}))
        walls += 1
        assert (o.code, o.outcome, o.strong) == (C.ObsCode.AUTH_WALL, C.ObsOutcome.FAIL, True), (seed, o)
    assert walls > 500
