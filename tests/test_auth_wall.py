"""auth_wall: ログイン用パス・IdP・password 欄／ログインフォームの検出（誤検出しないこと）と、チェッカー。"""
import pytest

import app.contracts as C
from app.checks.auth_wall import (
    LOGIN_PAGE_TEXT_MAX,
    check_auth_wall,
    hop_login_evidence,
    is_idp_host,
    is_login_form_page,
    is_login_path,
    is_spa_shell,
    last_location_path,
    path_fact,
)
from app.checks.html_signals import HtmlSignals, analyze_html, decode_body
from app.checks.http_probe import observe_probe
from tests.factories import make_verified
from tests.fetch_fakes import HOST, make_result, redirect


def sig(html: str) -> HtmlSignals:
    return analyze_html(html.encode("utf-8"), "text/html; charset=utf-8")


# ---------------------------------------------------------------------------
# ログイン用パス（セグメント単位）
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "path",
    [
        "/login", "/Login/", "/log-in", "/signin", "/sign-in", "/sign_in", "/users/sign_in", "/account/login",
        "/login.php", "/login.html", "/wp-login.php", "/auth", "/auth/login", "/oauth/authorize", "/oauth2/authorize",
        "/sso/start", "/saml2/idp", "/adfs/ls", "/%6cogin",  # %6c は "l"。エンコードで逃がさない
        "/fx/defect/login/", "/signin-oidc", "/login-required",
    ],
)  # fmt: skip
def test_login_paths_are_recognized(path):
    assert is_login_path(path) is True


@pytest.mark.parametrize(
    "path",
    ["/", "/logout", "/author", "/authors/alice", "/authority", "/sessions", "/sessions/keynote", "/catalog", "/blogin", "/design",
     "/event/details", "/fx/defect/submission/", "/loginfo", "/signing"],
)  # fmt: skip
def test_non_login_paths_are_not_mistaken(path):
    assert is_login_path(path) is False


@pytest.mark.parametrize(
    "host",
    ["accounts.google.com", "login.microsoftonline.com", "tenant.auth0.com", "acme.okta.com", "login.example.invalid",
     "sso.example.invalid", "auth.example.invalid", "ACCOUNTS.GOOGLE.COM", "x.b2clogin.com", "pool.amazoncognito.com"],
)  # fmt: skip
def test_idp_hosts_are_recognized(host):
    assert is_idp_host(host) is True


@pytest.mark.parametrize("host", ["", "www.example.invalid", "svc.example.invalid", "login", "authors.example.invalid", "notlogin.example.invalid", "example.invalid"])
def test_ordinary_hosts_are_not_idp(host):
    assert is_idp_host(host) is False


def test_path_fact_keeps_only_safe_short_fragments():
    assert path_fact("/login") == "/login"
    assert path_fact("/ログイン") == "/_"  # 非 ASCII を含む区間は伏せる
    assert path_fact("/a//b") == "/a/b"
    assert path_fact("/x" * 40) == ("/x" * 40)[:64]
    assert path_fact("/auth/" + "A" * 30) == "/auth/_"  # 長いトークン（ID 風）は伏せる
    assert "?" not in path_fact("/login?next=https://x")  # 呼び出し側はクエリを渡さないが、渡されても facts に使える形になる
    C.Observation(obs_id="O1", tool=C.ToolName.HTTP_PROBE, code=C.ObsCode.OK, outcome=C.ObsOutcome.PASS, facts={"p": path_fact("/ログイン?next=https://x")})


# ---------------------------------------------------------------------------
# 転送の連なりの証拠
# ---------------------------------------------------------------------------
def test_relative_login_redirect_is_evidence():
    ev = hop_login_evidence([redirect(location="/fx/defect/login/")], HOST)
    assert ev is not None and (ev.kind, ev.status, ev.path) == ("login_path", 302, "/fx/defect/login/")


def test_idp_redirect_is_evidence_even_when_the_path_looks_ordinary():
    hop = redirect(location="https://idp.example.invalid/x?client_id=abc&redirect_uri=https://svc.example.invalid/cb", followed=False)
    ev = hop_login_evidence([hop], HOST)
    assert ev is not None and ev.kind == "idp_host"


def test_oauth_query_keys_mark_a_cross_host_redirect_as_idp():
    hop = redirect(location="https://other.example.invalid/consent?client_id=x&response_type=code", followed=False)
    assert hop_login_evidence([hop], HOST).kind == "idp_host"  # type: ignore[union-attr]


def test_ordinary_redirects_are_not_evidence():
    for loc in ("/fx/defect/submission/index", "https://www.example.invalid/", "/", "/about"):
        assert hop_login_evidence([redirect(location=loc, followed=loc.startswith("/"))], HOST) is None


def test_same_host_redirect_is_not_judged_by_its_host_name():
    """提出物自身のホストが login.* でも、同じホストへの転送を IdP とは言わない。"""
    hop = redirect(frm="https://login.example.invalid/", location="https://login.example.invalid/home", followed=False)
    assert hop_login_evidence([hop], "login.example.invalid") is None


def test_first_evidence_in_a_chain_is_returned():
    chain = [redirect(location="/a"), redirect(frm=f"https://{HOST}/a", location="/signin")]
    assert hop_login_evidence(chain, HOST).path == "/signin"  # type: ignore[union-attr]


def test_broken_location_is_ignored_not_raised():
    assert hop_login_evidence([redirect(location="http://[bad", followed=False)], HOST) is None
    assert last_location_path([redirect(location="http://[bad", followed=False)]) == ""


# ---------------------------------------------------------------------------
# password 欄・ログインフォーム: 検出
# ---------------------------------------------------------------------------
def test_password_input_is_detected():
    s = sig('<form action="/session" method="post"><input type="text" name="u"><input type="password" name="p"></form>')
    assert s.has_password_input and s.forms[0].has_password and s.forms[0].other_inputs == 1


@pytest.mark.parametrize(
    "markup",
    [
        '<input type="PASSWORD">',  # 大文字
        "<input type=password>",  # 引用符なし
        '<input   type = "password"  />',  # 空白・自己終了
        '<input name="p" type="password" required>',
        '<INPUT TYPE="Password">',
    ],
)
def test_password_input_syntax_variants_are_detected(markup):
    assert sig(markup).has_password_input is True


# ---------------------------------------------------------------------------
# password 欄・ログインフォーム: 誤検出しない
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "markup",
    [
        '<form action="/search"><input type="search" name="q"><input type="submit" value="検索"></form>',  # 検索フォーム
        '<form><input type="text" name="q" placeholder="検索"></form>',
        '<form><input type="text" name="password_hint"></form>',  # name に password を含むだけの text 欄
        '<input type="text" name="password">',  # type が text なら password 欄ではない
        '<label for="p">パスワード</label>',  # 語だけ
        "<p>パスワードをお忘れですか？ ログインしてください。</p>",
        '<input type="hidden" name="password" value="x">',  # hidden
        '<input type="password" hidden>',  # hidden 属性
        '<input type="password" style="display:none">',
        '<input type="password" style="visibility: hidden">',
        '<input type="password" aria-hidden="true">',
        '<!-- <input type="password"> -->',  # コメント
        '<script>var t = \'<input type="password">\';</script>',  # script の中の文字列
        '<template><input type="password"></template>',
        '<noscript><input type="password"></noscript>',
        '<textarea><input type="password"></textarea>',
        '<pre>&lt;input type="password"&gt;</pre>',  # エスケープされた文字列（タグではない）
        '<code>&lt;input type=&quot;password&quot;&gt;</code>',
        '<style>input[type="password"] { color: red }</style>',
    ],
)  # fmt: skip
def test_password_look_alikes_are_not_password_inputs(markup):
    s = sig(markup)
    assert s.has_password_input is False
    assert all(not f.has_password for f in s.forms)


def test_search_only_page_is_not_a_login_form_page():
    s = sig('<h1>イベント</h1><form action="/search"><input type="search" name="q"></form>')
    assert is_login_form_page(s) is False


def test_forms_posting_to_a_login_path_count_as_login_forms_even_without_a_password_field():
    s = sig('<form action="/login" method="post"><input type="email" name="e"><button>メールでログイン</button></form>')
    assert not s.has_password_input and is_login_form_page(s) is True  # マジックリンク型の短いログイン画面


def test_a_search_form_posting_to_search_is_not_a_login_form():
    assert is_login_form_page(sig('<form action="/search"><input name="q"></form>')) is False


def test_content_rich_page_with_a_header_login_box_is_not_a_login_page():
    body = "".join(f"<p>{'あ' * 60}</p>" for _ in range(40))  # 2,400字
    s = sig(f'<header><form action="/session"><input type="password" name="p"></form></header>{body}')
    assert s.has_password_input and s.text_len > LOGIN_PAGE_TEXT_MAX
    assert is_login_form_page(s) is False  # 壁とは言い切れない（http_probe は不確定にする）


def test_login_title_makes_a_long_page_with_a_password_field_a_login_page():
    body = "".join(f"<p>{'あ' * 60}</p>" for _ in range(40))
    s = sig(f'<title>ログイン | サービス</title><form><input type="password"></form>{body}')
    assert s.title_login_words and is_login_form_page(s) is True


def test_login_title_without_a_password_field_does_not_make_a_login_page():
    body = "".join(f"<p>{'あ' * 60}</p>" for _ in range(40))
    assert is_login_form_page(sig(f"<title>ログインのしかた</title>{body}")) is False


# ---------------------------------------------------------------------------
# 本文長・SPA の裏取り
# ---------------------------------------------------------------------------
def test_visible_text_length_ignores_script_style_head_template_noscript():
    s = sig(
        "<html><head><title>題名題名</title><style>.a{}</style></head><body>"
        "<script>var s = 'あああああ';</script><template>てんぷれ</template><noscript>のすくりぷと</noscript>"
        "<p>本文 です</p></body></html>"
    )
    assert s.text_len == len("本文 です")


def test_whitespace_in_the_markup_is_collapsed_in_the_text_length():
    assert sig("<p>あ</p>\n\n   \n<p>い</p>").text_len == len("あ い")


def test_spa_shell_needs_empty_body_script_and_a_mount_marker():
    spa = sig('<body><div id="root"></div><script src="/static/app.js"></script></body>')
    assert spa.script_count == 1 and spa.mount_marker and is_spa_shell(spa)
    nojs = sig('<body><noscript>You need to enable JavaScript to run this app.</noscript><script src="/a.js"></script></body>')
    assert is_spa_shell(nojs)
    # 短い静的ページに解析用 script があるだけ（描画先の印なし）は SPA と決めつけない
    static = sig("<body><p>準備中です</p><script>ga('send')</script></body>")
    assert static.script_count == 1 and not is_spa_shell(static)
    # 本文が十分にある（SSR）ページは、描画先 id があっても SPA ではない
    ssr = sig(f'<div id="root"><p>{"あ" * 300}</p></div><script src="/a.js"></script>')
    assert not is_spa_shell(ssr)
    # script が無いなら JS 描画ではない
    assert not is_spa_shell(sig('<div id="root"></div>'))


def test_scripts_inside_a_template_are_not_counted():
    assert sig("<template><script>x</script></template>").script_count == 0


def test_meta_refresh_target_is_read_as_a_path_only():
    s = sig('<meta http-equiv="refresh" content="0; url=https://svc.example.invalid/login?next=%2F">')
    assert s.meta_refresh_path == "/login"
    assert sig('<meta http-equiv="refresh" content="5;URL=\'/signin\'">').meta_refresh_path == "/signin"
    assert sig('<meta name="viewport" content="width=device-width">').meta_refresh_path is None


def test_analyze_html_survives_broken_markup():
    s = analyze_html(b'<div><form><input type="password"', "text/html")
    assert isinstance(s.text_len, int)  # 例外を出さない
    assert analyze_html(b"", None) == analyze_html(b"", None)
    assert analyze_html(b"\xff\xfe\x00<<<>>><!--", "text/html").has_password_input is False


def test_unclosed_form_is_still_summarized():
    s = sig('<form action="/login"><input type="password">')
    assert s.has_password_input and len(s.forms) == 1 and s.forms[0].action_path == "/login"


def test_only_the_first_64kb_is_analyzed():
    pad = "<p>" + "あ" * 40_000 + "</p>"  # 先頭 64KB を超える位置の password 欄は見ない（http_probe は先頭 64KB だけ読む）
    s = analyze_html((pad + '<input type="password">').encode("utf-8"), "text/html")
    assert s.has_password_input is False


# ---------------------------------------------------------------------------
# 文字コード
# ---------------------------------------------------------------------------
def test_decode_body_honours_a_declared_japanese_charset():
    raw = "ログイン".encode("shift_jis")
    assert decode_body(raw, "text/html; charset=Shift_JIS") == "ログイン"
    assert decode_body("ログイン".encode("euc_jp"), "text/html; charset=euc-jp") == "ログイン"
    meta = b'<meta charset="shift_jis">' + raw
    assert decode_body(meta, None).endswith("ログイン")


def test_decode_body_does_not_call_non_text_codecs_named_in_the_page():
    assert decode_body(b"abc", "text/html; charset=rot13") == "abc"  # 変換 codec は使わず utf-8 にする
    assert decode_body(b"abc", "text/html; charset=nonexistent-xyz") == "abc"
    assert decode_body(b"\xff\xff", "text/html") == "��"  # 壊れたバイトは置換（\xff\xfe は UTF-16 の BOM になった）


def test_decoded_shift_jis_login_page_is_detected():
    body = '<title>ログイン</title><form><input type="password"></form>'.encode("shift_jis")
    s = analyze_html(body, "text/html; charset=Shift_JIS")
    assert s.has_password_input and s.title_login_words


# ---------------------------------------------------------------------------
# チェッカー: 保存済みの http_probe 観測を要件に結び付ける
# ---------------------------------------------------------------------------
def probe_obs(result, obs_id="O1", target="SUBMISSION_URL"):
    return observe_probe(result, obs_id=obs_id, target=target)


def auth_req():
    return make_verified("R2", check_class=C.CheckClass.AUTH_WALL)


def login_result():
    return make_result(
        redirects=(redirect(),), final_url=f"https://{HOST}/fx/defect/login/",
        body='<form><input type="password"></form>',
    )  # fmt: skip


def test_checker_carries_the_probe_decision_to_the_requirement():
    probe = probe_obs(login_result())
    obs = check_auth_wall(auth_req(), [probe], "O2")
    assert (obs.tool, obs.checker, obs.req_id, obs.obs_id) == (C.ToolName.RUN_CHECK, C.Checker.AUTH_WALL, "R2", "O2")
    assert (obs.code, obs.outcome, obs.strong) == (probe.code, probe.outcome, probe.strong)
    assert (obs.code, obs.outcome, obs.strong) == (C.ObsCode.AUTH_WALL, C.ObsOutcome.FAIL, True)
    assert obs.facts["location_path"] == "/fx/defect/login/" and obs.facts["has_password_input"] is True
    assert "attempts" not in obs.facts


def test_checker_without_a_probe_is_inconclusive_error():
    obs = check_auth_wall(auth_req(), [], "O2")
    assert (obs.code, obs.outcome) == (C.ObsCode.ERROR, C.ObsOutcome.INCONCLUSIVE)
    assert obs.facts["reason"] == "no_probe"


def test_checker_ignores_probes_of_other_targets_and_other_tools():
    other = probe_obs(login_result(), "O1", target="L3")
    assert check_auth_wall(auth_req(), [other], "O2").facts["reason"] == "no_probe"
    assert check_auth_wall(auth_req(), [other], "O2", target="L3").code is C.ObsCode.AUTH_WALL
    not_a_probe = C.Observation(obs_id="O1", tool=C.ToolName.RUN_CHECK, code=C.ObsCode.OK, outcome=C.ObsOutcome.PASS, facts={"target": "SUBMISSION_URL"})
    assert check_auth_wall(auth_req(), [not_a_probe], "O2").facts["reason"] == "no_probe"


def test_checker_prefers_the_latest_conclusive_probe():
    """一時的な失敗が挟まっても、結論つきの観測どうしが一致していれば最新を採る。"""
    ok1 = probe_obs(make_result(body="<p>" + "あ" * 400 + "</p>"), "O1")
    ok2 = probe_obs(make_result(body="<p>" + "い" * 400 + "</p>"), "O2")
    transient = probe_obs(make_result(status=503, headers={}, body=b""), "O3")
    assert check_auth_wall(auth_req(), [ok1, ok2, transient], "O9").code is C.ObsCode.NO_AUTH_WALL  # 最新の結論つき
    only_transient = check_auth_wall(auth_req(), [transient], "O9")
    assert only_transient.code is C.ObsCode.TRANSIENT and only_transient.outcome is C.ObsOutcome.INCONCLUSIVE


def test_checker_does_not_let_a_later_pass_wash_away_an_earlier_wall():
    """壁の観測の後に開く観測があっても、最新を採らない（応答が揺れる提出物は1回の観測で言い切れない）。"""
    wall = probe_obs(login_result(), "O1")
    ok = probe_obs(make_result(body="<p>" + "あ" * 400 + "</p>"), "O2")
    obs = check_auth_wall(auth_req(), [wall, ok], "O9")
    assert (obs.code, obs.outcome, obs.strong, obs.facts["reason"]) == (C.ObsCode.ERROR, C.ObsOutcome.INCONCLUSIVE, False, "probe_conflict")
