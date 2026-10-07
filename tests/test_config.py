"""config.py: RUN_CAPS・PRESETS・PRICE_TABLE・環境変数・起動時アサーション。"""
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

import app.config as cfg
from app.contracts import QUOTE_SPAN_MAX_CHARS, EnvName, PresetKind, UrlPrefix


# --- RUN_CAPS（設計 §3 の数値） -------------------------------------------------
def test_run_caps_match_the_design_table():
    c = cfg.RUN_CAPS
    assert (c.model_calls_reader, c.model_calls_planner, c.model_calls_spare, c.model_calls_total) == (10, 8, 4, 22)
    assert c.model_call_timeout_s == 25 and c.model_retries == 2 and c.retry_backoff_s == (1.0, 8.0)
    assert (c.tokens_in, c.tokens_out) == (90_000, 14_000)
    assert (c.thinking_budget_reader, c.thinking_budget_planner) == (0, 0)  # Reader は 10/7 の実測で 1,024→0（app/config.py の注記）
    assert c.tool_calls == 16
    assert (c.fetches_acquire, c.fetches_fetch_link, c.fetches_probe, c.fetches_total, c.third_party_origins) == (3, 3, 2, 8, 4)
    assert (c.requirements_obligatory, c.requirements_speculative, c.requirements_optional, c.requirements_request) == (64, 8, 8, 8)
    assert (c.quote_verify_max_chars, c.quote_display_max_chars) == (160, 80)
    assert c.wall_clock_s == 75 and c.planner_max_turns == 8 and c.tool_calls_per_requirement == 3
    assert (c.reader_total_chars, c.reader_chunk_chars, c.reader_chunk_overlap, c.reader_max_parallel) == (50_000, 6_000, 400, 3)


def test_reader_chunk_math_fits_the_reader_call_cap():
    """元設計の不整合（6文書×40,000字でチャンクが40になり8回上限と矛盾）が再発しないこと（§3）。"""
    c = cfg.RUN_CAPS
    step = c.reader_chunk_chars - c.reader_chunk_overlap
    chunks = -(-(c.reader_total_chars - c.reader_chunk_overlap) // step)
    assert chunks <= c.model_calls_reader


def test_quote_cap_agrees_with_the_contract_constant():
    assert cfg.RUN_CAPS.quote_verify_max_chars == QUOTE_SPAN_MAX_CHARS


# --- 単価・予約額 ----------------------------------------------------------------
def test_price_table_records_the_official_check_and_keeps_a_conservative_default():
    t = cfg.PRICE_TABLE
    assert not t.provisional and t.checked_on == "2026-10-08"  # 公式の料金ページを確認した日（確認日を更新せずに値だけ変えない）
    assert "公式" in t.source and "¥150/$" in t.source
    # 登録していないモデルは、安全側の暫定値で見積もる（予約額もこの default で最悪値を測る）
    assert (t.default.input_jpy_per_mtok, t.default.output_jpy_per_mtok) == (150, 750)
    # 公式: gemini-2.5-flash は入力 $0.30・出力 $2.50 / 100万トークン（×150円）。flash-lite は $0.10・$0.40
    assert t.cost_micro_jpy("gemini-2.5-flash", 1_000_000, 0) == 45_000_000
    assert t.cost_micro_jpy("gemini-2.5-flash", 0, 1_000_000) == 375_000_000
    assert t.cost_micro_jpy("gemini-2.5-flash-lite", 1_000_000, 1_000_000) == 75_000_000
    assert t.cost_micro_jpy("gemini-2.5-flash", 1000, 200) < t.cost_micro_jpy("unregistered-model", 1000, 200)


def test_reservation_covers_the_worst_case_run():
    worst = cfg.worst_case_micro_jpy()
    assert worst == 24_000_000  # 約¥24
    assert cfg.RESERVATION_MICRO_JPY == 25_000_000 >= worst


def test_cost_is_micro_yen_per_token():
    # 入力 1,000 + 出力 200 トークン = 1000*150 + 200*750 micro 円 = 0.3 円
    assert cfg.PRICE_TABLE.cost_micro_jpy("any-model", 1000, 200) == 300_000
    assert cfg.PRICE_TABLE.cost_micro_jpy("any-model", 0, 0) == 0


def test_price_table_accepts_a_verified_date_and_per_model_prices():
    t = cfg.PriceTable(
        checked_on="2026-10-03", source="公式価格表", default=cfg.ModelPrice(input_jpy_per_mtok=100, output_jpy_per_mtok=500),
        models={"m": cfg.ModelPrice(input_jpy_per_mtok=10, output_jpy_per_mtok=20)},
    )  # fmt: skip
    assert not t.provisional and t.cost_micro_jpy("m", 5, 5) == 150 and t.cost_micro_jpy("other", 1, 1) == 600
    with pytest.raises(ValidationError):
        cfg.PriceTable(checked_on="10/3", source="x", default=t.default)


def test_quota_and_guard_numbers_match_the_design():
    q = cfg.QUOTA_POLICY
    assert (q.judge.runs_per_day, q.judge.runs_per_hour, q.judge.daily_cap_micro_jpy, q.judge.total_cap_micro_jpy) == (10, 3, 250_000_000, 3_000_000_000)
    assert (q.anonymous.runs_per_day, q.anonymous.daily_cap_micro_jpy, q.anonymous.total_cap_micro_jpy) == (4, 100_000_000, 1_500_000_000)
    assert q.anonymous_slot_hours_jst == (0, 6, 12, 18) and q.reservation_ttl_s == 130 and q.live_concurrency_per_instance == 2
    assert cfg.GUARD_LIMITS.egress_bytes_per_min == 2 * 1024 * 1024 and cfg.GUARD_LIMITS.requests_per_min == 600


# --- Settings / 環境変数 -----------------------------------------------------------
def test_defaults_are_fail_closed(clean_env):
    s = cfg.load_settings({})
    assert s.env is EnvName.DEV and s.role is cfg.Role.AGENT and s.fetch_backend is cfg.FetchBackend.INPROC
    assert s.live_enabled is False and s.kill_switch is False and s.google_cloud_project is None
    assert s.gemini_model_reader == s.gemini_model_planner == "gemini-2.5-flash" and s.gemini_location == "asia-northeast1"


def test_environment_is_read_into_settings():
    s = cfg.load_settings(
        {
            "ROLE": "fetcher", "ENV": "public", "FETCH_MODE": "remote", "GOOGLE_CLOUD_PROJECT": "proj-x",
            "GEMINI_LOCATION": "asia-northeast1", "GEMINI_MODEL": "m-default", "GEMINI_MODEL_PLANNER": "m-planner",
            "PROMPT_VERSION": "pv1", "KILL_SWITCH": "1", "LIVE_ENABLED": "1", "LOG_LEVEL": "debug",
            "SELF_ORIGIN": "https://self.example.invalid", "FETCHER_URL": "https://f.example.invalid",
            "ALLOWED_PREFIXES": "exact:lp.example.invalid/event, self.example.invalid/fx/",
            "LP_SEED_URLS": "https://lp.example.invalid/event,https://lp.example.invalid/faq",
        }
    )  # fmt: skip
    assert (s.role, s.env, s.fetch_backend) == (cfg.Role.FETCHER, EnvName.PUBLIC, cfg.FetchBackend.REMOTE)
    assert s.gemini_model_reader == "m-default" and s.gemini_model_planner == "m-planner"
    assert s.kill_switch and s.live_enabled and s.log_level == "DEBUG"
    assert s.allowed_prefixes == (
        UrlPrefix(host="lp.example.invalid", path_prefix="/event", exact=True),
        UrlPrefix(host="self.example.invalid", path_prefix="/fx/"),
    )
    assert len(s.lp_seed_urls) == 2


@pytest.mark.parametrize("raw", ["0", "", "true", "yes", "2"])
def test_only_literal_1_turns_switches_on(raw):
    s = cfg.load_settings({"KILL_SWITCH": raw, "LIVE_ENABLED": raw})
    assert s.kill_switch is False and s.live_enabled is False


@pytest.mark.parametrize("env", [{"ENV": "prod"}, {"ROLE": "x"}, {"FETCH_MODE": "local"}, {"SELF_ORIGIN": "http://insecure.example.invalid"}, {"ALLOWED_PREFIXES": "127.0.0.1/x"}])
def test_invalid_environment_is_rejected(env):
    with pytest.raises(ValueError):
        cfg.load_settings(env)


def test_settings_are_frozen_and_forbid_extras():
    s = cfg.load_settings({})
    with pytest.raises(ValidationError):
        s.kill_switch = True
    with pytest.raises(ValidationError):
        cfg.Settings(unknown=1)


def test_load_settings_reads_os_environ_only_when_no_mapping_is_given(clean_env):
    clean_env.setenv("PROMPT_VERSION", "from-os")
    assert cfg.load_settings().prompt_version == "from-os"
    assert cfg.load_settings({}).prompt_version == "dev"


def test_environment_is_read_only_in_config():
    """環境変数を読むのは config.py だけ（既存の main.py は除く）。"""
    offenders = []
    for path in sorted(Path("app").rglob("*.py")):
        if path.as_posix() in ("app/config.py", "app/main.py"):
            continue
        src = path.read_text(encoding="utf-8")
        if "os.environ" in src or "getenv(" in src:
            offenders.append(path.as_posix())
    assert offenders == []


# --- プリセット -------------------------------------------------------------------
def test_three_presets_with_valid_ids(clean_env):
    presets = cfg.build_presets(cfg.load_settings({}))
    assert tuple(presets) == cfg.PRESET_IDS and len(presets) == 3
    kinds = [p.kind for p in presets.values()]
    assert kinds == [PresetKind.LIVE_LP, PresetKind.FIXTURE_DEFECT, PresetKind.FIXTURE_INJECTION]
    import re

    for pid, p in presets.items():
        assert re.fullmatch(cfg.PRESET_ID_PATTERN, pid) and p.preset_id == pid


def test_default_presets_use_only_placeholder_hosts():
    for p in cfg.PRESETS.values():
        urls = [*p.spec_seed_urls, *([p.submission_url] if p.submission_url else [])]
        assert urls and all(u.split("/")[2].endswith(".example.invalid") for u in urls)


def test_live_preset_scope_is_exact_urls_plus_self_root_and_fx():
    s = cfg.load_settings({"SELF_ORIGIN": "https://self.example.invalid", "LP_SEED_URLS": "https://lp.example.invalid/event,https://lp.example.invalid/faq"})
    p = cfg.build_presets(s)[cfg.PRESET_LP_SELF]
    scope = {(x.host, x.path_prefix, x.exact) for x in p.allowed_prefixes}
    assert scope == {
        ("lp.example.invalid", "/event", True),
        ("lp.example.invalid", "/faq", True),
        ("self.example.invalid", "/", True),  # 自サービスは "/" の完全一致だけ（/api/ は開けない）
        ("self.example.invalid", "/fx/", False),
    }
    assert p.submission_url == "https://self.example.invalid/"
    assert len(p.spec_seed_urls) == 2


def test_fixture_presets_are_scoped_to_their_own_fx_subtree():
    s = cfg.load_settings({"SELF_ORIGIN": "https://self.example.invalid"})
    presets = cfg.build_presets(s)
    d, i = presets[cfg.PRESET_SAMPLE_DEFECT], presets[cfg.PRESET_SAMPLE_INJECTION]
    assert [(x.path_prefix, x.exact) for x in d.allowed_prefixes] == [("/fx/defect/", False)]
    assert [(x.path_prefix, x.exact) for x in i.allowed_prefixes] == [("/fx/inject/", False)]
    assert all(u.startswith("https://self.example.invalid/fx/defect/") for u in (*d.spec_seed_urls, d.submission_url or ""))


def test_lp_seeds_are_capped_at_three():
    seeds = ",".join(f"https://lp.example.invalid/p{i}" for i in range(4))
    with pytest.raises(ValueError):
        cfg.load_settings({"LP_SEED_URLS": seeds})


# --- 起動時アサーション（§8 ⑩） -------------------------------------------------------
def _public(**kw):
    env = {"ENV": "public", "FETCH_MODE": "remote", "STATE_BACKEND": "firestore", "SELF_ORIGIN": "https://self.example.invalid", **kw}
    return cfg.load_settings(env), env


def test_public_startup_is_clean_when_configured_correctly():
    s, env = _public()
    assert cfg.startup_violations(s, env, {}) == []
    cfg.assert_startup_safe(s, env, {})


def test_public_startup_refuses_dangerous_configuration():
    s = cfg.load_settings({"ENV": "public", "FETCH_MODE": "inproc"})
    assert any("FETCH_MODE=remote" in v for v in cfg.startup_violations(s, {"ENV": "public"}, {}))
    s, env = _public(GOOGLE_APPLICATION_CREDENTIALS="/x/key.json")
    assert any("GOOGLE_APPLICATION_CREDENTIALS" in v for v in cfg.startup_violations(s, env, {}))
    s, env = _public(FAULT_VERTEX_429="1", SCRIPTED_PORT="1")
    v = cfg.startup_violations(s, env, {})
    assert any("FAULT_VERTEX_429" in x and "SCRIPTED_PORT" in x for x in v)
    s, env = _public()
    assert any("ScriptedPort" in x for x in cfg.startup_violations(s, env, {"app.model.scripted": object()}))
    with pytest.raises(cfg.StartupError):
        cfg.assert_startup_safe(s, env, {"app.model.scripted": object()})


def test_non_public_environments_are_not_blocked_by_the_public_checks():
    s = cfg.load_settings({"ENV": "staging"})
    assert cfg.startup_violations(s, {"FAULT_X": "1", "GOOGLE_APPLICATION_CREDENTIALS": "x"}, {"app.model.scripted": object()}) == []


def test_importing_the_production_modules_never_imports_scripted_port():
    """本番側のモジュールを読み込んでも ScriptedPort は入らない（⑩ の前提）。別プロセスで確認する。"""
    import subprocess
    import sys

    code = (
        "import sys, app.config, app.contracts, app.errors, app.jsonlog, app.model.port, app.model.gemini, app.model.retry;"
        "print('app.model.scripted' in sys.modules, 'app.model.cassette' in sys.modules)"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout.split()
    assert out == ["False", "False"]


def test_presets_json_has_no_real_identifiers():
    blob = json.dumps({k: v.model_dump(mode="json") for k, v in cfg.PRESETS.items()}, ensure_ascii=False)
    assert "example.invalid" in blob and ".run.app" not in blob and "zenn" not in blob.lower()
