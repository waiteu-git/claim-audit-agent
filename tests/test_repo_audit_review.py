"""第10弾の敵対レビューへの対応（PR #9 の追加コミット）のテスト。完全オフライン。

ライセンスの例は標準文の特徴的な語句を短く並べた合成文（全文のコピーではない）。検知対象の形は連結で組む。
"""
import ast
import asyncio
import io
import logging
import threading
from pathlib import Path

import anyio
import pytest
from pydantic import ValidationError

import app.agent.repo_audit as repo_audit_mod
import app.web.app as web_app
from app.adjudicate import RepoFacts, adjudicate_repo
from app.agent.repo_audit import audit_repo
from app.checks import leak_scan
from app.checks.repo_inspect import (
    LicenseKind,
    ReadmeFact,
    TechTraceFact,
    detect_license,
    scan_readme,
    tech_traces,
)
from app.config import FetchBackend, Settings, startup_violations
from app.contracts import (
    REPO_EVIDENCE_VOCAB,
    REPO_FETCH_NAMES,
    REPO_FETCH_STATUSES,
    REPO_ITEM_REASONS,
    REPO_LEAK_KINDS,
    REPO_LICENSE_IDS,
    FetchOutcome,
    FetchResult,
    RepoAuditResult,
    RepoEvidence,
    RepoFetched,
    RepoItem,
    RepoItemId,
    RepoItemTitle,
    RepoReason,
    RepoSummary,
    RepoWarning,
    VerdictLabel,
)
from app.errors import PUBLIC_MESSAGES, ErrorCode
from app.jsonlog import LOGGER_NAME, log_exception, setup_logging
from app.quota import InMemoryState
from tests.test_repo_audit import (
    CLEAN_README,
    DOCKER_HIT,
    INJECTION,
    JUDGE,
    JUDGE_HEADER,
    REF,
    REPO_URL,
    REQS_HIT,
    FakeRepoPort,
    audit,
    chips,
    items,
    never_live,
    plain,
    post,
    repo_deps,
    repo_settings,
    run_repo,
)
from tests.test_repo_inspect import AT, MIT, PRIVATE_KEY_HEADER
from tests.web_support import Clock, client, first, live_settings, make_deps, parse_sse, run_async

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def log_stream():
    stream = io.StringIO()
    setup_logging("DEBUG", stream)
    yield stream
    logging.getLogger(LOGGER_NAME).handlers.clear()


# ------------------------------------------------------------------ 1-1 ライセンスは「適合」を出さない
TAMPERED = {
    "extra-fee": MIT + "You owe the author 10 percent of any revenue.\n",
    "noncommercial": MIT + "Permitted for noncommercial use.\n",
    "preface": "The text below is only a reference and is not the license of this repository.\n\n" + MIT,
}


def test_license_phrases_give_presumed_pass_never_pass():
    lic = items(audit({"README.md": CLEAN_README, "LICENSE": MIT}).result)["license"]
    assert lic.label is VerdictLabel.PRESUMED_PASS and lic.reason_ja is RepoReason.LICENSE_PHRASES_PRESENT
    assert chips(lic) == ["MIT"]
    assert "一致しました" not in lic.reason_ja.value and "確かめていません" in lic.reason_ja.value


@pytest.mark.parametrize("name", sorted(TAMPERED))
def test_tampered_license_text_is_never_pass(name):
    lic = items(audit({"README.md": CLEAN_README, "LICENSE": TAMPERED[name]}).result)["license"]
    assert lic.label is not VerdictLabel.PASS
    assert lic.label in (VerdictLabel.PRESUMED_PASS, VerdictLabel.UNVERIFIABLE)


def test_no_path_gives_pass_for_the_license_item():
    for kind in LicenseKind:
        for st in REPO_FETCH_STATUSES:
            from app.checks.repo_inspect import LicenseFact

            fact = LicenseFact(present=kind is not LicenseKind.ABSENT, kind=kind)
            r = adjudicate_repo(RepoFacts({**{n: "found" for n in REPO_FETCH_NAMES}, "LICENSE": st}, fact, ReadmeFact(present=True), TechTraceFact()))
            assert items(r)["license"].label is not VerdictLabel.PASS, (kind, st)
    with pytest.raises(ValueError):  # 型でも作れない
        RepoItem(id=RepoItemId.LICENSE, title_ja=RepoItemTitle.LICENSE, label=VerdictLabel.PASS, reason_ja=RepoReason.LICENSE_PHRASES_PRESENT,
                 evidence=(RepoEvidence(label="MIT"),))  # fmt: skip


# ------------------------------------------------------------------ 1-2 無害な記述は漏洩に数えない
def S(*parts: str) -> str:
    return "".join(parts)


HARMLESS = "\n".join(
    [
        "Clone: git" + AT + "github.com:example-owner/example-repo.git",
        "Bot: noreply" + AT + "github.com and 12345+user" + AT + "users.noreply.github.com",
        "![logo](assets/logo" + AT + "2x.png)",
        "Demo: https://demo-app-x.a.run" + ".app/",
    ]
)


def test_harmless_readme_forms_are_not_counted():
    assert leak_scan.scan_text(HARMLESS)  # 対照: 提出物の検査（leak_scan 本体）は従来どおり数える
    f = scan_readme("# Example\n\n" + HARMLESS + "\n")
    assert f.leak_counts == () and f.leak_total == 0
    it = items(audit({"README.md": "# Example\n\n" + HARMLESS + "\n", "LICENSE": MIT}).result)["readme_leak"]
    assert (it.label, it.reason_ja) == (VerdictLabel.PASS, RepoReason.LEAK_NONE)


def test_real_leak_shapes_are_still_counted_next_to_harmless_ones():
    real = {
        "email": "Contact: person" + AT + "mail.example.invalid",
        "private_ip": "internal 10.1.2.3",
        "private_key": PRIVATE_KEY_HEADER,
        "github_token": "ghp_" + "a" * 36,
        "aws_key_id": "AKIA" + "B" * 16,
    }
    for kind, text in real.items():
        f = scan_readme(HARMLESS + "\n" + text + "\n")
        assert dict(f.leak_counts) == {kind: 1}, kind
    # git@ のクローン先の隣の実メールは数える
    f = scan_readme("git" + AT + "github.com:example-owner/example-repo.git and person" + AT + "mail.example.invalid")
    assert dict(f.leak_counts) == {"email": 1}


def test_harmless_stripping_is_linear_on_long_runs():
    import time

    for unit in ("a", "a.", "no", "a@", "git@a", "@1x"):
        t = time.perf_counter()
        scan_readme((unit * (300_000 // len(unit)))[:300_000])
        assert time.perf_counter() - t < 8, unit


# ------------------------------------------------------------------ 1-3 空の README
@pytest.mark.parametrize("body", ["", "   \n\t  \n", "﻿"])
def test_empty_readme_is_unverifiable_not_pass(body):
    out = audit({"README.md": body, "LICENSE": MIT})
    it = items(out.result)["readme_leak"]
    assert (it.label, it.reason_ja) == (VerdictLabel.UNVERIFIABLE, RepoReason.README_EMPTY)
    assert out.result.fetched[0].status == "found"


# ------------------------------------------------------------------ 1-4 / 1-5 / 2-9 ポート生成の失敗・期限切れ・種類
def test_port_factory_failure_gives_a_fixed_error_and_done(log_stream):
    def boom():
        raise RuntimeError("FETCHER_URL " + REPO_URL)

    deps = make_deps(repo_settings(), runner=never_live, repo_fetch=boom)
    r = post(client(deps), {"preset_id": "github_repo", "repo_url": REPO_URL})
    ev = parse_sse(r.text)
    assert [e for e, _ in ev if e != "heartbeat"] == ["mode", "error", "done"]
    assert first(ev, "error")["code"] == "REPO_UNAVAILABLE"
    assert "example-owner" not in r.text + log_stream.getvalue()


def test_startup_requires_fetcher_url_for_the_flag():
    base = dict(github_input_enabled=True, judge_code_sha256=(__import__("app.quota", fromlist=["x"]).code_digest(JUDGE),))
    assert any("FETCHER_URL" in v for v in startup_violations(Settings(**base, fetch_backend=FetchBackend.REMOTE), {}, {}))
    assert not startup_violations(Settings(**base), {}, {})  # 開発の既定（inproc）は要らない
    ok = Settings(**base, fetch_backend=FetchBackend.REMOTE, fetcher_url="https://fetcher.example.invalid")
    assert not startup_violations(ok, {}, {})


class SlowPort:
    def __init__(self) -> None:
        self.cancelled = False

    async def fetch(self, request):  # noqa: ANN001, ANN201
        try:
            await asyncio.sleep(5)  # 取り消されなければここで 5 秒止まる（期限の変異で無限に待たないよう、上限を置く）
        except asyncio.CancelledError:
            self.cancelled = True
            raise


def test_timeout_and_errors_use_fetch_failed_not_the_model_sentence(monkeypatch):
    monkeypatch.setattr(web_app, "REPO_AUDIT_TIMEOUT_S", 0.1)
    port = SlowPort()
    r, ev = run_repo(port)
    err = first(ev, "error")
    assert err == {"code": "FETCH_FAILED", "message": "ページを取得できませんでした。"}
    assert "モデル" not in err["message"] and port.cancelled  # 期限切れで取得のタスクを取り消す

    class Net:
        async def fetch(self, request):  # noqa: ANN001, ANN201
            raise ConnectionResetError("x")

    assert first(run_repo(Net())[1], "error")["code"] == "FETCH_FAILED"

    class Odd:
        async def fetch(self, request):  # noqa: ANN001, ANN201
            raise ValueError("x")

    assert first(run_repo(Odd())[1], "error")["code"] == "INTERNAL"


# ------------------------------------------------------------------ 1-6 走査は別スレッド・ハートビートは止まらない
def test_inspection_runs_off_the_event_loop_and_heartbeats_continue(monkeypatch):
    seen = {}
    real = repo_audit_mod._inspect_sync

    def slow(fetched):  # noqa: ANN001, ANN202
        import time

        seen["thread"] = threading.current_thread()
        time.sleep(0.4)
        return real(fetched)

    monkeypatch.setattr(repo_audit_mod, "_inspect_sync", slow)
    deps = make_deps(repo_settings(), runner=never_live, repo_fetch=lambda: FakeRepoPort({"README.md": CLEAN_README, "LICENSE": MIT}), heartbeat_s=0.05)
    r = post(client(deps), {"preset_id": "github_repo", "repo_url": REPO_URL})
    ev = parse_sse(r.text)
    assert seen["thread"] is not threading.main_thread() and seen["thread"].name != threading.current_thread().name
    assert sum(1 for e, _ in ev if e == "heartbeat") >= 2  # 走査の最中もハートビートが出る
    assert first(ev, "result") is not None


# ------------------------------------------------------------------ 1-7 検証失敗のログに本文が入らない
CANARY = "CANARY-ABC"


def _invalid_fetch_result() -> ValidationError:
    with pytest.raises(ValidationError) as ei:
        FetchResult(requested_url="https://x.example.invalid/", outcome=FetchOutcome.OK, status=None, body=CANARY.encode() * 3)
    return ei.value


def test_validation_error_logs_never_carry_the_input(log_stream):
    exc = _invalid_fetch_result()
    assert CANARY in str(exc)  # 対照: 素の str(e) には本文の抜粋が入る
    log_exception("t.invalid", exc)
    out = log_stream.getvalue()
    assert out and CANARY not in out and "ValidationError" in out


def test_safefetch_result_invalid_log_has_no_body(log_stream):
    from app.net.safefetch import SafeFetch, _Run

    sf = SafeFetch(())
    run = _Run(requested_url="https://x.example.invalid/", started=0.0)
    res = sf._build(run, outcome=FetchOutcome.OK, status=None, body=CANARY.encode() * 3)
    assert res.outcome is FetchOutcome.NETWORK_ERROR  # 失敗は fail-closed の結果になる
    out = log_stream.getvalue()
    assert "safefetch.result_invalid" in out and CANARY not in out


# ------------------------------------------------------------------ 1-8 403 に固定文
def test_403_carries_the_fixed_sentence_and_others_are_unchanged():
    c = client(repo_deps(FakeRepoPort()))
    r = post(c, {"preset_id": "github_repo", "repo_url": REPO_URL}, {})
    assert r.status_code == 403
    assert r.json() == {"ok": False, "code": "JUDGE_REQUIRED", "message": "この機能は審査員コードのある方だけ使えます。"}
    bad = post(c, {"preset_id": "github_repo", "repo_url": "x"})
    assert bad.json() == {"ok": False, "code": "INVALID_INPUT"}  # 既存の拒否の形は変えない


# ------------------------------------------------------------------ 2-1 切断（anyio の取り消し）でも予約が残らない
class YieldingState(InMemoryState):
    """本番の保存先のように、操作のたびに待つ（チェックポイントがある）。待たない保存先では、取り消し中の精算が偶然最後まで走ってしまう。"""

    async def transaction(self, keys, fn):  # noqa: ANN001, ANN201
        await asyncio.sleep(0)
        return await super().transaction(keys, fn)


def test_anyio_cancel_still_settles_the_reservation():
    store = YieldingState()
    settings = repo_settings()
    port = SlowPort()
    deps = make_deps(settings, runner=never_live, store=store, repo_fetch=lambda: port)

    async def go():
        adm = await deps.quota.admit(JUDGE, judge_only=True)
        scopes: list[anyio.CancelScope] = []

        async def consume():
            with anyio.CancelScope() as sc:
                scopes.append(sc)
                async for _ in web_app.repo_events(deps, REF, adm):
                    pass

        t = asyncio.ensure_future(consume())
        await asyncio.sleep(0.05)
        scopes[0].cancel()  # anyio の取り消し（以後、finally の最初の await も取り消される）
        await t
        return store.docs[f"{settings.env.value}/total"]

    total = run_async(go())
    assert total["reservations"] == {} and total["spent"]["judge"] == 0 and port.cancelled


# ------------------------------------------------------------------ 2-2 停止中は取得に進まない / 2-8 コード無しは 403
class CountingFactory:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self):  # noqa: ANN204
        self.calls += 1
        return FakeRepoPort({"README.md": CLEAN_README, "LICENSE": MIT})


@pytest.mark.parametrize(
    "settings, expected",
    [
        (lambda: repo_settings(kill_switch=True), "KILLED"),
        (lambda: Settings(self_origin="https://self.example.invalid", live_enabled=False, github_input_enabled=True, judge_code_sha256=repo_settings().judge_code_sha256), "KILLED"),
    ],
)
def test_stopped_service_never_fetches(settings, expected):
    factory = CountingFactory()
    deps = make_deps(settings(), runner=never_live, repo_fetch=factory)
    r = post(client(deps), {"preset_id": "github_repo", "repo_url": REPO_URL})
    ev = parse_sse(r.text)
    assert first(ev, "error") == {"code": expected, "message": PUBLIC_MESSAGES[ErrorCode(expected)]}
    assert [e for e, _ in ev] == ["mode"][:0] + ["error", "done"] and factory.calls == 0


def test_store_failure_never_fetches():
    store = InMemoryState()
    store.fail = True
    factory = CountingFactory()
    deps = make_deps(repo_settings(), runner=never_live, store=store, repo_fetch=factory)
    ev = parse_sse(post(client(deps), {"preset_id": "github_repo", "repo_url": REPO_URL}).text)
    assert first(ev, "error")["code"] == "STORE_UNAVAILABLE" and factory.calls == 0


def test_no_code_is_403_even_when_the_service_is_stopped():
    # コードの有無は停止中かどうかより先に見る（匿名には、停止中でも開けない・状態も教えない）。コードが「ある」時だけ停止中の固定文になる
    factory = CountingFactory()
    deps = make_deps(repo_settings(kill_switch=True), runner=never_live, repo_fetch=factory)
    c = client(deps)
    assert post(c, {"preset_id": "github_repo", "repo_url": REPO_URL}, {}).status_code == 403
    assert factory.calls == 0


# ------------------------------------------------------------------ 2-3 不正な URL は応答にもログにも出ない
@pytest.mark.parametrize(
    "bad",
    [
        "https://github.com/example-owner/exa mple",
        "http://github.com/example-owner/example-repo",
        "https://github.com/example-owner/example-repo/tree/main",
        "https://github.com" + AT + "evil.invalid/example-owner/example-repo",
        "https://github.com/example-owner/example-repo.git",
    ],
)
def test_rejected_url_is_never_echoed(bad, log_stream):
    deps = repo_deps(FakeRepoPort())
    r = post(client(deps), {"preset_id": "github_repo", "repo_url": bad})
    assert r.status_code == 400
    everything = r.text + log_stream.getvalue()
    for frag in ("example-owner", "example-repo", "evil.invalid", "exa mple"):
        assert frag not in everything


# ------------------------------------------------------------------ 2-4 モデル非依存（AST。推移的にも）
def _module_file(name: str) -> Path | None:
    p = ROOT / (name.replace(".", "/") + ".py")
    if p.exists():
        return p
    p = ROOT / name.replace(".", "/") / "__init__.py"
    return p if p.exists() else None


def _imports(path: Path, modname: str) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    pkg = modname if path.name == "__init__.py" else modname.rsplit(".", 1)[0]
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = pkg.split(".")
                base = base[: len(base) - (node.level - 1)]
                mod = ".".join(base + ([node.module] if node.module else []))
            else:
                mod = node.module or ""
            out.add(mod)
            out.update(f"{mod}.{a.name}" for a in node.names)  # `from app import model` の model も拾う
    return {m for m in out if m.startswith("app")}


def _closure(root: str) -> set[str]:
    seen: set[str] = set()
    todo = [root]
    while todo:
        m = todo.pop()
        if m in seen:
            continue
        f = _module_file(m)
        if f is None:
            continue
        seen.add(m)
        todo.extend(_imports(f, m))
        parent = m.rsplit(".", 1)[0]
        if "." in m:
            todo.append(parent)  # パッケージの __init__ も読み込まれる
    return seen


def test_repo_audit_never_imports_the_model_reader_or_planner_even_transitively():
    closure = _closure("app.agent.repo_audit")
    assert "app.agent.repo_audit" in closure and "app.adjudicate" in closure  # 走査が働いている
    bad = {m for m in closure if m == "app.model" or m.startswith("app.model.") or m in ("app.agent.reader", "app.agent.planner", "app.agent.run")}
    assert bad == set(), bad


def test_ast_import_walker_catches_the_sneaky_forms(tmp_path):
    f = tmp_path / "x.py"
    f.write_text("from app import model\nfrom . import reader\nfrom .planner import X\nimport app.model.gemini\n", encoding="utf-8")
    got = _imports(f, "app.agent.x")
    assert {"app.model", "app.agent.reader", "app.agent.planner", "app.model.gemini"} <= got


# ------------------------------------------------------------------ 2-5 adjudicate_repo の表
def facts(**st):  # noqa: ANN003
    statuses = {n: "found" for n in REPO_FETCH_NAMES} | st
    return RepoFacts(statuses, None, None, None)


def test_found_without_facts_is_unverifiable_never_pass():
    r = adjudicate_repo(facts())
    assert [i.label for i in r.items] == [VerdictLabel.UNVERIFIABLE] * 3
    assert all(i.reason_ja is RepoReason.UNCHECKED_NO_FACT for i in r.items)


@pytest.mark.parametrize("st", [s for s in REPO_FETCH_STATUSES if s != "found"])
def test_every_fetch_state_per_item(st):
    from app.checks.repo_inspect import LicenseFact

    r = adjudicate_repo(RepoFacts({n: st for n in REPO_FETCH_NAMES}, None, None, None))
    it = items(r)
    unchecked = {
        "rate_limited": RepoReason.UNCHECKED_RATE_LIMITED, "transient": RepoReason.UNCHECKED_TRANSIENT, "rejected": RepoReason.UNCHECKED_REJECTED,
        "unusable": RepoReason.UNCHECKED_UNUSABLE, "skipped": RepoReason.UNCHECKED_SKIPPED,
    }  # fmt: skip
    if st == "not_found":
        assert it["license"].label is VerdictLabel.FAIL and it["license"].reason_ja is RepoReason.LICENSE_MISSING
        assert it["readme_leak"].reason_ja is RepoReason.README_MISSING and it["readme_leak"].label is VerdictLabel.UNVERIFIABLE
        assert it["tech_trace"].reason_ja is RepoReason.TECH_NO_FILES and it["tech_trace"].label is VerdictLabel.UNVERIFIABLE
    else:
        assert all(i.label is VerdictLabel.UNVERIFIABLE and i.reason_ja is unchecked[st] for i in r.items)
    assert VerdictLabel.PASS not in {i.label for i in r.items}
    assert LicenseFact  # (import の確認)


def test_tech_reasons_split_missing_files_from_files_without_traces():
    both_missing = items(audit({"README.md": CLEAN_README, "LICENSE": MIT}).result)["tech_trace"]
    assert both_missing.reason_ja is RepoReason.TECH_NO_FILES
    seen_nothing = items(audit({"LICENSE": MIT, "Dockerfile": "FROM python:3.13\n"}).result)["tech_trace"]
    assert seen_nothing.reason_ja is RepoReason.TECH_NOT_SEEN


# ------------------------------------------------------------------ 2-6 警告の件数は等しい
def test_injection_warning_count_equals_the_number_of_attacks():
    filler = "\n\n" + "filler line. " * 60 + "\n\n"
    for n in (1, 2, 3):
        text = "# Example\n\n" + filler.join([INJECTION] * n) + "\n"
        r = audit({"README.md": text, "LICENSE": MIT}).result
        assert [(w.code, w.count) for w in r.warnings] == [("INJECTION_SUSPECTED", n)], n
    assert audit({"README.md": CLEAN_README, "LICENSE": MIT}).result.warnings == ()


# ------------------------------------------------------------------ 2-7 ADMIT ゲートは審査員専用の入口も通る
def test_admit_gate_applies_to_the_judge_only_entrance():
    deps = make_deps(repo_settings(), runner=never_live, repo_fetch=lambda: FakeRepoPort({"README.md": CLEAN_README}), mono=Clock(1000.0))
    c = client(deps)
    body = {"preset_id": "github_repo", "repo_url": REPO_URL}
    assert post(c, body).status_code == 200
    assert post(c, body).status_code == 429  # 同じ瞬間の2回目はゲート（1試行/秒）で断る
    assert post(c, body, {}).status_code == 429  # コード無しの試行も同じゲートを通る（総当たりの下限）


# ------------------------------------------------------------------ 3 README 走査の切れ目・Dockerfile・型の締め
def test_long_token_boundary_does_not_hide_or_double_count_a_key():
    key = "AKIA" + "B" * 16
    for lead in (1000, 1020, 1023, 1024, 1100, 2040, 2048):
        text = "=" * lead + key + "=" * 3000
        assert dict(scan_readme(text).leak_counts) == {"aws_key_id": 1}, lead
    two = "=" * 1010 + key + "=" * 1500 + key + "=" * 100
    assert dict(scan_readme(two).leak_counts)["aws_key_id"] == 2


@pytest.mark.parametrize(
    "run, hit",
    [
        ('RUN echo "x; pip install vertexai"', False),
        ("RUN echo 'ok' && pip install vertexai", True),
        ("RUN pip install vertexai", True),
        ("RUN cd /app && pip install google-genai", True),
        ('RUN sh -c "pip install vertexai"', False),
        ('RUN echo "a" ; pip install google-adk', True),
    ],
)
def test_dockerfile_quoted_text_is_not_a_command(run, hit):
    assert bool(tech_traces("FROM python:3.13\n" + run + "\n", None).in_dockerfile) is hit


def test_result_vocabularies_match_their_sources():
    from app.checks.repo_inspect import TECH_PACKAGES  # noqa: F401

    assert set(REPO_LICENSE_IDS) == {k.value for k in LicenseKind if k.name not in ("ABSENT", "UNREADABLE", "UNKNOWN")}
    assert set(REPO_LEAK_KINDS) == set(leak_scan.LEAK_PATTERNS) - {"service_url"}
    assert set(REPO_EVIDENCE_VOCAB) == set(RepoItemId) and set(REPO_ITEM_REASONS) == set(RepoItemId)


def test_type_fields_are_pinned_so_a_new_free_text_field_turns_this_red():
    assert set(RepoItem.model_fields) == {"id", "title_ja", "label", "reason_ja", "evidence"}
    assert set(RepoEvidence.model_fields) == {"label"}
    assert set(RepoFetched.model_fields) == {"name", "status"}
    assert set(RepoWarning.model_fields) == {"code", "count"}
    assert set(RepoSummary.model_fields) == {"verdict_counts"}
    assert set(RepoAuditResult.model_fields) == {"kind", "mode", "status", "preset_id", "items", "fetched", "warnings", "summary"}
    for model in (RepoItem, RepoEvidence, RepoFetched, RepoWarning, RepoSummary, RepoAuditResult):
        for name, fi in model.model_fields.items():
            assert fi.annotation is not str or (model, name) == (RepoEvidence, "label"), (model, name)  # 自由な str は証拠のチップだけ


def test_reason_and_evidence_are_limited_per_item():
    with pytest.raises(ValueError):
        RepoItem(id=RepoItemId.LICENSE, title_ja=RepoItemTitle.LICENSE, label=VerdictLabel.FAIL, reason_ja=RepoReason.LEAK_FOUND)  # 他の項目の理由
    with pytest.raises(ValueError):
        RepoItem(id=RepoItemId.README_LEAK, title_ja=RepoItemTitle.README_LEAK, label=VerdictLabel.FAIL, reason_ja=RepoReason.LEAK_FOUND,
                 evidence=(RepoEvidence(label="MIT"),))  # fmt: skip  他の項目の語彙
    with pytest.raises(ValueError):
        RepoItem(id=RepoItemId.TECH_TRACE, title_ja=RepoItemTitle.TECH_TRACE, label=VerdictLabel.PASS, reason_ja=RepoReason.TECH_FOUND,
                 evidence=(RepoEvidence(label="somepackage"),))  # fmt: skip  語彙の外
    RepoItem(id=RepoItemId.README_LEAK, title_ja=RepoItemTitle.README_LEAK, label=VerdictLabel.FAIL, reason_ja=RepoReason.LEAK_FOUND,
             evidence=(RepoEvidence(label="email ×2"),))  # fmt: skip


def test_moved_repo_stays_unavailable_by_decision():
    # 3xx（移し替えられたリポ）は、転送を追わない規則の結果として「いま使えません」。REPO_PUBLIC_ONLY には寄せない（理由は PR の表）
    assert audit(default=301).error is ErrorCode.REPO_UNAVAILABLE
    assert plain  # (import の確認)
