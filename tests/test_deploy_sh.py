"""deploy.sh: 既定は表示だけ（gcloud を一切呼ばない）・allUsers を付けない・設計の設定値。"""
import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BASE_ENV = {"PROJECT_ID": "test-project", "REGION": "asia-northeast1", "PROMPT_VERSION": "pv-test"}
AGENT = {**BASE_ENV, "SA_AGENT": "sa-agent@example.invalid"}
DEMO = {**BASE_ENV, "SA_DEMO": "sa-demo@example.invalid", "FETCHER_URL": "https://fetcher.example.invalid"}
FETCHER = {**BASE_ENV, "SA_FETCHER": "sa-fetcher@example.invalid", "ALLOWED_PREFIXES": "exact:lp.example.invalid/event,self.example.invalid/fx/"}


def run_deploy(tmp_path: Path, args: list[str], env: dict[str, str]) -> tuple[subprocess.CompletedProcess[str], Path]:
    """PATH の先頭に偽の gcloud を置く。呼ばれたら marker に書き、必ず失敗させる。"""
    stub = tmp_path / "bin"
    stub.mkdir(exist_ok=True)
    marker = tmp_path / "gcloud_called"
    g = stub / "gcloud"
    g.write_text(f'#!/bin/sh\necho "$@" >> "{marker}"\nexit 99\n', encoding="utf-8")
    g.chmod(0o755)
    full_env = {"PATH": f"{stub}:/usr/bin:/bin", "HOME": str(tmp_path), **env}
    cp = subprocess.run(["sh", str(ROOT / "deploy.sh"), *args], capture_output=True, text=True, env=full_env, cwd=ROOT)
    return cp, marker


def test_script_has_valid_shell_syntax_and_is_executable():
    assert subprocess.run(["sh", "-n", str(ROOT / "deploy.sh")]).returncode == 0
    assert os.access(ROOT / "deploy.sh", os.X_OK)


@pytest.mark.parametrize("target,env", [("agent", AGENT), ("demo", DEMO), ("fetcher", FETCHER)])
def test_default_is_a_dry_run_that_never_calls_gcloud(tmp_path, target, env):
    cp, marker = run_deploy(tmp_path, [target], env)
    assert cp.returncode == 0, cp.stderr
    assert not marker.exists(), "DRY_RUN で gcloud が呼ばれた"
    assert "DRY_RUN" in cp.stdout and "+ gcloud run deploy" in cp.stdout


@pytest.mark.parametrize("target,env", [("agent", AGENT), ("demo", DEMO), ("fetcher", FETCHER)])
def test_never_grants_public_access_or_secrets(tmp_path, target, env):
    cp, _ = run_deploy(tmp_path, [target], env)
    cmds = "\n".join(line for line in cp.stdout.splitlines() if line.startswith("+"))
    assert "--no-allow-unauthenticated" in cmds
    assert "--allow-unauthenticated" not in cmds.replace("--no-allow-unauthenticated", "")
    for bad in ("allUsers", "add-iam-policy-binding", "GOOGLE_APPLICATION_CREDENTIALS", "API_KEY", "--set-secrets"):
        assert bad not in cmds


def deploy_line(stdout: str) -> str:
    return next(line for line in stdout.splitlines() if line.startswith("+ gcloud run deploy"))


def test_s1_agent_settings(tmp_path):
    line = deploy_line(run_deploy(tmp_path, ["agent"], AGENT)[0].stdout)
    assert "claim-audit-agent" in line and "--service-account=sa-agent@example.invalid" in line
    assert "ROLE=agent@ENV=staging@FETCH_MODE=inproc@LIVE_ENABLED=0" in line
    assert "--max-instances=2" in line and "--no-allow-unauthenticated" in line


def test_s2_demo_settings_follow_the_design(tmp_path):
    line = deploy_line(run_deploy(tmp_path, ["demo"], DEMO)[0].stdout)
    for flag in ("--memory=1Gi", "--cpu=1", "--cpu-boost", "--concurrency=6", "--timeout=120", "--min-instances=0", "--max-instances=2"):
        assert flag in line
    assert "ROLE=agent@ENV=public@FETCH_MODE=remote@LIVE_ENABLED=0" in line  # ライブは二重ラッチの片方を閉じて出す
    assert "FETCHER_URL=https://fetcher.example.invalid" in line and "--service-account=sa-demo@example.invalid" in line


def test_s3_fetcher_settings_follow_the_design(tmp_path):
    cp, _ = run_deploy(tmp_path, ["fetcher"], FETCHER)
    line = deploy_line(cp.stdout)
    for flag in ("--memory=512Mi", "--concurrency=16", "--timeout=20", "--max-instances=2"):
        assert flag in line
    assert "ROLE=fetcher" in line and "FETCH_MODE" not in line and "GOOGLE_CLOUD_PROJECT" not in line  # 権限ゼロの SA。Vertex の設定を持たない
    assert "ALLOWED_PREFIXES=exact:lp.example.invalid/event,self.example.invalid/fx/" in line  # カンマ入りの値が壊れない
    assert "^@^" in line


def test_traffic_is_pinned_to_the_latest_revision(tmp_path):
    out = run_deploy(tmp_path, ["demo"], DEMO)[0].stdout
    assert "update-traffic claim-audit-demo" in out and "--to-latest" in out
    assert re.search(r"services describe claim-audit-demo.*status\.traffic", out)


def test_required_variables_are_enforced(tmp_path):
    for target, env, missing in [("agent", AGENT, "SA_AGENT"), ("demo", DEMO, "SA_DEMO"), ("demo", DEMO, "FETCHER_URL"), ("fetcher", FETCHER, "ALLOWED_PREFIXES")]:
        e = {k: v for k, v in env.items() if k != missing}
        cp, marker = run_deploy(tmp_path, [target], e)
        assert cp.returncode != 0 and missing in cp.stderr and not marker.exists()
    cp, _ = run_deploy(tmp_path, ["agent"], {k: v for k, v in AGENT.items() if k != "PROJECT_ID"})
    assert cp.returncode != 0 and "PROJECT_ID" in cp.stderr
    cp, _ = run_deploy(tmp_path, ["bogus"], AGENT)
    assert cp.returncode == 2 and "使い方" in cp.stderr


def test_only_the_explicit_apply_flag_runs_gcloud(tmp_path):
    cp, marker = run_deploy(tmp_path, ["agent", "--apply"], AGENT)
    assert marker.exists() and "run deploy claim-audit-agent" in marker.read_text()  # 偽の gcloud が呼ばれた（exit 99 で停止）
    assert cp.returncode != 0
    other = tmp_path / "second"
    other.mkdir()
    cp, marker = run_deploy(other, ["agent"], {**AGENT, "DRY_RUN": "0"})
    assert marker.exists()  # DRY_RUN=0 を明示した場合も実行される


def test_no_real_identifiers_in_the_script():
    text = (ROOT / "deploy.sh").read_text(encoding="utf-8")
    assert not re.search(r"\.iam\.gserviceaccount\.com|\.run\.app|projects/[a-z]", text)
