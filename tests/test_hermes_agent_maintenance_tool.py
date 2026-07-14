from __future__ import annotations

import fcntl
import json
import os
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "profiles/hermes/modules/hermes-agent-maintenance-tool"
TOOL = MODULE / "files_root/usr/local/libexec/hermes-agent-maintenance"


def fake_tools(tmp_path: Path) -> tuple[Path, Path, Path]:
    log = tmp_path / "calls.jsonl"
    hermes = tmp_path / "hermes"
    systemctl = tmp_path / "systemctl"
    hermes.write_text(
        """#!/usr/bin/env python3
import json, os, sys
with open(os.environ['FAKE_CALL_LOG'], 'a', encoding='utf-8') as h:
    h.write(json.dumps(['hermes', *sys.argv[1:]]) + '\\n')
args = sys.argv[1:]
if args == ['--version']:
    count_path = os.environ.get('FAKE_VERSION_COUNT')
    count = 1
    if count_path:
        try:
            with open(count_path, encoding='utf-8') as h:
                count = int(h.read()) + 1
        except FileNotFoundError:
            pass
        with open(count_path, 'w', encoding='utf-8') as h:
            h.write(str(count))
    if os.environ.get('FAKE_VERSION_FAIL') == '1' or (os.environ.get('FAKE_VERSION_FAIL_AFTER') == '1' and count > 1):
        print('version failed', file=sys.stderr); raise SystemExit(6)
    print('Hermes Agent v0.18.2')
elif args[-2:] == ['update', '--check']:
    print('Update available: 3 commits behind origin/main.' if os.environ.get('FAKE_UPDATE_AVAILABLE') == '1' else os.environ.get('FAKE_CURRENT_TEXT', 'Already up to date.'))
elif 'update' in args and '--yes' in args:
    if os.environ.get('FAKE_UPDATE_FAIL') == '1':
        print('update failed', file=sys.stderr); raise SystemExit(9)
    print('updated')
elif args[-2:] == ['gateway', 'status']:
    print(os.environ.get('FAKE_GATEWAY_STATUS', 'Gateway service is running'))
else:
    print('unexpected hermes args', args, file=sys.stderr); raise SystemExit(8)
""",
        encoding="utf-8",
    )
    systemctl.write_text(
        """#!/usr/bin/env python3
import json, os, sys
with open(os.environ['FAKE_CALL_LOG'], 'a', encoding='utf-8') as h:
    h.write(json.dumps(['systemctl', *sys.argv[1:]]) + '\\n')
if 'restart' in sys.argv and os.environ.get('FAKE_RESTART_FAIL') == '1':
    raise SystemExit(7)
raise SystemExit(0)
""",
        encoding="utf-8",
    )
    hermes.chmod(hermes.stat().st_mode | stat.S_IXUSR)
    systemctl.chmod(systemctl.stat().st_mode | stat.S_IXUSR)
    return hermes, systemctl, log


def run_tool(tmp_path: Path, **extra: str) -> tuple[subprocess.CompletedProcess[str], dict, list[list[str]]]:
    hermes, systemctl, log = fake_tools(tmp_path)
    receipt_dir = tmp_path / "receipts"
    env = os.environ.copy()
    env.update(
        {
            "HERMES_MAINTENANCE_HERMES_BIN": str(hermes),
            "HERMES_MAINTENANCE_SYSTEMCTL_BIN": str(systemctl),
            "HERMES_MAINTENANCE_RECEIPT_DIR": str(receipt_dir),
            "HERMES_MAINTENANCE_LOCK_PATH": str(tmp_path / "maintenance.lock"),
            "FAKE_CALL_LOG": str(log),
            "FAKE_VERSION_COUNT": str(tmp_path / "version-count"),
        }
    )
    env.update(extra)
    result = subprocess.run([str(TOOL)], text=True, capture_output=True, env=env, check=False)
    receipt = json.loads((receipt_dir / "latest.json").read_text(encoding="utf-8"))
    calls = (
        [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        if log.exists()
        else []
    )
    return result, receipt, calls


def test_public_module_is_tool_only_and_contains_no_private_machine_policy() -> None:
    manifest = json.loads((MODULE / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["id"] == "hermes-agent-maintenance-tool"
    assert [step["tool"] for step in manifest["ladder"]] == ["files"]
    source = TOOL.read_text(encoding="utf-8")
    assert "/home/owner" not in source
    assert "OnCalendar" not in source
    assert "hermes-gateway.service" in source


def test_update_success_restarts_only_selected_gateway_and_writes_receipt(tmp_path: Path) -> None:
    result, receipt, calls = run_tool(tmp_path, FAKE_UPDATE_AVAILABLE="1")
    assert result.returncode == 0
    assert receipt["ok"] is True
    assert receipt["updated"] is True
    assert receipt["state"] == "gateway-restarted-after-update"
    assert ["systemctl", "--user", "restart", "hermes-gateway.service"] in calls
    assert ["hermes", "update", "--yes"] in calls


def test_failed_update_preserves_running_gateway(tmp_path: Path) -> None:
    result, receipt, calls = run_tool(
        tmp_path,
        FAKE_UPDATE_AVAILABLE="1",
        FAKE_UPDATE_FAIL="1",
    )
    assert result.returncode == 1
    assert receipt["state"] == "hermes-update-failed"
    assert receipt["gateway_restart_attempted"] is False
    assert not any(call[:3] == ["systemctl", "--user", "restart"] for call in calls)


def test_current_install_still_gets_nightly_selected_gateway_restart(tmp_path: Path) -> None:
    result, receipt, calls = run_tool(tmp_path, FAKE_UPDATE_AVAILABLE="0")
    assert result.returncode == 0
    assert receipt["updated"] is False
    assert receipt["state"] == "gateway-restarted-current"
    assert not any("--yes" in call for call in calls)
    assert ["systemctl", "--user", "restart", "hermes-gateway.service"] in calls


def test_no_update_available_phrase_is_not_a_false_positive(tmp_path: Path) -> None:
    result, receipt, calls = run_tool(
        tmp_path,
        FAKE_UPDATE_AVAILABLE="0",
        FAKE_CURRENT_TEXT="No update available.",
    )
    assert result.returncode == 0
    assert receipt["updated"] is False
    assert not any("--yes" in call for call in calls)


def test_named_profile_derives_named_gateway_and_uses_profile_cli(tmp_path: Path) -> None:
    result, receipt, calls = run_tool(
        tmp_path,
        HERMES_MAINTENANCE_PROFILE="research",
        FAKE_UPDATE_AVAILABLE="0",
    )
    assert result.returncode == 0
    assert receipt["gateway_unit"] == "hermes-gateway-research.service"
    assert ["systemctl", "--user", "restart", "hermes-gateway-research.service"] in calls
    assert ["hermes", "-p", "research", "update", "--check"] in calls
    assert ["hermes", "-p", "research", "gateway", "status"] in calls


def test_gateway_override_must_match_selected_lifecycle_boundary(tmp_path: Path) -> None:
    result, receipt, calls = run_tool(
        tmp_path,
        HERMES_MAINTENANCE_GATEWAY_UNIT="unrelated.service",
    )
    assert result.returncode == 1
    assert receipt["state"] == "hermes-gateway-unit-mismatch"
    assert calls == []


def test_named_multiplex_profile_restarts_and_proves_default_gateway(tmp_path: Path) -> None:
    result, receipt, calls = run_tool(
        tmp_path,
        HERMES_MAINTENANCE_PROFILE="research",
        HERMES_MAINTENANCE_GATEWAY_MODE="multiplex-default",
        HERMES_MAINTENANCE_GATEWAY_UNIT="hermes-gateway.service",
        FAKE_UPDATE_AVAILABLE="0",
    )
    assert result.returncode == 0
    assert receipt["gateway_mode"] == "multiplex-default"
    assert ["hermes", "-p", "research", "update", "--check"] in calls
    assert ["systemctl", "--user", "restart", "hermes-gateway.service"] in calls
    assert ["hermes", "gateway", "status"] in calls


def test_invalid_timeout_writes_failure_receipt_before_commands(tmp_path: Path) -> None:
    result, receipt, calls = run_tool(
        tmp_path,
        HERMES_MAINTENANCE_TIMEOUT_SECONDS="not-a-number",
    )
    assert result.returncode == 1
    assert receipt["state"] == "hermes-timeout-invalid"
    assert calls == []


def test_failed_version_probe_preserves_gateway(tmp_path: Path) -> None:
    result, receipt, calls = run_tool(tmp_path, FAKE_VERSION_FAIL="1")
    assert result.returncode == 1
    assert receipt["state"] == "hermes-pre-update-cli-failed"
    assert receipt["gateway_restart_attempted"] is False
    assert not any(call[:3] == ["systemctl", "--user", "restart"] for call in calls)


def test_failed_post_update_version_probe_preserves_gateway(tmp_path: Path) -> None:
    result, receipt, calls = run_tool(tmp_path, FAKE_VERSION_FAIL_AFTER="1")
    assert result.returncode == 1
    assert receipt["state"] == "hermes-post-update-cli-failed"
    assert receipt["gateway_restart_attempted"] is False
    assert not any(call[:3] == ["systemctl", "--user", "restart"] for call in calls)


def test_invalid_profile_writes_failure_receipt(tmp_path: Path) -> None:
    result, receipt, calls = run_tool(
        tmp_path,
        HERMES_MAINTENANCE_PROFILE="../../other-unit",
    )
    assert result.returncode == 1
    assert receipt["state"] == "hermes-profile-invalid"
    assert calls == []


def test_semantically_inactive_gateway_status_is_red(tmp_path: Path) -> None:
    result, receipt, _ = run_tool(
        tmp_path,
        FAKE_GATEWAY_STATUS="Gateway service is inactive",
    )
    assert result.returncode == 1
    assert receipt["state"] == "hermes-gateway-status-failed"


def test_lock_contention_does_not_overwrite_active_run_receipt(tmp_path: Path) -> None:
    hermes, systemctl, log = fake_tools(tmp_path)
    receipt_dir = tmp_path / "receipts"
    lock_path = tmp_path / "maintenance.lock"
    env = os.environ.copy()
    env.update(
        {
            "HERMES_MAINTENANCE_HERMES_BIN": str(hermes),
            "HERMES_MAINTENANCE_SYSTEMCTL_BIN": str(systemctl),
            "HERMES_MAINTENANCE_RECEIPT_DIR": str(receipt_dir),
            "HERMES_MAINTENANCE_LOCK_PATH": str(lock_path),
            "FAKE_CALL_LOG": str(log),
        }
    )
    with lock_path.open("a+", encoding="utf-8") as held:
        fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = subprocess.run([str(TOOL)], text=True, capture_output=True, env=env, check=False)
    skipped = json.loads(
        (receipt_dir / "last-skipped-locked.json").read_text(encoding="utf-8")
    )
    assert result.returncode == 0
    assert skipped["state"] == "skipped-locked"
    assert not (receipt_dir / "latest.json").exists()
    assert not log.exists()
