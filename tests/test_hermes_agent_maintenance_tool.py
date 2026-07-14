from __future__ import annotations

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
    print('Hermes Agent v0.18.2')
elif args[-2:] == ['update', '--check']:
    print('Update available: 3 commits behind origin/main.' if os.environ.get('FAKE_UPDATE_AVAILABLE') == '1' else os.environ.get('FAKE_CURRENT_TEXT', 'Already up to date.'))
elif 'update' in args and '--yes' in args:
    if os.environ.get('FAKE_UPDATE_FAIL') == '1':
        print('update failed', file=sys.stderr); raise SystemExit(9)
    print('updated')
elif args[-2:] == ['gateway', 'status']:
    print('Gateway service is running')
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
        }
    )
    env.update(extra)
    result = subprocess.run([str(TOOL)], text=True, capture_output=True, env=env, check=False)
    receipt = json.loads((receipt_dir / "latest.json").read_text(encoding="utf-8"))
    calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
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
