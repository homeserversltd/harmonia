from __future__ import annotations

import argparse
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

SOURCE_ROOT = Path("/opt/harmonia/source")
DEFAULT_BIN = Path("/usr/local/bin/harmonia")
DEFAULT_CONFIG_DIR = Path("/etc/harmonia")
DEFAULT_STATE_DIR = Path("/var/lib/harmonia")
DEFAULT_LOG_DIR = Path("/var/log/harmonia")
DEFAULT_RECEIPT_DIR = DEFAULT_STATE_DIR / "receipts"
DEFAULT_SYSTEMD_DIR = Path("/etc/systemd/system")


@dataclass(frozen=True)
class InstallPaths:
    bin_path: Path
    config_dir: Path
    state_dir: Path
    log_dir: Path
    receipt_dir: Path
    systemd_dir: Path

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "InstallPaths":
        return cls(
            bin_path=Path(args.bin_path),
            config_dir=Path(args.config_dir),
            state_dir=Path(args.state_dir),
            log_dir=Path(args.log_dir),
            receipt_dir=Path(args.receipt_dir),
            systemd_dir=Path(args.systemd_dir),
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = args.command or "help"
    if command == "help":
        parser.print_help()
        return 0
    if command == "menu":
        print_menu()
        return 0
    if command == "status":
        return status(InstallPaths.from_args(args))
    if command == "build":
        return build(args)
    if command == "install-timer":
        return install_timer(args)
    if command == "uninstall-timer":
        return uninstall_timer(args)
    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="./cli.py",
        description=(
            "Harmonia repo-local control face. Build, inspect, and control Harmonia "
            "systemd units from this repository."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Common paths:
  ./cli.py                         Show this full menu.
  ./cli.py build                   Compile target/release/harmonia from this repo.
  ./cli.py status                  Read installed shape.
  ./cli.py install-timer             Dry-run timer-only installation.
  sudo ./cli.py install-timer --apply  Install and enable only the Harmonia timer.
  sudo ./cli.py uninstall-timer --apply  Disable and remove only the Harmonia timer units.

Installation contract:
  deployables owns Harmonia installation and uninstallation. Harmonia retains
  control of its own systemd service and timer units.
""".strip(),
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("help", help="Show the full command menu.")
    sub.add_parser("menu", help="Show a concise option menu.")

    build_p = sub.add_parser("build", help="Build the Harmonia Rust binary from this repo.")
    build_p.add_argument("--debug", action="store_true", help="Build debug artifact instead of release.")
    build_p.add_argument("--cargo", default="cargo", help="Cargo executable to use.")
    build_p.add_argument("--package", default="harmonia", help="Cargo package name.")

    timer_install_p = sub.add_parser("install-timer", help="Install and enable only harmonia.service/harmonia.timer.")
    add_timer_path_args(timer_install_p)
    timer_install_p.add_argument("--apply", action="store_true", help="Actually write units and enable the timer. Omit for dry-run.")
    timer_install_p.add_argument("--dry-run", action="store_true", help="Compatibility spelling for the default non-mutating plan.")

    timer_uninstall_p = sub.add_parser("uninstall-timer", help="Disable and remove only harmonia.service/harmonia.timer.")
    add_timer_path_args(timer_uninstall_p)
    timer_uninstall_p.add_argument("--apply", action="store_true", help="Actually disable/remove units. Omit for dry-run.")
    timer_uninstall_p.add_argument("--dry-run", action="store_true", help="Compatibility spelling for the default non-mutating plan.")

    status_p = sub.add_parser("status", help="Read the current installed shape.")
    add_common_path_args(status_p)
    return parser


def add_common_path_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--bin-path", default=str(DEFAULT_BIN), help=f"Installed binary path (default {DEFAULT_BIN}).")
    parser.add_argument("--config-dir", default=str(DEFAULT_CONFIG_DIR), help=f"Config root (default {DEFAULT_CONFIG_DIR}).")
    parser.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR), help=f"State root (default {DEFAULT_STATE_DIR}).")
    parser.add_argument("--log-dir", default=str(DEFAULT_LOG_DIR), help=f"Log root (default {DEFAULT_LOG_DIR}).")
    parser.add_argument("--receipt-dir", default=str(DEFAULT_RECEIPT_DIR), help=f"Receipt root (default {DEFAULT_RECEIPT_DIR}).")
    parser.add_argument("--systemd-dir", default=str(DEFAULT_SYSTEMD_DIR), help=f"Systemd unit dir (default {DEFAULT_SYSTEMD_DIR}).")


def add_timer_path_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--systemd-dir", "--systemd-root", dest="systemd_dir", default=str(DEFAULT_SYSTEMD_DIR),
        help=f"Systemd unit directory (default {DEFAULT_SYSTEMD_DIR}; --systemd-root is a compatibility alias).",
    )


def print_menu() -> None:
    print("Harmonia repo-local installer menu")
    print("  help       full help and examples")
    print("  build      cargo build -p harmonia from this repo")
    print("  install-timer    dry-run or apply timer-only install")
    print("  uninstall-timer  dry-run or apply timer-only removal")
    print("  status     read installed binary/config/state shape")


def status(paths: InstallPaths) -> int:
    payload = {
        "schema": "harmonia.installer.status.v1",
        "ok": True,
        "repo_root": str(SOURCE_ROOT),
        "binary": describe_path(paths.bin_path),
        "config_dir": describe_path(paths.config_dir),
        "state_dir": describe_path(paths.state_dir),
        "receipt_dir": describe_path(paths.receipt_dir),
        "log_dir": describe_path(paths.log_dir),
        "systemd_service": describe_path(paths.systemd_dir / "harmonia.service"),
        "systemd_timer": describe_path(paths.systemd_dir / "harmonia.timer"),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def build(args: argparse.Namespace) -> int:
    cmd = [args.cargo, "build", "-p", args.package]
    if not getattr(args, "debug", False):
        cmd.append("--release")
    return run_checked_as_source_owner(cmd, cwd=SOURCE_ROOT)


def install_timer(args: argparse.Namespace) -> int:
    root = Path(args.systemd_dir)
    apply = bool(args.apply) and not bool(getattr(args, "dry_run", False))
    service = root / "harmonia.service"
    timer = root / "harmonia.timer"
    host = root == DEFAULT_SYSTEMD_DIR
    emit_plan("harmonia.installer.timer_plan.v1", apply, [
        f"install unit -> {service}",
        f"install unit -> {timer}",
        *( ["daemon-reload", "enable --now harmonia.timer"] if host else [] ),
    ])
    if not apply:
        return 0
    if os.geteuid() != 0 and host:
        print("harmonia timer apply requires root for the host systemd directory", file=sys.stderr)
        return 1
    paths = InstallPaths(DEFAULT_BIN, DEFAULT_CONFIG_DIR, DEFAULT_STATE_DIR, DEFAULT_LOG_DIR, DEFAULT_RECEIPT_DIR, root)
    install_systemd_units(paths)
    if host:
        code = run_checked(["systemctl", "daemon-reload"], cwd=SOURCE_ROOT, allow_missing=True)
        if code != 0:
            return code
        return run_checked(["systemctl", "enable", "--now", "harmonia.timer"], cwd=SOURCE_ROOT, allow_missing=True)
    return 0


def uninstall_timer(args: argparse.Namespace) -> int:
    root = Path(args.systemd_dir)
    apply = bool(args.apply) and not bool(getattr(args, "dry_run", False))
    service = root / "harmonia.service"
    timer = root / "harmonia.timer"
    host = root == DEFAULT_SYSTEMD_DIR
    emit_plan("harmonia.installer.timer_plan.v1", apply, [
        *( ["disable --now harmonia.timer", "daemon-reload"] if host else [] ),
        f"remove unit -> {timer}",
        f"remove unit -> {service}",
    ])
    if not apply:
        return 0
    if os.geteuid() != 0 and host:
        print("harmonia timer uninstall requires root for the host systemd directory", file=sys.stderr)
        return 1
    if host:
        code = run_checked(["systemctl", "disable", "--now", "harmonia.timer"], cwd=SOURCE_ROOT, allow_missing=True)
        if code != 0:
            return code
    for path in (timer, service):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    if host:
        return run_checked(["systemctl", "daemon-reload"], cwd=SOURCE_ROOT, allow_missing=True)
    return 0

def emit_plan(schema: str, apply: bool, lines: Iterable[str]) -> None:
    print(f"schema={schema}")
    print("ok=true")
    print(f"apply={str(apply).lower()}")
    for line in lines:
        print(f"plan={line}")


def describe_path(path: Path) -> dict[str, object]:
    exists = path.exists()
    return {
        "path": str(path),
        "exists": exists,
        "is_dir": path.is_dir() if exists else False,
        "mode": oct(stat.S_IMODE(path.stat().st_mode)) if exists else None,
    }


def run_checked(cmd: Sequence[str], cwd: Path, allow_missing: bool = False) -> int:
    if allow_missing and shutil.which(cmd[0]) is None:
        print(f"skip missing command: {cmd[0]}")
        return 0
    print("run=" + " ".join(cmd))
    completed = subprocess.run(cmd, cwd=str(cwd), check=False)
    return completed.returncode


def run_checked_as_source_owner(cmd: Sequence[str], cwd: Path) -> int:
    """Keep privileged enrollment builds in the checkout owner's filesystem plane."""
    if os.geteuid() != 0:
        return run_checked(cmd, cwd=cwd)
    source = cwd.stat()
    if source.st_uid == 0 or source.st_gid == 0:
        print(f"root-owned-source-build-refused={cwd}", file=sys.stderr)
        return 1
    account = pwd.getpwuid(source.st_uid)
    target = cwd / "target"
    target.mkdir(parents=True, exist_ok=True)
    for path in [target, *target.rglob("*")]:
        metadata = path.lstat()
        if metadata.st_uid != source.st_uid or metadata.st_gid != source.st_gid:
            os.chown(path, source.st_uid, source.st_gid, follow_symlinks=False)
    env = os.environ.copy()
    env.update(
        {
            "HOME": account.pw_dir,
            "USER": account.pw_name,
            "LOGNAME": account.pw_name,
            "XDG_CONFIG_HOME": str(Path(account.pw_dir) / ".config"),
        }
    )
    for name in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_COUNT", "GIT_ASKPASS", "SSH_ASKPASS"):
        env.pop(name, None)
    print("run_as_source_owner=" + account.pw_name)
    print("run=" + " ".join(cmd))
    completed = subprocess.run(
        cmd,
        cwd=str(cwd),
        check=False,
        env=env,
        user=source.st_uid,
        group=source.st_gid,
        extra_groups=[],
    )
    return completed.returncode


def install_systemd_units(paths: InstallPaths) -> None:
    receipt_latest = f"{paths.receipt_dir}/update-latest"
    run_command = f"{paths.bin_path} update --apply --receipt-dir {receipt_latest}"
    service_name = "harmonia.service"
    timer_name = "harmonia.timer"
    service = f"""[Unit]
Description=Run Harmonia convergence for the selected profile
Documentation=file:{receipt_latest}/run.json
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={run_command}
Nice=10
IOSchedulingClass=idle
"""
    timer = f"""[Unit]
Description=Run Harmonia selected-profile convergence on schedule

[Timer]
OnBootSec=2min
OnCalendar=*:0/10
OnUnitActiveSec=10min
AccuracySec=30s
Persistent=true
Unit={service_name}

[Install]
WantedBy=timers.target
"""
    paths.systemd_dir.mkdir(parents=True, exist_ok=True)
    (paths.systemd_dir / service_name).write_text(service)
    (paths.systemd_dir / timer_name).write_text(timer)


if __name__ == "__main__":
    raise SystemExit(main())
