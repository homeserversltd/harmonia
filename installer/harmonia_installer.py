from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
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
    if command == "install":
        return install(args)
    if command == "uninstall":
        return uninstall(args)
    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="./cli.py",
        description=(
            "Harmonia repo-local control face. Build and install Harmonia from this "
            "repository without external private helpers."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Common paths:
  ./cli.py                         Show this full menu.
  ./cli.py build                   Compile target/release/harmonia from this repo.
  ./cli.py install                 Dry-run the install plan.
  sudo ./cli.py install --apply    Build, install binary/config/assets, and optionally systemd units.
  ./cli.py status                  Read installed shape.
  sudo ./cli.py uninstall --apply  Remove installed Harmonia surfaces.

Install contract:
  The repo owns its own install instructions. External automation may call this
  CLI, but does not replace it.
""".strip(),
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("help", help="Show the full command menu.")
    sub.add_parser("menu", help="Show a concise option menu.")

    build_p = sub.add_parser("build", help="Build the Harmonia Rust binary from this repo.")
    build_p.add_argument("--debug", action="store_true", help="Build debug artifact instead of release.")
    build_p.add_argument("--cargo", default="cargo", help="Cargo executable to use.")
    build_p.add_argument("--package", default="harmonia", help="Cargo package name.")

    install_p = sub.add_parser("install", help="Build and install Harmonia from this repo.")
    add_common_path_args(install_p)
    install_p.add_argument("--apply", action="store_true", help="Actually write install surfaces. Omit for dry-run.")
    install_p.add_argument("--skip-build", action="store_true", help="Install existing target artifact without running cargo build.")
    install_p.add_argument("--debug", action="store_true", help="Use target/debug/harmonia instead of target/release/harmonia.")
    install_p.add_argument("--profile", default="homeconsole", help="Profile to install under /etc/harmonia/profiles/<profile>.")
    install_p.add_argument("--cargo", default="cargo", help="Cargo executable to use.")
    install_p.add_argument("--package", default="harmonia", help="Cargo package name.")
    install_p.add_argument("--with-systemd", action="store_true", help="Install harmonia service/timer units.")
    install_p.add_argument("--enable-timer", action="store_true", help="Enable harmonia.timer after installing units; implies --with-systemd.")

    uninstall_p = sub.add_parser("uninstall", help="Remove installed Harmonia surfaces.")
    add_common_path_args(uninstall_p)
    uninstall_p.add_argument("--apply", action="store_true", help="Actually remove install surfaces. Omit for dry-run.")
    uninstall_p.add_argument("--keep-state", action="store_true", help="Preserve /var/lib/harmonia state and receipts.")
    uninstall_p.add_argument("--keep-config", action="store_true", help="Preserve /etc/harmonia config.")
    uninstall_p.add_argument("--with-systemd", action="store_true", help="Remove harmonia service/timer units too.")

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


def print_menu() -> None:
    print("Harmonia repo-local installer menu")
    print("  help       full help and examples")
    print("  build      cargo build -p harmonia from this repo")
    print("  install    dry-run or apply binary/config/profile install")
    print("  uninstall  dry-run or apply removal")
    print("  status     read installed binary/config/state shape")


def status(paths: InstallPaths) -> int:
    payload = {
        "schema": "harmonia.installer.status.v1",
        "ok": True,
        "repo_root": str(REPO_ROOT),
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
    return run_checked(cmd, cwd=REPO_ROOT)


def install(args: argparse.Namespace) -> int:
    paths = InstallPaths.from_args(args)
    apply = bool(args.apply)
    with_systemd = bool(args.with_systemd or args.enable_timer)
    artifact = REPO_ROOT / "target" / ("debug" if getattr(args, "debug", False) else "release") / "harmonia"
    plan = [
        f"build binary with cargo unless --skip-build ({artifact})",
        f"install binary -> {paths.bin_path}",
        f"install profiles -> {paths.config_dir / 'profiles'}",
        f"install modules -> {paths.config_dir / 'modules'}",
        f"install locks -> {paths.config_dir / 'locks'}",
        f"ensure state/log/receipt dirs -> {paths.state_dir}, {paths.log_dir}, {paths.receipt_dir}",
    ]
    if with_systemd:
        plan.append(f"install systemd units -> {paths.systemd_dir}/harmonia.service and harmonia.timer")
    emit_plan("harmonia.installer.install_plan.v1", apply, plan)
    if not apply:
        return 0
    if not args.skip_build:
        code = build(args)
        if code != 0:
            return code
    if not artifact.exists():
        print(f"missing build artifact: {artifact}", file=sys.stderr)
        return 1
    install_file(artifact, paths.bin_path, mode=0o755)
    copy_tree(REPO_ROOT / "profiles", paths.config_dir / "profiles")
    copy_tree(REPO_ROOT / "modules", paths.config_dir / "modules")
    copy_tree(REPO_ROOT / "locks", paths.config_dir / "locks")
    for directory in [paths.state_dir, paths.receipt_dir, paths.log_dir]:
        directory.mkdir(parents=True, exist_ok=True)
    if with_systemd:
        install_systemd_units(paths, profile=args.profile)
        run_checked(["systemctl", "daemon-reload"], cwd=REPO_ROOT, allow_missing=True)
        if args.enable_timer:
            run_checked(["systemctl", "enable", "--now", "harmonia.timer"], cwd=REPO_ROOT, allow_missing=True)
    print("schema=harmonia.installer.install.v1")
    print("ok=true")
    print(f"binary={paths.bin_path}")
    print(f"config_dir={paths.config_dir}")
    return 0


def uninstall(args: argparse.Namespace) -> int:
    paths = InstallPaths.from_args(args)
    apply = bool(args.apply)
    targets: list[Path] = [paths.bin_path]
    if args.with_systemd:
        targets.extend([paths.systemd_dir / "harmonia.service", paths.systemd_dir / "harmonia.timer"])
    if not args.keep_config:
        targets.append(paths.config_dir)
    if not args.keep_state:
        targets.extend([paths.state_dir, paths.log_dir])
    emit_plan("harmonia.installer.uninstall_plan.v1", apply, [f"remove {target}" for target in targets])
    if not apply:
        return 0
    if args.with_systemd:
        run_checked(["systemctl", "disable", "--now", "harmonia.timer"], cwd=REPO_ROOT, allow_missing=True)
        run_checked(["systemctl", "daemon-reload"], cwd=REPO_ROOT, allow_missing=True)
    for target in targets:
        remove_path(target)
    print("schema=harmonia.installer.uninstall.v1")
    print("ok=true")
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


def install_file(src: Path, dst: Path, mode: int) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_name(dst.name + ".harmonia-new")
    shutil.copy2(src, tmp)
    os.chmod(tmp, mode)
    os.replace(tmp, dst)


def copy_tree(src: Path, dst: Path) -> None:
    if not src.exists():
        return
    dst.mkdir(parents=True, exist_ok=True)
    for path in src.rglob("*"):
        rel = path.relative_to(src)
        target = dst / rel
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)


def install_systemd_units(paths: InstallPaths, profile: str) -> None:
    service = f"""[Unit]
Description=Harmonia profile update runner
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={paths.bin_path} run-profile {paths.config_dir}/profiles/{profile}/index.json --apply --receipt-dir {paths.receipt_dir}/{profile}-latest
"""
    timer = """[Unit]
Description=Run Harmonia profile update periodically

[Timer]
OnBootSec=5min
OnUnitActiveSec=1d
Persistent=true

[Install]
WantedBy=timers.target
"""
    paths.systemd_dir.mkdir(parents=True, exist_ok=True)
    (paths.systemd_dir / "harmonia.service").write_text(service)
    (paths.systemd_dir / "harmonia.timer").write_text(timer)


def remove_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
