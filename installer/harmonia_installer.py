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
DEFAULT_ESTATE_ARTIFACT_REPO = "git@git.home.arpa:HOMESERVERSLTD/blessed-artifacts.git"
DEFAULT_GLOBAL_ARTIFACT_REPO = "https://github.com/homeserversltd/blessed-artifacts.git"


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
    install_p.add_argument("--lane", default="upstream", choices=("upstream", "owner"), help="Machine subscription lane to seed after apply.")
    install_p.add_argument("--source", default=None, help="Machine subscription source repo URL or capsule origin. Defaults to git origin or repo path.")
    install_p.add_argument("--ref", default=None, help="Machine subscription ref. Defaults to this repo HEAD.")
    install_p.add_argument("--cargo", default="cargo", help="Cargo executable to use.")
    install_p.add_argument("--package", default="harmonia", help="Cargo package name.")
    install_p.add_argument("--artifact-repo", default=None, help="Estate blessed-artifacts SSH git repo. Defaults to git@git.home.arpa:HOMESERVERSLTD/blessed-artifacts.git.")
    install_p.add_argument("--artifact-github-repo", default=None, help="Canonical global blessed-artifacts HTTPS repo. Defaults to https://github.com/homeserversltd/blessed-artifacts.git.")
    install_p.add_argument("--artifact-transport-chain", default=None, help="JSON list overriding the full ordered artifact transport chain.")
    install_p.add_argument("--artifact-branch", default="main", help="Blessed artifact repo branch (default main).")
    install_p.add_argument("--artifact-cache-dir", default=None, help="Local cache dir for blessed engine artifacts. Defaults under state-dir.")
    install_p.add_argument("--ratchet-lock", default=None, help="Kernel-owned engine ratchet lock path. Defaults beside engine.json.")
    install_p.add_argument("--with-systemd", action="store_true", help="Install harmonia-homeconsole service/timer units.")
    install_p.add_argument("--enable-timer", action="store_true", help="Enable harmonia-homeconsole.timer after installing units; implies --with-systemd.")

    uninstall_p = sub.add_parser("uninstall", help="Remove installed Harmonia surfaces.")
    add_common_path_args(uninstall_p)
    uninstall_p.add_argument("--apply", action="store_true", help="Actually remove install surfaces. Omit for dry-run.")
    uninstall_p.add_argument("--purge-state", action="store_true", help="Remove /var/lib/harmonia state/receipts and logs. Default preserves history.")
    uninstall_p.add_argument("--keep-state", action="store_true", help=argparse.SUPPRESS)
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
        "systemd_service": describe_path(paths.systemd_dir / "harmonia-homeconsole.service"),
        "systemd_timer": describe_path(paths.systemd_dir / "harmonia-homeconsole.timer"),
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
    capsule_dir = paths.state_dir / "capsules" / args.profile
    plan = [
        f"build binary with cargo unless --skip-build ({artifact})",
        f"install binary -> {paths.bin_path}",
        f"seed kernel-owned engine config -> {paths.config_dir / 'engine.json'}",
        f"pack capsule for profile {args.profile} -> {capsule_dir}",
        f"install capsule into {paths.config_dir} (lane=capsule)",
        f"ensure state/log/receipt dirs -> {paths.state_dir}, {paths.log_dir}, {paths.receipt_dir}",
    ]
    if with_systemd:
        plan.append(
            f"install systemd units -> {paths.systemd_dir}/harmonia-{args.profile}.service and harmonia-{args.profile}.timer"
        )
    emit_plan("harmonia.installer.install_plan.v1", apply, plan)
    if not apply:
        return 0
    if requires_root(paths) and os.geteuid() != 0:
        print("harmonia installer apply requires root for system paths; rerun with sudo or pass fake --*-dir paths for hermetic tests", file=sys.stderr)
        return 1
    if not args.skip_build:
        code = build(args)
        if code != 0:
            return code
    if not artifact.exists():
        print(f"missing build artifact: {artifact}", file=sys.stderr)
        return 1
    install_file(artifact, paths.bin_path, mode=0o755)
    seed_engine_config(
        paths.config_dir / "engine.json",
        source=args.source or repo_source(),
        ref=args.ref or repo_ref(),
        source_dir=REPO_ROOT,
        install_bin=paths.bin_path,
        enabled=True,
        ratchet_lock=Path(args.ratchet_lock) if args.ratchet_lock else None,
        artifact_repo=args.artifact_repo,
        artifact_github_repo=args.artifact_github_repo,
        artifact_transport_chain=json.loads(args.artifact_transport_chain) if args.artifact_transport_chain else None,
        artifact_branch=args.artifact_branch,
        artifact_cache_dir=Path(args.artifact_cache_dir) if args.artifact_cache_dir else paths.state_dir / "engine-artifacts",
    )
    for directory in [paths.state_dir, paths.receipt_dir, paths.log_dir]:
        directory.mkdir(parents=True, exist_ok=True)
    pack_code = run_checked(
        [str(paths.bin_path), "capsule", "pack", args.profile, "--out", str(capsule_dir), "--harmonia-root", str(REPO_ROOT)],
        cwd=REPO_ROOT,
    )
    print(f"capsule_pack_exit={pack_code}")
    if pack_code != 0:
        print("ok=false")
        return pack_code
    try:
        packed_module_count = validate_packed_capsule(REPO_ROOT, capsule_dir, args.profile)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"capsule_pack_validation_failed={exc}", file=sys.stderr)
        print("ok=false")
        return 1
    print(f"capsule_pack_validated_module_count={packed_module_count}")
    install_code = run_checked(
        [str(paths.bin_path), "capsule", "install", str(capsule_dir), "--config-dir", str(paths.config_dir), "--apply"],
        cwd=REPO_ROOT,
    )
    print(f"capsule_install_exit={install_code}")
    if install_code != 0:
        print("ok=false")
        return install_code
    seed_subscription_record(
        paths.state_dir / "subscription.json",
        capsule_dir / "capsule.json",
        lane=args.lane,
        source=args.source or repo_source(),
        ref=args.ref or repo_ref(),
        selected_profile=args.profile,
    )
    if with_systemd:
        install_systemd_units(paths, profile=args.profile)
        daemon_reload = run_checked(["systemctl", "daemon-reload"], cwd=REPO_ROOT, allow_missing=True)
        print(f"systemctl_daemon_reload_exit={daemon_reload}")
        if daemon_reload != 0:
            print("ok=false")
            return daemon_reload
        if args.enable_timer:
            enable_timer = run_checked(
                ["systemctl", "enable", "--now", f"harmonia-{args.profile}.timer"],
                cwd=REPO_ROOT,
                allow_missing=True,
            )
            print(f"systemctl_enable_timer_exit={enable_timer}")
            if enable_timer != 0:
                print("ok=false")
                return enable_timer
    print("schema=harmonia.installer.install.v1")
    print("ok=true")
    print("profile=" + args.profile)
    print("lane=capsule")
    print(f"subscription={paths.state_dir / 'subscription.json'}")
    print(f"binary={paths.bin_path}")
    print(f"config_dir={paths.config_dir}")
    return 0


def uninstall(args: argparse.Namespace) -> int:
    paths = InstallPaths.from_args(args)
    apply = bool(args.apply)
    targets: list[Path] = [paths.bin_path]
    if args.with_systemd:
        targets.extend(
            [
                paths.systemd_dir / "harmonia-homeconsole.service",
                paths.systemd_dir / "harmonia-homeconsole.timer",
            ]
        )
    if not args.keep_config:
        targets.append(paths.config_dir)
    purge_state = bool(getattr(args, "purge_state", False)) and not bool(getattr(args, "keep_state", False))
    if purge_state:
        targets.extend([paths.state_dir, paths.log_dir])
    emit_plan("harmonia.installer.uninstall_plan.v1", apply, [f"remove {target}" for target in targets])
    if not apply:
        return 0
    if args.with_systemd:
        run_checked(
            ["systemctl", "disable", "--now", "harmonia-homeconsole.timer"],
            cwd=REPO_ROOT,
            allow_missing=True,
        )
        run_checked(["systemctl", "daemon-reload"], cwd=REPO_ROOT, allow_missing=True)
    for target in targets:
        remove_path(target)
    print("schema=harmonia.installer.uninstall.v1")
    print("ok=true")
    print(f"purge_state={str(purge_state).lower()}")
    print(f"state_preserved={str(not purge_state).lower()}")
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
    receipt_latest = f"{paths.receipt_dir}/{profile}-update-latest"
    if profile == "homeconsole":
        run_command = f"{paths.bin_path} homeconsole-update {paths.config_dir}/profiles/{profile}/index.json --apply --receipt-dir {receipt_latest}"
    elif profile == "homeserver":
        run_command = f"{paths.bin_path} homeserver-update {paths.config_dir}/profiles/{profile}/index.json --apply --receipt-dir {receipt_latest}"
    elif profile == "tv":
        run_command = f"{paths.bin_path} tv-update {paths.config_dir}/profiles/{profile}/index.json --apply --receipt-dir {receipt_latest}"
    else:
        run_command = f"{paths.bin_path} run-profile {paths.config_dir}/profiles/{profile}/index.json --apply --receipt-dir {receipt_latest}"
    service_name = f"harmonia-{profile}.service"
    timer_name = f"harmonia-{profile}.timer"
    service = f"""[Unit]
Description=Run Harmonia {profile} profile convergence
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
Description=Run Harmonia {profile} profile convergence on schedule

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


def validate_packed_capsule(harmonia_root: Path, capsule_dir: Path, profile: str) -> int:
    profile_path = harmonia_root / "profiles" / profile / "index.json"
    capsule_path = capsule_dir / "capsule.json"
    declared = json.loads(profile_path.read_text(encoding="utf-8"))
    packed = json.loads(capsule_path.read_text(encoding="utf-8"))
    declared_modules = declared.get("modules")
    packed_entries = packed.get("modules")
    if not isinstance(declared_modules, list) or not all(isinstance(item, str) for item in declared_modules):
        raise ValueError(f"profile-modules-invalid path={profile_path}")
    if not isinstance(packed_entries, list):
        raise ValueError(f"capsule-modules-invalid path={capsule_path}")
    packed_modules = [entry.get("id") if isinstance(entry, dict) else None for entry in packed_entries]
    if len(packed_modules) != len(declared_modules) or packed_modules != declared_modules:
        raise ValueError(
            "capsule-module-set-mismatch "
            f"declared_count={len(declared_modules)} packed_count={len(packed_modules)} "
            f"declared={declared_modules} packed={packed_modules}"
        )
    expected_ref = repo_ref(harmonia_root)
    created_from = packed.get("created_from")
    if expected_ref == "unknown" or len(expected_ref) != 40 or any(ch not in "0123456789abcdef" for ch in expected_ref.lower()):
        raise ValueError(f"source-revision-unavailable root={harmonia_root}")
    if created_from != expected_ref:
        raise ValueError(f"capsule-created-from-mismatch expected={expected_ref} packed={created_from}")
    return len(packed_modules)


def seed_subscription_record(path: Path, capsule_manifest_path: Path, *, lane: str, source: str, ref: str, selected_profile: str) -> None:
    capsule = json.loads(capsule_manifest_path.read_text())
    if path.exists():
        existing: dict[str, object] = json.loads(path.read_text())
    else:
        existing = {}
    raw_modules = existing.get("modules", {})
    modules = dict(raw_modules) if isinstance(raw_modules, dict) else {}
    run_id = f"installer-{os.getpid()}"
    for module in capsule.get("modules", []):
        modules[module["id"]] = {
            "version": module["version"],
            "tree_sha256": module["tree_sha256"],
            "received_at_run_id": run_id,
        }
    existing.update(
        {
            "schema": "harmonia.subscription.v1",
            "lane": lane,
            "source": source,
            "ref": ref,
            "selected_profile": selected_profile,
            "engine_version_received": capsule.get("engine_version", "unknown"),
            "modules": modules,
            "updated_at_unix_ms": int(__import__("time").time() * 1000),
        }
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".harmonia-new")
    tmp.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, path)


def seed_engine_config(
    path: Path,
    *,
    source: str,
    ref: str,
    source_dir: Path,
    install_bin: Path,
    enabled: bool,
    ratchet_lock: Path | None = None,
    artifact_repo: str | None = None,
    artifact_github_repo: str | None = None,
    artifact_transport_chain: list[dict[str, object]] | None = None,
    artifact_branch: str = "main",
    artifact_cache_dir: Path | None = None,
) -> None:
    if path.exists():
        try:
            raw = json.loads(path.read_text())
            existing: dict[str, object] = dict(raw) if isinstance(raw, dict) else {}
        except json.JSONDecodeError:
            existing = {}
    else:
        existing = {}
    update = {
        "source_repo_url": source,
        "branch": "main",
        "source_dir": str(source_dir),
        "install_bin": str(install_bin),
        "enabled": enabled,
        "git_bearer": "owner",
    }
    update["ratchet_lock"] = str(ratchet_lock or (path.parent / "engine-ratchet-lock.json"))
    base_cache = artifact_cache_dir or Path("/var/lib/harmonia/engine-artifacts")
    if artifact_transport_chain is not None:
        update["artifact_transports"] = artifact_transport_chain
    else:
        estate_repo = artifact_repo or DEFAULT_ESTATE_ARTIFACT_REPO
        global_repo = artifact_github_repo or DEFAULT_GLOBAL_ARTIFACT_REPO
        update["artifact_transports"] = [
            {
                "name": "estate-forge",
                "repo_url": estate_repo,
                "branch": artifact_branch or "main",
                "cache_dir": str(base_cache / "estate-forge"),
            },
            {
                "name": "github-canonical",
                "repo_url": global_repo,
                "branch": artifact_branch or "main",
                "cache_dir": str(base_cache / "github-canonical"),
            },
        ]
    existing.pop("artifact_transport", None)
    existing.update(update)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".harmonia-new")
    tmp.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, path)


def repo_source() -> str:
    completed = subprocess.run(["git", "remote", "get-url", "origin"], cwd=REPO_ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    return completed.stdout.strip() if completed.returncode == 0 and completed.stdout.strip() else str(REPO_ROOT)


def repo_ref(root: Path = REPO_ROOT) -> str:
    completed = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    return completed.stdout.strip() if completed.returncode == 0 and completed.stdout.strip() else "unknown"


def requires_root(paths: InstallPaths) -> bool:
    system_prefixes = (Path("/etc"), Path("/usr"), Path("/var"))
    for path in [paths.bin_path, paths.config_dir, paths.state_dir, paths.log_dir, paths.receipt_dir, paths.systemd_dir]:
        try:
            resolved = path if path.is_absolute() else (Path.cwd() / path)
            if any(resolved == prefix or prefix in resolved.parents for prefix in system_prefixes):
                return True
        except OSError:
            continue
    return False


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
