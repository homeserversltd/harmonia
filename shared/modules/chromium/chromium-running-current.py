#!/usr/bin/env python3
"""Restart a desktop Chromium that a package upgrade left running on a deleted binary.

check   prints "current" when no desktop browser runs a replaced binary, else "stale"
restart closes each stale desktop browser cleanly and relaunches it in its owner's
        Sway session when available (Hyprland is the fallback), then waits for a fresh
        browser process with --restore-last-session

Automation browsers (Playwright, DevTools, headless, any --user-data-dir) are never touched.
"""
import os
import pwd
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

BINARY = "/usr/lib/chromium/chromium"
FOREIGN_FLAGS = ("--type=", "--user-data-dir", "--remote-debugging", "--headless")


def desktop_browsers():
    found = []
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            exe = os.readlink(proc / "exe")
            argv = (proc / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        if exe.removesuffix(" (deleted)") != BINARY:
            continue
        # Chromium rewrites child command lines into one space-joined string.
        args = b" ".join(argv).decode(errors="replace").split()[1:]
        if any(a.startswith(FOREIGN_FLAGS) for a in args):
            continue
        found.append((int(proc.name), proc.stat().st_uid, exe.endswith(" (deleted)")))
    return found


def hyprland_signature(uid):
    hypr = Path(f"/run/user/{uid}/hypr")
    live = [d for d in hypr.glob("*") if (d / ".socket.sock").exists()] if hypr.is_dir() else []
    if not live:
        return None
    return max(live, key=lambda d: d.stat().st_mtime).name


def sway_socket(uid, user):
    runtime_dir = Path(f"/run/user/{uid}")
    candidates = []
    try:
        for socket_path in runtime_dir.glob("sway-ipc.*.sock"):
            try:
                info = socket_path.lstat()
            except OSError:
                continue
            if info.st_uid != uid or not stat.S_ISSOCK(info.st_mode):
                continue
            candidates.append((info.st_mtime_ns, str(socket_path), socket_path))
    except OSError:
        return None

    # Probe newest candidates first; the path tiebreak makes equal mtimes stable.
    for _, _, socket_path in sorted(candidates, key=lambda item: (-item[0], item[1])):
        try:
            result = subprocess.run(
                ["/usr/sbin/runuser", "-u", user, "--", "/usr/bin/env",
                 f"XDG_RUNTIME_DIR=/run/user/{uid}", f"SWAYSOCK={socket_path}",
                 "/usr/bin/swaymsg", "-s", str(socket_path), "-t", "get_version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=3,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            return socket_path
    return None


def usable_hyprland_signature(uid, user):
    signature = hyprland_signature(uid)
    if signature is None:
        return None
    try:
        result = subprocess.run(
            ["/usr/sbin/runuser", "-u", user, "--", "/usr/bin/env",
             f"XDG_RUNTIME_DIR=/run/user/{uid}",
             f"HYPRLAND_INSTANCE_SIGNATURE={signature}",
             "/usr/bin/hyprctl", "-j", "version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return signature if result.returncode == 0 else None


def compositor_for(uid, user):
    socket_path = sway_socket(uid, user)
    if socket_path is not None:
        return ("sway", socket_path)
    signature = usable_hyprland_signature(uid, user)
    if signature is not None:
        return ("hyprland", signature)
    return None


def restart():
    stale = [(pid, uid) for pid, uid, deleted in desktop_browsers() if deleted]
    for pid, uid in stale:
        user = pwd.getpwuid(uid).pw_name
        compositor = compositor_for(uid, user)
        if compositor is None:
            sys.exit(f"chromium-restart-refused: no usable Sway or Hyprland session for {user}")
        os.kill(pid, signal.SIGTERM)
        for _ in range(60):
            if not Path(f"/proc/{pid}").exists():
                break
            time.sleep(0.5)
        else:
            sys.exit(f"chromium-restart-failed: pid {pid} did not exit after SIGTERM")
        if compositor[0] == "sway":
            socket_path = compositor[1]
            launch = [
                "/usr/sbin/runuser", "-u", user, "--", "/usr/bin/env",
                f"XDG_RUNTIME_DIR=/run/user/{uid}", f"SWAYSOCK={socket_path}",
                "/usr/bin/swaymsg", "-s", str(socket_path), "exec",
                "chromium --restore-last-session",
            ]
        else:
            signature = compositor[1]
            launch = [
                "/usr/sbin/runuser", "-u", user, "--", "/usr/bin/env",
                f"XDG_RUNTIME_DIR=/run/user/{uid}",
                f"HYPRLAND_INSTANCE_SIGNATURE={signature}",
                "/usr/bin/hyprctl", "dispatch", "exec",
                "chromium --restore-last-session",
            ]
        subprocess.run(launch, check=True)
        for _ in range(60):
            if any(u == uid and not deleted for _, u, deleted in desktop_browsers()):
                break
            time.sleep(0.5)
        else:
            sys.exit(f"chromium-restart-failed: no fresh browser for {user} after relaunch")


def main():
    verb = sys.argv[1] if len(sys.argv) > 1 else ""
    if verb == "check":
        print("stale" if any(deleted for _, _, deleted in desktop_browsers()) else "current")
    elif verb == "restart":
        restart()
    else:
        sys.exit("usage: chromium-running-current.py check|restart")


if __name__ == "__main__":
    main()
