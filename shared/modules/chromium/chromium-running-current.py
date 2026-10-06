#!/usr/bin/env python3
"""Restart a desktop Chromium that a package upgrade left running on a deleted binary.

check   prints "current" when no desktop browser runs a replaced binary, else "stale"
restart closes each stale desktop browser cleanly and relaunches it in its owner's
        Hyprland session with --restore-last-session, then waits for the new process

Automation browsers (Playwright, DevTools, headless, any --user-data-dir) are never touched.
"""
import os
import pwd
import signal
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


def restart():
    stale = [(pid, uid) for pid, uid, deleted in desktop_browsers() if deleted]
    for pid, uid in stale:
        user = pwd.getpwuid(uid).pw_name
        signature = hyprland_signature(uid)
        if signature is None:
            sys.exit(f"chromium-restart-refused: no live Hyprland session for {user}")
        os.kill(pid, signal.SIGTERM)
        for _ in range(60):
            if not Path(f"/proc/{pid}").exists():
                break
            time.sleep(0.5)
        else:
            sys.exit(f"chromium-restart-failed: pid {pid} did not exit after SIGTERM")
        subprocess.run(
            ["/usr/sbin/runuser", "-u", user, "--", "/usr/bin/env",
             f"XDG_RUNTIME_DIR=/run/user/{uid}", f"HYPRLAND_INSTANCE_SIGNATURE={signature}",
             "/usr/bin/hyprctl", "dispatch", "exec", "chromium --restore-last-session"],
            check=True,
        )
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
