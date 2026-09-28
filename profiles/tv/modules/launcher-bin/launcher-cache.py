#!/usr/bin/env python3
"""Compare the TV KDE service cache with desktop-file inputs; refresh if stale."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

OWNER_HOME = Path("/home/owner")
REFRESH = OWNER_HOME / "bin/refresh-launcher-cache.sh"


def cache_directory() -> Path:
    return OWNER_HOME / ".cache"


def input_directories() -> list[Path]:
    return [
        OWNER_HOME / ".local/share/applications",
        Path("/usr/local/share/applications"),
        Path("/usr/share/applications"),
    ]


def newest_mtime(path: Path) -> int | None:
    try:
        return path.stat().st_mtime_ns if path.is_file() else None
    except OSError:
        return None


def state() -> str:
    cache_mtimes = [
        mtime
        for item in cache_directory().glob("ksycoca6_*")
        if (mtime := newest_mtime(item)) is not None
    ]
    if not cache_mtimes:
        return "Different"
    cache_mtime = max(cache_mtimes)
    newest_input = 0
    for directory in input_directories():
        try:
            items = directory.rglob("*.desktop") if directory.is_dir() else ()
            for item in items:
                mtime = newest_mtime(item)
                if mtime is not None:
                    newest_input = max(newest_input, mtime)
        except OSError:
            continue
    refresh_mtime = newest_mtime(REFRESH)
    if refresh_mtime is not None:
        newest_input = max(newest_input, refresh_mtime)
    return "Empty" if cache_mtime >= newest_input else "Different"


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"--check", "--refresh"}:
        print("usage: launcher-cache.py --check|--refresh", file=sys.stderr)
        return 2
    try:
        if sys.argv[1] == "--check":
            print(state())
            return 0
        result = subprocess.run(
            ["/usr/bin/sudo", "--user", "owner", "--", str(REFRESH)],
            check=False,
        )
        if result.returncode != 0:
            return result.returncode
        final = state()
        print(final)
        if final != "Empty":
            print("launcher cache remains missing or stale after refresh", file=sys.stderr)
            return 1
        return 0
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
