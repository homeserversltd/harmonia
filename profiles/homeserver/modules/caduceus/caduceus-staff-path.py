#!/usr/bin/env python3
"""Observe and converge the existing Caduceus staff import-path declaration."""

from __future__ import annotations

import os
import site
import stat
import sys
from pathlib import Path

EXPECTED = "/usr/local/sbin\n"


def staff_path_file() -> Path:
    roots = [Path(path) for path in site.getsitepackages() if path.endswith("/site-packages")]
    if len(roots) != 1 or not roots[0].is_dir():
        raise RuntimeError("caduceus-staff-site-packages-not-unique-or-absent")
    return roots[0] / "caduceus-staff.pth"


def _open_regular(path: Path, flags: int) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags | nofollow)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise RuntimeError(f"staff path target is not a regular file: {path}")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_existing(path: Path) -> str:
    descriptor = _open_regular(path, os.O_RDONLY)
    with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
        return stream.read()


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"--check", "--apply"}:
        print("usage: caduceus-staff-path.py --check|--apply", file=sys.stderr)
        return 2
    try:
        path = staff_path_file()
        try:
            target_stat = path.lstat()
        except FileNotFoundError:
            if sys.argv[1] == "--check":
                print("Different")
                return 0
            raise RuntimeError(f"birth-debt: existing staff path file absent: {path}")
        if stat.S_ISLNK(target_stat.st_mode):
            raise RuntimeError(f"staff path target is a symlink: {path}")
        if not stat.S_ISREG(target_stat.st_mode):
            raise RuntimeError(f"staff path target is not a regular file: {path}")
        current = _read_existing(path)
        if sys.argv[1] == "--check":
            sys.stdout.write("/usr/local/sbin\n" if current == EXPECTED else "Different\n")
            return 0
        if current != EXPECTED:
            descriptor = _open_regular(path, os.O_WRONLY)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                os.ftruncate(descriptor, 0)
                stream.write(EXPECTED)
        return 0
    except (OSError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
