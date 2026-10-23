#!/usr/bin/env python3
"""Reconcile owner units selected by the shared streaming job's profile values."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time


def systemctl(*args, quiet=False):
    result = subprocess.run(
        ['/usr/bin/systemctl', '--user', *args],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL if quiet else None,
        timeout=15,
        check=False,
    )
    return result.returncode == 0


def selected(values_path, profile_path):
    certificate = json.loads(profile_path.read_text())
    kernel = certificate.get('kernel')
    profile = kernel.get('profile') if isinstance(kernel, dict) else None
    # The device certificate owns identity. Keep the older flat reader's
    # alias only when the canonical field is absent, never over its value.
    if profile is None:
        profile = certificate.get('profile')
    if not isinstance(profile, str) or not profile.strip():
        raise KeyError('kernel.profile')
    return json.loads(values_path.read_text()).get(profile.strip())


def current(values):
    units = [values['desktop'], *values['session_services']]
    return (
        all(systemctl('is-enabled', '--quiet', unit, quiet=True) for unit in units)
        and systemctl('is-active', '--quiet', values['desktop'], quiet=True)
        and systemctl('is-active', '--quiet', values['session'], quiet=True)
        and all(systemctl('is-active', '--quiet', unit, quiet=True)
                for unit in values['session_services'])
    )


def apply(values):
    units = [values['desktop'], *values['session_services']]
    for args in [('daemon-reload',), ('enable', *units), ('start', values['desktop'])]:
        if not systemctl(*args):
            raise RuntimeError('owner-unit-command-failed')
    # Sway's inherited, socket-checked handoff imports its actual display before
    # starting the shared session target. Never guess a Wayland display number.
    deadline = time.monotonic() + 60
    while not systemctl('is-active', '--quiet', values['session'], quiet=True):
        if time.monotonic() >= deadline:
            raise RuntimeError('owner-desktop-session-not-ready')
        time.sleep(1)
    if not systemctl('start', *values['session_services']):
        raise RuntimeError('owner-streaming-services-start-failed')
    if not current(values):
        raise RuntimeError('owner-streaming-services-not-current')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['check', 'apply'])
    parser.add_argument('--profile-file', type=Path, default=Path('/etc/appliance/profile.json'))
    parser.add_argument('--values', type=Path, default=Path(__file__).with_name('service-values.json'))
    args = parser.parse_args()
    started = time.monotonic()
    try:
        values = selected(args.values, args.profile_file)
        if values is None:
            if args.action == 'check':
                print('current')
            return 0
        if args.action == 'check':
            settled = current(values)
            print('current' if settled else 'needs-enable')
            return 0 if settled else 1
        apply(values)
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired) as error:
        if args.action == 'apply':
            signal = str(error) if isinstance(error, RuntimeError) else type(error).__name__
            field = str(error.args[0]) if isinstance(error, KeyError) else 'none'
            print(f'who=owner verb=reconcile target=desktop-streaming outcome=failed duration_ms={int((time.monotonic()-started)*1000)} signal={signal} first_missing_field={field}', file=sys.stderr)
        return 1
    print(f'who=owner verb=reconcile target=desktop-streaming outcome=current duration_ms={int((time.monotonic()-started)*1000)}', file=sys.stderr)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
