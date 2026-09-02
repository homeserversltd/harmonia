#!/usr/bin/env python3
import json
import os
import sys
import urllib.error
import urllib.request

API = "https://git.home.arpa/api/v1/repos/HOMESERVERSLTD/caduceus"
PACKAGE_ROOT = "https://git.home.arpa/api/packages/HOMESERVERSLTD/generic/caduceus"
LOCK_PATH = "locks/beam.json"
SCHEMA = "harmonia.beam-lock-mint.v1"
HEX40 = set("0123456789abcdef")
HEX64 = set("0123456789abcdef")
BLOCKER = "beam-lock-drift-no-source-seat-lane"
receipt_state = {"caduceus_sha": "", "env_sha": "", "minted_from": {}}

def valid_hex(value, length):
    alphabet = HEX40 if length == 40 else HEX64
    return isinstance(value, str) and len(value) == length and set(value) <= alphabet

def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True)

def emit(ok, changed, first_missing_signal=None):
    print(compact({"schema": SCHEMA, "ok": ok, "changed": changed,
                   "caduceus_sha": receipt_state["caduceus_sha"], "env_sha": receipt_state["env_sha"],
                   "minted_from": receipt_state["minted_from"], "first_missing_signal": first_missing_signal}))

def request(url):
    headers = {"User-Agent": "harmonia-beam-lock-mint"}
    token = os.environ.get("FORGEJO_TOKEN", "")
    if token:
        headers["Authorization"] = f"token {token}"
    try:
        request_obj = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(request_obj, timeout=180) as response:
            if response.status != 200:
                raise RuntimeError(f"HTTP {response.status}")
            return response.read()
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError("Forgejo request failed") from exc

def parse_json(raw, label):
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{label} is invalid JSON") from exc

def canonical(lock):
    return (json.dumps(lock, indent=2) + "\n").encode("utf-8")

def main():
    dry_run = False
    crown_route = None
    supplied_ci_sha = None
    args = sys.argv[1:]
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--dry-run":
            dry_run = True
        elif arg == "--ci-commit-sha" and index + 1 < len(args):
            index += 1
            supplied_ci_sha = args[index]
        elif arg == "--ci-crown-route" and index + 1 < len(args):
            index += 1
            crown_route = args[index]
        else:
            raise RuntimeError("unsupported arguments")
        index += 1
    harmonia_sha = supplied_ci_sha if supplied_ci_sha is not None else os.environ.get("CI_COMMIT_SHA", "")
    if dry_run and supplied_ci_sha is None:
        raise RuntimeError("--dry-run requires an explicitly supplied --ci-commit-sha")
    if not valid_hex(harmonia_sha, 40):
        raise RuntimeError("CI_COMMIT_SHA must be exactly 40 lowercase hexadecimal characters")
    receipt_state["minted_from"] = {"harmonia_sha": harmonia_sha}
    latest = parse_json(request(f"{API}/releases/latest"), "latest release")
    tag = latest.get("tag_name")
    target = latest.get("target_commitish")
    if not valid_hex(tag, 40):
        raise RuntimeError("latest release tag_name must be exactly 40 lowercase hexadecimal characters")
    receipt_state["caduceus_sha"] = tag
    receipt_state["minted_from"]["caduceus_release_tag"] = tag
    if target != tag:
        raise RuntimeError("latest release target_commitish does not align with tag_name")
    manifest = parse_json(request(f"{PACKAGE_ROOT}/{tag}/manifest.json"), "manifest.json")
    if manifest.get("schema") != "estate.artifact.manifest.v1":
        raise RuntimeError("manifest.json has an unsupported schema")
    manifest_source_sha = manifest.get("source_sha")
    env_sha = manifest.get("env_sha")
    receipt_state["env_sha"] = env_sha if isinstance(env_sha, str) else ""
    if manifest_source_sha != tag:
        raise RuntimeError("manifest source_sha does not equal release tag")
    if not valid_hex(env_sha, 64):
        raise RuntimeError("manifest env_sha must be exactly 64 lowercase hexadecimal characters")
    desired = {"schema": "harmonia.beam-lock.v1", "caduceus_sha": tag, "env_sha": env_sha,
               "minted_from": receipt_state["minted_from"]}
    try:
        with open(LOCK_PATH, "rb") as lock_file:
            current = lock_file.read()
    except OSError as exc:
        raise RuntimeError("locks/beam.json cannot be read") from exc
    changed = current != canonical(desired)
    if not changed:
        emit(True, False)
        return
    if crown_route is not None:
        if crown_route != "POST /v1/registry-pen/stamp":
            raise RuntimeError("unsupported crown route")
        emit(False, True, BLOCKER)
        raise SystemExit(1)
    if dry_run:
        emit(True, True)
        return
    raise RuntimeError("one of --dry-run or --ci-crown-route is required")

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        emit(False, False, str(exc))
        raise SystemExit(1)
