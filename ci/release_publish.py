#!/usr/bin/env python3
import hashlib
import json
import os
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request

API_ROOT = "https://git.home.arpa/api/v1"
OWNER, REPO = "HOMESERVERSLTD", "harmonia"
PROJECT = f"{OWNER}/{REPO}"
RELEASES = f"{API_ROOT}/repos/{OWNER}/{REPO}/releases"
HEX40 = set("0123456789abcdef")
HEX64 = set("0123456789abcdef")


def fail(message):
    print(f"release_publish: {message}", file=sys.stderr)
    raise SystemExit(1)


def valid_hex(value, length):
    return isinstance(value, str) and len(value) == length and set(value) <= (HEX40 if length == 40 else HEX64)


def request(method, url, token, body=None, content_type=None, accept=None):
    headers = {"Authorization": f"token {token}", "User-Agent": "harmonia-woodpecker-release"}
    if content_type:
        headers["Content-Type"] = content_type
    if accept:
        headers["Accept"] = accept
    if isinstance(body, (dict, list)):
        body = json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    try:
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=180) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        fail(f"{method} {url} transport failure: {exc}")


def decode(raw, description):
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(f"{description} returned invalid JSON")


def assets_of(release):
    assets = release.get("assets")
    if not isinstance(assets, list):
        fail("release response has no asset list")
    result = {}
    for asset in assets:
        name = asset.get("name") if isinstance(asset, dict) else None
        if not isinstance(name, str) or name in result:
            fail("release contains an invalid or duplicate asset name")
        result[name] = asset
    return result


def download(asset, token, name, release_id):
    asset_id = asset.get("id")
    if not isinstance(asset_id, int):
        fail(f"asset {name} has no numeric id")
    status, raw = request("GET", f"{RELEASES}/{release_id}/assets/{asset_id}", token, accept="application/octet-stream")
    if status != 200:
        fail(f"download of {name} returned HTTP {status}")
    return raw


def verify(release, token, sha, digest, sidecar, manifest):
    if release.get("tag_name") != sha or release.get("target_commitish") != sha:
        fail("existing release has mutable or conflicting commit identity")
    if release.get("name") != f"harmonia {sha[:8]}":
        fail("existing release has conflicting name")
    release_id = release.get("id")
    if not isinstance(release_id, int):
        fail("release has no numeric id")
    assets = assets_of(release)
    expected = {"harmonia-x86_64", "harmonia-x86_64.sha256", "manifest.json"}
    if set(assets) != expected:
        fail("release assets do not exactly match the immutable release contract")
    if hashlib.sha256(download(assets["harmonia-x86_64"], token, "harmonia-x86_64", release_id)).hexdigest() != digest:
        fail("downloaded harmonia-x86_64 has a conflicting digest")
    if download(assets["harmonia-x86_64.sha256"], token, "harmonia-x86_64.sha256", release_id) != sidecar:
        fail("downloaded harmonia-x86_64.sha256 has conflicting contents")
    if download(assets["manifest.json"], token, "manifest.json", release_id) != manifest:
        fail("downloaded manifest.json has conflicting contents")


def receipt(status, changed, sha, env_sha, digest, release_url):
    print(json.dumps({"schema": "harmonia.release_publish.v1", "ok": True, "status": status,
                      "changed": changed, "project": PROJECT, "tag": sha, "commit": sha,
                      "env_sha": env_sha, "assets": ["harmonia-x86_64", "harmonia-x86_64.sha256", "manifest.json"],
                      "sha256": digest, "release_url": release_url}, separators=(",", ":")))


def main():
    token = os.environ.get("FORGEJO_TOKEN", "")
    if not token:
        fail("FORGEJO_TOKEN is required")
    sha = os.environ.get("CI_COMMIT_SHA", "")
    if not valid_hex(sha, 40):
        fail("CI_COMMIT_SHA must be exactly 40 lowercase hexadecimal characters")
    env_sha = os.environ.get("HARMONIA_BUILD_ENV_SHA", "")
    if not valid_hex(env_sha, 64):
        try:
            with open(os.path.join(".release", "env-sha"), "r", encoding="ascii") as env_file:
                env_sha = env_file.read().strip()
        except (OSError, UnicodeError):
            env_sha = ""
    if not valid_hex(env_sha, 64):
        fail("build env_sha must be exactly 64 lowercase hexadecimal characters")
    try:
        with open("Cargo.toml", "rb") as cargo_file:
            package = tomllib.load(cargo_file).get("package", {})
    except (OSError, tomllib.TOMLDecodeError) as exc:
        fail(f"cannot read Cargo.toml: {exc}")
    if package.get("name") != REPO:
        fail(f"Cargo package name must be {REPO}")
    version = package.get("version")
    if not isinstance(version, str) or not version:
        fail("Cargo package version is missing")
    binary_path = os.path.join("target", "release", REPO)
    if not os.path.isfile(binary_path):
        fail(f"release binary does not exist: {binary_path}")
    with open(binary_path, "rb") as binary_file:
        binary = binary_file.read()
    digest = hashlib.sha256(binary).hexdigest()
    sidecar = f"{digest}  harmonia-x86_64\n".encode("ascii")
    manifest_obj = {"schema": "estate.artifact.manifest.v1", "source_sha": sha, "env_sha": env_sha,
                    "component": REPO, "target": "x86_64-unknown-linux-gnu", "sha256": digest,
                    "version": version}
    manifest = (json.dumps(manifest_obj, indent=2) + "\n").encode("utf-8")
    tag_url = f"{RELEASES}/tags/{urllib.parse.quote(sha, safe='')}"
    status, raw = request("GET", tag_url, token)
    if status == 200:
        verify(decode(raw, "existing release"), token, sha, digest, sidecar, manifest)
        receipt("no-op", False, sha, env_sha, digest, tag_url)
        return
    if status != 404:
        fail(f"GET release tag returned HTTP {status}")
    payload = {"tag_name": sha, "name": f"harmonia {sha[:8]}", "target_commitish": sha,
               "draft": False, "prerelease": False}
    status, raw = request("POST", RELEASES, token, payload)
    if status == 409:
        status, raw = request("GET", tag_url, token)
        if status != 200:
            fail(f"release collision reread returned HTTP {status}")
        verify(decode(raw, "existing release"), token, sha, digest, sidecar, manifest)
        receipt("no-op", False, sha, env_sha, digest, tag_url)
        return
    if status not in (200, 201):
        fail(f"release creation returned HTTP {status}")
    release = decode(raw, "release creation")
    release_id = release.get("id")
    if not isinstance(release_id, int):
        fail("created release has no numeric id")
    if assets_of(release):
        fail("new release unexpectedly contains assets")
    upload_url = f"{RELEASES}/{release_id}/assets"
    for name, content, content_type in (("harmonia-x86_64", binary, "application/octet-stream"),
                                         ("harmonia-x86_64.sha256", sidecar, "text/plain; charset=utf-8"),
                                         ("manifest.json", manifest, "application/json")):
        url = f"{upload_url}?{urllib.parse.urlencode({'name': name})}"
        status, _ = request("POST", url, token, content, content_type=content_type)
        if status not in (200, 201):
            fail(f"upload of {name} returned HTTP {status}")
    status, raw = request("GET", tag_url, token)
    if status != 200:
        fail(f"reread of release returned HTTP {status}")
    verify(decode(raw, "release reread"), token, sha, digest, sidecar, manifest)
    receipt("published", True, sha, env_sha, digest, tag_url)


if __name__ == "__main__":
    main()
