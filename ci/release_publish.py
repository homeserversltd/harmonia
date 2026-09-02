#!/usr/bin/env python3
import hashlib, json, os, sys, tomllib, urllib.error, urllib.parse, urllib.request

API_ROOT = "https://git.home.arpa/api/v1"
OWNER, REPO = "HOMESERVERSLTD", "harmonia"
RELEASES = f"{API_ROOT}/repos/{OWNER}/{REPO}/releases"
EXPECTED_ASSETS = ("harmonia-x86_64", "harmonia-x86_64.sha256")
FACTS = {"status": "error", "tag": None, "name": None, "assets": None, "sha256": None, "cargo_version": None}

def emit():
    print(json.dumps(FACTS, separators=(",", ":")))

def fail(message):
    emit()
    print(f"release_publish: {message}", file=sys.stderr)
    raise SystemExit(1)

def conflict(message):
    FACTS["status"] = "conflict"
    fail(message)

def request(method, url, token, body=None, content_type=None, accept=None, conflict_on_transport=False):
    headers = {"Authorization": f"token {token}", "User-Agent": "harmonia-woodpecker-release"}
    if content_type: headers["Content-Type"] = content_type
    if accept: headers["Accept"] = accept
    if isinstance(body, (dict, list)):
        body = json.dumps(body, separators=(",", ":")).encode(); headers["Content-Type"] = "application/json"
    try:
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=180) as response: return response.status, response.read()
    except urllib.error.HTTPError as exc: return exc.code, exc.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        if conflict_on_transport: conflict(f"{method} {url} transport failure: {exc}")
        fail(f"{method} {url} transport failure: {exc}")

def decode(raw, description):
    try: return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError): fail(f"{description} returned invalid JSON")

def assets_of(release):
    assets = release.get("assets")
    if not isinstance(assets, list): fail("release response has no asset list")
    result = {}
    for asset in assets:
        name = asset.get("name") if isinstance(asset, dict) else None
        if not isinstance(name, str) or name in result: fail("release contains an invalid or duplicate asset name")
        result[name] = asset
    return result

def download(asset, token, name):
    url = asset.get("browser_download_url")
    try:
        parsed = urllib.parse.urlparse(url) if isinstance(url, str) else None
        valid_url = parsed is not None and parsed.scheme == "https" and parsed.hostname == "git.home.arpa"
    except ValueError:
        valid_url = False
    if not valid_url:
        conflict(f"asset {name} has an invalid browser_download_url")
    status, raw = request("GET", url, token, accept="application/octet-stream", conflict_on_transport=True)
    if status != 200: conflict(f"download of {name} returned HTTP {status}")
    return raw

def verify(release, token, sha, release_name, digest, sidecar):
    if release.get("tag_name") != sha or release.get("name") != release_name or release.get("target_commitish") != sha:
        conflict("existing release identity conflicts with CI_COMMIT_SHA")
    assets = assets_of(release)
    if set(assets) != set(EXPECTED_ASSETS): conflict("existing release assets do not exactly match the expected names")
    if hashlib.sha256(download(assets[EXPECTED_ASSETS[0]], token, EXPECTED_ASSETS[0])).hexdigest() != digest:
        conflict(f"downloaded {EXPECTED_ASSETS[0]} has a conflicting digest")
    if download(assets[EXPECTED_ASSETS[1]], token, EXPECTED_ASSETS[1]) != sidecar:
        conflict(f"downloaded {EXPECTED_ASSETS[1]} has conflicting contents")

def main():
    token = os.environ.get("FORGEJO_TOKEN", "")
    if not token: fail("FORGEJO_TOKEN is required")
    sha = os.environ.get("CI_COMMIT_SHA", "")
    if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha): fail("CI_COMMIT_SHA must be exactly 40 lowercase hexadecimal characters")
    FACTS.update(tag=sha, name=f"harmonia {sha[:8]}", assets=list(EXPECTED_ASSETS))
    try:
        with open("Cargo.toml", "rb") as cargo_file: package = tomllib.load(cargo_file).get("package", {})
    except (OSError, tomllib.TOMLDecodeError) as exc: fail(f"cannot read Cargo.toml: {exc}")
    if package.get("name") != REPO: fail(f"Cargo package name must be {REPO}")
    version = package.get("version")
    if not isinstance(version, str) or not version: fail("Cargo package version is missing")
    FACTS["cargo_version"] = version
    binary_path = os.path.join("target", "release", REPO)
    if not os.path.isfile(binary_path): fail(f"release binary does not exist: {binary_path}")
    with open(binary_path, "rb") as binary_file: binary = binary_file.read()
    digest = hashlib.sha256(binary).hexdigest(); FACTS["sha256"] = digest
    sidecar = f"{digest}  harmonia-x86_64\n".encode("ascii")
    tag_url = f"{RELEASES}/tags/{urllib.parse.quote(sha, safe='')}"; status, raw = request("GET", tag_url, token)
    if status == 200:
        verify(decode(raw, "existing release"), token, sha, FACTS["name"], digest, sidecar); FACTS["status"] = "no-op"; emit(); return
    if status != 404: fail(f"GET release tag returned HTTP {status}")
    payload = {"tag_name": sha, "name": FACTS["name"], "target_commitish": sha, "draft": False, "prerelease": False}; status, raw = request("POST", RELEASES, token, payload)
    if status == 409:
        status, raw = request("GET", tag_url, token)
        if status != 200: fail(f"release collision reread returned HTTP {status}")
        verify(decode(raw, "existing release"), token, sha, FACTS["name"], digest, sidecar); FACTS["status"] = "no-op"; emit(); return
    if status not in (200, 201): fail(f"release creation returned HTTP {status}")
    release = decode(raw, "release creation"); release_id = release.get("id")
    if not isinstance(release_id, int): fail("created release has no numeric id")
    if assets_of(release): fail("new release unexpectedly contains assets")
    upload_url = f"{RELEASES}/{release_id}/assets"
    for name, content, content_type in ((EXPECTED_ASSETS[0], binary, "application/octet-stream"), (EXPECTED_ASSETS[1], sidecar, "text/plain; charset=utf-8")):
        url = f"{upload_url}?{urllib.parse.urlencode({'name': name})}"; status, _ = request("POST", url, token, content, content_type=content_type)
        if status not in (200, 201): fail(f"upload of {name} returned HTTP {status}")
    status, raw = request("GET", tag_url, token)
    if status != 200: fail(f"reread of release returned HTTP {status}")
    verify(decode(raw, "release reread"), token, sha, FACTS["name"], digest, sidecar); FACTS["status"] = "published"; emit()

if __name__ == "__main__": main()
