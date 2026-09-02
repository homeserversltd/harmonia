#!/usr/bin/env python3
import hashlib, json, os, sys, time, tomllib, urllib.error, urllib.parse, urllib.request

API_ROOT = "https://git.home.arpa/api/v1"
OWNER, REPO = "HOMESERVERSLTD", "harmonia"
RELEASES = f"{API_ROOT}/repos/{OWNER}/{REPO}/releases"
EXPECTED_ASSETS = ("harmonia-x86_64", "harmonia-x86_64.sha256", "manifest.json")
FACTS = {"status": "error", "tag": None, "name": None, "assets": None, "sha256": None, "env_sha": None, "cargo_version": None}

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

def verify(release, token, sha, release_name, digest, sidecar, env_sha):
    if release.get("tag_name") != sha or release.get("name") != release_name or release.get("target_commitish") != sha:
        conflict("existing release identity conflicts with CI_COMMIT_SHA")
    assets = assets_of(release)
    if set(assets) != set(EXPECTED_ASSETS): conflict("existing release assets do not exactly match the expected names")
    if hashlib.sha256(download(assets[EXPECTED_ASSETS[0]], token, EXPECTED_ASSETS[0])).hexdigest() != digest:
        conflict(f"downloaded {EXPECTED_ASSETS[0]} has a conflicting digest")
    if download(assets[EXPECTED_ASSETS[1]], token, EXPECTED_ASSETS[1]) != sidecar:
        conflict(f"downloaded {EXPECTED_ASSETS[1]} has conflicting contents")
    manifest_obj = decode(download(assets[EXPECTED_ASSETS[2]], token, EXPECTED_ASSETS[2]), "manifest.json")
    expected_keys = {"schema", "component", "source_sha", "env_sha", "target", "sha256", "built_at", "pipeline_url"}
    if not isinstance(manifest_obj, dict) or set(manifest_obj) != expected_keys: conflict("manifest.json has an invalid key set")
    if any((manifest_obj["schema"] != "estate.artifact.manifest.v1", manifest_obj["component"] != REPO, manifest_obj["source_sha"] != sha, manifest_obj["env_sha"] != env_sha, manifest_obj["target"] != "x86_64-unknown-linux-gnu", manifest_obj["sha256"] != digest)): conflict("manifest.json has conflicting contents")
    if not isinstance(manifest_obj["built_at"], str) or not manifest_obj["built_at"] or not isinstance(manifest_obj["pipeline_url"], str) or not manifest_obj["pipeline_url"]: conflict("manifest.json has invalid build metadata")

def main():
    token = os.environ.get("FORGEJO_TOKEN", "")
    if not token: fail("FORGEJO_TOKEN is required")
    sha = os.environ.get("CI_COMMIT_SHA", "")
    if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha): fail("CI_COMMIT_SHA must be exactly 40 lowercase hexadecimal characters")
    FACTS.update(tag=sha, name=f"harmonia {sha[:8]}", assets=list(EXPECTED_ASSETS))
    if "HARMONIA_BUILD_ENV_SHA" in os.environ:
        env_sha = os.environ["HARMONIA_BUILD_ENV_SHA"]
    else:
        try:
            with open(".release/env-sha", "r", encoding="utf-8") as env_sha_file: env_sha = env_sha_file.read().strip()
        except (OSError, UnicodeDecodeError) as exc: fail(f"cannot read .release/env-sha: {exc}")
    if len(env_sha) != 64 or any(c not in "0123456789abcdef" for c in env_sha): fail("build env_sha must be exactly 64 lowercase hexadecimal characters")
    pipeline_url = os.environ.get("CI_PIPELINE_URL", "")
    if not pipeline_url: fail("CI_PIPELINE_URL is required")
    FACTS["env_sha"] = env_sha
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
    manifest_obj = {"schema":"estate.artifact.manifest.v1", "component":REPO, "source_sha":sha, "env_sha":env_sha, "target":"x86_64-unknown-linux-gnu", "sha256":digest, "built_at":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "pipeline_url":pipeline_url}
    manifest = (json.dumps(manifest_obj, indent=2) + "\n").encode("utf-8")
    tag_url = f"{RELEASES}/tags/{urllib.parse.quote(sha, safe='')}"; status, raw = request("GET", tag_url, token)
    if status == 200:
        verify(decode(raw, "existing release"), token, sha, FACTS["name"], digest, sidecar, env_sha); FACTS["status"] = "no-op"; emit(); return
    if status != 404: fail(f"GET release tag returned HTTP {status}")
    payload = {"tag_name": sha, "name": FACTS["name"], "target_commitish": sha, "draft": False, "prerelease": False}; status, raw = request("POST", RELEASES, token, payload)
    if status == 409:
        status, raw = request("GET", tag_url, token)
        if status != 200: fail(f"release collision reread returned HTTP {status}")
        verify(decode(raw, "existing release"), token, sha, FACTS["name"], digest, sidecar, env_sha); FACTS["status"] = "no-op"; emit(); return
    if status not in (200, 201): fail(f"release creation returned HTTP {status}")
    release = decode(raw, "release creation"); release_id = release.get("id")
    if not isinstance(release_id, int): fail("created release has no numeric id")
    if assets_of(release): fail("new release unexpectedly contains assets")
    upload_url = f"{RELEASES}/{release_id}/assets"
    for name, content, content_type in ((EXPECTED_ASSETS[0], binary, "application/octet-stream"), (EXPECTED_ASSETS[1], sidecar, "text/plain; charset=utf-8"), (EXPECTED_ASSETS[2], manifest, "application/json")):
        url = f"{upload_url}?{urllib.parse.urlencode({'name': name})}"; status, _ = request("POST", url, token, content, content_type=content_type)
        if status not in (200, 201): fail(f"upload of {name} returned HTTP {status}")
    status, raw = request("GET", tag_url, token)
    if status != 200: fail(f"reread of release returned HTTP {status}")
    verify(decode(raw, "release reread"), token, sha, FACTS["name"], digest, sidecar, env_sha); FACTS["status"] = "published"; emit()

if __name__ == "__main__": main()
