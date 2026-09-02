#!/usr/bin/env python3
import hashlib, json, os, sys, time, tomllib, urllib.error, urllib.parse, urllib.request
API_ROOT = "https://git.home.arpa/api/v1"
OWNER, REPO = "HOMESERVERSLTD", "harmonia"
PROJECT = f"{OWNER}/{REPO}"
RELEASES = f"{API_ROOT}/repos/{OWNER}/{REPO}/releases"
def fail(message):
    print(f"release_publish: {message}", file=sys.stderr); raise SystemExit(1)
def request(method, url, token, body=None, content_type=None, accept=None):
    headers = {"Authorization": f"token {token}", "User-Agent": "harmonia-woodpecker-release"}
    if content_type: headers["Content-Type"] = content_type
    if accept: headers["Accept"] = accept
    if isinstance(body, (dict, list)):
        body = json.dumps(body, separators=(",", ":")).encode(); headers["Content-Type"] = "application/json"
    try:
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=180) as response: return response.status, response.read()
    except urllib.error.HTTPError as exc: return exc.code, exc.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc: fail(f"{method} {url} transport failure: {exc}")
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
def download(asset, token, name, release_id):
    asset_id = asset.get("id")
    if not isinstance(asset_id, int): fail(f"asset {name} has no numeric id")
    url = f"{RELEASES}/{release_id}/assets/{asset_id}"
    status, raw = request("GET", url, token, accept="application/octet-stream")
    if status != 200: fail(f"download of {name} returned HTTP {status}")
    return raw
def verify(release, token, version, sha, env_sha, digest, binary_name, sidecar_name, sidecar):
    release_id = release.get("id")
    if not isinstance(release_id, int): fail("release has no numeric id")
    assets = assets_of(release)
    for name in (binary_name, sidecar_name, "manifest.json"):
        if name not in assets: fail(f"release is missing expected asset {name}")
    if hashlib.sha256(download(assets[binary_name], token, binary_name, release_id)).hexdigest() != digest: fail(f"downloaded {binary_name} has a conflicting digest")
    if download(assets[sidecar_name], token, sidecar_name, release_id) != sidecar: fail(f"downloaded {sidecar_name} has conflicting contents")
    manifest_obj = decode(download(assets["manifest.json"], token, "manifest.json", release_id), "manifest.json")
    if not isinstance(manifest_obj, dict) or set(manifest_obj) != {"schema", "component", "source_sha", "env_sha", "target", "sha256", "built_at", "pipeline_url"}: fail("manifest.json has an invalid key set")
    if manifest_obj["schema"] != "estate.artifact.manifest.v1" or manifest_obj["component"] != REPO or manifest_obj["source_sha"] != sha or manifest_obj["env_sha"] != env_sha or manifest_obj["target"] != "x86_64-unknown-linux-gnu" or manifest_obj["sha256"] != digest: fail("manifest.json has conflicting contents")
    if not isinstance(manifest_obj["built_at"], str) or not manifest_obj["built_at"] or not isinstance(manifest_obj["pipeline_url"], str) or not manifest_obj["pipeline_url"]: fail("manifest.json has invalid build metadata")
def main():
    token = os.environ.get("FORGEJO_TOKEN", "")
    if not token: fail("FORGEJO_TOKEN is required")
    sha = os.environ.get("CI_COMMIT_SHA", "")
    if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha): fail("CI_COMMIT_SHA must be exactly 40 lowercase hexadecimal characters")
    if "HARMONIA_BUILD_ENV_SHA" in os.environ:
        env_sha = os.environ["HARMONIA_BUILD_ENV_SHA"]
    else:
        try:
            with open(".release/env-sha", "r", encoding="utf-8") as env_sha_file:
                env_sha = env_sha_file.read().strip()
        except (OSError, UnicodeDecodeError) as exc:
            fail(f"cannot read .release/env-sha: {exc}")
    if len(env_sha) != 64 or any(c not in "0123456789abcdef" for c in env_sha): fail("build env_sha must be exactly 64 lowercase hexadecimal characters")
    pipeline_url = os.environ.get("CI_PIPELINE_URL", "")
    if not pipeline_url: fail("CI_PIPELINE_URL is required")
    try:
        with open("Cargo.toml", "rb") as cargo_file: package = tomllib.load(cargo_file).get("package", {})
    except (OSError, tomllib.TOMLDecodeError) as exc: fail(f"cannot read Cargo.toml: {exc}")
    if package.get("name") != REPO: fail(f"Cargo package name must be {REPO}")
    version = package.get("version")
    if not isinstance(version, str) or not version: fail("Cargo package version is missing")
    binary_name = f"{REPO}-{version}-x86_64"; sidecar_name = f"{binary_name}.sha256"
    binary_path = os.path.join("target", "release", REPO)
    if not os.path.isfile(binary_path): fail(f"release binary does not exist: {binary_path}")
    with open(binary_path, "rb") as binary_file: binary = binary_file.read()
    digest = hashlib.sha256(binary).hexdigest(); sidecar = f"{digest}  {binary_name}\n".encode("ascii")
    manifest_obj = {"schema":"estate.artifact.manifest.v1", "component":REPO, "source_sha":sha, "env_sha":env_sha, "target":"x86_64-unknown-linux-gnu", "sha256":digest, "built_at":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "pipeline_url":pipeline_url}
    manifest = (json.dumps(manifest_obj, indent=2) + "\n").encode("utf-8")
    tag_url = f"{RELEASES}/tags/{urllib.parse.quote(version, safe='')}"; status, raw = request("GET", tag_url, token)
    if status == 200:
        verify(decode(raw, "existing release"), token, version, sha, env_sha, digest, binary_name, sidecar_name, sidecar)
        print(json.dumps({"schema":"harmonia.release_publish.v1", "ok":True, "status":"no-op", "changed":False, "project":PROJECT, "tag":version, "commit":sha, "env_sha":env_sha, "assets":[binary_name, sidecar_name, "manifest.json"], "sha256":digest, "release_url":tag_url}, separators=(",", ":"))); return
    if status != 404: fail(f"GET release tag returned HTTP {status}")
    payload = {"tag_name":version, "name":version, "target_commitish":sha, "draft":False, "prerelease":False}; status, raw = request("POST", RELEASES, token, payload)
    if status == 409:
        status, raw = request("GET", tag_url, token)
        if status != 200: fail(f"release collision reread returned HTTP {status}")
        verify(decode(raw, "existing release"), token, version, sha, env_sha, digest, binary_name, sidecar_name, sidecar)
        print(json.dumps({"schema":"harmonia.release_publish.v1", "ok":True, "status":"no-op", "changed":False, "project":PROJECT, "tag":version, "commit":sha, "env_sha":env_sha, "assets":[binary_name, sidecar_name, "manifest.json"], "sha256":digest, "release_url":tag_url}, separators=(",", ":"))); return
    if status not in (200, 201): fail(f"release creation returned HTTP {status}")
    release = decode(raw, "release creation"); release_id = release.get("id")
    if not isinstance(release_id, int): fail("created release has no numeric id")
    if assets_of(release): fail("new release unexpectedly contains assets")
    upload_url = f"{RELEASES}/{release_id}/assets"
    for name, content, content_type in ((binary_name, binary, "application/octet-stream"), (sidecar_name, sidecar, "text/plain; charset=utf-8"), ("manifest.json", manifest, "application/json")):
        url = f"{upload_url}?{urllib.parse.urlencode({'name':name})}"; status, _ = request("POST", url, token, content, content_type=content_type)
        if status not in (200, 201): fail(f"upload of {name} returned HTTP {status}")
    status, raw = request("GET", tag_url, token)
    if status != 200: fail(f"reread of release returned HTTP {status}")
    verify(decode(raw, "release reread"), token, version, sha, env_sha, digest, binary_name, sidecar_name, sidecar)
    print(json.dumps({"schema":"harmonia.release_publish.v1", "ok":True, "status":"published", "changed":True, "project":PROJECT, "tag":version, "commit":sha, "env_sha":env_sha, "assets":[binary_name, sidecar_name, "manifest.json"], "sha256":digest, "release_url":tag_url}, separators=(",", ":")))
if __name__ == "__main__": main()
