#!/usr/bin/env python3
import hashlib, json, os, sys, tomllib, urllib.error, urllib.parse, urllib.request
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
def verify(release, token, binary_name, sidecar_name, digest, sidecar):
    release_id = release.get("id")
    if not isinstance(release_id, int): fail("release has no numeric id")
    assets = assets_of(release)
    for name in (binary_name, sidecar_name):
        if name not in assets: fail(f"release is missing expected asset {name}")
    if hashlib.sha256(download(assets[binary_name], token, binary_name, release_id)).hexdigest() != digest: fail(f"downloaded {binary_name} has a conflicting digest")
    if download(assets[sidecar_name], token, sidecar_name, release_id) != sidecar: fail(f"downloaded {sidecar_name} has conflicting contents")
def main():
    token = os.environ.get("FORGEJO_TOKEN", "")
    if not token: fail("FORGEJO_TOKEN is required")
    sha = os.environ.get("CI_COMMIT_SHA", "")
    if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha): fail("CI_COMMIT_SHA must be exactly 40 lowercase hexadecimal characters")
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
    tag_url = f"{RELEASES}/tags/{urllib.parse.quote(version, safe='')}"; status, raw = request("GET", tag_url, token)
    if status == 200:
        verify(decode(raw, "existing release"), token, binary_name, sidecar_name, digest, sidecar)
        print(json.dumps({"schema":"harmonia.release_publish.v1", "ok":True, "status":"no-op", "changed":False, "project":PROJECT, "tag":version, "commit":sha, "assets":[binary_name, sidecar_name], "sha256":digest, "release_url":tag_url}, separators=(",", ":"))); return
    if status != 404: fail(f"GET release tag returned HTTP {status}")
    payload = {"tag_name":version, "name":version, "target_commitish":sha, "draft":False, "prerelease":False}; status, raw = request("POST", RELEASES, token, payload)
    if status == 409:
        status, raw = request("GET", tag_url, token)
        if status != 200: fail(f"release collision reread returned HTTP {status}")
        verify(decode(raw, "existing release"), token, binary_name, sidecar_name, digest, sidecar)
        print(json.dumps({"schema":"harmonia.release_publish.v1", "ok":True, "status":"no-op", "changed":False, "project":PROJECT, "tag":version, "commit":sha, "assets":[binary_name, sidecar_name], "sha256":digest, "release_url":tag_url}, separators=(",", ":"))); return
    if status not in (200, 201): fail(f"release creation returned HTTP {status}")
    release = decode(raw, "release creation"); release_id = release.get("id")
    if not isinstance(release_id, int): fail("created release has no numeric id")
    if assets_of(release): fail("new release unexpectedly contains assets")
    upload_url = f"{RELEASES}/{release_id}/assets"
    for name, content, content_type in ((binary_name, binary, "application/octet-stream"), (sidecar_name, sidecar, "text/plain; charset=utf-8")):
        url = f"{upload_url}?{urllib.parse.urlencode({'name':name})}"; status, _ = request("POST", url, token, content, content_type=content_type)
        if status not in (200, 201): fail(f"upload of {name} returned HTTP {status}")
    status, raw = request("GET", tag_url, token)
    if status != 200: fail(f"reread of release returned HTTP {status}")
    verify(decode(raw, "release reread"), token, binary_name, sidecar_name, digest, sidecar)
    print(json.dumps({"schema":"harmonia.release_publish.v1", "ok":True, "status":"published", "changed":True, "project":PROJECT, "tag":version, "commit":sha, "assets":[binary_name, sidecar_name], "sha256":digest, "release_url":tag_url}, separators=(",", ":")))
if __name__ == "__main__": main()
