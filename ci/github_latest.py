#!/usr/bin/env python3
"""Mirror the source-bound Forgejo release into GitHub's rolling `latest` release."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

FORGEJO_API = "https://git.home.arpa/api/v1"
FORGEJO_GIT_REMOTE = "https://git.home.arpa/HOMESERVERSLTD/harmonia.git"
FORGEJO_OWNER = "HOMESERVERSLTD"
REPOSITORY = "harmonia"
GITHUB_API = "https://api.github.com"
GITHUB_OWNER = "homeserversltd"
FORGEJO_PUSH_MIRRORS_SYNC_URL = (
    f"{FORGEJO_API}/repos/{FORGEJO_OWNER}/{REPOSITORY}/push_mirrors-sync"
)
LATEST_TAG = "latest"
EXPECTED_ASSETS = (
    "harmonia-x86_64",
    "harmonia-x86_64.sha256",
    "manifest.json",
    "release.flag",
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MIRROR_TIMEOUT_SECONDS = 180
MIRROR_POLL_SECONDS = 3
REQUEST_TIMEOUT_SECONDS = 90
RELEASE_READBACK_TIMEOUT_SECONDS = 60
RELEASE_READBACK_BACKOFF_SECONDS = (1, 2, 3, 5)


class PublishError(RuntimeError):
    pass


class Superseded(RuntimeError):
    pass


class SafeHTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep TLS on and never forward credentials across an HTTPS origin change."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if (req.get_method() == "POST"
                and req.full_url == FORGEJO_PUSH_MIRRORS_SYNC_URL):
            raise urllib.error.HTTPError(
                newurl, code, "refusing Forgejo push mirror sync redirect", headers, fp
            )
        source = urllib.parse.urlsplit(req.full_url)
        target = urllib.parse.urlsplit(newurl)
        if target.scheme != "https" or not target.hostname:
            raise urllib.error.HTTPError(
                newurl, code, "refusing non-HTTPS redirect", headers, fp
            )
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and (
            source.scheme.lower(), (source.hostname or "").lower(), source.port
        ) != (
            target.scheme.lower(), (target.hostname or "").lower(), target.port
        ):
            for header in ("Authorization", "Cookie", "Proxy-Authorization"):
                redirected.remove_header(header)
        return redirected


class Publisher:
    def __init__(self, forgejo_token, github_token, plan=False):
        self.forgejo_token = forgejo_token
        self.github_token = github_token
        self.plan = plan
        self.opener = urllib.request.build_opener(SafeHTTPSRedirectHandler())
        self.facts = {
            "status": "error",
            "source_sha": None,
            "forgejo_main_sha": None,
            "forgejo_latest_tag_sha": None,
            "github_latest_tag_sha": None,
            "tag_move": None,
            "assets": [],
            "github_assets": [],
            "action": None,
            "notice": None,
            "plan_request_policy": "GET-only; never mutates" if plan else None,
            "push_mirror_sync": {
                "method": "POST",
                "endpoint": FORGEJO_PUSH_MIRRORS_SYNC_URL,
                "required": False,
                "attempted": False,
                "http_status": None,
            },
        }

    def request(self, provider, method, url, body=None, content_type=None,
                accept=None, allowed_hosts=None):
        method = method.upper()
        if self.plan and method != "GET":
            raise PublishError("internal refusal: --plan permits GET requests only")
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise PublishError(f"refusing non-HTTPS {provider} URL")
        if allowed_hosts is not None and parsed.hostname.lower() not in allowed_hosts:
            raise PublishError(f"refusing unexpected {provider} host")

        headers = {"User-Agent": "harmonia-github-latest-publisher"}
        if provider == "forgejo":
            headers["Authorization"] = f"token {self.forgejo_token}"
            headers["Accept"] = accept or "application/json"
        elif provider == "github":
            if method != "GET":
                headers["Authorization"] = f"Bearer {self.github_token}"
            headers["Accept"] = accept or "application/vnd.github+json"
            headers["X-GitHub-Api-Version"] = "2022-11-28"
        else:
            raise PublishError("unknown API provider")

        data = body
        if isinstance(body, (dict, list)):
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif content_type:
            headers["Content-Type"] = content_type

        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            # Do not stringify request objects or headers; secrets never enter diagnostics.
            raise PublishError(
                f"{provider} {method} transport failure ({type(exc).__name__})"
            ) from exc

    @staticmethod
    def decode_json(raw, label):
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PublishError(f"{label} returned invalid JSON") from exc
        if not isinstance(value, (dict, list)):
            raise PublishError(f"{label} returned an invalid JSON value")
        return value

    @staticmethod
    def sha256(raw):
        return hashlib.sha256(raw).hexdigest()

    def forgejo_release_url(self, sha):
        tag = urllib.parse.quote(f"sha-{sha}", safe="")
        return (f"{FORGEJO_API}/repos/{FORGEJO_OWNER}/{REPOSITORY}"
                f"/releases/tags/{tag}")

    def get_forgejo_release(self, sha):
        status, raw = self.request(
            "forgejo", "GET", self.forgejo_release_url(sha),
            allowed_hosts={"git.home.arpa"},
        )
        if status == 404:
            return None
        if status != 200:
            raise PublishError(f"Forgejo release lookup returned HTTP {status}")
        release = self.decode_json(raw, "Forgejo release")
        if not isinstance(release, dict):
            raise PublishError("Forgejo release is not an object")
        return release

    @staticmethod
    def asset_map(release, provider):
        values = release.get("assets")
        if not isinstance(values, list):
            raise PublishError(f"{provider} release has no asset list")
        result = {}
        for asset in values:
            if not isinstance(asset, dict):
                raise PublishError(f"{provider} release has an invalid asset entry")
            name = asset.get("name")
            if not isinstance(name, str) or not name or name in result:
                raise PublishError(f"{provider} release has an invalid or duplicate asset name")
            result[name] = asset
        return result

    @staticmethod
    def validate_asset_url(url, expected_host, provider, name):
        try:
            parsed = urllib.parse.urlsplit(url)
            valid = (
                parsed.scheme == "https"
                and parsed.hostname is not None
                and parsed.hostname.lower() == expected_host
                and parsed.username is None
                and parsed.password is None
            )
        except (TypeError, ValueError):
            valid = False
        if not valid:
            raise PublishError(f"{provider} asset {name} has an invalid download URL")
        return url

    def download_forgejo_asset(self, asset, name):
        url = self.validate_asset_url(
            asset.get("browser_download_url"), "git.home.arpa", "Forgejo", name
        )
        status, raw = self.request(
            "forgejo", "GET", url, accept="application/octet-stream",
            allowed_hosts={"git.home.arpa"},
        )
        if status != 200:
            raise PublishError(f"Forgejo asset {name} download returned HTTP {status}")
        return raw

    @staticmethod
    def parse_object(raw, label):
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PublishError(f"{label} is invalid JSON") from exc
        if not isinstance(value, dict):
            raise PublishError(f"{label} is not an object")
        return value

    def load_source_assets(self, release, sha):
        if release.get("tag_name") != f"sha-{sha}":
            raise PublishError("Forgejo release tag does not match CI_COMMIT_SHA")
        if release.get("target_commitish") != sha:
            raise PublishError("Forgejo release target_commitish does not exactly match CI_COMMIT_SHA")
        if "target_commit" in release and release.get("target_commit") != sha:
            raise PublishError("Forgejo release target_commit conflicts with CI_COMMIT_SHA")
        assets = self.asset_map(release, "Forgejo")
        if set(assets) != set(EXPECTED_ASSETS):
            raise PublishError("Forgejo release asset names do not exactly match the expected set")

        contents = {
            name: self.download_forgejo_asset(assets[name], name)
            for name in EXPECTED_ASSETS
        }
        binary = contents["harmonia-x86_64"]
        if not binary:
            raise PublishError("Forgejo binary asset is empty")
        binary_digest = self.sha256(binary)
        sidecar = contents["harmonia-x86_64.sha256"]
        expected_sidecar = f"{binary_digest}  harmonia-x86_64\n".encode("ascii")
        if sidecar != expected_sidecar:
            raise PublishError("Forgejo binary sha256 sidecar does not match the binary bytes")

        manifest = self.parse_object(contents["manifest.json"], "Forgejo manifest.json")
        if (manifest.get("schema") != "estate.artifact.manifest.v1"
                or manifest.get("component") != REPOSITORY
                or manifest.get("source_sha") != sha
                or manifest.get("sha256") != binary_digest):
            raise PublishError("Forgejo manifest.json identity or binary digest conflicts")
        flag = self.parse_object(contents["release.flag"], "Forgejo release.flag")
        if (flag.get("schema") != "estate.release-flag.v1"
                or flag.get("component") != REPOSITORY
                or flag.get("source_sha") != sha
                or flag.get("sha256") != binary_digest):
            raise PublishError("Forgejo release.flag source identity or binary digest conflicts")
        return contents

    def forgejo_main_sha(self):
        url = f"{FORGEJO_API}/repos/{FORGEJO_OWNER}/{REPOSITORY}/branches/main"
        status, raw = self.request(
            "forgejo", "GET", url, allowed_hosts={"git.home.arpa"}
        )
        if status != 200:
            raise PublishError(f"Forgejo main branch lookup returned HTTP {status}")
        branch = self.decode_json(raw, "Forgejo main branch")
        commit = branch.get("commit") if isinstance(branch, dict) else None
        sha = commit.get("id", commit.get("sha")) if isinstance(commit, dict) else None
        if not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
            raise PublishError("Forgejo main branch response has no exact commit SHA")
        return sha

    def ref_url(self, provider):
        if provider == "forgejo":
            return (f"{FORGEJO_API}/repos/{FORGEJO_OWNER}/{REPOSITORY}"
                    "/git/refs/tags/latest")
        return (f"{GITHUB_API}/repos/{GITHUB_OWNER}/{REPOSITORY}"
                "/git/ref/tags/latest")

    def dereference_tag(self, provider, ref):
        if isinstance(ref, list):
            exact = [item for item in ref if isinstance(item, dict)
                     and item.get("ref") == "refs/tags/latest"]
            if len(exact) != 1:
                raise PublishError(f"{provider} latest tag reference response is ambiguous")
            ref = exact[0]
        if not isinstance(ref, dict):
            raise PublishError(f"{provider} latest tag reference is not an object")
        if ref.get("ref") not in (None, "refs/tags/latest"):
            raise PublishError(f"{provider} returned a foreign tag reference")
        obj = ref.get("object")
        for _ in range(5):
            if not isinstance(obj, dict):
                raise PublishError(f"{provider} latest tag object is invalid")
            object_sha = obj.get("sha")
            object_type = obj.get("type")
            if not isinstance(object_sha, str) or not SHA_RE.fullmatch(object_sha):
                raise PublishError(f"{provider} latest tag object has an invalid SHA")
            if object_type == "commit":
                return object_sha
            if object_type != "tag":
                raise PublishError(f"{provider} latest tag does not resolve to a commit")
            tag_url = f"{(FORGEJO_API if provider == 'forgejo' else GITHUB_API)}/repos/"
            owner = FORGEJO_OWNER if provider == "forgejo" else GITHUB_OWNER
            tag_url += f"{owner}/{REPOSITORY}/git/tags/{object_sha}"
            status, raw = self.request(
                provider, "GET", tag_url,
                allowed_hosts={"git.home.arpa" if provider == "forgejo" else "api.github.com"},
            )
            if status != 200:
                raise PublishError(f"{provider} annotated latest tag lookup returned HTTP {status}")
            tag_obj = self.decode_json(raw, f"{provider} annotated latest tag")
            obj = tag_obj.get("object") if isinstance(tag_obj, dict) else None
        raise PublishError(f"{provider} latest tag nesting is too deep")

    def get_tag_sha(self, provider):
        status, raw = self.request(
            provider, "GET", self.ref_url(provider),
            allowed_hosts={"git.home.arpa" if provider == "forgejo" else "api.github.com"},
        )
        if status == 404:
            return None
        if status != 200:
            raise PublishError(f"{provider} latest tag lookup returned HTTP {status}")
        return self.dereference_tag(provider, self.decode_json(raw, f"{provider} latest tag"))

    def set_forgejo_latest_tag(self, sha, previous_sha):
        if previous_sha == sha:
            return False
        current = self.forgejo_main_sha()
        self.facts["forgejo_main_sha"] = current
        if current != sha:
            raise Superseded("CI_COMMIT_SHA is no longer Forgejo main; Forgejo latest tag was not changed")

        git_env = os.environ.copy()
        git_env.pop("FORGEJO_TOKEN", None)
        git_env["GIT_CONFIG_COUNT"] = "1"
        git_env["GIT_CONFIG_KEY_0"] = "http.https://git.home.arpa/.extraheader"
        git_env["GIT_CONFIG_VALUE_0"] = f"Authorization: token {self.forgejo_token}"
        git_env["GIT_TERMINAL_PROMPT"] = "0"
        try:
            result = subprocess.run(
                [
                    "git", "push", "--force", "--no-follow-tags",
                    FORGEJO_GIT_REMOTE, f"{sha}:refs/tags/latest",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=REQUEST_TIMEOUT_SECONDS,
                check=False,
                env=git_env,
            )
        except subprocess.TimeoutExpired:
            raise PublishError("Forgejo latest tag push timed out") from None
        except OSError as exc:
            raise PublishError(
                f"Forgejo latest tag push could not start ({type(exc).__name__})"
            ) from None

        if result.returncode != 0:
            # Git diagnostics can contain remote echoes; never relay captured output.
            # An idempotent race is acceptable only if the exact ref now resolves to this SHA.
            observed = self.get_tag_sha("forgejo")
            if observed != sha:
                raise PublishError(
                    f"Forgejo latest tag push failed (git exit {result.returncode})"
                )
        observed = self.get_tag_sha("forgejo")
        if observed != sha:
            raise PublishError("Forgejo latest tag readback does not resolve to CI_COMMIT_SHA")
        return True

    def sync_forgejo_push_mirror(self):
        sync = self.facts["push_mirror_sync"]
        sync["attempted"] = True
        status, _raw = self.request(
            "forgejo", "POST", sync["endpoint"],
            allowed_hosts={"git.home.arpa"},
        )
        sync["http_status"] = status
        if not 200 <= status < 300:
            raise PublishError(f"Forgejo push mirror sync returned HTTP {status}")

    def wait_for_github_tag(self, sha):
        deadline = time.monotonic() + MIRROR_TIMEOUT_SECONDS
        last = None
        while True:
            last = self.get_tag_sha("github")
            self.facts["github_latest_tag_sha"] = last
            if last == sha:
                return
            if time.monotonic() >= deadline:
                raise PublishError(
                    "GitHub mirror did not expose refs/tags/latest at the expected commit "
                    f"within {MIRROR_TIMEOUT_SECONDS}s (observed {last or 'absent'})"
                )
            time.sleep(MIRROR_POLL_SECONDS)

    def github_release_url(self):
        return (f"{GITHUB_API}/repos/{GITHUB_OWNER}/{REPOSITORY}"
                f"/releases/tags/{urllib.parse.quote(LATEST_TAG, safe='')}")

    def get_github_release(self):
        status, raw = self.request(
            "github", "GET", self.github_release_url(),
            allowed_hosts={"api.github.com"},
        )
        if status == 404:
            return None
        if status != 200:
            raise PublishError(f"GitHub latest release lookup returned HTTP {status}")
        release = self.decode_json(raw, "GitHub latest release")
        if not isinstance(release, dict) or release.get("tag_name") != LATEST_TAG:
            raise PublishError("GitHub latest release response has an invalid tag identity")
        return release

    @staticmethod
    def github_release_id(release):
        release_id = release.get("id")
        if not isinstance(release_id, int) or isinstance(release_id, bool) or release_id <= 0:
            raise PublishError("GitHub latest release has an invalid numeric id")
        return release_id

    def wait_for_github_release(self, expected_id, ready, context):
        deadline = time.monotonic() + RELEASE_READBACK_TIMEOUT_SECONDS
        attempt = 0
        last_observed_id = None
        while True:
            release = self.get_github_release()
            if release is not None:
                observed_id = self.github_release_id(release)
                last_observed_id = observed_id
                if expected_id is None or observed_id == expected_id:
                    if ready(release):
                        return release
            else:
                last_observed_id = None

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                if (expected_id is not None and last_observed_id is not None
                        and last_observed_id != expected_id):
                    raise PublishError(
                        f"GitHub latest release identity conflict during {context}: "
                        f"expected id {expected_id}, observed id {last_observed_id} "
                        f"through the {RELEASE_READBACK_TIMEOUT_SECONDS}s readback bound"
                    )
                raise PublishError(
                    f"GitHub latest release {context} readback did not converge "
                    f"within {RELEASE_READBACK_TIMEOUT_SECONDS}s"
                )
            delay = RELEASE_READBACK_BACKOFF_SECONDS[
                min(attempt, len(RELEASE_READBACK_BACKOFF_SECONDS) - 1)
            ]
            time.sleep(min(delay, remaining))
            attempt += 1

    def download_github_asset(self, asset, name, allow_not_found=False):
        asset_id = asset.get("id")
        if not isinstance(asset_id, int) or isinstance(asset_id, bool) or asset_id <= 0:
            raise PublishError(f"GitHub asset {name} has an invalid numeric id")
        url = (f"{GITHUB_API}/repos/{GITHUB_OWNER}/{REPOSITORY}"
               f"/releases/assets/{asset_id}")
        status, raw = self.request(
            "github", "GET", url, accept="application/octet-stream",
            allowed_hosts={"api.github.com"},
        )
        if allow_not_found and status == 404:
            return None
        if status != 200:
            raise PublishError(f"GitHub asset {name} download returned HTTP {status}")
        return raw

    def github_asset_contents(self, release, allow_not_found=False):
        assets = self.asset_map(release, "GitHub")
        if set(assets) != set(EXPECTED_ASSETS):
            return assets, None
        contents = {}
        for name in EXPECTED_ASSETS:
            content = self.download_github_asset(
                assets[name], name, allow_not_found=allow_not_found
            )
            if content is None:
                return assets, None
            contents[name] = content
        return assets, contents

    def create_github_release(self, sha):
        current = self.forgejo_main_sha()
        self.facts["forgejo_main_sha"] = current
        if current != sha:
            raise Superseded("CI_COMMIT_SHA is no longer Forgejo main; GitHub release was not created")
        url = f"{GITHUB_API}/repos/{GITHUB_OWNER}/{REPOSITORY}/releases"
        payload = {
            "tag_name": LATEST_TAG,
            "target_commitish": sha,
            "name": "Harmonia latest",
            "body": f"Mirrored from Forgejo release sha-{sha}.",
            "draft": False,
            "prerelease": False,
            "generate_release_notes": False,
            "make_latest": "true",
        }
        status, raw = self.request(
            "github", "POST", url, body=payload,
            allowed_hosts={"api.github.com"},
        )
        if status == 201:
            release = self.decode_json(raw, "GitHub release creation")
            if not isinstance(release, dict) or release.get("tag_name") != LATEST_TAG:
                raise PublishError("created GitHub release has an invalid tag identity")
            release_id = self.github_release_id(release)
            return self.wait_for_github_release(
                release_id,
                lambda current: (
                    current.get("target_commitish") == sha
                    and current.get("draft") is False
                    and current.get("prerelease") is False
                ),
                "creation",
            )
        if status in (409, 422):
            return self.wait_for_github_release(
                None, lambda current: True, f"creation conflict after HTTP {status}"
            )
        raise PublishError(f"GitHub release creation returned HTTP {status}")

    def github_upload_url(self, release):
        release_id = release.get("id")
        if not isinstance(release_id, int) or isinstance(release_id, bool) or release_id <= 0:
            raise PublishError("GitHub latest release has an invalid numeric id")
        template = release.get("upload_url")
        if not isinstance(template, str) or not template:
            raise PublishError("GitHub latest release has no upload URL")
        url = template.split("{?", 1)[0]
        parsed = urllib.parse.urlsplit(url)
        expected_path = f"/repos/{GITHUB_OWNER}/{REPOSITORY}/releases/{release_id}/assets"
        if (parsed.scheme != "https" or parsed.hostname != "uploads.github.com"
                or parsed.path != expected_path or parsed.query or parsed.fragment):
            raise PublishError("GitHub latest release has an unexpected upload URL")
        return url

    def ensure_current_main(self, sha, context):
        current = self.forgejo_main_sha()
        self.facts["forgejo_main_sha"] = current
        if current != sha:
            raise Superseded(
                f"CI_COMMIT_SHA is no longer Forgejo main; stopped before {context}"
            )

    def patch_release_publication_state(self, release, sha):
        if (release.get("draft") is False
                and release.get("prerelease") is False
                and release.get("target_commitish") == sha):
            return release, False
        release_id = self.github_release_id(release)
        self.ensure_current_main(sha, "GitHub release state update")
        url = f"{GITHUB_API}/repos/{GITHUB_OWNER}/{REPOSITORY}/releases/{release_id}"
        status, raw = self.request(
            "github", "PATCH", url,
            body={"draft": False, "prerelease": False, "target_commitish": sha},
            allowed_hosts={"api.github.com"},
        )
        if status not in (200, 201):
            raise PublishError(f"GitHub release state update returned HTTP {status}")
        updated = self.decode_json(raw, "GitHub release state update")
        if not isinstance(updated, dict) or updated.get("tag_name") != LATEST_TAG:
            raise PublishError("GitHub release state update returned an invalid release")
        returned_id = self.github_release_id(updated)
        if returned_id != release_id:
            raise PublishError("GitHub latest release identity changed during state update")
        reread = self.wait_for_github_release(
            returned_id,
            lambda current: (
                current.get("draft") is False
                and current.get("prerelease") is False
                and current.get("target_commitish") == sha
            ),
            "publication-state update",
        )
        return reread, True

    def delete_github_assets(self, release, assets, sha, expected_release_id):
        release_id = self.github_release_id(release)
        if release_id != expected_release_id:
            raise PublishError("GitHub latest release identity changed before asset deletion")
        for name, asset in assets.items():
            asset_id = asset.get("id")
            if not isinstance(asset_id, int) or isinstance(asset_id, bool) or asset_id <= 0:
                raise PublishError(f"GitHub old asset {name} has an invalid numeric id")
            self.ensure_current_main(sha, f"deletion of GitHub asset {name}")
            url = (f"{GITHUB_API}/repos/{GITHUB_OWNER}/{REPOSITORY}"
                   f"/releases/assets/{asset_id}")
            status, _raw = self.request(
                "github", "DELETE", url, allowed_hosts={"api.github.com"}
            )
            if status not in (200, 204):
                raise PublishError(f"GitHub asset {name} deletion returned HTTP {status}")
        return self.wait_for_github_release(
            expected_release_id,
            lambda current: not self.asset_map(current, "GitHub"),
            "old asset deletion",
        )

    def upload_github_assets(self, release, contents, sha, expected_release_id):
        if self.github_release_id(release) != expected_release_id:
            raise PublishError("GitHub latest release identity changed before asset upload")
        upload_url = self.github_upload_url(release)
        uploaded_ids = {}
        for name in EXPECTED_ASSETS:
            self.ensure_current_main(sha, f"upload of GitHub asset {name}")
            url = upload_url + "?" + urllib.parse.urlencode({"name": name})
            status, raw = self.request(
                "github", "POST", url, body=contents[name],
                content_type=("application/octet-stream" if name == "harmonia-x86_64"
                              else "text/plain; charset=utf-8" if name.endswith(".sha256")
                              else "application/json"),
                allowed_hosts={"uploads.github.com"},
            )
            if status not in (200, 201):
                raise PublishError(f"GitHub asset {name} upload returned HTTP {status}")
            uploaded = self.decode_json(raw, f"GitHub asset {name} upload")
            if not isinstance(uploaded, dict) or uploaded.get("name") != name:
                raise PublishError(f"GitHub asset {name} upload returned an invalid asset identity")
            asset_id = uploaded.get("id")
            if not isinstance(asset_id, int) or isinstance(asset_id, bool) or asset_id <= 0:
                raise PublishError(f"GitHub asset {name} upload returned an invalid numeric id")
            uploaded_ids[name] = asset_id

            def asset_visible(current):
                observed = self.asset_map(current, "GitHub").get(name)
                return observed is not None and observed.get("id") == asset_id

            self.wait_for_github_release(
                expected_release_id,
                asset_visible,
                f"upload of asset {name}",
            )
        return uploaded_ids

    def compare_and_publish(self, sha, source_contents):
        self.ensure_current_main(sha, "GitHub release inspection")
        release = self.get_github_release()
        created = False
        if release is None:
            release = self.create_github_release(sha)
            created = True

        expected_release_id = self.github_release_id(release)
        release, release_state_changed = self.patch_release_publication_state(release, sha)
        old_assets, old_contents = self.github_asset_contents(release)
        exact_names = set(old_assets) == set(EXPECTED_ASSETS)
        exact_bytes = False
        if exact_names and old_contents is not None:
            self.facts["github_assets"] = self.describe_assets(old_contents)
            exact_bytes = old_contents == source_contents and all(
                self.sha256(old_contents[name]) == self.sha256(source_contents[name])
                for name in EXPECTED_ASSETS
            )
        github_tag_sha = self.get_tag_sha("github")
        self.facts["github_latest_tag_sha"] = github_tag_sha
        self.ensure_current_main(sha, "GitHub latest verification")

        if (not created and not release_state_changed and exact_bytes
                and github_tag_sha == sha):
            self.facts["status"] = "verified-noop"
            self.facts["action"] = "verified-noop"
            self.facts["notice"] = "GitHub latest already has the current tag and byte-identical assets"
            return

        # A mismatch replaces the complete asset set, including unexpected old names.
        if old_assets:
            release = self.delete_github_assets(
                release, old_assets, sha, expected_release_id
            )
        uploaded_ids = self.upload_github_assets(
            release, source_contents, sha, expected_release_id
        )
        verified_contents = None

        def final_assets_visible(current):
            nonlocal verified_contents
            assets = self.asset_map(current, "GitHub")
            if set(assets) != set(EXPECTED_ASSETS):
                return False
            for name in EXPECTED_ASSETS:
                observed_id = assets[name].get("id")
                if (not isinstance(observed_id, int) or isinstance(observed_id, bool)
                        or observed_id <= 0):
                    raise PublishError(f"GitHub asset {name} has an invalid numeric id")
                if observed_id != uploaded_ids.get(name):
                    return False
            _assets, contents = self.github_asset_contents(
                current, allow_not_found=True
            )
            if contents is None:
                return False
            if contents != source_contents or any(
                self.sha256(contents[name]) != self.sha256(source_contents[name])
                for name in EXPECTED_ASSETS
            ):
                return False
            verified_contents = contents
            return True

        verified = self.wait_for_github_release(
            expected_release_id, final_assets_visible, "final asset verification"
        )
        self.facts["github_assets"] = self.describe_assets(verified_contents)
        github_tag_sha = self.get_tag_sha("github")
        self.facts["github_latest_tag_sha"] = github_tag_sha
        if github_tag_sha != sha:
            raise PublishError("GitHub mirrored latest tag no longer resolves to CI_COMMIT_SHA")
        self.ensure_current_main(sha, "final GitHub release verification")
        self.facts["status"] = "published"
        self.facts["action"] = "assets-replaced" if old_assets else "assets-published"
        self.facts["notice"] = "GitHub latest assets were read back and verified against Forgejo"

    def describe_assets(self, contents):
        return [
            {"name": name, "sha256": self.sha256(contents[name])}
            for name in EXPECTED_ASSETS
        ]

    def plan_output(self, sha, source_contents, forgejo_tag_sha):
        self.facts["assets"] = self.describe_assets(source_contents)
        github_tag_sha = self.get_tag_sha("github")
        self.facts["github_latest_tag_sha"] = github_tag_sha
        mirror_sync = self.facts["push_mirror_sync"]
        mirror_sync["required"] = forgejo_tag_sha != sha or github_tag_sha != sha
        release = self.get_github_release()
        old_names = []
        exact_bytes = False
        if release is not None:
            old_assets, old_contents = self.github_asset_contents(release)
            old_names = sorted(old_assets)
            if set(old_assets) == set(EXPECTED_ASSETS) and old_contents is not None:
                self.facts["github_assets"] = self.describe_assets(old_contents)
                release_id = release.get("id")
                exact_bytes = (
                    old_contents == source_contents
                    and all(self.sha256(old_contents[name]) == self.sha256(source_contents[name])
                            for name in EXPECTED_ASSETS)
                    and release.get("draft") is False
                    and release.get("prerelease") is False
                    and release.get("target_commitish") == sha
                    and isinstance(release_id, int)
                    and not isinstance(release_id, bool)
                    and release_id > 0
                )
        current = self.forgejo_main_sha()
        self.facts["forgejo_main_sha"] = current
        self.facts["tag_move"] = {
            "from": forgejo_tag_sha,
            "to": sha,
            "required": forgejo_tag_sha != sha,
        }
        if current != sha:
            mirror_sync["required"] = False
            self.facts.update(
                status="superseded",
                action="no-mutation",
                notice="CI_COMMIT_SHA is not the current Forgejo main head",
            )
            return
        if (forgejo_tag_sha == sha and github_tag_sha == sha
                and release is not None and exact_bytes):
            self.facts.update(
                status="plan",
                action="verified-noop",
                notice="No mutation proposed; release identity, current tag, and every asset match",
            )
            return
        self.facts.update(
            status="plan",
            action="move-tag-and-publish",
            notice="GET-only plan; runtime will recheck Forgejo main before each write",
        )
        self.facts["delete_assets"] = old_names
        self.facts["upload_assets"] = list(EXPECTED_ASSETS)

    def run(self, sha):
        self.facts["source_sha"] = sha
        release = self.get_forgejo_release(sha)
        if release is None:
            self.facts.update(
                status="skipped-no-forgejo-release",
                action="no-mutation",
                notice=f"No Forgejo Release exists for sha-{sha}; nothing was changed",
            )
            return
        source_contents = self.load_source_assets(release, sha)
        self.facts["assets"] = self.describe_assets(source_contents)
        main_sha = self.forgejo_main_sha()
        self.facts["forgejo_main_sha"] = main_sha
        if main_sha != sha:
            self.facts.update(
                status="superseded",
                action="no-mutation",
                notice="CI_COMMIT_SHA is not the current Forgejo main head; nothing was changed",
            )
            return

        forgejo_tag_sha = self.get_tag_sha("forgejo")
        self.facts["forgejo_latest_tag_sha"] = forgejo_tag_sha
        self.facts["tag_move"] = {
            "from": forgejo_tag_sha,
            "to": sha,
            "required": forgejo_tag_sha != sha,
        }
        if self.plan:
            self.plan_output(sha, source_contents, forgejo_tag_sha)
            return

        mirror_sync = self.facts["push_mirror_sync"]
        moved = self.set_forgejo_latest_tag(sha, forgejo_tag_sha)
        self.facts["forgejo_latest_tag_sha"] = sha
        self.facts["tag_move"]["changed"] = moved
        if moved:
            mirror_sync["required"] = True
            self.sync_forgejo_push_mirror()
        else:
            github_tag_sha = self.get_tag_sha("github")
            self.facts["github_latest_tag_sha"] = github_tag_sha
            mirror_sync["required"] = github_tag_sha != sha
            if mirror_sync["required"]:
                self.sync_forgejo_push_mirror()
        self.wait_for_github_tag(sha)
        self.compare_and_publish(sha, source_contents)


def valid_sha(value):
    return isinstance(value, str) and SHA_RE.fullmatch(value) is not None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", action="store_true", help="perform GET-only inspection and print the proposed changes")
    args = parser.parse_args()
    sha = os.environ.get("CI_COMMIT_SHA", "")
    if not valid_sha(sha):
        print(json.dumps({"status": "error", "notice": "CI_COMMIT_SHA must be exactly 40 lowercase hexadecimal characters"}, separators=(",", ":")))
        return 1
    forgejo_token = os.environ.get("FORGEJO_TOKEN", "")
    github_token = os.environ.get("GITHUB_TOKEN", "")
    if not forgejo_token or (not args.plan and not github_token):
        missing = []
        if not forgejo_token:
            missing.append("FORGEJO_TOKEN")
        if not args.plan and not github_token:
            missing.append("GITHUB_TOKEN")
        print(json.dumps({"status": "error", "notice": "missing required secret environment: " + ", ".join(missing)}, separators=(",", ":")))
        return 1

    publisher = Publisher(forgejo_token, github_token, plan=args.plan)
    try:
        publisher.run(sha)
    except Superseded as exc:
        publisher.facts.update(status="superseded", action="stopped-before-write", notice=str(exc))
    except PublishError as exc:
        publisher.facts.update(status="error", notice=str(exc))
        print(json.dumps(publisher.facts, separators=(",", ":")))
        print(f"github_latest: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        publisher.facts.update(status="error", notice=f"unexpected failure ({type(exc).__name__})")
        print(json.dumps(publisher.facts, separators=(",", ":")))
        print(f"github_latest: unexpected failure ({type(exc).__name__})", file=sys.stderr)
        return 1
    print(json.dumps(publisher.facts, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
