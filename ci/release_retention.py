#!/usr/bin/env python3
"""Keep the newest twenty source-bound Forgejo releases and their tags."""
import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

API_ROOT = "https://git.home.arpa/api/v1"
WEB_ROOT = "https://git.home.arpa"
OWNER = "HOMESERVERSLTD"
KEEP_COUNT = 20
PAGE_SIZE = 50
TAG_PATTERN = re.compile(r"^sha-([0-9a-fA-F]{40})$")


class RetentionError(RuntimeError):
    pass


def request(method, url, token, body=None):
    headers = {"Authorization": f"token {token}", "User-Agent": "forgejo-release-retention"}
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RetentionError(f"{method} request transport failed: {exc}") from exc


def fetch_releases(repo, token):
    releases = []
    page = 1
    while True:
        url = f"{API_ROOT}/repos/{OWNER}/{urllib.parse.quote(repo, safe='')}/releases?limit={PAGE_SIZE}&page={page}"
        status, raw = request("GET", url, token)
        if status != 200:
            raise RetentionError(f"release-list page {page} returned HTTP {status}")
        try:
            batch = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RetentionError(f"release-list page {page} returned invalid JSON") from exc
        if not isinstance(batch, list):
            raise RetentionError(f"release-list page {page} is not a JSON list")
        releases.extend(batch)
        if len(batch) < PAGE_SIZE:
            return releases
        page += 1


def eligible_releases(releases):
    eligible = []
    for release in releases:
        if not isinstance(release, dict) or release.get("draft"):
            continue
        tag = release.get("tag_name")
        match = TAG_PATTERN.fullmatch(tag) if isinstance(tag, str) else None
        if not match or release.get("target_commitish") != match.group(1):
            continue
        rid = release.get("id")
        created = release.get("created_at")
        if not isinstance(rid, int) or isinstance(rid, bool) or not isinstance(created, str):
            raise RetentionError("eligible release has invalid id or created_at")
        try:
            timestamp = dt.datetime.fromisoformat(created.replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                raise ValueError("timezone missing")
            timestamp = timestamp.astimezone(dt.timezone.utc)
        except ValueError as exc:
            raise RetentionError(f"eligible release {rid} has invalid created_at") from exc
        eligible.append({"id": rid, "tag": tag, "timestamp": timestamp, "created_at": created})
    return sorted(eligible, key=lambda item: (item["timestamp"], item["id"]), reverse=True)


def plan(repo, token, protect_id=None):
    ordered = eligible_releases(fetch_releases(repo, token))
    keep = ordered[:KEEP_COUNT]
    if protect_id is not None:
        protected = next((item for item in ordered if item["id"] == protect_id), None)
        if protected is None:
            raise RetentionError(f"just-published release id {protect_id} is not an eligible release")
        if all(item["id"] != protect_id for item in keep):
            keep.append(protected)
            keep.sort(key=lambda item: (item["timestamp"], item["id"]), reverse=True)
    keep_ids = {item["id"] for item in keep}
    delete = [item for item in ordered if item["id"] not in keep_ids]
    boundary_ties = []
    if len(ordered) > KEEP_COUNT:
        cutoff = ordered[KEEP_COUNT - 1]["timestamp"]
        boundary_ties = [item["id"] for item in ordered if item["timestamp"] == cutoff]
    return {"repo": repo, "kept_count": len(keep), "keep": keep, "delete": delete,
            "boundary_ties_at_rank_20": boundary_ties}


def git_run(repo, token, args):
    status, raw = request("GET", f"{API_ROOT}/user", token)
    if status != 200:
        raise RetentionError(f"authenticated Forgejo user lookup returned HTTP {status}")
    try:
        login = json.loads(raw).get("login")
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError) as exc:
        raise RetentionError("authenticated Forgejo user lookup returned invalid identity") from exc
    if not isinstance(login, str) or not login:
        raise RetentionError("authenticated Forgejo user lookup has no login")
    with tempfile.TemporaryDirectory(prefix="release-retention-", dir=os.environ.get("TMPDIR")) as temp:
        askpass = os.path.join(temp, "askpass")
        with open(askpass, "w", encoding="utf-8") as stream:
            stream.write("#!/bin/sh\ncase \"$1\" in *sername*) printf '%s\\n' \"$FORGEJO_LOGIN\" ;; *) printf '%s\\n' \"$FORGEJO_TOKEN\" ;; esac\n")
        os.chmod(askpass, 0o700)
        env = {**os.environ, "GIT_ASKPASS": askpass, "GIT_TERMINAL_PROMPT": "0", "FORGEJO_TOKEN": token, "FORGEJO_LOGIN": login}
        if "SSL_CERT_FILE" in os.environ:
            env["GIT_SSL_CAINFO"] = os.environ["SSL_CERT_FILE"]
        url = f"{WEB_ROOT}/{OWNER}/{repo}.git"
        # Both ls-remote and push take the repository before their final ref/refspec.
        command = ["git", *args[:-1], url, args[-1]]
        try:
            result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, env=env, check=False)
        except OSError as exc:
            raise RetentionError(
                f"authenticated git operation could not be started (errno {exc.errno})"
            ) from exc
        if result.returncode:
            raise RetentionError(f"authenticated git operation failed: {result.stderr.strip() or result.returncode}")
        return result.stdout


def git_ref_exists(repo, tag, token):
    output = git_run(repo, token, ["ls-remote", "--refs", f"refs/tags/{tag}"])
    return any(line.split("\t", 1)[-1] == f"refs/tags/{tag}" for line in output.splitlines())


def delete_git_ref(repo, tag, token):
    """Delete only the exact tag ref through authenticated git and verify it absent."""
    git_run(repo, token, ["push", f":refs/tags/{tag}"])
    if git_ref_exists(repo, tag, token):
        raise RetentionError(f"git tag ref {tag} still exists after deletion")


def apply(repo, token, protect_id=None):
    result = plan(repo, token, protect_id)
    deleted_releases = []
    deleted_tags = []
    failures = []
    for candidate in result["delete"]:
        rid, tag = candidate["id"], candidate["tag"]
        url = f"{API_ROOT}/repos/{OWNER}/{repo}/releases/{rid}"
        try:
            status, _ = request("DELETE", url, token)
        except RetentionError as exc:
            failures.append({"release_id": rid, "tag": tag, "step": "release-delete", "error": str(exc)})
            continue
        if status not in (200, 204):
            failures.append({"release_id": rid, "tag": tag, "step": "release-delete", "http_status": status})
            continue
        deleted_releases.append(rid)
        tag_url = f"{API_ROOT}/repos/{OWNER}/{repo}/tags/{urllib.parse.quote(tag, safe='')}"
        try:
            tag_status, _ = request("DELETE", tag_url, token)
        except RetentionError as exc:
            failures.append({"release_id": rid, "tag": tag, "step": "tag-delete", "error": str(exc)})
        else:
            if tag_status not in (200, 204, 404):
                failures.append({"release_id": rid, "tag": tag, "step": "tag-delete", "http_status": tag_status})
        try:
            if git_ref_exists(repo, tag, token):
                delete_git_ref(repo, tag, token)
            else:
                # The authenticated read above already observed this exact ref absent.
                pass
            deleted_tags.append(tag)
        except RetentionError as exc:
            failures.append({"release_id": rid, "tag": tag, "step": "git-ref-delete-or-read", "error": str(exc)})
    receipt = {"repo": repo, "kept_count": result["kept_count"],
               "deleted_release_ids": deleted_releases, "deleted_tags": deleted_tags,
               "failures": failures, "status": "partial-failure" if failures else "complete"}
    print(json.dumps(receipt, separators=(",", ":")))
    if failures:
        raise RetentionError("retention incomplete; published release was not rolled back")
    return receipt


def print_plan(result):
    def simplified(items):
        return [{"id": item["id"], "tag": item["tag"], "created_at": item["created_at"]} for item in items]
    output = {"repo": result["repo"], "kept_count": result["kept_count"],
              "keep": simplified(result["keep"]), "delete": simplified(result["delete"]),
              "boundary_ties_at_rank_20": result["boundary_ties_at_rank_20"]}
    print(json.dumps(output, separators=(",", ":")))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", choices=("harmonia", "caduceus", "kether"))
    parser.add_argument("--plan", action="store_true", required=True,
                        help="GET-only ordered retention plan (required)")
    args = parser.parse_args()
    token = os.environ.get("FORGEJO_TOKEN", "")
    if not token:
        raise SystemExit("FORGEJO_TOKEN is required")
    try:
        print_plan(plan(args.repo, token))
    except RetentionError as exc:
        print(f"release_retention: {exc}", file=sys.stderr)
        raise SystemExit(1)


def retain_current_release(repo, release_id):
    if repo != "harmonia":
        raise RetentionError("publisher retention is restricted to harmonia")
    if not isinstance(release_id, int) or isinstance(release_id, bool):
        raise RetentionError("verified release id must be an integer")
    token = os.environ.get("FORGEJO_TOKEN", "")
    if not token:
        raise RetentionError("FORGEJO_TOKEN is required")
    return apply(repo, token, release_id)


if __name__ == "__main__":
    main()
