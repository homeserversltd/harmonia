#!/usr/bin/env python3
"""Keep the newest twenty source-bound Forgejo Releases; attempt API tag deletion and record surviving refs nonfatally."""
import argparse
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

API_ROOT = "https://git.home.arpa/api/v1"
OWNER = "HOMESERVERSLTD"
SUPPORTED_REPOS = ("harmonia", "harmonia-monad")
KEEP_COUNT = 20
PAGE_SIZE = 50
TAG_PATTERN = re.compile(r"^sha-([0-9a-fA-F]{40})$")


class RetentionError(RuntimeError):
    pass


def validated_repo(repo):
    if repo not in SUPPORTED_REPOS:
        raise RetentionError("publisher retention is restricted to harmonia or harmonia-monad")
    return repo


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


def fetch_releases(token, repo):
    releases = []
    page = 1
    while True:
        url = f"{API_ROOT}/repos/{OWNER}/{repo}/releases?limit={PAGE_SIZE}&page={page}"
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


def plan(token, repo, protect_id=None):
    repo = validated_repo(repo)
    ordered = eligible_releases(fetch_releases(token, repo))
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


def observe_tag_ref(tag, token, repo):
    url = f"{API_ROOT}/repos/{OWNER}/{repo}/git/refs/tags/{urllib.parse.quote(tag, safe='')}"
    try:
        status, _ = request("GET", url, token)
    except RetentionError as exc:
        return "failed", str(exc)
    if status == 200:
        return "present", None
    if status == 404:
        return "absent", None
    return "failed", f"tag-ref observation returned HTTP {status}"


def apply(token, repo, protect_id=None):
    repo = validated_repo(repo)
    result = plan(token, repo, protect_id)
    deleted_releases = []
    deleted_tags = []
    remaining_tag_refs = []
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
        tag_delete_succeeded = False
        try:
            tag_status, _ = request("DELETE", tag_url, token)
        except RetentionError as exc:
            failures.append({"release_id": rid, "tag": tag, "step": "tag-delete", "error": str(exc)})
        else:
            if tag_status in (200, 204):
                tag_delete_succeeded = True
            elif tag_status != 404:
                failures.append({"release_id": rid, "tag": tag, "step": "tag-delete", "http_status": tag_status})
        ref_state, ref_error = observe_tag_ref(tag, token, repo)
        if ref_state == "present":
            remaining_tag_refs.append(tag)
        elif ref_state == "failed":
            failures.append({"release_id": rid, "tag": tag, "step": "tag-ref-observation", "error": ref_error})
        if tag_delete_succeeded:
            deleted_tags.append(tag)
    receipt = {"repo": repo, "kept_count": result["kept_count"],
               "deleted_release_ids": deleted_releases, "deleted_tags": deleted_tags,
               "remaining_tag_refs": remaining_tag_refs,
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
    parser.add_argument("--plan", action="store_true", required=True,
                        help="GET-only ordered retention plan (required)")
    args = parser.parse_args()
    try:
        repo = validated_repo(os.environ.get("CI_REPO_NAME"))
    except RetentionError as exc:
        print(f"release_retention: {exc}", file=sys.stderr)
        raise SystemExit(1)
    token = os.environ.get("FORGEJO_TOKEN", "")
    if not token:
        raise SystemExit("FORGEJO_TOKEN is required")
    try:
        print_plan(plan(token, repo))
    except RetentionError as exc:
        print(f"release_retention: {exc}", file=sys.stderr)
        raise SystemExit(1)


def retain_current_release(repo, release_id):
    repo = validated_repo(repo)
    if not isinstance(release_id, int) or isinstance(release_id, bool):
        raise RetentionError("verified release id must be an integer")
    token = os.environ.get("FORGEJO_TOKEN", "")
    if not token:
        raise RetentionError("FORGEJO_TOKEN is required")
    return apply(token, repo, release_id)


if __name__ == "__main__":
    main()
