#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: tools/publish-engine-artifact.sh --artifact-repo <ssh-git-url-or-path> [--version <v>] [--source-head <sha>] [--arch <arch>]

Builds the Harmonia engine binary at the current admitted source head, computes sha256,
and publishes a per-version artifact plus harmonia.engine.ratchet_lock.v1 into the
blessed-artifacts git repo over the existing SSH deploy-key lane. Transport remains
untrusted: bodies promote only after lock sha256 verification in preflight.

Canonical product release surface split:
  - estate transport: blessed-artifacts git repo over SSH root deploy keys;
  - Forgejo release: may mirror the same artifact/sha as product release surface;
  - GitHub mirror: later customer-egress lane, not used here.
EOF
}

artifact_repo=""
version=""
source_head=""
arch="${HARMONIA_ARTIFACT_ARCH:-$(uname -m)}"
remote="origin"
branch="main"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact-repo) artifact_repo="${2:?}"; shift 2 ;;
    --version) version="${2:?}"; shift 2 ;;
    --source-head) source_head="${2:?}"; shift 2 ;;
    --arch) arch="${2:?}"; shift 2 ;;
    --branch) branch="${2:?}"; shift 2 ;;
    --remote) remote="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$artifact_repo" ]]; then
  echo "artifact repo required; use the Forgejo-canonical blessed-artifacts SSH repo" >&2
  exit 2
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"
version="${version:-$(python3 - <<'PY'
import tomllib
print(tomllib.loads(open('Cargo.toml','rb').read().decode())['package']['version'])
PY
)}"
source_head="${source_head:-$(git rev-parse HEAD)}"
case "$arch" in
  x86_64|amd64) arch="x86_64" ;;
esac

cargo build -p harmonia --release
artifact_name="harmonia-${version}-${arch}"
staging="target/engine-artifacts/${version}"
mkdir -p "$staging"
cp target/release/harmonia "$staging/$artifact_name"
chmod 755 "$staging/$artifact_name"
sha256="$(sha256sum "$staging/$artifact_name" | awk '{print $1}')"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git clone "$artifact_repo" "$work/blessed-artifacts"
cd "$work/blessed-artifacts"
git checkout "$branch" 2>/dev/null || git checkout -b "$branch"
mkdir -p "engine/${version}/${arch}" locks
cp "$repo_root/$staging/$artifact_name" "engine/${version}/${arch}/$artifact_name"
cat > "locks/harmonia-engine-${version}.json" <<EOF
{
  "schema": "harmonia.engine.ratchet_lock.v1",
  "engine_version": "${version}",
  "source_head_sha": "${source_head}",
  "artifacts": {
    "${arch}": {
      "name": "engine/${version}/${arch}/${artifact_name}",
      "sha256": "${sha256}"
    }
  }
}
EOF
python3 -m json.tool "locks/harmonia-engine-${version}.json" >/tmp/harmonia-engine-ratchet-lock-check.json
git add "engine/${version}/${arch}/${artifact_name}" "locks/harmonia-engine-${version}.json"
git commit -m "Publish Harmonia engine ${version} ${arch}" || true
git push "$remote" "$branch"
cat <<EOF
schema=harmonia.engine.artifact_publication.v1
ok=true
transport=blessed-artifacts-git-ssh
version=${version}
arch=${arch}
artifact_name=${artifact_name}
sha256=${sha256}
source_head_sha=${source_head}
lock_path=locks/harmonia-engine-${version}.json
forgejo_release_surface=mirror-same-artifact-and-sha-product-surface
github_mirror=out-of-scope-later-customer-egress
EOF
