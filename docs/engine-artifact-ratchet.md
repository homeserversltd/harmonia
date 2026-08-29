# Engine Artifact Ratchet

The local ratchet lock is Harmonia’s trust authority for engine artifacts.
Transport and hosting are untrusted retrieval and publication surfaces.

## Lock

The kernel-owned lock lives beside `engine.json` by default:

```json
{
  "schema": "harmonia.engine.ratchet_lock.v1",
  "engine_version": "0.1.1",
  "source_head_sha": "<admitted harmonia source head>",
  "artifacts": {
    "x86_64": {
      "name": "harmonia-0.1.1-x86_64",
      "sha256": "<artifact sha256>"
    }
  }
}
```

A body converges only to the local blessed lock. Newer observed releases are
receipt evidence, not local authority. A body does not self-advance this lock.

## Version releases and assets

Every source repository owns a version release on its Forgejo or GitHub project.
The tag is the version. Each architecture publishes the binary asset
`harmonia-<version>-<arch>` and the sidecar
`harmonia-<version>-<arch>.sha256`. The release’s hosting location is transport
only; it never replaces the local lock or the proof battery.

## Retrieval and mirrors

The default retrieval chain is explicitly ordered:

1. Forgejo release for the same source repository at `git.home.arpa`;
2. GitHub release for that same source repository.

The release tag is the version, and each release carries the binary asset
`harmonia-<version>-<arch>` plus its checksum asset
`harmonia-<version>-<arch>.sha256`. Chrysalis’ `release-publish` tool in
deployables publishes these releases and mirrors the assets.

This is the local-fork/precession model: an estate may run a local Forgejo fork
and explicitly precess/bless it, while the same source repository’s GitHub
release remains the ordered fallback. A MISS (missing repository, release,
asset, or fetch) is receipted and continues to the next transport. A SHA-256
mismatch after a successful fetch is tamper evidence: the walk stops hard-red
and never tries a later transport.

The lock remains sovereign: every fetched binary must match the locally blessed
lock SHA-256 before proof and promotion. Harmonia consumes assets; it does not
publish, mirror, install, or uninstall machine surfaces.

## Transport configuration

A release chain uses this exact shape (legacy Git entries may omit `kind` and
continue to parse as `git`):

```json
{
  "credential_scopes": {
    "forgejo-release": {"https_host": "git.home.arpa", "https_token_path": "/home/owner/.ssh/forgejo-token"}
  },
  "artifact_transports": [
    {"kind": "forgejo-release", "base_url": "https://git.home.arpa", "owner": "HOMESERVERSLTD", "repo": "harmonia", "credential_scope": "forgejo-release", "cache_dir": "/var/cache/harmonia/artifacts/forgejo"},
    {"kind": "github-release", "owner": "homeserversltd", "repo": "harmonia", "cache_dir": "/var/cache/harmonia/artifacts/github"}
  ]
}
```

Existing singular `artifact_transport` configs remain valid as a one-element
chain, and existing `artifact_transports` configs remain valid. Both singular
and plural Git configurations parse without `kind`, which defaults to `git`. A
missing Git repository remains a receipted MISS and continues to the next
transport.

## Local source checkout possession

A body may declare `local_source_checkout` in `/etc/harmonia/engine.json`. It
must equal `source_dir` and name an owner-refreshed Git checkout. In this mode
the root engine lane performs only local `git rev-parse`/branch readback, builds
from that checkout, and promotes only after the usual proof battery. It does
not clone, fetch, configure a credential helper, or open an SSH key for source
possession. The owner-plane refresh lane owns source freshness; the engine
receipt names that split as `declared-local-checkout-owner-plane-freshness`.

## Owner-bearer Forgejo SSH transport

`/etc/harmonia/engine.json` may declare `git_ssh_key_path` beside
`git_bearer`. It is an absolute path to the named non-root bearer's Forgejo
key; no default is inferred. Harmonia validates only that the declared path
exists as a regular file, then starts Git with
`GIT_SSH_COMMAND="ssh -i <declared-path> -o IdentitiesOnly=yes"`. When the
engine parent is root, Git and its SSH child execute only after the existing
`setgroups -> setgid -> setuid` drop to `git_bearer`; root never opens or
uses that key for Git authentication. Omitting the field preserves ordinary
Git SSH resolution for bodies with a correctly provisioned default key.

## Source HTTPS credentials

The generated zero-configuration `/etc/harmonia/engine.json` uses
`https://github.com/homeserversltd/harmonia.git` as `source_repo_url`. It uses
anonymous HTTPS and never adds a credential helper.

An estate that serves its source from a private HTTPS forge declares both
`git_https_credential_host` and `git_https_credential_token_path` in that same
engine configuration, alongside its private `source_repo_url`. The helper is
constructed only when both settings are present and the requested repository
uses `https://<git_https_credential_host>/`. It is passed to Git as a
command-local setting after the Git child has dropped to `git_bearer`; the token
path is never opened by the parent and no credential is written to Git config,
environment, or receipts. A missing setting, a non-HTTPS repository, or a host
mismatch leaves the helper disengaged.

## Product and operator boundary

Deployables owns installation and uninstallation. Harmonia owns runtime
convergence and control of `harmonia.service` and `harmonia.timer`. Chrysalis’
release-publish tool owns publication and mirroring. These boundaries do not
change the lock’s role as the sole artifact trust authority.
