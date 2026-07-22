# Engine Artifact Ratchet

Harmonia engine self-possession uses a version+sha lock as the trust anchor. Transport is untrusted.

## Lock

The kernel-owned lock lives beside `engine.json` by default:

```json
{
  "schema": "harmonia.engine.ratchet_lock.v1",
  "engine_version": "0.1.1",
  "source_head_sha": "<admitted harmonia source head>",
  "artifacts": {
    "x86_64": {
      "name": "engine/0.1.1/x86_64/harmonia-0.1.1-x86_64",
      "sha256": "<artifact sha256>"
    }
  }
}
```

A body converges only to the local blessed lock. Newer observed releases are receipt evidence, not local authority. A body does not self-advance this lock.

## Federated transport chain

Artifact transport is an ordered retrieval chain, not trust authority. The lock stays sovereign: every fetched binary must match the locally blessed lock sha before proof and promotion.

The default chain is:

1. estate forge: `git@git.home.arpa:HOMESERVERSLTD/blessed-artifacts.git` over existing root SSH deploy keys;
2. global canonical: `https://github.com/homeserversltd/blessed-artifacts.git` over anonymous HTTPS read.

This is the fork-and-precession model. Each estate runs its own forge and may bless locally as an explicit sovereign act. An estate that has not blessed locally autonomically falls up to the homeserversltd GitHub canonical state. Global state is maintained automatically; local precession remains explicit.

A transport MISS is an unreachable repo, fetch failure, or artifact name absent in the fetched tree. Misses are receipted and the next transport is tried. If the chain is exhausted, the existing source-fallback lane runs unchanged. A SHA mismatch after successful fetch and stage is tamper evidence: the walk stops hard-red before promotion and does not continue to later transports.

Existing singular `artifact_transport` configs remain valid and behave as a one-element chain. New configs use `artifact_transports`.

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

## Product surfaces

The estate forge is the local blessing surface. The homeserversltd GitHub repo is the canonical global transport of last resort and product mirror. Forgejo releases remain a product release surface and may be minted with the same artifact and sha. None of these hosting surfaces replaces the lock or proof battery as the engine trust path.

## Publication rig

`installer/bin/publish-engine-artifact.sh` builds `target/release/harmonia`, computes sha256, copies the binary into the blessed-artifacts repo, writes `locks/harmonia-engine-<version>.json`, commits, pushes, and emits `harmonia.engine.artifact_publication.v1`.

The rig may optionally mirror the same blessed commit to the homeserversltd GitHub repo using an existing configured git remote/auth lane. Mirror failure is a warning in the publication receipt, never a trust event.

The publication rig is outside the engine trust path. Installed bodies trust only the blessed lock sha256 and the proof battery.
