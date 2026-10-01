# Engine Artifact Ratchet

The local ratchet lock records Harmonia's local engine state. Source declarations
come from the appliance configuration; artifact and source acquisition use those
declarations and the forge. There is no private engine configuration sidecar or
transport table.

## Lock

The ratchet lock, when present, lives under Harmonia’s owned state root at
`/var/lib/harmonia/engine-ratchet-lock.json`:

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

The local lock records the last converged engine identity. It does not select an
artifact: artifact mode selects the newest eligible engine Release from the
configured repository, while developer mode builds the remote `main` head.

## Compiled engine defaults

The engine uses compiled local defaults rather than an engine configuration
file. It installs at `/usr/local/bin/harmonia` and acquires source under
`/var/lib/harmonia/engine-source`; developer mode builds there and artifact mode
uses the same tree as its content seat. It stages artifacts below that source
root and derives the profile index from the owned module root. Unit activation
is the enablement state; there is no separate `enabled` setting.

Artifact mode selects the newest published engine Release in the configured
repository that carries the engine assets and `release.flag`, ordered by
`created_at` and then release `id`. It validates and stages that artifact without
compiling. When HEAD has no Release, it uses the newest eligible Release that
exists. If no eligible Release can be retrieved, preflight records a named
failure and preserves the installed engine; it never builds from source.

Developer mode bypasses Release selection even when a Release exists. It resolves
the remote `main` head, acquires the source pinned to that SHA, and builds it.

For either policy, the selected artifact/source SHA is also the expected content
seat. Renew-self seats the Harmonia source tree at that exact commit before any
engine promotion or StageProfile molt. The preflight and post-stage receipts keep
that selected SHA; artifact mode does not report repository HEAD as the installed
engine's identity. A failed source move or head mismatch is a red engine-preflight
stage: the staged binary is not promoted and the Apply transaction stops before
profile molt or downstream convergence, preserving the previous binary and
profile projection. Report-only records the selected identity and drift without
mutating the source seat.

The `engine-preflight/content-seat.json` receipt records the selected SHA as
`expected_head`, the observed content head, whether they match, whether source
mutation was possible, and the final paired/mismatch state. `engine-preflight/run.json`
repeats that selected SHA as `source_head`, plus the observed head and
match/failure fields. Report-only records the selected identity and observed
drift without mutating the source seat.

An already-current binary does not waive the content-seat check: Apply still
pairs the content tree to the resolved SHA, then runs the usual profile molt and
convergence. Quiet source acquisition may leave the tree unchanged, but its
observed head is still receipted.

## Source authority

`/etc/appliance/config.json` is the source authority. Its `sources`
declaration supplies candidate URLs and refs for each source, and the forge
provides the release/source acquisition surface. The engine component identity
is compiled into the binary from `HARMONIA_COMPONENT` (defaulting to
`harmonia`), and renew-self resolves the matching source entry. No private
engine file selects which engine is running.

If the compiled component has no matching source entry, acquisition, build,
and promotion are refused and the installed engine remains untouched. The
same preservation rule applies when the selected source declaration is
malformed or unusable.

Credentials are selected from the candidate URL host: `git.home.arpa` uses the
owner credential in `/etc/default/forgejo`, while foreign hosts are attempted
anonymously. The `credential_selector` field is syntax-validated metadata only;
it is not a credential possession request and cannot alter host-selected
credentials or the owner-only acquisition lane.

## Owner-borne SSH custody

Source acquisition runs as the owner over the owner's SSH identity. That
owner-borne SSH identity is the complete credential story for the engine source
lane. The engine does not accept a configured alternate identity or other
credential input, and it never writes credential material to its receipts or
observed state.

## Artifact trust

Artifact mode trusts a release only after the repository's published Release is
selected and its engine asset, checksum sidecar, and `release.flag` are verified.
Release order is publish time (`created_at`), then release `id`; neither the tag
string nor version ordering substitutes for publish order. A missing or
unretrievable eligible Release is receipted as a refusal, and the installed
engine remains untouched. Source compilation is not a fallback.

## Observed appliance state

`ruyi.json` is engine-maintained observed appliance state. Projection owns its
readback and writes; it is not a declaration, source authority, credential
authority, or replacement for `/etc/appliance/config.json`. Observed state can
describe what was seen on the appliance, but it cannot select a source or
authorize an engine change.

## Product and operator boundary

Deployables owns installation and uninstallation. Harmonia owns runtime
convergence and control of `harmonia.service` and `harmonia.timer`. Chrysalis’
release-publish tool owns publication and mirroring. The local ratchet lock
records the last converged engine identity; verified published Releases provide
the artifact selection authority in artifact mode.
