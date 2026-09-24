# Engine Artifact Ratchet

The local ratchet lock is Harmonia’s trust authority for engine artifacts.
Source declarations come from the appliance configuration; release and source
acquisition use those declarations and the forge. There is no private engine
configuration sidecar or transport table.

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

A body converges only to the local blessed lock. Newer observed releases are
receipt evidence, not local authority. A body does not self-advance this lock.

## Compiled engine defaults

The engine uses compiled local defaults rather than an engine configuration
file. It installs at `/usr/local/bin/harmonia`, acquires and builds source
under `/var/lib/harmonia/engine-source`, stages the release below that source
root, and derives the profile index from the owned module root. Unit activation
is the enablement state; there is no separate `enabled` setting.

The local ratchet lock's `source_head_sha` binds the engine release to the exact
admitted source head. Every Apply press first resolves that head, then seats the
Harmonia content tree at the same commit before any engine promotion or
StageProfile molt. This is true when the binary arrives from the artifact lane
as well as when the source-build fallback provides it. The artifact lane stages
and verifies the binary but does not compile it; the source tree is acquired
only as the paired content seat.

The `engine-preflight/content-seat.json` receipt records the expected head, the
observed content head, whether they match, whether source mutation was possible,
and the final paired/mismatch state. `engine-preflight/run.json` repeats the
observed head and match/failure fields. A failed source move or head mismatch is
a red engine-preflight stage: the staged binary is not promoted and the Apply
transaction stops before profile molt or downstream convergence, preserving the
previous binary and profile projection. Report-only records the observed source
head and drift without mutating the source seat.

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

Versioned engine artifacts are subordinate to the local ratchet lock. The lock
is the only artifact trust authority; a release or forge can supply an
observation, but cannot change the admitted version or checksum. A missing or
unusable artifact is receipted as a refusal, and an integrity mismatch stops
the walk rather than changing authority.

## Observed appliance state

`ruyi.json` is engine-maintained observed appliance state. Projection owns its
readback and writes; it is not a declaration, source authority, credential
authority, or replacement for `/etc/appliance/config.json`. Observed state can
describe what was seen on the appliance, but it cannot select a source or
authorize an engine change.

## Product and operator boundary

Deployables owns installation and uninstallation. Harmonia owns runtime
convergence and control of `harmonia.service` and `harmonia.timer`. Chrysalis’
release-publish tool owns publication and mirroring. These boundaries do not
change the lock’s role as the sole artifact trust authority.
