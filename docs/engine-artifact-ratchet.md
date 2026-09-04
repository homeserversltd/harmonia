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

## Versioned artifacts and local trust

Versioned engine artifacts are subordinate to the local ratchet lock. The lock
is the only artifact trust authority; a release, cache, or transport can supply
an observation, but cannot change the admitted version or checksum. A missing
or unusable artifact is receipted as a refusal, and an integrity mismatch stops
the walk rather than changing authority.

## Source authority

`engine.json` contains local engine mechanics only: enablement, installation,
build/staging, profile-index, ratchet-lock, and receipt/cache concerns. It does
not declare source identity, source selection, or credentials.

`profile.json` is the source authority. Its `sources` declaration together with
`kernel.engine_component` selects the exact public or private component for the
engine. The engine consumes that selected declaration; it does not infer a
component from the host, an installed path, a release, or a fallback name.

An absent `kernel.engine_component`, or a component that is absent from the
profile's `sources`, is a hard block before acquisition, build, or promotion.
The installed engine remains untouched in either case. The same preservation
rule applies when the selected source declaration is malformed or unusable.

The `credential_selector` field is syntax-validated metadata only. It is not a
credential possession request, is ignored after validation, and is never used
to select engine credentials or alter the owner-only acquisition lane.

## Owner-borne SSH custody

Source acquisition runs as the owner over the owner's SSH identity. That
owner-borne SSH identity is the complete credential story for the engine source
lane. The engine does not accept a configured alternate identity or other
credential input, and it never writes credential material to its
configuration, environment, receipts, or observed state.

## Observed appliance state

`ruyi.json` is engine-maintained observed appliance state. Projectio owns its
readback and writes; it is not a declaration, source authority, credential
authority, or replacement for `profile.json`. Observed state can describe what
was seen on the appliance, but it cannot select a source or authorize an engine
change.

## Product and operator boundary

Deployables owns installation and uninstallation. Harmonia owns runtime
convergence and control of `harmonia.service` and `harmonia.timer`. Chrysalis’
release-publish tool owns publication and mirroring. These boundaries do not
change the lock’s role as the sole artifact trust authority.
