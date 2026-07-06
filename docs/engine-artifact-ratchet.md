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

## Estate transport

The estate transport is the Forgejo-canonical `blessed-artifacts` git repository over existing root SSH deploy keys. This adds no new per-body token lane and avoids the auth-walled Forgejo API read path. Bodies fetch from this repo into `artifact_transport.cache_dir`, verify the staged binary against the lock sha256, then run the same proof battery as the source lane before promotion.

Forgejo releases remain the canonical product release surface and may be minted with the same artifact and sha. They are not the estate body's trust path. GitHub mirroring is a later customer-egress lane; the lock's version+sha grammar keeps hosting interchangeable.

## Publication rig

`installer/bin/publish-engine-artifact.sh` builds `target/release/harmonia`, computes sha256, copies the binary into the blessed-artifacts repo, writes `locks/harmonia-engine-<version>.json`, commits, pushes, and emits `harmonia.engine.artifact_publication.v1`.

The publication rig is outside the engine trust path. Installed bodies trust only the blessed lock sha256 and the proof battery.
