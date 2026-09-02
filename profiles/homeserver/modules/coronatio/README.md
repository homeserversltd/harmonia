# Coronatio

This module carries the HOMESERVER product crown configuration lifted from the original website configuration. Harmonia owns runtime convergence from the repository's own Forgejo Release and maintains the configuration on an already-born appliance.

Harmonia owns the Coronatio service runtime convergence; this module retains configuration custody alongside it.

The ladder:

- captures `/etc/appliance/config.json` as a non-empty, valid JSON household document but never overwrites it; Caduceus is its sole writer;
- always converges the secret-free product baseline to `/etc/appliance/config.factory`, backing up replaced bytes; Harmonia owns that factory baseline;
- fetches and verifies the native Forgejo Release, atomically installs it, restarts Coronatio, and health-checks the runtime.

The factory baseline preserves the quarry tab, portal, upload, mount, permissions, theme and visibility shape. The admin PIN and site-specific remote URLs are empty for birth-owned fill. Generated release timestamps/build identity and instance network notes are not carried.

The file names services, local portal URLs, NAS paths, mount labels, users and groups owned by other concerns. Their binaries, units, certificates, keys, storage, permissions and runtime state remain outside this module. Premium-tab patches, logs, browser state and generated backups are also outside this module.
