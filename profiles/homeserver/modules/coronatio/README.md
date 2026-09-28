# Coronatio

This module carries the HOMESERVER product crown configuration lifted from the original website configuration. Harmonia converges the native Coronatio service runtime from the repository's own Forgejo Release on an already-born appliance.

Harmonia owns only Coronatio service runtime convergence. Chrysalis birth writes and seals `/etc/appliance/config.factory`, then seeds `/etc/appliance/config.json` from this module's unchanged `files_root` payload. Harmonia only reads both files. Live changes to `/etc/appliance/config.json` belong to Caduceus.

The ladder:

- captures `/etc/appliance/config.json` as a non-empty, valid JSON household document but never overwrites it;
- validates `/etc/appliance/config.factory` as JSON but never writes or converges it;
- fetches and verifies the native Forgejo Release, atomically installs it, restarts Coronatio, and health-checks the runtime.

The factory baseline preserves the quarry tab, portal, upload, mount, permissions, theme and visibility shape. The admin PIN and site-specific remote URLs are empty for birth-owned fill. Generated release timestamps/build identity and instance network notes are not carried.

The file names services, local portal URLs, NAS paths, mount labels, users and groups owned by other concerns. Their binaries, units, certificates, keys, storage, permissions and runtime state remain outside this module. Premium-tab patches, logs, browser state and generated backups are also outside this module.
