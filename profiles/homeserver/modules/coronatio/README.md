# Coronatio

This module carries the HOMESERVER product crown configuration lifted from the original website configuration. Harmonia maintains configuration on an already-born appliance; it does not install or build Coronatio, install a unit, or own the service lifecycle.

The ladder:

- fails closed unless the birth-provided `coronatio` executable exists;
- requires `/etc/homeserver.json` to be non-empty and valid JSON, but never overwrites that household-edited live file;
- converges the secret-free product baseline to `/etc/homeserver.factory`, backing up replaced bytes;
- validates the installed factory baseline;
- performs no restart because Coronatio reads the household JSON when serving configuration-backed routes.

The factory baseline preserves the quarry tab, portal, upload, mount, permissions, theme and visibility shape. The admin PIN and site-specific remote URLs are empty for birth-owned fill. Generated release timestamps/build identity and instance network notes are not carried.

The file names services, local portal URLs, NAS paths, mount labels, users and groups owned by other concerns. Their binaries, units, certificates, keys, storage, permissions and runtime state remain outside this module. Premium-tab patches, logs, browser state and generated backups are also outside this module.
