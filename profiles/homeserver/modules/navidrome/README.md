# Navidrome

This module carries the HOMESERVER product Navidrome desired state lifted from the private initialization quarry. Harmonia maintains configuration and service flags on an already-born appliance; it does not install Navidrome or FFmpeg, create users or directories, download releases, initialize an administrator, or own music and runtime data.

The ladder:

- fails closed unless the birth-provided `navidrome` and `ffmpeg` executables exist;
- requires the installed `navidrome.toml` to be non-empty but never overwrites it;
- converges the quarry `navidrome.service` unit with a backup of any replaced file;
- reloads systemd and restarts Navidrome only when this module changed managed material;
- enables the service when needed and proves it is active.

The public TOML is a user-editable birth seed, not a maintenance overwrite. Its quarry `${PORT}` placeholder is resolved to the product port `4533`; `${ADMIN_PASSWORD}` remains an unfilled birth-owned placeholder. The quarry installer fills that value from `/root/key/skeleton.key` for first launch and then removes the entire `DevAutoCreateAdminPassword` line, so Harmonia does not restore or replace the appliance copy. Both carried files otherwise preserve quarry text; the public copies only remove trailing spaces and add final newlines for repository-safe module form.

Navidrome owns mutable database state under `/var/lib/navidrome` and transcoding cache under `/var/cache/navidrome`; those instance artifacts are not carried. Music under `/mnt/nas/music` crosses into the NAS concern, `vault.mount` crosses into the systemd/vault concern, and port `4533` comes from the nginx concern's port registry. The module carries no files from those concerns. The Navidrome binary under `/opt/navidrome`, FFmpeg, service account, directories, logs, credentials, and filled secrets remain birth or runtime material.
