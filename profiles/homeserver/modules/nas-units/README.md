# Fixed NAS units

This public HOMESERVER profile carries fixed NAS unit bytes for the `primary` and `backup` roles. Device identity is fixed by PARTLABEL: `/dev/disk/by-partlabel/homeserver-primary-nas` and `/dev/disk/by-partlabel/homeserver-backup-nas`; the opened mapper names are `homeserver-primary-nas` and `homeserver-backup-nas`.

The module's declared `nas-mountpoints.conf` contains only the two service-backed mountpoint directories, `/mnt/nas` and `/mnt/nas_backup`, both `0755 root:root`. This narrowly supports the two NAS mount units; it is not a generic directory-only module. The ladder first observes both paths with `stat`; only a difference runs `systemd-tmpfiles --create` from this data, and the command step observes the paths again to prove the result.

Each opener waits for its own PARTLABEL device using `Wants=` and `After=` with the escaped systemd device name. The template retains `After=local-fs.target vault.mount`; neither the device nor `vault.mount` is pulled in with `Requires=`. Opener serialization behind primary is owned by the separate in-flight contract `contract-sbin-keyman-export-waits-its-turn-20261016`; that contract has not landed or been proved by this module change.

Both mounts order `After=vault.mount` and after their existing matching opener; the opener orders after `local-fs.target`, `vault.mount`, and its role device. Both mounts retain `DefaultDependencies=no`, their vault and PARTLABEL conditions, fixed unit names, and shutdown `Conflicts=umount.target` / `Before=umount.target`. Each mount still requires its matching opener instance. The opener's `StandardInputText` supplies the bare role JSON (`{"role":"primary"}` or `{"role":"backup"}`); its staff argv remains `storage/nas/open`.

The primary and backup mount units remain boot-elected with `WantedBy=multi-user.target`. Their ladder entries use `systemd/enable` only. The module does not start, restart, stop, or probe a NAS unit; enablement does not start either mount. Drift in a NAS unit file remains a proposal, and an absent unit-file target remains absent rather than being created by this module.

The birth export roster is the original three unit paths plus module-root `nas-mountpoints.conf`, `manifest.json`, and optional `README.md`. Its consumer must accept and implement all four existing ladder steps, including mountpoint creation and enable-only actions. Consumer compatibility is outside this module change.

The agathodaimon staff owns NAS `attach`, `detach`, `open`, and `setup`. The Castle's harmonia-monad overlay excludes this public HOMESERVER profile module and remains separate.
