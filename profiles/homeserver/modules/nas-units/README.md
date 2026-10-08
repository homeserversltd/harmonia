# Fixed NAS units

This public HOMESERVER profile carries fixed NAS unit bytes for the `primary` and `backup` roles. Device identity is fixed by PARTLABEL: `/dev/disk/by-partlabel/homeserver-primary-nas` and `/dev/disk/by-partlabel/homeserver-backup-nas`; the opened mapper names are `homeserver-primary-nas` and `homeserver-backup-nas`.

This is a bytes-only Harmonia module: it does not perform NAS unit operations, including starting, restarting, stopping, or probing units. Drift in a NAS unit file is a proposal, never a write. An absent unit-file target is not created by this module.

Chrysalis birth owns placement and enabling for all three units: it enables `mnt-nas.mount` and `mnt-nas_backup.mount` and starts neither mount. The templated opener has no `[Install]` section. Each mount pulls in its matching opener instance; that opener's `StandardInputText` supplies the bare role JSON (`{"role":"primary"}` or `{"role":"backup"}`) to the opener. Both mounts set `DefaultDependencies=no` to avoid the inherited `Before=local-fs.target` ordering that would form a cycle with the required opener `After=local-fs.target` ordering; their vault and role conditions remain in place.

The agathodaimon staff owns NAS `attach`, `detach`, and `open`. The castle's harmonia-monad overlay is separate from this public HOMESERVER profile module.
