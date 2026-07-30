# Systemd

This module carries the residual generic HOMESERVER systemd desired state lifted from the private `initialization/files/systemd/` quarry. Harmonia maintains these appliance units and their enabled/active flags on an already-born appliance; it does not install systemd, create the encrypted mapper, mount storage outside the declared unit, or install the `/vault` scripts.

The ladder:

- fails closed unless the birth-provided `systemd-analyze`, `/dev/mapper/vault`, and executable `/vault/scripts/init.sh` exist;
- converges `vault.mount` and `mountNas.service` with backups of replaced files;
- validates both installed units with `systemd-analyze verify`;
- reloads systemd and restarts each unit only when this module changed managed material;
- enables both units when needed and proves they are active.

Both carried files are proposed as product-owned appliance wiring. Their quarry text is preserved apart from adding final newlines and removing the trailing space from `vault.mount`'s `WantedBy` line for repository-safe module form.

The quarry's third file, `transmissionPIA.service`, is deliberately excluded because the landed `transmission` concern owns and converges that exact service unit. No certificates, logs, filled secrets, credentials, or generated instance artifacts exist in the quarry systemd tree.

Cross-concern boundaries remain external: `vault.mount` requires the birth-owned `/dev/mapper/vault` encrypted device; `mountNas.service` requires that mount and executes the vault concern's `/vault/scripts/init.sh`. This module does not absorb the mapper's birth configuration, vault scripts, NAS content, Transmission launcher, VPN credentials, or any service-specific units already owned by other modules.
