# Systemd

This module carries the residual generic HOMESERVER systemd desired state lifted from the private `initialization/files/systemd/` quarry. Harmonia owns `vault.mount` only on an already-born appliance; it does not install systemd, create the encrypted mapper, mount storage outside the declared unit, or install the `/vault` scripts.

The ladder:

- fails closed unless the birth-provided `systemd-analyze`, `/dev/mapper/vault`, and executable `/vault/scripts/init.sh` exist;
- converges `vault.mount` with backups of replaced files;
- reloads systemd and restarts `vault.mount` only when this module changed managed material;
- enables `vault.mount` when needed and proves it is active.

`mountNas.service` is birth-owned, runs once at boot, and is never converged or restarted by Harmonia.

The carried file is proposed as product-owned appliance wiring. Its quarry text is preserved apart from adding a final newline and removing the trailing space from `vault.mount`'s `WantedBy` line for repository-safe module form.

The quarry's third file, `transmissionPIA.service`, is deliberately excluded because the landed `transmission` concern owns and converges that exact service unit. No certificates, logs, filled secrets, credentials, or generated instance artifacts exist in the quarry systemd tree.

This module does not absorb the mapper's birth configuration, vault scripts, NAS content, Transmission launcher, VPN credentials, or any service-specific units already owned by other modules.
