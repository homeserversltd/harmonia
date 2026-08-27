# Udev

This module carries the HOMESERVER product udev desired state lifted from the private initialization quarry. Harmonia maintains the static device rule on an already-born appliance; it does not install udev or own the power-monitoring application.

The ladder:

- fails closed unless the birth-provided `udevadm` executable exists;
- converges the product-owned RAPL permissions rule with a backup of any replaced file;
- proves the udev daemon is active.

`99-rapl-permissions.rules.tmpl` is the single desired-state file consumed at appliance birth. `files_root/etc/udev/rules.d/99-rapl-permissions.rules` is a same-module symlink projection used by the convergence ladder so birth and later convergence read the same source bytes.

The rule crosses into the kernel powercap sysfs tree at `/sys/class/powercap/%k/energy_uj` and grants its group read permission to `www-data` for power monitoring. Kernel powercap devices and the power-monitoring application remain outside this module.

No certificates, logs, credentials, filled secrets, generated device identities, or other instance artifacts exist in the quarry udev tree or are carried here.
