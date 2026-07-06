# machine-id-truncate (PARKED)

`machine-id-truncate` is a parked, manual-only Harmonia module. It is present and documented, but inert: no profile `index.json` references it, no automation calls it, and it performs no reboot.

## Why

`/etc/machine-id` is a stable 128-bit host identifier readable by any process. Well-behaved software uses `sd_id128_get_machine_app_specific()` to derive a keyed per-app identifier, but adoption is spotty: Electron's `node-machine-id` reads the raw value, and Chrome reads it for enterprise device management. Truncating the machine-id before a reboot caps its lifetime as a correlator while allowing the system to mint a fresh identity at the next boot.

## Manual-only footgun ledger

This module is deliberately holstered because rotating machine identity is not a routine maintenance act. Journald history partitions by machine-id; DHCP DUID/IAID may derive from it, so leases can present as a new device; per-machine app registrations and licenses can reset; and any estate observability keyed on machine-id would silently lie across rotations. The module truncates `/etc/machine-id` to zero bytes only. It explicitly does not write the string `uninitialized`, because that value triggers systemd first-boot semantics such as `ConditionFirstBoot=` and preset re-application. Empty file means regenerate identity at next boot, nothing more.

## Operation

When explicitly invoked through the Harmonia profile/module ladder, the module first verifies `/var/lib/dbus/machine-id` is a symlink to `/etc/machine-id`. If the D-Bus path is a divergent regular file or points anywhere else, it refuses and emits a receipt naming the divergence. If `/etc/machine-id` already has zero bytes, the result is `ok=true, changed=false`. If it contains an existing identity, the result is `ok=true, changed=true`, with a receipt stating the old machine-id is gone and a new identity is minted at next boot. The module performs no reboot.

## Fork recipe

Corpus convention wins over a global module spine: Harmonia executes modules from the selected profile's adjacent `profiles/<profile>/modules/<module-id>/manifest.json` tree. To arm this parked tool for a future profile, copy or fork this directory into that profile's `modules/` directory if it is not already there, add `"machine-id-truncate"` to that profile's `index.json` `modules` array, and converge that profile intentionally. That arming ceremony is intentionally left undone here.
