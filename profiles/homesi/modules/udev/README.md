# Udev

This module keeps the HomeSI's hardware-monitoring udev rule current. It is the twin of the homeserver profile's `udev` module. Harmonia maintains the static rule on an already-born appliance; it does not install udev or own the power-monitoring application.

On a HomeSI, Caduceus runs as user `caduceus`, not as root as it does on the HomeServer. The kernel creates the RAPL `energy_uj` files mode 0400 root, so without this rule the power chip never has a reading. The rule grants group `caduceus` read on `/sys/class/powercap/%k/energy_uj`.

The ladder:

- converges `files_root/etc/udev/rules.d/99-rapl-permissions.rules`, the one source of the rule bytes, with a backup of any replaced file;
- reloads udev rules when that step changed the rule;
- whenever `/sys/class/powercap/intel-rapl:0/energy_uj` is not group `caduceus`, replays powercap `add` events and waits for them to settle, then re-reads the group; the press stays red until the grant holds, and a later press tries again.

Who can read the counters: the `caduceus` group holds the `caduceus` service user and, through the shared `caduceus` module's owner-group step, the household `owner` account. The household owner can read the CPU energy counters; no other account can. This matches the HomeServer precedent, where group `www-data` reads them. RAPL counters are a known power side channel, which is why the kernel defaults them to root; the grant is deliberately limited to the service that draws the power chip and the box's owner.

Birth places the rule: the HomeSI spine's `udev` intent lifts these exact bytes from public Harmonia. Harmonia keeps a rule birth placed and never creates it; an absent rule is a red press, never a write, and a born HomeSI without the rule receives it by hand from these bytes.

Governing tablet: `pali:si-homesi-website-portals-and-hermes-count-20261024`, organ HomesiPowerCounter.
