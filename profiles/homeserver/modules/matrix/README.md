# Matrix and Element Web

This public HOMESERVER module converges a private Matrix collaboration surface:

- Synapse listens only on `127.0.0.1:8008` and has federation disabled.
- nginx terminates TLS for `matrix.home.arpa` and serves Element Web at `element.home.arpa`.
- the product firewall remains the network authority: HTTPS is accepted only from the HOMESERVER LAN (`192.168.123.0/24`) and `tailscale0`; Synapse is never directly exposed.
- Unbound publishes both names as `192.168.123.1`, matching existing `home.arpa` records.
- PostgreSQL owns database `synapse` and peer-authenticated role `matrix-synapse` without a repository password.
- `/etc/matrix-synapse/conf.d/90-birth-secrets.yaml` is generated only when absent, mode `0600`, and is never replaced by Harmonia.

Element Web is part of the same concern because it is the static client for this Synapse endpoint. Portal/crown registry data is intentionally not present here: live Harmonia source does not yet own the deployed `homeserver.json` registry.

The canonical fleet port registry currently has no Matrix allocation. This module therefore uses the requested fallback loopback port `8008`; add `matrix-synapse-loopback` to the fleet registry before any future renumbering.
