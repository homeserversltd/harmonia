# Matrix and Element Web

This public HOMESERVER module converges a private Matrix collaboration surface:

- Synapse listens only on `127.0.0.1:8008` and has federation disabled.
- nginx terminates TLS for Synapse at `matrix.home.arpa` and serves Element Web, the customer chat portal, at canonical `chat.home.arpa` (with `element.home.arpa` retained as a compatibility alias).
- the product firewall remains the network authority: HTTPS is accepted only from the HOMESERVER LAN (`192.168.123.0/24`) and `tailscale0`; Synapse is never directly exposed.
- Unbound publishes `matrix.home.arpa`, `chat.home.arpa`, and the compatibility alias as `192.168.123.1`, matching existing `home.arpa` records.
- PostgreSQL owns database `synapse` and peer-authenticated role `matrix-synapse` without a repository password.
- `/etc/matrix-synapse/conf.d/90-birth-secrets.yaml` is generated only when absent, mode `0600`, and is never replaced by Harmonia.

Element Web is part of the same concern because it is the static client and the portal surface for this Synapse endpoint. Harmonia now converges the `homeserver.json` `tabs.portals` Element record with local URL `https://chat.home.arpa`, leaving the top-level `tabs/global/capabilities/settings` schema intact.

The maintenance helper installs the Matrix package floor as part of convergence so already-born HOMESERVER bodies can receive the module before the next full birth walk. The canonical fleet port registry currently has no admitted Matrix allocation. This module therefore uses the requested fallback loopback port `8008`; add `matrix-synapse-loopback` to the fleet registry before any future renumbering.
