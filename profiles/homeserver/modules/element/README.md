# Element

This public HOMESERVER module maintains the Element Web client and portal surface. Element follows Synapse because its configuration targets and validates the Synapse endpoint.

The module owns the Element nginx entry point, Element Web configuration, and local DNS records for `chat.home.arpa`, `element.home.arpa`, and the Synapse-facing host. Its portal is `element` at `https://chat.home.arpa`. The client configuration points to `https://matrix.home.arpa`, so Synapse must be converged first.

Element does not own the Synapse service, its systemd unit, its PostgreSQL declaration, or the Synapse convergence helper. Runtime assets and instance state remain outside public source.
