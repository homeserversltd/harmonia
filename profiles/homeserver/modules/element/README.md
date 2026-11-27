# Element

This public HOMESERVER module maintains the Element Web client and portal surface. Element follows Synapse because its configuration targets and validates the Synapse endpoint.

The module owns the Element nginx entry point, Element Web configuration, and local DNS records for `agora.home.arpa` and the Synapse-facing host. Its portal is `Agora` at `https://agora.home.arpa`. The client configuration points to `https://matrix.home.arpa`, so Synapse must be converged first.

`chat.home.arpa` answers only as a 301 redirect to `agora.home.arpa` on the agora leaf, and `agora.home.arpa` remains the one Element address.

Element does not own the Synapse service, its systemd unit, its PostgreSQL declaration, or the Synapse convergence helper. Runtime assets and instance state remain outside public source.
