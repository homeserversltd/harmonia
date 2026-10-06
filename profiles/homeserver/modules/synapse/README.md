# Synapse

This public HOMESERVER module maintains the private Synapse chat service on an already-born appliance. It owns the non-secret server configuration, birth-preserved secrets, PostgreSQL declaration, loopback API, LAN/Tailscale nginx entry point, log rotation, and the `matrix-synapse.service` service census.

The ladder manages the Synapse payload, invokes the declared Agathodaimon substrate helper with `cli.py matrix matrix-converge`, and reloads systemd after the Synapse unit drop-in is converged. Synapse is the service substrate; the Element client is a separate module that follows it. The managed-files step declares exact-path mode overrides for `homeserver.yaml` and `log.yaml` as decimal `416` (`0640`), without changing their bytes.

Synapse listens only on `127.0.0.1:8008`, uses `home.arpa` as its server name, and serves `matrix.home.arpa`. Federation is disabled and the product firewall remains the network authority for LAN and Tailscale exposure. Runtime credentials, signing keys, media, logs, and other instance state are not carried in public source.
