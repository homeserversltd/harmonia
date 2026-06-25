# HomeServer profile skeleton

Public Harmonia surface.

This profile is the fleet product truth for the reusable HOMESERVER appliance. It carries product configuration, module declarations, and public-common service config that every matching body may converge.

Public contents:

- `config/` — reusable product configuration and templates
- `modules/` — Harmonia module spine for the `homeserver` profile
- `apps/searxng-search/` — public/common search service slot when selected for the product profile

Private/operator surfaces live in `HOMESERVERSLTD/harmonia-monad` under `profiles/owner-homeserver/`: control plane, CI automation, web-crawl ingest, personal media/library choices, recipes, deployment lanes, topology, credentials, keys, and owner-only services.

Birth orchestration remains private deployables/Fulcrum/Athanor/Chrysalis authority. Public Harmonia describes product desired state; it does not publish the control plane.
