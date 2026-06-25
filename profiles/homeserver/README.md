# HomeServer profile scaffold

Public Harmonia surface.

This profile is the fleet product truth for the reusable HOMESERVER appliance. It carries public, non-secret product configuration and module declarations. Birth orchestration remains Chrysalis/deployable authority; this tree is the desired-state source Chrysalis consumes.

Visible public config concerns:

- `config/nginx/`
- `config/coronatio/`
- `config/firewall/`
- `config/postgres/`
- `config/tailscale/`
- `config/calibreweb/`
- `config/filebrowser/`
- `config/jellyfin/`
- `config/piwigo/`
- `config/transmission/`
- `config/mkdocs/`
- `config/forgejo/`
- `config/yarr/`
- `config/navidrome/`
- `config/samba/`
- `config/vaultwarden/`
- `config/udev/`
- `config/systemd/`

Each folder is one product concern and later one Chrysalis phase/unit. Do not duplicate these as public `*-runtime` config folders.

Forbidden here: control plane, CI automation, web-crawl ingest, personal media/library choices, recipes/personal apps, operator deployment lanes, private topology, credentials, tokens, private keys, and vault contents.
