# HomeServer profile scaffold

Public Harmonia surface.

This profile is the fleet product truth for the reusable HOMESERVER appliance. The visible hierarchy is intentionally collapsed to one family: `modules/`.

Visible public modules:

- `modules/coronatio/`
- `modules/caduceus/`
- `modules/nginx/`
- `modules/firewall/`
- `modules/postgres/`
- `modules/tailscale/`
- `modules/calibreweb/`
- `modules/filebrowser/`
- `modules/jellyfin/`
- `modules/piwigo/`
- `modules/transmission/`
- `modules/mkdocs/`
- `modules/forgejo/`
- `modules/yarr/`
- `modules/navidrome/`
- `modules/samba/`
- `modules/vaultwarden/`
- `modules/udev/`
- `modules/systemd/`
- `modules/searx/`

There is no separate `apps/` tree and no separate `config/` tree in this profile. SearXNG is represented as the public `searx` module.

Each module folder is one product concern and later one Chrysalis phase/unit. Folder READMEs are scaffold-only unless paired with executable Rust module code and sidecar constants.

Forbidden here: control plane, CI automation, web-crawl ingest, personal media/library choices, recipes/personal apps, operator deployment lanes, private topology, credentials, tokens, private keys, and vault contents.
