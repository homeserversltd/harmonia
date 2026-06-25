# HomeServer profile

This is the public HOMESERVER appliance profile for Harmonia.

Harmonia is a Rust appliance update manager. It keeps a selected appliance profile current by running ordered modules and writing receipts.

A profile names one appliance identity and the modules that maintain it. Each folder under `modules/` names one reusable, non-secret product concern. Module code and sidecar constants describe how Harmonia checks or applies that concern when the profile is run.

A Harmonia run reads `index.json`, runs the declared modules, and writes receipts showing what was checked, what changed, and the first missing signal if the appliance is not current.

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

This profile is safe for public source. It contains product module scaffolding and public constants only. Runtime credentials, keys, tokens, passwords, and site-specific values are supplied outside public source.
