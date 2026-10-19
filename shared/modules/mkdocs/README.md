# MkDocs

This shared module configures the MkDocs hub on an already-born appliance. The shared `documentation` module owns the documentation bytes in `/opt/docs/docs`; this module consumes that shelf and keeps the whole hub serving at loopback `127.0.0.1:8005` on every sold appliance. Only the HomeServer nginx concern publishes it to the LAN.

Harmonia does not install Python or other packages, create or install a virtual environment, install MkDocs, or acquire documentation source. Birth supplies these prerequisites; convergence stops if they are absent.

The ladder:

- requires `/opt/docs/venv/bin/mkdocs` to exist and be executable;
- requires the shared documentation shelf at `/opt/docs/docs`;
- converges `files_root`'s `/opt/docs/mkdocs.yml` and `mkdocs.service`, backing up replaced files;
- validates the systemd unit with `systemd-analyze verify`;
- reloads systemd after file convergence;
- proves `mkdocs.service` is active.

Generated site output under `/opt/docs/site`, the virtual environment under `/opt/docs/venv`, logs under `/var/log/mkdocs`, and runtime systemd state are instance artifacts, not carried by this module. The separate nginx concern owns the LAN reverse proxy and certificate paths; only its HomeServer configuration publishes the hub to the LAN.
