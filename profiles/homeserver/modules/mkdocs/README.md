# MkDocs

This module carries the HOMESERVER product MkDocs configuration lifted from the private initialization quarry. Harmonia maintains configuration on an already-born appliance; it does not install Python, create the virtual environment, install MkDocs packages, or acquire documentation source.

The ladder:

- fails closed unless the birth-provided `/opt/docs/venv/bin/mkdocs` executable exists;
- fails closed unless birth supplied the documentation tree at `/opt/docs/docs`;
- converges the quarry `mkdocs.yml` and systemd unit with backups of replaced files;
- reloads systemd after file convergence;
- proves the service is active.

The documentation source is a separately owned gitlink in the quarry (`HOMESERVERSLTD/documentation`, pinned there at `5fad1e1068aedb159be06442e873f8fb3a88b2f2`). Its Markdown content is not absorbed into this configuration module. Birth must place that content under `/opt/docs/docs`; absence stops convergence.

Generated site output under `/opt/docs/site`, the virtual environment under `/opt/docs/venv`, logs under `/var/log/mkdocs`, and runtime systemd state are instance artifacts and are not carried. The nginx reverse proxy, its certificate paths, and its `homeserver-mkdocs` virtual host remain owned by the nginx concern.
