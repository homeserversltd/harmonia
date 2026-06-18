# Harmonia installer

The installer tranche will install:

- `/usr/local/bin/harmonia`
- `/etc/harmonia/identity.json`
- `/var/lib/harmonia/state/`
- `/var/log/harmonia/`
- `/var/lib/harmonia/receipts/`
- `harmonia.service`
- `harmonia.timer`

Shell may download/place the first binary, but all update logic belongs to Harmonia Rust code.
