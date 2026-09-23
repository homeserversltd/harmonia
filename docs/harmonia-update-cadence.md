# Harmonia update cadence

The appliance may declare its Harmonia convergence schedule in
`/etc/appliance/config.json` under `harmonia.update_interval`. The value is a
systemd calendar expression and controls `OnCalendar` only. For example:

```json
{"harmonia":{"update_interval":"hourly"}}
```

When the key is absent, Harmonia uses `hourly` and reports source `default`;
when present, it reports source `declared`. A malformed present value refuses
with `invalid-config-key harmonia.update_interval` rather than silently falling
back. Calendar forms accepted by the installer include systemd aliases such as
`hourly`, periodic `*:0/10`, and date/time forms such as `*-*-* 03:00`.

The installer uses this declaration for birth and `install-timer`. On each
`harmonia update` press, the engine observes the bytes at
`/etc/systemd/system/harmonia.timer` against the declared render. A report-only
update runs this check without `--apply`: it reports drift and movement `none`,
without writing the timer file or calling `systemctl daemon-reload`. An update
with `--apply` may converge the timer bytes and calls `systemctl daemon-reload`
only when the host systemd-directory file changes. Receipts retain the observed
drift and whether bytes moved. This convergence never starts, enables, stops, or
arms a timer.
`OnBootSec=2min`, `AccuracySec=30s`, and `Persistent=true` remain constants;
`OnUnitActiveSec` is intentionally absent.
