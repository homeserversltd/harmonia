# udev

HOMESERVER UDEV rule module. The real deployed RAPL rule lives here:

```text
files/99-rapl-permissions.rules.tmpl
```

This module renders and deploys it to `/etc/udev/rules.d/99-rapl-permissions.rules`. Files belong in this module because `udev` is the intent.
