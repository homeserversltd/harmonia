# Harmonia profiles

Profiles select one appliance identity and one ordered Rust module spine.

HomeConsole is the sole console identity:

```json
{
  "schema": "harmonia.profile.v1",
  "id": "homeconsole",
  "identity": "homeconsole",
  "module_spine_entered": "profiles/homeconsole/modules",
  "modules": ["identity", "system-packages"]
}
```

Module sidecars live beside the selected profile at `profiles/<id>/modules/<module>/sidecar.json` and carry constants only. Rust module logic lives in `crates/harmonia/src/modules/` and shared tools live in `crates/harmonia/src/tools*.rs`.
