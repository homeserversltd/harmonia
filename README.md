# Harmonia

Harmonia is a Rust appliance update engine. Each invocation follows one bounded ritual: **ask → compare → do → attest**.

## Engine shape

- Atoms are the engine floor. They host primitive operations and engines: comparison, command capture, AUR work, Git artifact work, systemd work, package work, declaration handling, and the embedded `declarations.json` authority.
- Tools compose those atom capabilities. The tool layer owns the managed-files dispatcher, ordered routines, virtual-environment work, household-time work, and artifact-lock compatibility work. Other tool paths are re-export seats for atom or tool implementations.
- Bands are the execution faces. A band calls tools, and tools call atoms. Bands do not call atoms directly, except `renew-self`, whose `replace_process` path is an intended direct atom exception.
- The `do` directory contains twenty true-named transactional atoms, one folder per atom. Mutating atoms require diff-minted `Authorization` and the exact `--apply-or-timer` invocation key.
- `src/atoms/attest/` redacts caller-injected secrets before serialization and forwards fields derived from the redacted value.

Profiles provide ordered module declarations and constants. Receipts are written for the run and its module and tool work.

HomeConsole selects package authority from the body's `/etc/os-release`: `package_authorities` is keyed by exact `ID`, with each key mapping to an `{ "os_family": ..., "package_manager": ... }` pair (for example, `ubuntu` maps to `ubuntu`/`apt`). An undeclared known ID such as `ubuntu` is refused rather than downgraded; only an unknown derivative may select the first declared `ID_LIKE` entry. Legacy profiles with one `package_authority` pair keep their existing behavior and do not read body OS identity. HomeConsole declares `debian`/`apt` alongside its unchanged `arch`/`pacman` and `ubuntu`/`apt` seats. Its `constants.packages_by_family` lowers to `constants.packages` for the resolved `arch`, `ubuntu`, or `debian` authority; Ubuntu platform fragments use Debian fragments only as per-filename fallback, with Ubuntu taking same-name precedence, while `all/` and the `homeconsole` behavioral pool stay unchanged. This changes package/backend and fragment selection only; it moves no operator configuration or settings.

The TV profile declares `debian`/`apt` and retains the `tv` dotfile pool and existing file-module spine. Both HomeConsole and TV carry `gamescope-backports-pin`, a files-only module with a trixie-backports source and one preference stanza lifting only `gamescope` to priority 500. Module manifests may declare an optional top-level `authorities` list of OS families; absent means all. Projection interprets it once, and inspection labels a nonmatching module `authority-excluded`. Only HomeConsole's Netplan module declares it (`["ubuntu"]`), so Debian never projects that Ubuntu configuration.

HomeSuperintelligence (`homesi`) is the Debian 13 appliance: the household's Hermes on a local model, Caduceus controls, `agora.home.arpa`, documentation, and the private `models` and `inbox` Samba shelves at `homesi.home.arpa`. Its profile declares only `debian`/`apt`, retains the console's non-gaming capabilities in their original order, and uses its own pool in the one shared dot-files module. Sway, CUA Driver, and the Hermes seat use the one shared nine-module kit in `shared/modules`: `sway-seat`, `cua-driver`, `hermes-seat`, `hermes-sway-config`, `hermes-wayvnc-config`, `hermes-sway-seat`, `hermes-cua-driver-service`, `hermes-gateway-service`, and `local-ai-runtime`. The complete console source trees, including every existing Arch, Ubuntu, and Debian twin, are seated once; both profiles retain their module ids and order and resolve those ids through the shared fallback. GRUB branding, documentation, and MkDocs likewise use their existing shared seats, with no homesi copies. The shared MkDocs default remains `site_name: Home Server Documentation`, the same value the console, TV, and previous homesi copy used; there is no homesi-specific title override or unconsumed profile-values field. Birth still owns packages, accounts, and directories. Further fleet-wide consolidation of the remaining profile-local updater, Keyman, Rust toolchain, household-time, sbin, and system-packages modules is separate-lane debt; model-shelf remains local. Sudoers reads `shared/modules/sudoers/files_root/all/caduceus-owner` and `shared/modules/sudoers/files_root/all/caduceus-staff`, unchanged. The compiler considers `all/` plus the selected appliance pool; there is no `homesi/` sudoers pool and this profile declares no inheritance, so only those `all/` fragments are selected and no sudoers byte moves. Dropped modules: `homeconsole-network`, `arcadia-gui-runtime`, `console-session`, `retroarch-input`, `gamescope-backports-pin`, `sway-seat-arch-config`, `sway-seat-arch-wayvnc-config`, `homeconsole-netplan`, `homeconsole-sddm-autologin`, `homeconsole-sway-session`, `steam-device-rules`, `steam-polkit-helpers`. The update cleanup is retained as `homesi-update-runtime`; the visible owner desktop and netplan-dependent wait-online override are not part of the hidden Hermes seat. Caduceus uses the shared module and its `homesi` runtime input, selecting `caduceus-homesi-x86_64` with `profiles/homesi/index.yaml` as its profile source. face member inferred as Sway from the Hermes seat; the true face is the rung-4 portal; debt. No index-level face declaration is added. Model-shelf binds only loopback and private IPv4 LAN interfaces, permits only owner, exposes exactly `/home/owner/Models` and `/home/owner/Inbox`, and declares `systemctl restart smbd.service` as `command`/`act` with observation `{"kind":"module_changed_before_step"}`. That gate restarts only after an earlier change in the same module; `/etc/samba/smb.conf` remains Config-class, so a later owner-accepted file proposal does not itself run the restart step: standing fleet debt, not repaired here. HomeConsole's module ordering, on-body paths, and platform payloads remain; only the named source seats and species-neutral wording change.

HomeSI also links the shared `sunshine`, `sway`, `kitty`, `waybar`, and `chromium` jobs for the owner's full desktop, separate from Hermes's private seat. Sunshine uses wlroots capture, UPnP disabled and a LAN-origin Web UI, without a box firewall or bind narrowing; the household owns its router. The console's Sunshine bytes and TV's desktop bytes remain unchanged. The Debian owner Sway unit is gated by the HomeSI pool, and HomeSI-only service values enable its desktop, bar and Sunshine after Sway's display handoff. Birth supplies the binaries; Moonlight pairing and a born-box witness remain outside this source lane.

The package tool's apt `check` lane refreshes private lists and caches, suppresses host update hooks, simulates upgrades there, and removes the temporary state. Its `upgrade` lane is unchanged. This is distinct from the cached-only `update --check` query below.

The eleven bands execute in this order: `renew-self` → `migrations` → `stage-profile` → `pull-source` → `compare` → `install-packages` → `ratchet-binaries` → `backfill-files` → `restart-services` → `propose-edits` → `report-home`. Rolling-update source acquisition is a prelude outside this band walk; within the walk, profile staging precedes source routines and managed-file backfill precedes service activation.

`profile.json` and `config.json` are declarations; `/etc/appliance/ruyi.json` is engine-maintained observed state, not declaration or source authority.

## Repository map

```text
src/atoms/       primitive operations and the ask/do/attest surfaces
src/bands/       eleven charter-ordered execution faces
src/tools/       composition tools and re-export seats
profiles/        selected profile and module declarations
installer/       Harmonia build, status, and systemd unit control
docs/            architecture and engine notes
```


## Safe development commands

```bash
cargo run -p harmonia -- --help
cargo run -p harmonia -- explain --help
cargo run -p harmonia -- toolbelt --help
cargo build --locked
```

Apply-capable commands require explicit authorization and are outside this documentation's read-only smoke examples.

## Trace-free update query

Run `harmonia update --check` (exactly one `--check`; it cannot be combined with `--apply` or `--receipt-dir`). The command returns exactly one JSON line on stdout. Exit status `0` means pending apply work was observed; `7` means no pending work was observed; `1` means the query or its arguments failed. JSON fields include `ok`, `pending`, `pending_software_steps`, `config_proposals`, `first_missing_signal`, `index_refresh`, `freshness`, and `cached_index_roots_consulted`. On failure the pending/count fields are `null`, not zero. A successful query reports supported differing software/apply steps, including file convergence; each differing package upgrade step contributes one step, while package-check steps only observe explicitly scoped installed packages and never count as apply work. Empty or omitted package-check scope is allowed and observes no package. Configuration differences are proposals, deduplicated by target path, rather than pending apply work. Results are relative to cached indexes only: there is no index refresh or invented age threshold. Apt checks only the default `/var/lib/apt/lists` and `/var/lib/dpkg/status` state paths; custom apt state paths are unsupported. For package upgrades the roots reported are `/var/lib/apt/lists` and `/var/lib/dpkg/status` (apt), or the configured `pacman-conf DBPath/{sync,local}` (pacman); no roots are claimed when no package upgrade query ran. The command executes no Act/Prove path and writes no receipt, ledger, or other state. Release/artifact and Git transport observers are unsupported; unsupported or unobservable actuators fail with a named `first_missing_signal` and are never treated as current.
