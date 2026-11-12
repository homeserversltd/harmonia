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

The TV profile is Debian 13 HomeTV: profile id `hometv`, `debian`/`apt`, Sway, and the `hometv` dotfile pool. Its 21 maintenance modules follow the named birth-intent order, with `system-packages` first to upgrade already-installed apt packages, `mkdocs` beside `documentation`, and `dot-files` last. Package-only birth intents such as `kde-apps` and `network-applet` stay current through `system-packages`; birth-only identity, installation, and boot handoffs gain no maintenance module. Harmonia's engine owns its own currentness and birth owns its scheduler; the profile adds neither a scheduler nor configuration-write authority. The separate Caduceus source lane must align its Beam TV face mapping (`routes/beam/index.rs`) and its Ruyi face allowance (`schema/caduceus.ruyi.v1.json` and `routes/ruyi/index.rs`) with Sway; this Harmonia cut does not alter those Caduceus readers. Configuration changes are per-item interactables. Module manifests may declare an optional top-level `authorities` list of OS families; absent means all. Projection interprets it once, and inspection labels a nonmatching module `authority-excluded`. Only HomeConsole's Netplan module declares it (`["ubuntu"]`), so Debian never projects that Ubuntu configuration.

HomeSuperintelligence (`homesi`) is the Debian 13 appliance: the household's Hermes on a local model, Caduceus controls, `agora.home.arpa`, documentation, and the private `models` and `inbox` Samba shelves at `homesi.home.arpa`. Its profile declares only `debian`/`apt`, retains the console's non-gaming capabilities in their original order, and uses its own pool in the one shared dot-files module. Sway, CUA Driver, and the Hermes seat use the one shared nine-module kit in `shared/modules`: `sway-seat`, `cua-driver`, `hermes-seat`, `hermes-sway-config`, `hermes-wayvnc-config`, `hermes-sway-seat`, `hermes-cua-driver-service`, `hermes-gateway-service`, and `local-ai-runtime`. The complete console source trees, including every existing Arch, Ubuntu, and Debian twin, are seated once; both profiles retain their module ids and order and resolve those ids through the shared fallback. GRUB branding, documentation, and MkDocs likewise use their existing shared seats, with no homesi copies. The shared MkDocs default remains `site_name: Home Server Documentation`, the same value the console, TV, and previous homesi copy used; there is no homesi-specific title override or unconsumed profile-values field. Birth still owns packages, accounts, and directories. Further fleet-wide consolidation of the remaining profile-local updater, Keyman, Rust toolchain, household-time, sbin, and system-packages modules is separate-lane debt; model-shelf remains local. Sudoers reads `shared/modules/sudoers/files_root/all/caduceus-owner` and `shared/modules/sudoers/files_root/all/caduceus-staff`, unchanged. The compiler considers `all/` plus the selected appliance pool; there is no `homesi/` sudoers pool and this profile declares no inheritance, so only those `all/` fragments are selected and no sudoers byte moves. Dropped modules: `homeconsole-network`, `arcadia-gui-runtime`, `retroarch-input`, `sway-seat-arch-config`, `sway-seat-arch-wayvnc-config`, `homeconsole-netplan`, `homeconsole-sddm-autologin`, `homeconsole-sway-session`. The update cleanup is retained as `homesi-update-runtime`; the visible owner desktop and netplan-dependent wait-online override are not part of the hidden Hermes seat. Caduceus uses the shared module and its `homesi` runtime input, selecting `caduceus-homesi-x86_64` with `profiles/homesi/index.yaml` as its profile source. face member inferred as Sway from the Hermes seat; the true face is the rung-4 portal; debt. No index-level face declaration is added. Model-shelf binds only loopback and private IPv4 LAN interfaces, permits only owner, exposes exactly `/home/owner/Models` and `/home/owner/Inbox`, and declares `systemctl restart smbd.service` as `command`/`act` with observation `{"kind":"module_changed_before_step"}`. That gate restarts only after an earlier change in the same module; `/etc/samba/smb.conf` remains Config-class, so a later owner-accepted file proposal does not itself run the restart step: standing fleet debt, not repaired here. HomeConsole's module ordering, on-body paths, and platform payloads remain; only the named source seats and species-neutral wording change.

HomeSI uses the shared TV desktop jobs and the profile-local `sunshine-homesi` job, separate from Hermes's private seat. Its distinct module id avoids an ambiguous private/shared Sunshine source at birth while leaving HomeConsole's `sunshine` job unchanged. Sunshine uses wlroots capture, UPnP disabled and a LAN-origin Web UI; the household owns its router. `sunshine-homesi` maintains the one owner Sway session entry and its supervisor unit and session wiring; the shared `screen-supervisor` moves the session between outputs and restarts Sunshine after a switch, while Hermes defaults to WayVNC. Harmonia places the files without enabling or starting the desktop, Sunshine or supervisor. Birth supplies the binaries and SDDM autologin; Caduceus starts SDDM and Sunshine. Moonlight pairing and a born-box witness remain outside this source lane.

HomeSI's local `model-shelf` keeps `/etc/nftables.conf` as a Config target beside `smb.conf`, comparing it against birth's exact SMB/NetBIOS LAN-gate bytes. Drift becomes an interactable; only the owner's acceptance writes the proposed file. The `module_changed_before_step`-gated `systemctl reload nftables.service` step runs only when the module itself changed in that press, never for a proposal alone. Reload after an accepted proposal, like the existing `smbd.service` restart, waits on engine lane `contract-harmonia-accepted-config-proposal-runs-its-module-act-20261023`; until then `nftables.service` loads the file at boot. This is the existing SMB gate, not a Sunshine firewall.

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

Run `harmonia update --check` for one JSON answer describing pending updates, configuration proposals, and unobserved steps; it observes readable file steps, refreshes package lists before checking upgrades, and compares our releases and source checkouts against the house. It does not apply updates or write Harmonia receipts or state: apt refreshes its system lists, while pacman refreshes a temporary database rather than the system sync database; exit `0` means pending, `7` means no pending work was observed, and `1` means the query or its arguments failed.
