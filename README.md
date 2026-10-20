# Harmonia

Harmonia is a Rust appliance update engine. Each invocation follows one bounded ritual: **ask → compare → do → attest**.

## Engine shape

- Atoms are the engine floor. They host primitive operations and engines: comparison, command capture, AUR work, Git artifact work, systemd work, package work, declaration handling, and the embedded `declarations.json` authority.
- Tools compose those atom capabilities. The tool layer owns the managed-files dispatcher, ordered routines, virtual-environment work, household-time work, and artifact-lock compatibility work. Other tool paths are re-export seats for atom or tool implementations.
- Bands are the execution faces. A band calls tools, and tools call atoms. Bands do not call atoms directly, except `renew-self`, whose `replace_process` path is an intended direct atom exception.
- The `do` directory contains twenty true-named transactional atoms, one folder per atom. Mutating atoms require diff-minted `Authorization` and the exact `--apply-or-timer` invocation key.
- `src/atoms/attest/` redacts caller-injected secrets before serialization and forwards fields derived from the redacted value.

Profiles provide ordered module declarations and constants. Receipts are written for the run and its module and tool work.

HomeConsole selects package authority from the body's `/etc/os-release`: `package_authorities` is keyed by exact `ID`, with each key mapping to an `{ "os_family": ..., "package_manager": ... }` pair (for example, `ubuntu` maps to `ubuntu`/`apt`). An undeclared known ID such as `ubuntu` is refused rather than downgraded; only an unknown derivative may select the first declared `ID_LIKE` entry. Legacy profiles with one `package_authority` pair keep their existing behavior and do not read body OS identity. HomeConsole's `constants.packages_by_family` lowers to `constants.packages` for the resolved `arch` or `ubuntu` authority; Ubuntu platform fragments use Debian fragments only as per-filename fallback, with Ubuntu taking same-name precedence, while `all/` and the `homeconsole` behavioral pool stay unchanged. This changes package/backend and fragment selection only; it moves no operator configuration or settings.

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
