# Harmonia profiles

Profiles declare one appliance identity and an ordered module spine. The selected profile supplies module declarations and constants; execution remains inside the one `ask → compare → do → attest` ritual.

Profile modules resolve their tool usage through `src/tools/index.json`. Mutating work is admitted only through the twenty transactional do atoms and both keys: diff-minted `Authorization` plus `--apply-or-timer`.

The ten execution bands are entered in charter order, with `restart-services` before `backfill-files`. A closing census with zero missing signals is reported as `first_missing_signal=none`.

The profile and module paths are checkable in the repository, for example `profiles/homeconsole/index.json` and `profiles/homeconsole/modules/`.

## One-level overlays

An overlay index may declare `"extends": "<base-profile-id>"` and optionally an ordered `"excludes": ["<base-module-id>", ...]` list. Exclusions filter only modules inherited from the one-level base; surviving base modules stay in base order, followed by the overlay's own modules in their declared order. Exclusions are validated first: every excluded ID must be present in the full base module list and must not be declared by the overlay. Unknown IDs refuse as `profile-extends-exclude-unknown`; overlay-owned IDs refuse as `profile-extends-exclude-declared`. The unchanged duplicate-module refusal then checks the full base list against overlay modules before filtering, so exclusions cannot silently shadow overlay-owned IDs or hide another duplicate.

`excludes` is invalid without a non-null `extends`, including when it is explicitly `[]`; the refusal is `profile-extends-exclude-without-extends`. Base indexes cannot declare their own exclusions. An omitted `excludes` field preserves the prior profile behavior and output; when declared, `excluded_module_ids` records the declared list (including an explicit empty list).

Copy-mode molt and capsule materialize the filtered module union, remove active `extends` and `excludes`, and preserve lineage as inert `source_extends` and, when declared, `source_excludes`. These lineage fields do not trigger another base lookup. Unknown profile-index fields remain preserved.
