# desktop-config-payload

This is the one public homeserver dotfile pool for Debian backend servers. The canonical files live under `files_root/shell-rc/` and converge to `/home/owner` with `backup_existing: true`. The module performs file maintenance only: it installs no packages, writes no keys, and restarts no services.

## Provenance

The pool was captured read-only from the living `owner` home on the homeserver. The legacy `HOMESERVERSLTD/homeserver` initialization tree was read through a blob-filtered sparse checkout as quarry. Live bytes win every disagreement.

Material quarry comparison:

- `.zshrc`, `.aliases`, `.functions`, `.inputrc`, and `.nanorc` already byte-match the living files.
- The living `.profile` adds the Atuin environment hook that the quarry copy lacks; the living file is retained.
- The living `.tmux.conf` retains the static status IP placeholder and a commented dynamic-IP alternative. Quarry `tmux.conf` enables the dynamic form. Quarry `legacy-console-capture.conf` is a separate damaged console capture with pasted prompt text, extra tool-specific pane settings, and a trailing `%`; neither quarry variant overrides the living homeserver file.
- `.bashrc`, `.bash-preexec.sh`, `.lesskey`, `.enhanced_less_config`, and `.gitconfig` exist on the living body but not as canonical files in the quarry initialization tree. The quarry installer only generated the less configuration procedurally.
- The living `.zshrc` currently contains no `.zshrc.secrets` source hook, and no hook is invented here because this pool is byte-identical to the living set. Secret bytes remain forbidden; if a hook is introduced, it may point only to the untracked `~/.zshrc.secrets` file.

Noise, histories, receipts, and per-body variants are outside this pool.
