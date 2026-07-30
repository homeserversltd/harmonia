# Dotfiles: two pools

There are exactly two dotfile pools.

1. The TV set is the one canonical pool for front-facing Arch machines: TV, laptop, and workstation. Every such body receives the same complete `.zshrc`; there is no loader, sidecar, per-body variant, or template.
2. The homeserver set is the one canonical pool for backend Debian servers. Every backend body receives the same captured `.zshrc`, `.aliases`, `.functions`, and `.profile` bytes. No Arch profile references this pool.

Deployables and harmonia-monad dereference these pools; they do not carry variants. Application keys and credential exports never belong in any rc payload. Machine-local shell credentials, when needed, live only in the untracked `~/.zshrc.secrets` file sourced by the canonical Arch `.zshrc`. Every file converge step keeps `backup_existing: true`.

Declaration: `pali:dotfiles-two-pool-law`.
