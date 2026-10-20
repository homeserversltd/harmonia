# HomeConsole desktop upkeep

## Arcadia OS Ubuntu underlay

The existing `package_authorities.ubuntu` selector remains the source of the Ubuntu family. Ubuntu-specific payload bytes live in `platform/ubuntu/` fragments and are compiled per target with `files` / `compile-fragments`; they are not embedded as program strings in manifests. Platform fragments are active only for steps that explicitly compile them. The baseline `sunshine` and `retroarch-input` manifests and their original `files_root/home/owner/...` payloads remain unchanged; this underlay does not convert them to Ubuntu no-claims.

The underlay offers these Ubuntu placements:

| Plane | Target | Mode / ownership | Source |
|---|---|---|---|
| Config proposal | `/etc/netplan/00-installer-config.yaml` | `0600`; preserve existing ownership, or inherit the existing parent (`root:root`) if absent | `modules/homeconsole-netplan/files_root/netplan/platform/ubuntu/00-installer-config.yaml` |
| Config proposal | `/etc/sddm.conf.d/10-homeconsole-autologin.conf` | `0644`; preserve existing ownership, or inherit the existing parent (`root:root`) if absent | `modules/homeconsole-sddm-autologin/files_root/sddm/platform/ubuntu/10-homeconsole-autologin.conf` |
| Software | `/usr/share/wayland-sessions/homeconsole-sway.desktop` | `0644 root:root` | `modules/homeconsole-sway-session/files_root/session/platform/ubuntu/homeconsole-sway.desktop` |
| Software | `/usr/lib/udev/rules.d/60-steam-input.rules` | `0644 root:root` | `modules/steam-device-rules/files_root/input/platform/ubuntu/60-steam-input.rules` |
| Software | `/usr/lib/udev/rules.d/60-steam-vr.rules` | `0644 root:root` | `modules/steam-device-rules/files_root/vr/platform/ubuntu/60-steam-vr.rules` |
| Software | `/usr/bin/steamos-polkit-helpers/steamos-update` | `0755 root:root` | `modules/steam-polkit-helpers/files_root/update/platform/ubuntu/steamos-update` |
| Software | `/usr/bin/steamos-select-branch` | `0755 root:root` | `modules/steam-polkit-helpers/files_root/select-branch/platform/ubuntu/steamos-select-branch` |
| Software | `/usr/bin/steamos-session-select` | `0755 root:root` | `modules/steam-polkit-helpers/files_root/session-select/platform/ubuntu/steamos-session-select` |
| Software | `/usr/local/bin/hermes` | `0755 root:root` | Arch original and `modules/hermes-seat/files_root/fragments/hermes-wrapper/platform/ubuntu/hermes` |
| Software | `/usr/local/libexec/sway-seat/sway-seat-wait-ready` | `0755 root:root` | Arch original and `modules/sway-seat/files_root/fragments/ready-helper/platform/ubuntu/sway-seat-wait-ready` |
| Software | `/usr/local/libexec/sway-seat/sway-seat-screen-supervisor` | `0755 root:root` | Arch original and `modules/cua-driver/files_root/fragments/screen-supervisor/platform/ubuntu/sway-seat-screen-supervisor` |
| Config proposal | `/home/hermes/.config/sway/config` | `0644 hermes:hermes` when absent under the birth-owned home; preserve ownership when present | `modules/hermes-sway-config/files_root/config/platform/ubuntu/config` |
| Config proposal | `/home/hermes/.config/wayvnc/config` | `0600 hermes:hermes` when absent under the birth-owned home; preserve ownership when present | `modules/hermes-wayvnc-config/files_root/config/platform/ubuntu/config` |
| Config proposal | `/home/hermes/.config/systemd/user/sway-seat.service` | `0644 hermes:hermes` when absent under the birth-owned home; preserve ownership when present | `modules/hermes-sway-seat/files_root/sway-seat/platform/ubuntu/sway-seat.service` |
| Config proposal | `/home/hermes/.config/systemd/user/wayvnc-seat.service` | `0644 hermes:hermes` when absent under the birth-owned home; preserve ownership when present | `modules/hermes-sway-seat/files_root/wayvnc-seat/platform/ubuntu/wayvnc-seat.service` |
| Config proposal | `/home/hermes/.config/systemd/user/cua-driver.service` | `0644 hermes:hermes` when absent under the birth-owned home; preserve ownership when present | `modules/hermes-cua-driver-service/files_root/service/platform/ubuntu/cua-driver.service` |
| Config proposal | `/home/hermes/.config/systemd/user/hermes-gateway.service` | `0644 hermes:hermes` when absent under the birth-owned home; preserve ownership when present | `modules/hermes-gateway-service/files_root/service/platform/ubuntu/hermes-gateway.service` |

All new Ubuntu Config targets above use `backup_existing=true` and produce proposals rather than silently applying operator configuration. The Netplan payload replaces the target contents with the global `NetworkManager` renderer and DHCP on wired `e*` interfaces; it does not remove the target. The SDDM proposal selects the existing staff-owned `steam-gamescope-wayland.desktop`, sets `User=owner` and `Relogin=true`, and uses the existing owner login identity without adding a `steam` account. The existing Steam desktop entry and its `Exec=/usr/local/sbin/agathodaimon/cli.py console session` remain unchanged; Gamescope flags and sentinels remain staff-owned. The separate Sway session is ordinary Software under `/usr/share/wayland-sessions`, not mislabeled Config.

The session and branch helpers now hand off to the sbin staff CLI. The Ubuntu helper executable lines are:

- `steamos-update`: `printf '%s\n' 'Arcadia OS: steamos-update is unavailable.' >&2; exit 7`
- `steamos-select-branch`: `exec /usr/local/sbin/agathodaimon/cli.py console select-branch "$@"`
- `steamos-session-select`: `exec /usr/local/sbin/agathodaimon/cli.py console session-select "$@"`

The current Dove supplied sbin `main` commit `c78f49d98ec8ee30be016bd6adbb573ca3a69d1c`; the parent verified it with `ls-remote`. Both staff calls forward their original arguments with `"$@"`. Only the `steamos-update` refusal line awaits the future `harmonia --check` lane. No elevation or sudoers grant is defined or added.

The Ubuntu Sway seat runs under Hermes's lingering user manager with `WLR_BACKENDS=headless`, a private `%t` runtime, and no `seat0` or VT binding. WayVNC binds `127.0.0.1:5900`. The owner desktop entry executes `/usr/bin/sway -c /etc/sway/config`; birth must provide this distro desktop configuration at `/etc/sway/config`. The owner desktop does not read the legacy headless `/home/owner/.config/sway/config` or launch the Hermes Sway supervisor/session helper. The Sway screen supervisor, readiness helper, CUA Driver user unit, and Hermes gateway unit use the Hermes home/runtime and do not import `/run/sway-seat/session.env` or any owner socket. The Ubuntu Hermes launcher does not import the shared owner session environment or force `HERMES_HOME`; its final line is `exec /opt/hermes/venv/bin/hermes "$@"` and respects the invoking caller's `HOME` and `HERMES_HOME`. The gateway unit keeps its own `HERMES_HOME=/home/hermes/.hermes` and private Wayland runtime while invoking the venv binary directly.

The original `packages_by_family` arrays are unchanged. The `system-packages` and `homeconsole-update-runtime` modules remain at their baseline profile positions with their existing package, update, and cleanup behavior; this underlay does not remove or redesign them. Birth owns the `hermes` system user and `/home/hermes`, its config/runtime directories, the lingering marker and XDG runtime, and user-unit enable links. Birth must provide the parents of absent Config proposals before convergence: `/etc/netplan`, `/etc/sddm.conf.d`, `/home/hermes/.config/sway`, `/home/hermes/.config/wayvnc`, and `/home/hermes/.config/systemd/user`. It must also provide the Software parents `/usr/bin/steamos-polkit-helpers`, `/usr/bin`, `/usr/lib/udev/rules.d`, `/usr/share/wayland-sessions`, `/usr/local/bin`, and `/usr/local/libexec/sway-seat` when absent. Birth owns the existing owner console login identity, required desktop/runtime dependencies, the `/home/hermes/.hermes` home, private `/run/user/<hermes-uid>` runtime, and activation links for `sway-seat.service`, `wayvnc-seat.service`, `cua-driver.service`, and `hermes-gateway.service`. The new underlay modules do not create accounts or call systemctl start/enable/restart; the baseline package and update modules remain in their existing profile order.

The two controller rule files are the unmodified raw files from `ValveSoftware/steam-devices`, pinned to commit `22ec85e5ff5ea2e15c56d71a41bcbef46356cd60`:

- `60-steam-input.rules` — SHA-256 `284930f83cf8fde8a247057d46f48083d5e4aefc23a54310db02cfc2dbe42e50`
- `60-steam-vr.rules` — SHA-256 `e12cda322c9f5f7c6336d8048264877690d3488e1b0f1b750cce18a836160420`

Raw source URLs:

- `https://raw.githubusercontent.com/ValveSoftware/steam-devices/22ec85e5ff5ea2e15c56d71a41bcbef46356cd60/60-steam-input.rules`
- `https://raw.githubusercontent.com/ValveSoftware/steam-devices/22ec85e5ff5ea2e15c56d71a41bcbef46356cd60/60-steam-vr.rules`

## Existing owner-seat payloads

The original owner-seat Sway, WayVNC, Sunshine, and RetroArch source files remain at their baseline paths. The Arch-specific Sway/WayVNC fragments are supplemental copies; the Ubuntu path uses the Hermes-private configuration and helpers. The original `sunshine` and `retroarch-input` manifests retain their baseline owner-path declarations and are not converted into Ubuntu no-claims. Shared helper source files remain unchanged; the Arch-selected copies preserve the old owner-session behavior, while Ubuntu selects the Hermes-private readiness helper and supervisor. The generic Hermes ladder retains its source-root and launcher presence checks but no longer probes `constants.hermes_home`; that original constant remains `/home/owner/.hermes`. Ubuntu's `/home/hermes/.hermes` and required parent directories are birth-owned and compiler-observed by the changed placement steps; no OS metadata is added to make generic runtime checks conditional. The `system-packages` and `homeconsole-update-runtime` modules remain in baseline order with their existing package, update, and cleanup declarations unchanged.

These owner-seat targets and their source paths remain intact. `Arch-selected` marks underlay fragments used by the Arch overlay; `Baseline module` marks the unchanged Sunshine and RetroArch declarations:

| Scope | Owner target | Mode / ownership | Source path |
|---|---|---|---|
| Arch-selected Config proposal | `/home/owner/.config/sway/config` | `0644 owner:owner` when absent under the birth-owned home; preserve ownership when present | `modules/sway-seat-arch-config/files_root/config/platform/arch/config` |
| Arch-selected Config proposal | `/home/owner/.config/wayvnc/config` | `0600 owner:owner` when absent under the birth-owned home; preserve ownership when present | `modules/sway-seat-arch-wayvnc-config/files_root/config/platform/arch/config` |
| Arch-selected Config proposal | `/home/owner/.config/systemd/user/sway-seat.service` | `0644 owner:owner` when absent under the birth-owned home; preserve ownership when present | `modules/sway-seat/files_root/fragments/owner-sway-unit/platform/arch/sway-seat.service` |
| Arch-selected Config proposal | `/home/owner/.config/systemd/user/wayvnc-seat.service` | `0644 owner:owner` when absent under the birth-owned home; preserve ownership when present | `modules/sway-seat/files_root/fragments/owner-wayvnc-unit/platform/arch/wayvnc-seat.service` |
| Baseline module | `/home/owner/.config/sunshine/sunshine.conf` | `0644 owner:owner` when absent under the birth-owned home; preserve ownership when present | `modules/sunshine/files_root/home/owner/.config/sunshine/sunshine.conf` |
| Baseline module | `/home/owner/.config/retroarch/autoconfig/udev/Sony Interactive Entertainment DualSense Wireless Controller.cfg` | `0644 owner:owner` when absent under the birth-owned home; preserve ownership when present | `modules/retroarch-input/files_root/home/owner/.config/retroarch/autoconfig/udev/Sony Interactive Entertainment DualSense Wireless Controller.cfg` |
| Baseline module | `/home/owner/.config/retroarch/autoconfig/udev/Sunshine PS5 (virtual) pad.cfg` | `0644 owner:owner` when absent under the birth-owned home; preserve ownership when present | `modules/retroarch-input/files_root/home/owner/.config/retroarch/autoconfig/udev/Sunshine PS5 (virtual) pad.cfg` |
| Arch-selected Config proposal | `/etc/tmpfiles.d/sway-seat.conf` | `0644 root:root` | `modules/sway-seat/files_root/fragments/tmpfiles/platform/arch/sway-seat.conf` |
| Arch-selected Software | `/usr/local/libexec/sway-seat/sway-seat-session` | `0755 root:root` | `modules/sway-seat/files_root/fragments/session-helper/platform/arch/sway-seat-session` |

No live-body deployment or runtime proof is asserted here.
