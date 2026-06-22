#!/usr/bin/env sh
set -eu

home="${HOME:-$(getent passwd "$(id -un)" | cut -d: -f6)}"
state_home="${XDG_STATE_HOME:-$home/.local/state}"
cache_dir="$state_home/arch-tv-launcher"

update-desktop-database "$home/.local/share/applications" 2>/dev/null || true
rm -f "$home/.cache"/ksycoca6_* 2>/dev/null || true
kbuildsycoca6 --noincremental 2>/dev/null || true
rm -f "$cache_dir/wofi-drun-cache" 2>/dev/null || true