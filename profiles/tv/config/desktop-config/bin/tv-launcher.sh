#!/usr/bin/env sh
set -eu

home="${HOME:-$(getent passwd "$(id -un)" | cut -d: -f6)}"
state_home="${XDG_STATE_HOME:-$home/.local/state}"
cache_dir="$state_home/arch-tv-launcher"
mkdir -p "$cache_dir"

exec wofi \
  --show drun \
  --conf "$home/.config/wofi/config" \
  --style "$home/.config/wofi/style.css" \
  --cache-file "$cache_dir/wofi-drun-cache" \
  --sort-order default \
  --allow-images \
  --parse-search \
  --no-custom-entry
