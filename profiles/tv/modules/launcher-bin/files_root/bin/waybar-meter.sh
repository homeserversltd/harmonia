#!/usr/bin/env bash
set -euo pipefail

kind="${1:-}"

bars_for() {
  local pct="${1%.*}"
  local filled=$(( (pct + 24) / 25 ))
  (( filled < 0 )) && filled=0
  (( filled > 4 )) && filled=4
  local out=""
  for i in 1 2 3 4; do
    if (( i <= filled )); then out+="▰"; else out+="▱"; fi
  done
  printf '%s' "$out"
}

class_for() {
  local pct="${1%.*}"
  if (( pct >= 85 )); then printf high
  elif (( pct >= 60 )); then printf medium
  else printf low
  fi
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

temp_c() {
  local hwmon input label zone type raw

  # Prefer CPU package temperature from hwmon/coretemp.
  for hwmon in /sys/class/hwmon/hwmon*; do
    [[ -r "$hwmon/name" ]] || continue
    [[ "$(<"$hwmon/name")" == "coretemp" ]] || continue
    for label in "$hwmon"/temp*_label; do
      [[ -r "$label" ]] || continue
      if [[ "$(<"$label")" == "Package id 0" ]]; then
        input="${label%_label}_input"
        [[ -r "$input" ]] && awk '{printf "%d", ($1 + 500) / 1000}' "$input" && return 0
      fi
    done
    input="$hwmon/temp1_input"
    [[ -r "$input" ]] && awk '{printf "%d", ($1 + 500) / 1000}' "$input" && return 0
  done

  # Fallback to thermal zone exposed by the kernel.
  for zone in /sys/class/thermal/thermal_zone*; do
    [[ -r "$zone/type" && -r "$zone/temp" ]] || continue
    type="$(<"$zone/type")"
    if [[ "$type" == "x86_pkg_temp" || "$type" == "acpitz" ]]; then
      raw="$(<"$zone/temp")"
      awk -v t="$raw" 'BEGIN {printf "%d", (t + 500) / 1000}'
      return 0
    fi
  done

  return 1
}

temp_class_for() {
  local c="$1"
  if (( c >= 90 )); then printf high
  elif (( c >= 75 )); then printf medium
  else printf low
  fi
}

case "$kind" in
  cpu)
    read -r _ u1 n1 s1 i1 w1 irq1 soft1 steal1 _ < /proc/stat
    idle1=$((i1 + w1))
    total1=$((u1 + n1 + s1 + i1 + w1 + irq1 + soft1 + steal1))
    sleep 0.25
    read -r _ u2 n2 s2 i2 w2 irq2 soft2 steal2 _ < /proc/stat
    idle2=$((i2 + w2))
    total2=$((u2 + n2 + s2 + i2 + w2 + irq2 + soft2 + steal2))
    dt=$((total2 - total1)); di=$((idle2 - idle1))
    pct=0
    if (( dt > 0 )); then pct=$(( (100 * (dt - di)) / dt )); fi
    text="CPU $(bars_for "$pct")"
    class=$(class_for "$pct")
    tooltip="CPU: ${pct}%"
    ;;
  ram|memory)
    read -r total used _ < <(free -m | awk 'NR==2{print $2, $3}')
    pct=$(( used * 100 / total ))
    text="RAM $(bars_for "$pct")"
    class=$(class_for "$pct")
    tooltip="RAM: ${pct}% (${used}/${total} MiB)"
    ;;
  disk|root)
    read -r used total pct < <(df -Pm / | awk 'NR==2{gsub(/%/,"",$5); print $3, $2, $5}')
    text="DSK $(bars_for "$pct")"
    class=$(class_for "$pct")
    tooltip="Disk /: ${pct}% (${used}/${total} MiB)"
    ;;
  temp|temperature)
    if c=$(temp_c); then
      # Scale 30–100°C to the four-bar gauge.
      pct=$(( (c - 30) * 100 / 70 ))
      (( pct < 0 )) && pct=0
      (( pct > 100 )) && pct=100
      text="TMP $(bars_for "$pct")"
      class=$(temp_class_for "$c")
      tooltip="CPU package temperature: ${c}°C"
    else
      text="TMP ????"; class="high"; tooltip="No temperature sensor found"
    fi
    ;;
  *)
    text="????"; class="low"; tooltip="usage: waybar-meter.sh cpu|ram|temp|disk"
    ;;
esac

printf '{"text":"%s","tooltip":"%s","class":"%s"}\n' \
  "$(json_escape "$text")" "$(json_escape "$tooltip")" "$(json_escape "$class")"
