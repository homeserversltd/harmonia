#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 forward|backward" >&2
  exit 1
fi
command="$1"
case "$command" in
  forward|backward) ;;
  *)
    echo "Invalid argument: $command" >&2
    echo "Usage: $0 forward|backward" >&2
    exit 1
    ;;
esac

python3 - "$command" <<'PY'
import json
import subprocess
import sys

command = sys.argv[1]

def ipc(*args):
    result = subprocess.run(
        ["swaymsg", "-r", *args], check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    return json.loads(result.stdout)

tree = ipc("-t", "get_tree")
workspaces = ipc("-t", "get_workspaces")
outputs = ipc("-t", "get_outputs")
workspace_by_name = {row["name"]: row for row in workspaces}
active_outputs = {row["name"] for row in outputs if row.get("active") is True}
windows = []

def walk(node, workspace=None, output=None):
    kind = node.get("type")
    if kind == "output":
        output = node.get("name")
    elif kind == "workspace":
        workspace = node.get("name")

    children = list(node.get("nodes") or []) + list(node.get("floating_nodes") or [])
    if kind == "con" and not children:
        props = node.get("window_properties") or {}
        app_id = node.get("app_id") or ""
        window_class = props.get("class") or ""
        row = workspace_by_name.get(workspace)
        scratch = node.get("scratchpad_state") not in (None, "", "none")
        is_client = bool(app_id or window_class or node.get("window") is not None)
        hidden_here = bool(row and row.get("visible") is True and node.get("visible") is False)
        if row and output in active_outputs and is_client and not scratch and not hidden_here:
            num = row.get("num", -1)
            if not isinstance(num, int) or num < 0:
                num = 2**31 - 1
            rect = node.get("rect") or {}
            windows.append({
                "id": node.get("id"),
                "workspace": workspace,
                "workspace_num": num,
                "output": output,
                "y": rect.get("y", 0),
                "x": rect.get("x", 0),
                "focused": node.get("focused") is True,
            })
    for child in children:
        walk(child, workspace, output)

walk(tree)
windows = [row for row in windows if isinstance(row.get("id"), int)]
windows.sort(key=lambda row: (
    row["workspace_num"], row["workspace"], row["output"],
    row["y"], row["x"], row["id"],
))
if not windows:
    raise SystemExit(0)

active_id = next((row["id"] for row in windows if row["focused"]), None)
active_index = next((i for i, row in enumerate(windows) if row["id"] == active_id), -1)
if active_index >= 0:
    index = active_index
elif command == "forward":
    index = -1
else:
    index = 0
index = (index + 1) % len(windows) if command == "forward" else (index - 1) % len(windows)
target = windows[index]

def run_sway(command_text):
    subprocess.run(["swaymsg", command_text], check=True, stdout=subprocess.DEVNULL)

run_sway(f"focus output {json.dumps(target['output'])}")
run_sway(f"workspace {json.dumps(target['workspace'])}")
run_sway(f'[con_id="{target["id"]}"] focus')
PY
