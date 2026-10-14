#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
import json
import subprocess
import sys


def ipc(*args):
    result = subprocess.run(
        ["swaymsg", "-r", *args], check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    return json.loads(result.stdout)

workspaces = ipc("-t", "get_workspaces")
current = next((row for row in workspaces if row.get("focused") is True), None)
if current is None:
    raise SystemExit("No focused Sway workspace")
current_name = current["name"]
workspace_names = {row["name"] for row in workspaces}
tree = ipc("-t", "get_tree")
windows = []


def walk(node, workspace=None):
    if node.get("type") == "workspace":
        workspace = node.get("name")
    children = list(node.get("nodes") or []) + list(node.get("floating_nodes") or [])
    if node.get("type") == "con" and not children:
        props = node.get("window_properties") or {}
        app_id = node.get("app_id") or ""
        window_class = props.get("class") or ""
        scratch = node.get("scratchpad_state") not in (None, "", "none")
        is_client = bool(app_id or window_class or node.get("window") is not None)
        if (workspace in workspace_names and workspace != current_name
                and is_client and not scratch and isinstance(node.get("id"), int)):
            windows.append(node["id"])
    for child in children:
        walk(child, workspace)


walk(tree)
try:
    for con_id in windows:
        selector = f'[con_id="{con_id}"] move container to workspace {json.dumps(current_name)}'
        subprocess.run(["swaymsg", selector], check=True, stdout=subprocess.DEVNULL)
finally:
    # Moving containers never relies on a guessed directional focus operation.
    subprocess.run(
        ["swaymsg", f"workspace {json.dumps(current_name)}"],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
PY
