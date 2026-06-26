from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REBIS = ROOT / "profiles/rebis"
WAYBAR = REBIS / "modules/rebis-waybar-config/files/waybar"


def test_rebis_profile_owns_waybar_config_through_module_path() -> None:
    profile = (REBIS / "index.json").read_text(encoding="utf-8")
    sidecar = (REBIS / "modules/rebis-waybar-config/sidecar.json").read_text(encoding="utf-8")
    assert '"id": "rebis"' in profile
    assert '"rebis-waybar-config"' in profile
    assert '"source_dir": "profiles/rebis/modules/rebis-waybar-config/files/waybar"' in sidecar
    assert '".config/waybar/waybar.conf"' in sidecar
    assert '"bin/waybar-clipboard.sh"' in sidecar


def test_rebis_waybar_preserves_local_land_guard_and_laptop_controls() -> None:
    config = (WAYBAR / ".config/waybar/waybar.conf").read_text(encoding="utf-8")
    style = (WAYBAR / ".config/waybar/style.css").read_text(encoding="utf-8")
    assert '"custom/land-guard"' in config
    assert '"exec": "$HOME/bin/rebis status"' in config
    assert '"on-click": "$HOME/bin/rebis toggle"' in config
    assert '"on-click-right": "$HOME/bin/rebis receipt"' in config
    assert '"custom/clipboard"' in config
    assert '"backlight"' in config
    assert '"battery"' in config
    assert '"custom/printer"' in config
    assert '#custom-land-guard.local' in style
    assert '#custom-land-guard.locked' in style
    assert '#custom-land-guard.broken' in style
    assert '#custom-land-guard.pending' in style


def test_rebis_waybar_helper_scripts_are_local_and_executable_intent() -> None:
    clipboard = (WAYBAR / "bin/waybar-clipboard.sh").read_text(encoding="utf-8")
    meter = (WAYBAR / "bin/waybar-meter.sh").read_text(encoding="utf-8")
    assert "ydotool" in clipboard
    assert "clipman pick --tool wofi" in clipboard
    assert "CPU $(bars_for" in meter
    assert "RAM $(bars_for" in meter
    assert "TMP $(bars_for" in meter
