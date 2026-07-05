from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WINDOWS = ROOT / "profiles/tv/modules/desktop-config-payload/files_root/hyprland/.config/hypr/windows.conf"
AUTOSTART = ROOT / "profiles/tv/modules/desktop-config-payload/files_root/hyprland/.config/hypr/autostart.conf"


def test_tv_bitwarden_windows_float_in_hyprland_profile() -> None:
    rules = WINDOWS.read_text(encoding="utf-8")
    assert "windowrule = float 1, match:class ^(Bitwarden|bitwarden)$" in rules
    assert "windowrule = center 1, match:class ^(Bitwarden|bitwarden)$" in rules
    assert "windowrule = float 1, match:title ^Bitwarden$" in rules
    assert "windowrule = center 1, match:title ^Bitwarden$" in rules
    assert "windowrule = float 1, match:class ^chrome-nngceckbapebfimnlniiiahkandclblb-.*$" in rules
    assert "windowrule = center 1, match:initial_class ^chrome-nngceckbapebfimnlniiiahkandclblb-.*$" in rules
    assert "bitwarden-popup-float.sh" not in rules
    assert "windowrulev2" not in rules


def test_tv_hyprland_autostart_owns_bitwarden_listener() -> None:
    rules = WINDOWS.read_text(encoding="utf-8")
    autostart = AUTOSTART.read_text(encoding="utf-8")
    assert "bitwarden-popup-float.sh" in autostart
    assert "bitwarden-popup-float.sh" not in rules
    assert "windowrulev2" not in rules
