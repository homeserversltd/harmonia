from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_tv_bitwarden_windows_float_in_hyprland_profile() -> None:
    rules = (ROOT / "profiles/tv/config/desktop-config/.config/hypr/windows.conf").read_text(encoding="utf-8")
    assert 'name = "bitwarden-float"' in rules
    assert 'match:class = "^(Bitwarden|bitwarden)$"' in rules
    bitwarden_block = rules.split('name = "bitwarden-float"', 1)[1]
    assert "float = true" in bitwarden_block
    assert "center = true" in bitwarden_block
