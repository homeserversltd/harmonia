from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_tv_bitwarden_windows_float_in_hyprland_profile() -> None:
    rules = (ROOT / "profiles/tv/config/desktop-config/.config/hypr/windows.conf").read_text(encoding="utf-8")
    assert 'name = "bitwarden-float"' in rules
    assert 'match:class = "^(Bitwarden|bitwarden)$"' in rules
    assert 'name = "bitwarden-title-float"' in rules
    assert 'match:title = "^Bitwarden$"' in rules
    assert 'name = "bitwarden-chrome-extension-float"' in rules
    assert 'match:class = "^chrome-nngceckbapebfimnlniiiahkandclblb-.*$"' in rules
    bitwarden_block = rules.split('name = "bitwarden-float"', 1)[1]
    assert "float = true" in bitwarden_block
    assert "center = true" in bitwarden_block
    title_block = rules.split('name = "bitwarden-title-float"', 1)[1]
    assert "float = true" in title_block
    assert "center = true" in title_block
