# Chromium

This is the single shared browser/Chromium configuration seat. Selection is explicit opt-in by profile module listing. Profiles without the `chromium` module remain non-tenants.

Harmonia owns Chromium configuration and launch flags; it does not install browsers.

When a package upgrade replaces `/usr/lib/chromium/chromium` under a running desktop browser, the `restart-stale-browser` step prefers a live Sway session and otherwise uses the owner's Hyprland session to close that browser cleanly and relaunch it with `--restore-last-session`. The check is the running process itself: its exe link must not read `(deleted)`. Automation browsers (Playwright, DevTools, headless, any `--user-data-dir`) are never touched. Law: `pali:update-engine-new-binary-restarts-the-process-law`.
