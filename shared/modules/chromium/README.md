# Chromium

This is the single shared browser/Chromium configuration seat. Selection is explicit opt-in by profile module listing. Profiles without the `chromium` module remain non-tenants.

Harmonia owns Chromium configuration and launch flags; it does not install browsers.

Harmonia never closes, signals or relaunches Chrome; a Chromium flag or policy change takes effect at the browser's own next start (`pali:update-engine-new-binary-restarts-the-process-law`).
