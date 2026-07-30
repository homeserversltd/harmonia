# Chromium

This is Harmonia's single shared Chromium configuration module. Profiles consume it by listing the module id `chromium`; the resolver selects this canonical `modules/chromium` seat when no profile-local module exists.

Harmonia owns Chromium configuration and launch flags only. It does not install, remove, or upgrade the Chromium package. Each body's deployable provides the package at birth.

A body that needs additional flags or policy uses a body-local overlay in its private Harmonia Monad profile. The overlay may add the body's delta, but it must not copy, fork, or replace this shared module. Public, common Chromium state remains here so all consumers converge from one source.
