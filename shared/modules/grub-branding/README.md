# GRUB branding

This shared Harmonia module converges the HOMESERVER boot theme where GRUB is installed. It validates `theme.txt` and its background image, atomically converges `GRUB_THEME` and `GRUB_GFXMODE=auto`, regenerates GRUB configuration only after material change on the actual root, and readbacks the result. On hosts without `/etc/default/grub` and without GRUB installed, it records an observed skip and does not install packages or write files. Fake roots never call a host GRUB generator.

The byte-for-byte payload is the theme source at `files_root/boot/grub/themes/homeserver/`. The deployables birth-lane twin is the Chrysalis GRUB theme module/payload under `/fulcrum/attachments/deployables/grub-theme/homeserver`; this Harmonia module maintains the same theme after birth.
