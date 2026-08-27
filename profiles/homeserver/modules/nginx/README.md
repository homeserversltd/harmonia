# Nginx

This module carries the HOMESERVER product nginx desired state lifted from the private initialization quarry. Harmonia maintains configuration on an already-born appliance; it does not install nginx, generate certificates, or own application services.

The ladder:

- fails closed unless the birth-provided `nginx` executable exists;
- converges the quarry nginx configuration and unit with backups of replaced files;
- enables the quarry site set through validated links;
- validates the complete nginx configuration;
- reloads systemd after file convergence;
- proves nginx is active.

The public payload contains certificate paths only. Certificate and key bytes under `/etc/ssl/home.arpa/`, logs under `/var/log/nginx/`, runtime PID state under `/run/`, and runtime service data are not carried.

The virtual hosts cross into service-owned surfaces: the legacy main web root and Unix socket, Forgejo, Jellyfin, Calibre-Web, FileBrowser, MkDocs, Navidrome, Piwigo/PHP-FPM, Transmission's VPN namespace, Vaultwarden, and Yarr. Those services and their data remain outside this module.
