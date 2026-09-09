//! One process-start observation of the appliance's Caduceus door.
use std::net::{IpAddr, Ipv6Addr};
use std::sync::OnceLock;

pub(crate) const UNDECLARED: &str = "caduceus-bind-undeclared";
static BASE: OnceLock<Result<String, &'static str>> = OnceLock::new();

/// Retain absence as well as success: receipt forwarding must not repeatedly
/// read configuration, and no consumer may invent a replacement door.
pub(crate) fn base_url() -> Result<&'static str, &'static str> {
    BASE.get_or_init(|| {
        let bind = crate::bands::stage_profile::read_device_caduceus_bind()
            .map_err(|_| UNDECLARED)?
            .ok_or(UNDECLARED)?;
        resolve_bind(&bind)
    })
    .as_deref()
    .map_err(|signal| *signal)
}

/// Accept a host:port declaration, never a URL or an environment fallback.
pub(crate) fn resolve_bind(bind: &str) -> Result<String, &'static str> {
    let (host, port) = bind.rsplit_once(':').ok_or(UNDECLARED)?;
    if port.is_empty()
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || !port.parse::<u16>().is_ok_and(|port| port != 0)
    {
        return Err(UNDECLARED);
    }
    let address = if let Some(ip) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        Some(IpAddr::V6(ip.parse::<Ipv6Addr>().map_err(|_| UNDECLARED)?))
    } else if let Ok(ip) = host.parse::<IpAddr>() {
        if !ip.is_ipv4() {
            return Err(UNDECLARED); // IPv6 authorities must be bracketed.
        }
        Some(ip)
    } else {
        let name = host.strip_suffix('.').unwrap_or(host);
        if name.is_empty()
            || name.len() > 253
            || name
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
            || !name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return Err(UNDECLARED);
        }
        None
    };
    let host = if address.is_some_and(|ip| ip.is_unspecified()) {
        "127.0.0.1"
    } else {
        host
    };
    Ok(format!("http://{host}:{port}"))
}
