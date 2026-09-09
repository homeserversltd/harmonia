use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

const HYALOS_PATH: &str = "/api/v1/hyalos/reflect";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// Forward a receipt to Hyalos without affecting Harmonia's local receipt path.
///
/// This is deliberately best-effort: the caller must never observe transport,
/// serialization, or Hyalos errors.
pub(crate) fn forward_receipt(
    kind: &str,
    message: &str,
    attributes_redacted: Option<Value>,
    ok: Option<bool>,
    correlation_id: Option<&str>,
) {
    let base = match crate::atoms::ask::caduceus_door::base_url() {
        Ok(base) => base,
        Err(signal) => {
            // Declaration absence remains visible without recursively trying
            // to forward its own diagnostic through the missing door.
            static DECLARATION_REPORTED: std::sync::Once = std::sync::Once::new();
            DECLARATION_REPORTED.call_once(|| {
                eprintln!("harmonia hyalos first_missing_signal={signal}");
            });
            return;
        }
    };
    let _ = forward_receipt_inner(
        base,
        kind,
        message,
        attributes_redacted,
        ok,
        correlation_id,
    );
}

fn forward_receipt_inner(
    base: &str,
    kind: &str,
    message: &str,
    attributes_redacted: Option<Value>,
    ok: Option<bool>,
    correlation_id: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let host = base.strip_prefix("http://").expect("resolved HTTP base");
    let mut payload = json!({
        "organ": "harmonia",
        "kind": kind,
        "message": message,
    });
    if let Some(attributes) = attributes_redacted {
        payload["attributes_redacted"] = attributes;
    }
    if let Some(value) = ok {
        payload["ok"] = json!(value);
    }
    if let Some(value) = correlation_id {
        payload["correlation_id"] = json!(value);
    }
    let body = serde_json::to_vec(&payload)?;
    let mut stream = host
        .to_socket_addrs()?
        .find_map(|address| TcpStream::connect_timeout(&address, REQUEST_TIMEOUT).ok())
        .ok_or_else(|| std::io::Error::other("hyalos-door-unreachable"))?;
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;
    stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    write!(
        stream,
        "POST {HYALOS_PATH} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    Ok(())
}
