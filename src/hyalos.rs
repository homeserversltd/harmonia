use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const DEFAULT_CADUCEUS_BIND: &str = "127.0.0.1:8787";
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
) {
    let _ = forward_receipt_inner(kind, message, attributes_redacted, ok);
}

fn forward_receipt_inner(
    kind: &str,
    message: &str,
    attributes_redacted: Option<Value>,
    ok: Option<bool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let bind = std::env::var("CADUCEUS_BIND")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_CADUCEUS_BIND.to_string());
    let host = bind
        .strip_prefix("http://")
        .or_else(|| bind.strip_prefix("https://"))
        .unwrap_or(&bind);
    let host = match host {
        "0.0.0.0:8787" | "[::]:8787" => DEFAULT_CADUCEUS_BIND,
        _ => host,
    };
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
    let body = serde_json::to_vec(&payload)?;
    let mut stream = TcpStream::connect_timeout(&host.parse()?, REQUEST_TIMEOUT)?;
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
