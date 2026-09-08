//! Startup-loaded public seats. This module is a reader, not a schema copy.
use serde_json::Value;
use std::sync::OnceLock;
use std::time::Duration;

pub(crate) const RELEASE_FLAG: &str = "estate.release-flag.v1";
pub(crate) const UPDATE_SET: &str = "harmonia.update-set.v1";

#[derive(Debug)]
pub(crate) struct Seat {
    id: &'static str,
    raw: Value,
}

impl Seat {
    fn load(id: &'static str, port: u16) -> Result<Self, String> {
        let url = format!("http://127.0.0.1:{port}/api/v1/schema/{id}");
        let observed = super::read_only_command_with_timeout(
            "/usr/bin/curl",
            &["-fsS".into(), "--max-time".into(), "3".into(), url],
            Duration::from_secs(4),
        );
        if !observed.ok {
            return Err(format!("schema-seat-unreachable {id}"));
        }
        let raw: Value = serde_json::from_str(&observed.stdout).map_err(|_| {
            format!("schema-seat-desync {id}: invalid seat JSON; reload through Make Modern")
        })?;
        if raw.get("schema").and_then(Value::as_str) != Some(id) {
            return Err(format!(
                "schema-seat-desync {id}: foreign schema {}; reload through Make Modern",
                raw.get("schema").unwrap_or(&Value::Null)
            ));
        }
        if !raw
            .get("required")
            .and_then(Value::as_array)
            .is_some_and(|fields| fields.iter().all(|field| field.as_str().is_some()))
        {
            return Err(format!("schema-seat-desync {id}: missing frozen kernel declaration; reload through Make Modern"));
        }
        Ok(Self { id, raw })
    }

    /// Only the loaded seat names the frozen kernel. Additive fields are not
    /// projected away and schema-version equality is deliberately not a gate.
    pub(crate) fn validate(&self, envelope: &Value) -> Result<(), String> {
        if envelope.get("schema").and_then(Value::as_str) != Some(self.id) {
            return Err(format!("schema-foreign {}", self.id));
        }
        self.validate_kernel(&self.raw, envelope, self.id)
    }

    fn validate_kernel(
        &self,
        declaration: &Value,
        value: &Value,
        path: &str,
    ) -> Result<(), String> {
        if let Some(required) = declaration.get("required").and_then(Value::as_array) {
            for name in required.iter().filter_map(Value::as_str) {
                if value.get(name).is_none_or(Value::is_null) {
                    return Err(format!(
                        "schema-frozen-kernel-missing {} {path}.{name}",
                        self.id
                    ));
                }
            }
        }
        if let Some(name) = declaration.get("type_ref").and_then(Value::as_str) {
            let declared_type = self
                .raw
                .get("types")
                .and_then(|types| types.get(name))
                .ok_or_else(|| format!("schema-seat-desync {}: missing type {name}", self.id))?;
            return self.validate_kernel(declared_type, value, path);
        }
        if let Some(fields) = declaration.get("fields").and_then(Value::as_object) {
            for (name, child) in fields {
                if let Some(present) = value.get(name).filter(|value| !value.is_null()) {
                    self.validate_kernel(child, present, &format!("{path}.{name}"))?;
                }
            }
        }
        if let (Some(items), Some(values)) = (declaration.get("items"), value.as_array()) {
            for (index, item) in values.iter().enumerate() {
                self.validate_kernel(items, item, &format!("{path}[{index}]"))?;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct MintSeats {
    pub(crate) release_flag: Result<Seat, String>,
    pub(crate) update_set: Result<Seat, String>,
}

static SEATS: OnceLock<MintSeats> = OnceLock::new();

/// Called at update-run start. Failed observations are retained, not retried
/// after convergence, and never prevent modules from running.
pub(crate) fn at_start() -> &'static MintSeats {
    SEATS.get_or_init(|| {
        let port = std::env::var("CADUCEUS_BIND")
            .ok()
            .and_then(|bind| {
                bind.rsplit_once(':')
                    .and_then(|(_, port)| port.parse::<u16>().ok())
            })
            .unwrap_or(3014);
        MintSeats {
            release_flag: Seat::load(RELEASE_FLAG, port),
            update_set: Seat::load(UPDATE_SET, port),
        }
    })
}

impl MintSeats {
    pub(crate) fn signal(&self) -> Option<&str> {
        self.release_flag
            .as_ref()
            .err()
            .or(self.update_set.as_ref().err())
            .map(String::as_str)
    }
}
