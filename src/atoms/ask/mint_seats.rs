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
    /// Shared transport/JSON primitive; each reader owns its admission policy.
    fn load_declaration(id: &'static str, base: &str) -> Result<Value, String> {
        let url = format!("{base}/api/v1/schema/{id}");
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
        Ok(raw)
    }

    pub(crate) fn load(id: &'static str, base: &str) -> Result<Self, String> {
        let raw = Self::load_declaration(id, base)?;
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

    /// Ruyi keeps usable declarations even when they declare no kernel.
    /// Only an explicitly foreign seat ID is a refusal, not unavailability.
    pub(crate) fn load_ruyi(id: &'static str, base: &str) -> Result<Self, String> {
        let raw = Self::load_declaration(id, base)
            .map_err(|_| "ruyi-schema-seat-unreachable".to_string())?;
        match raw.get("schema").and_then(Value::as_str) {
            Some(declared) if declared != id => {
                return Err(format!("ruyi-schema-seat-foreign expected={id} got={declared}"));
            }
            Some(_) => {}
            None => return Err("ruyi-schema-seat-unreachable".into()),
        }
        Ok(Self { id, raw })
    }

    /// Read present fields through the retained declaration without imposing
    /// its required list. Unknown envelope fields remain in the raw value.
    pub(crate) fn validate_ruyi(&self, envelope: &Value) -> Result<(), String> {
        if envelope.get("schema").filter(|value| !value.is_null())
            .is_some_and(|value| value.as_str() != Some(self.id))
        {
            return Err(format!("schema-foreign {}", self.id));
        }
        self.validate_kernel(&self.raw, envelope, self.id, false)
    }

    /// Only the loaded seat names the frozen kernel. Additive fields are not
    /// projected away and schema-version equality is deliberately not a gate.
    pub(crate) fn validate(&self, envelope: &Value) -> Result<(), String> {
        if envelope.get("schema").and_then(Value::as_str) != Some(self.id) {
            return Err(format!("schema-foreign {}", self.id));
        }
        self.validate_kernel(&self.raw, envelope, self.id, true)
    }

    fn validate_kernel(
        &self,
        declaration: &Value,
        value: &Value,
        path: &str,
        strict: bool,
    ) -> Result<(), String> {
        if let Some(required) = declaration.get("required").and_then(Value::as_array).filter(|_| strict) {
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
                .and_then(|types| types.get(name));
            return match declared_type {
                Some(declared_type) => self.validate_kernel(declared_type, value, path, strict),
                None if !strict => Ok(()),
                None => Err(format!("schema-seat-desync {}: missing type {name}", self.id)),
            };
        }
        if let Some(fields) = declaration.get("fields").and_then(Value::as_object) {
            for (name, child) in fields {
                if let Some(present) = value.get(name).filter(|value| !value.is_null()) {
                    self.validate_kernel(child, present, &format!("{path}.{name}"), strict)?;
                }
            }
        }
        if let (Some(items), Some(values)) = (declaration.get("items"), value.as_array()) {
            for (index, item) in values.iter().enumerate() {
                self.validate_kernel(items, item, &format!("{path}[{index}]"), strict)?;
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
    SEATS.get_or_init(|| match super::caduceus_door::base_url() {
        Ok(base) => MintSeats {
            release_flag: Seat::load(RELEASE_FLAG, base),
            update_set: Seat::load(UPDATE_SET, base),
        },
        Err(signal) => MintSeats {
            release_flag: Err(signal.into()),
            update_set: Err(signal.into()),
        },
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
