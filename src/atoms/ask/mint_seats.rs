//! Startup-loaded public seats. This module is a reader, not a schema copy.
use serde_json::Value;
use std::sync::OnceLock;
use std::time::Duration;

pub(crate) const RELEASE_FLAG: &str = "estate.release-flag.v1";
pub(crate) const UPDATE_SET: &str = "harmonia.update-set.v1";
pub(crate) const SOURCE_RESOLUTION: &str = "harmonia.engine.source_resolution.v1";
pub(crate) const XENIA: &str = "appliance.xenia.v1";

#[derive(Debug, Clone)]
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

    pub(crate) fn validate_compatible(
        &self,
        envelope: &Value,
        compatible_ids: &[&str],
    ) -> Result<(), String> {
        let declared = envelope.get("schema").and_then(Value::as_str);
        if declared != Some(self.id) && !compatible_ids.iter().any(|id| Some(*id) == declared) {
            return Err(format!("schema-foreign {}", self.id));
        }
        self.validate_kernel(&self.raw, envelope, self.id, true)
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

pub(crate) const INTERACTABLE_FEED: &str = "harmonia.config_proposals.feed.v1";
pub(crate) const RUYI_BUMP_RECEIPT: &str = "harmonia.interactables.ruyi_bump.receipt.v1";
pub(crate) const DNS_RECORD_RECEIPT: &str = "harmonia.interactables.dns_record.receipt.v1";
pub(crate) const RUYI_PERSPECTIVE_SEED_RECEIPT: &str =
    "harmonia.interactables.ruyi_perspective_seed.receipt.v1";

#[derive(Debug)]
pub(crate) struct InteractableSeats {
    pub(crate) feed: Result<Seat, String>,
    pub(crate) ruyi_bump_receipt: Result<Seat, String>,
    pub(crate) dns_record_receipt: Result<Seat, String>,
    pub(crate) ruyi_perspective_seed_receipt: Result<Seat, String>,
}

static INTERACTABLE_SEATS: OnceLock<InteractableSeats> = OnceLock::new();

pub(crate) fn interactables_at_start() -> &'static InteractableSeats {
    INTERACTABLE_SEATS.get_or_init(|| match super::caduceus_door::base_url() {
        Ok(base) => InteractableSeats {
            feed: Seat::load(INTERACTABLE_FEED, base),
            ruyi_bump_receipt: Seat::load(RUYI_BUMP_RECEIPT, base),
            dns_record_receipt: Seat::load(DNS_RECORD_RECEIPT, base),
            ruyi_perspective_seed_receipt: Seat::load(RUYI_PERSPECTIVE_SEED_RECEIPT, base),
        },
        Err(signal) => InteractableSeats {
            feed: Err(format!("schema-seat-unreachable {INTERACTABLE_FEED}: {signal}")),
            ruyi_bump_receipt: Err(format!("schema-seat-unreachable {RUYI_BUMP_RECEIPT}: {signal}")),
            dns_record_receipt: Err(format!("schema-seat-unreachable {DNS_RECORD_RECEIPT}: {signal}")),
            ruyi_perspective_seed_receipt: Err(format!(
                "schema-seat-unreachable {RUYI_PERSPECTIVE_SEED_RECEIPT}: {signal}"
            )),
        },
    })
}

pub(crate) fn emit_interactable_seat_signals() {
    let seats = interactables_at_start();
    for (id, seat) in [
        (INTERACTABLE_FEED, &seats.feed),
        (RUYI_BUMP_RECEIPT, &seats.ruyi_bump_receipt),
        (DNS_RECORD_RECEIPT, &seats.dns_record_receipt),
        (
            RUYI_PERSPECTIVE_SEED_RECEIPT,
            &seats.ruyi_perspective_seed_receipt,
        ),
    ] {
        if seat.is_err() {
            eprintln!("schema-seat-unreachable {id}");
        }
    }
}

#[derive(Debug)]
pub(crate) struct MintSeats {
    pub(crate) release_flag: Result<Seat, String>,
    pub(crate) update_set: Result<Seat, String>,
}

static SEATS: OnceLock<MintSeats> = OnceLock::new();
static SOURCE_RESOLUTION_SEAT: OnceLock<Seat> = OnceLock::new();
static XENIA_SEAT: OnceLock<Seat> = OnceLock::new();

fn retryable_seat(cell: &'static OnceLock<Seat>, id: &'static str) -> Result<Seat, String> {
    if let Some(seat) = cell.get() {
        return Ok(seat.clone());
    }
    let base = super::caduceus_door::base_url()?;
    let loaded = Seat::load(id, base)?;
    let _ = cell.set(loaded.clone());
    Ok(cell.get().cloned().unwrap_or(loaded))
}

pub(crate) fn source_resolution() -> Result<Seat, String> {
    retryable_seat(&SOURCE_RESOLUTION_SEAT, SOURCE_RESOLUTION)
}

pub(crate) fn xenia() -> Result<Seat, String> {
    retryable_seat(&XENIA_SEAT, XENIA)
}

/// Called at update-run start. Existing release/update seat behavior remains
/// process-retained. Source/Xenia seats are attempted at startup, retain only
/// successful loads, and retry lazily after startup failures.
pub(crate) fn at_start() -> &'static MintSeats {
    SEATS.get_or_init(|| match super::caduceus_door::base_url() {
        Ok(base) => {
            let release_flag = Seat::load(RELEASE_FLAG, base);
            let update_set = Seat::load(UPDATE_SET, base);
            if let Ok(seat) = Seat::load(SOURCE_RESOLUTION, base) {
                let _ = SOURCE_RESOLUTION_SEAT.set(seat);
            }
            if let Ok(seat) = Seat::load(XENIA, base) {
                let _ = XENIA_SEAT.set(seat);
            }
            MintSeats {
                release_flag,
                update_set,
            }
        }
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
