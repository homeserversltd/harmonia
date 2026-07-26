use serde::Serialize;
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

pub const CONFIG_SCHEMA: &str = "harmonia.application-presets.config.v1";
pub const DECLARATION_MALFORMED: &str = "application-presets-declaration-malformed";
pub const DEFAULT_DESKTOP_ENTRY_UNAVAILABLE: &str = "default-desktop-entry-unavailable";
pub const MANAGED_USER_TIER_UNACCOUNTED: &str = "managed-user-tier-unaccounted";
pub const RECEIPT_SCHEMA: &str = "harmonia.application-presets.declaration-receipt.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MimeDefaultsDeclaration {
    pub scope: String,
    pub requires: MimeDefaultsRequirements,
    pub associations: Vec<MimeDefaultAssociation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MimeDefaultsRequirements {
    pub desktop_entry_available: bool,
    pub mime_association: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MimeDefaultAssociation {
    pub mime_type: String,
    pub desktop_entry_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum DeclarationOutcome {
    NoPresetsDeclared,
    Validated(MimeDefaultsDeclaration),
    Rejected { reason: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProfileDocument {
    /// The complete parsed document stays beside the narrow declaration view.
    /// Harmonia is read-only here; callers that later gain write authority must
    /// patch this raw document rather than reconstructing it from typed fields.
    pub raw: Value,
    pub declaration_source: PathBuf,
    pub declaration: DeclarationOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeclarationReceipt {
    pub schema: &'static str,
    pub declaration_source: PathBuf,
    pub harmonia_present: bool,
    pub application_presets_present: bool,
    pub mime_defaults_present: bool,
    pub outcome: DeclarationOutcome,
    pub first_blocker: Option<&'static str>,
}

impl ProfileDocument {
    pub fn parse(source: impl AsRef<Path>, text: &str) -> Self {
        let source = source.as_ref().to_path_buf();
        let raw = match serde_json::from_str(text) {
            Ok(raw) => raw,
            Err(error) => {
                return Self {
                    raw: Value::Null,
                    declaration_source: source,
                    declaration: DeclarationOutcome::Rejected {
                        reason: format!("profile-document-json-invalid: {error}"),
                    },
                }
            }
        };
        let declaration = validate_declaration(&raw);
        Self {
            raw,
            declaration_source: source,
            declaration,
        }
    }

    pub fn receipt(&self) -> DeclarationReceipt {
        let (harmonia_present, application_presets_present, mime_defaults_present) =
            declaration_presence(&self.raw);
        let first_blocker = match self.declaration {
            DeclarationOutcome::Rejected { .. } => Some(DECLARATION_MALFORMED),
            DeclarationOutcome::NoPresetsDeclared | DeclarationOutcome::Validated(_) => None,
        };
        DeclarationReceipt {
            schema: RECEIPT_SCHEMA,
            declaration_source: self.declaration_source.clone(),
            harmonia_present,
            application_presets_present,
            mime_defaults_present,
            outcome: self.declaration.clone(),
            first_blocker,
        }
    }
}

fn declaration_presence(raw: &Value) -> (bool, bool, bool) {
    let Some(root) = raw.as_object() else {
        return (false, false, false);
    };
    let Some(harmonia) = root.get("harmonia") else {
        return (false, false, false);
    };
    let Some(harmonia) = harmonia.as_object() else {
        return (true, false, false);
    };
    let Some(block) = harmonia.get("application-presets") else {
        return (true, false, false);
    };
    let Some(block) = block.as_object() else {
        return (true, true, false);
    };
    (true, true, block.contains_key("mime-defaults"))
}

fn validate_declaration(raw: &Value) -> DeclarationOutcome {
    let Some(root) = raw.as_object() else {
        return rejected("profile-document-root-must-be-an-object");
    };
    let Some(harmonia) = root.get("harmonia") else {
        return DeclarationOutcome::NoPresetsDeclared;
    };
    let Some(harmonia) = harmonia.as_object() else {
        return rejected("harmonia-must-be-an-object");
    };
    let Some(block) = harmonia.get("application-presets") else {
        return DeclarationOutcome::NoPresetsDeclared;
    };
    let Some(block) = block.as_object() else {
        return rejected("application-presets-must-be-an-object");
    };
    let Some(family) = block.get("mime-defaults") else {
        return DeclarationOutcome::NoPresetsDeclared;
    };
    let Some(family) = family.as_object() else {
        return rejected("mime-defaults-must-be-an-object");
    };
    if family.is_empty() {
        return DeclarationOutcome::NoPresetsDeclared;
    }

    if required_string(block, "schema") != Some(CONFIG_SCHEMA) {
        return rejected("schema-must-equal-harmonia.application-presets.config.v1");
    }
    let Some(scope) = required_string(block, "scope") else {
        return rejected("scope-must-be-a-non-empty-string");
    };
    let Some(requires) = block.get("requires").and_then(Value::as_object) else {
        return rejected("requires-must-be-an-object");
    };
    let requirements = match requirements(requires) {
        Ok(requirements) => requirements,
        Err(reason) => return rejected(reason),
    };

    let mut associations = Vec::with_capacity(family.len());
    for (mime_type, candidate_ids) in family {
        if mime_type.trim().is_empty() {
            return rejected("mime-defaults-mime-type-must-be-non-empty");
        }
        let Some(candidate_ids) = candidate_ids.as_array() else {
            return rejected("mime-defaults-candidates-must-be-an-array");
        };
        if candidate_ids.is_empty() {
            return rejected("mime-defaults-candidates-must-not-be-empty");
        }
        let mut desktop_entry_ids = Vec::with_capacity(candidate_ids.len());
        for candidate in candidate_ids {
            let Some(candidate) = candidate.as_str() else {
                return rejected("mime-defaults-candidate-must-be-a-string");
            };
            if candidate.trim().is_empty() {
                return rejected("mime-defaults-candidate-must-be-non-empty");
            }
            desktop_entry_ids.push(candidate.to_string());
        }
        associations.push(MimeDefaultAssociation {
            mime_type: mime_type.to_string(),
            desktop_entry_ids,
        });
    }
    associations.sort_by(|left, right| left.mime_type.cmp(&right.mime_type));

    DeclarationOutcome::Validated(MimeDefaultsDeclaration {
        scope: scope.to_string(),
        requires: requirements,
        associations,
    })
}

fn required_string<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn requirements(object: &Map<String, Value>) -> Result<MimeDefaultsRequirements, &'static str> {
    let desktop_entry_available = object
        .get("desktop-entry-available")
        .and_then(Value::as_bool)
        .ok_or("requires.desktop-entry-available-must-be-a-boolean")?;
    let mime_association = object
        .get("mime-association")
        .and_then(Value::as_bool)
        .ok_or("requires.mime-association-must-be-a-boolean")?;
    if !desktop_entry_available || !mime_association {
        return Err("requires-must-demand-desktop-entry-availability-and-mime-association");
    }
    Ok(MimeDefaultsRequirements {
        desktop_entry_available,
        mime_association,
    })
}

fn rejected(reason: impl Into<String>) -> DeclarationOutcome {
    DeclarationOutcome::Rejected {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = "/etc/profile.json";
    const VALID: &str = r#"{
        "schema": "homeserver.device-profile.v1",
        "kernel": { "profile": "tv" },
        "harmonia": {
          "application-presets": {
            "schema": "harmonia.application-presets.config.v1",
            "scope": "user-desktop",
            "requires": {
              "desktop-entry-available": true,
              "mime-association": true
            },
            "mime-defaults": {
              "image/png": ["org.kde.gwenview.desktop", "chromium.desktop"],
              "text/plain": ["org.kde.kate.desktop"]
            }
          }
        }
      }"#;

    #[test]
    fn valid_declaration_is_typed_and_receipted() {
        let document = ProfileDocument::parse(SOURCE, VALID);
        let DeclarationOutcome::Validated(declaration) = &document.declaration else {
            panic!(
                "expected a validated declaration: {:?}",
                document.declaration
            );
        };
        assert_eq!(declaration.scope, "user-desktop");
        assert_eq!(declaration.associations.len(), 2);
        assert_eq!(
            declaration.associations[0].desktop_entry_ids,
            ["org.kde.gwenview.desktop", "chromium.desktop"]
        );
        let receipt = document.receipt();
        assert_eq!(receipt.schema, RECEIPT_SCHEMA);
        assert_eq!(receipt.declaration_source, PathBuf::from(SOURCE));
        assert!(receipt.harmonia_present);
        assert!(receipt.application_presets_present);
        assert!(receipt.mime_defaults_present);
        assert_eq!(receipt.first_blocker, None);
        let rendered = serde_json::to_value(&receipt).unwrap();
        assert_eq!(rendered["schema"], RECEIPT_SCHEMA);
        assert_eq!(rendered["declaration_source"], SOURCE);
    }

    #[test]
    fn absent_harmonia_is_no_presets_declared() {
        let document = ProfileDocument::parse(SOURCE, r#"{"kernel":{"profile":"tv"}}"#);
        assert_eq!(document.declaration, DeclarationOutcome::NoPresetsDeclared);
        let receipt = document.receipt();
        assert_eq!(
            (
                receipt.harmonia_present,
                receipt.application_presets_present
            ),
            (false, false)
        );
        assert_eq!(receipt.first_blocker, None);
    }

    #[test]
    fn absent_application_presets_is_no_presets_declared() {
        let document = ProfileDocument::parse(SOURCE, r#"{"harmonia":{"other":true}}"#);
        assert_eq!(document.declaration, DeclarationOutcome::NoPresetsDeclared);
        let receipt = document.receipt();
        assert_eq!(
            (
                receipt.harmonia_present,
                receipt.application_presets_present
            ),
            (true, false)
        );
        assert_eq!(receipt.first_blocker, None);
    }

    #[test]
    fn empty_mime_defaults_is_no_presets_declared() {
        let document = ProfileDocument::parse(
            SOURCE,
            r#"{"harmonia":{"application-presets":{"mime-defaults":{}}}}"#,
        );
        assert_eq!(document.declaration, DeclarationOutcome::NoPresetsDeclared);
        let receipt = document.receipt();
        assert!(receipt.mime_defaults_present);
        assert_eq!(receipt.first_blocker, None);
    }

    #[test]
    fn malformed_present_declaration_has_the_named_blocker() {
        let document = ProfileDocument::parse(
            SOURCE,
            r#"{"harmonia":{"application-presets":{"schema":"wrong","mime-defaults":{"text/plain":[]}}}}"#,
        );
        let DeclarationOutcome::Rejected { reason } = &document.declaration else {
            panic!("expected malformed outcome: {:?}", document.declaration);
        };
        assert!(reason.contains("schema"));
        let receipt = document.receipt();
        assert_eq!(receipt.first_blocker, Some(DECLARATION_MALFORMED));
    }

    #[test]
    fn unknown_keys_survive_the_read_only_typed_access() {
        let document = ProfileDocument::parse(
            SOURCE,
            r#"{
              "unowned-sibling": {"kept": true},
              "harmonia": {
                "application-presets": {
                  "schema": "harmonia.application-presets.config.v1",
                  "scope": "user-desktop",
                  "requires": {"desktop-entry-available": true, "mime-association": true},
                  "unknown-presets-key": ["kept"],
                  "mime-defaults": {"text/plain": ["org.kde.kate.desktop"]}
                }
              }
            }"#,
        );
        assert!(matches!(
            document.declaration,
            DeclarationOutcome::Validated(_)
        ));
        assert_eq!(document.raw["unowned-sibling"]["kept"], true);
        assert_eq!(
            document.raw["harmonia"]["application-presets"]["unknown-presets-key"][0],
            "kept"
        );
    }
}
