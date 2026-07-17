//! Predicate registry: typed, schema-validated payloads for Treeship receipts.
//!
//! A Treeship receipt (`treeship/receipt/v1`) carries a free-form `kind` and an
//! opaque JSON `payload`. The predicate registry makes specific `kind` values
//! *typed*: each registered suffix is bound to a JSON Schema, and at attest time
//! the payload is validated against that schema before the receipt is signed
//! ([`validate`]). A registered predicate that fails validation is rejected, so
//! a downstream verifier can rely on the shape, not just the signature.
//!
//! This is purely additive and backward compatible. A `kind` with no registered
//! schema attests exactly as before (sign-on-submit); existing artifact types,
//! signing logic, and chain structure are untouched.
//!
//! ## Validation depth, deliberately
//!
//! Core does a small, dependency-free **structural** check: every `required`
//! field is present and each present field whose schema declares a primitive
//! `type` matches that type (including union types like `["string","null"]`).
//! That is the *complete* contract for the flat `memory.write.v1` /
//! `memory.read.v1` predicates, which use only `required` + `type`.
//!
//! `boundary.v1` is a richer JSON Schema (`const`/`enum`/`pattern`/`$ref`). Core
//! enforces its required-field/type structure and ships the full schema as the
//! canonical published artifact (`schema_json("boundary.v1")`); the complete
//! constraint set is delegated to that schema for external validators. We keep
//! the core validator dependency-free on purpose: pulling a full JSON-Schema
//! engine (and its transitive surface) into the security-critical signing crate,
//! and into the WASM verifier build, is not worth it for an attest-time check.

use serde_json::Value;
use std::fmt;

/// Registered predicate suffixes and their JSON Schemas. The suffix is the
/// receipt `kind`. Schemas are embedded at compile time so there is no runtime
/// file IO (keeps the WASM build clean).
const REGISTRY: &[(&str, &str)] = &[
    (
        "memory.write.v1",
        include_str!("schemas/memory.write.v1.json"),
    ),
    (
        "memory.read.v1",
        include_str!("schemas/memory.read.v1.json"),
    ),
    (
        "memory.quarantine-check.v1",
        include_str!("schemas/memory.quarantine-check.v1.json"),
    ),
    ("boundary.v1", include_str!("schemas/boundary.v1.json")),
    ("agent_card.v1", include_str!("schemas/agent_card.v1.json")),
    (
        "agent_card_revocation.v1",
        include_str!("schemas/agent_card_revocation.v1.json"),
    ),
    ("session.v1", include_str!("schemas/session.v1.json")),
    ("agent_cert.v1", include_str!("schemas/agent_cert.v1.json")),
    ("profile.v1", include_str!("schemas/profile.v1.json")),
];

/// Returns the raw JSON Schema text for a registered predicate suffix, if any.
/// This is the canonical published schema for the predicate.
pub fn schema_json(suffix: &str) -> Option<&'static str> {
    REGISTRY.iter().find(|(k, _)| *k == suffix).map(|(_, s)| *s)
}

/// Every registered predicate suffix.
pub fn registered_suffixes() -> Vec<&'static str> {
    REGISTRY.iter().map(|(k, _)| *k).collect()
}

/// A payload that does not conform to its predicate schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PredicateError {
    /// A `required` field was absent from the payload.
    MissingField { suffix: String, field: String },
    /// A present field did not match its declared type.
    TypeMismatch {
        suffix: String,
        field: String,
        expected: String,
    },
    /// The payload was not a JSON object (registered predicates require one).
    NotAnObject { suffix: String },
    /// A present field's value was not among the schema's `enum` (or did not
    /// equal its `const`). This is what stops a self-declared field from
    /// carrying an out-of-vocabulary value (AUD-06).
    NotInEnum {
        suffix: String,
        field: String,
        allowed: String,
    },
    /// The embedded schema itself failed to parse (a build-time bug).
    SchemaParse { suffix: String, detail: String },
}

impl fmt::Display for PredicateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PredicateError::MissingField { suffix, field } => {
                write!(f, "{suffix}: missing required field `{field}`")
            }
            PredicateError::TypeMismatch {
                suffix,
                field,
                expected,
            } => write!(
                f,
                "{suffix}: field `{field}` has the wrong type (expected {expected})"
            ),
            PredicateError::NotAnObject { suffix } => {
                write!(f, "{suffix}: payload must be a JSON object")
            }
            PredicateError::NotInEnum {
                suffix,
                field,
                allowed,
            } => write!(
                f,
                "{suffix}: field `{field}` has a value outside its allowed set ({allowed})"
            ),
            PredicateError::SchemaParse { suffix, detail } => {
                write!(f, "{suffix}: registered schema is invalid JSON: {detail}")
            }
        }
    }
}

impl std::error::Error for PredicateError {}

/// Validate a receipt payload against the registered schema for `suffix`.
///
/// - If `suffix` is **not** registered, returns `Ok(())` (backward compatible:
///   the receipt attests sign-on-submit, exactly as before).
/// - If `suffix` **is** registered, the payload must be a JSON object that
///   carries every `required` field and whose present fields match their
///   declared primitive types. A missing payload is treated as the empty object
///   and therefore fails any predicate that has required fields.
pub fn validate(suffix: &str, payload: Option<&Value>) -> Result<(), PredicateError> {
    let Some(schema_str) = schema_json(suffix) else {
        return Ok(());
    };
    let schema: Value =
        serde_json::from_str(schema_str).map_err(|e| PredicateError::SchemaParse {
            suffix: suffix.to_string(),
            detail: e.to_string(),
        })?;

    // A registered predicate requires a JSON object. A missing payload is the
    // empty object, so any predicate with required fields fails closed here.
    let empty = Value::Object(serde_json::Map::new());
    let value = payload.unwrap_or(&empty);
    let map = value
        .as_object()
        .ok_or_else(|| PredicateError::NotAnObject {
            suffix: suffix.to_string(),
        })?;

    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for entry in required {
            if let Some(name) = entry.as_str() {
                if !map.contains_key(name) {
                    return Err(PredicateError::MissingField {
                        suffix: suffix.to_string(),
                        field: name.to_string(),
                    });
                }
            }
        }
    }

    if let Some(props) = schema.get("properties").and_then(Value::as_object) {
        for (field, subschema) in props {
            let Some(actual) = map.get(field) else {
                continue; // optional-and-absent; `required` already enforced presence
            };

            // Primitive type, when declared.
            if let Some(type_decl) = subschema.get("type") {
                if !type_matches(actual, type_decl) {
                    return Err(PredicateError::TypeMismatch {
                        suffix: suffix.to_string(),
                        field: field.to_string(),
                        expected: type_decl.to_string(),
                    });
                }
            }

            // AUD-06: enforce `enum` and `const`, independently of whether a
            // `type` is also declared. Before this, a field with a declared
            // enum (e.g. session.v1 `attestation_class`) passed on type alone,
            // so an out-of-vocabulary value slipped through. A missing type is
            // no longer a free pass either.
            if let Some(allowed) = subschema.get("enum").and_then(Value::as_array) {
                if !allowed.iter().any(|a| a == actual) {
                    return Err(PredicateError::NotInEnum {
                        suffix: suffix.to_string(),
                        field: field.to_string(),
                        allowed: Value::Array(allowed.clone()).to_string(),
                    });
                }
            }
            if let Some(constant) = subschema.get("const") {
                if actual != constant {
                    return Err(PredicateError::NotInEnum {
                        suffix: suffix.to_string(),
                        field: field.to_string(),
                        allowed: constant.to_string(),
                    });
                }
            }
        }
    }

    Ok(())
}

/// Does `value` satisfy a JSON Schema `type` declaration (a string, or an array
/// of strings for a union)?
fn type_matches(value: &Value, type_decl: &Value) -> bool {
    match type_decl {
        Value::String(t) => json_is(value, t),
        Value::Array(types) => types
            .iter()
            .any(|t| t.as_str().is_some_and(|t| json_is(value, t))),
        // A type declaration we don't recognize is not structurally enforced
        // here; the canonical schema is the full contract.
        _ => true,
    }
}

/// Map a JSON Schema primitive type name onto a `serde_json::Value` shape.
/// `integer` requires a non-fractional number.
fn json_is(value: &Value, ty: &str) -> bool {
    match ty {
        "string" => value.is_string(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "null" => value.is_null(),
        // Unknown type keyword: not enforced structurally.
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn registry_lists_the_three_seed_predicates() {
        let suffixes = registered_suffixes();
        assert!(suffixes.contains(&"memory.write.v1"));
        assert!(suffixes.contains(&"memory.read.v1"));
        assert!(suffixes.contains(&"boundary.v1"));
        assert!(suffixes.contains(&"agent_card.v1"));
        assert!(schema_json("memory.write.v1").is_some());
        assert!(schema_json("nope.v1").is_none());
    }

    #[test]
    fn embedded_schemas_parse() {
        for s in registered_suffixes() {
            let raw = schema_json(s).unwrap();
            serde_json::from_str::<Value>(raw).expect("embedded schema must be valid JSON");
        }
    }

    #[test]
    fn quarantine_check_valid_passes() {
        let payload = json!({
            "action_id": "aac_1f2e3d4c",
            "provider": "system://zmem",
            "chain_root": "u3v9xJ2kQm4Zr8pW1sTnA7bCdEfGhIjKlMnOpQrStUv",
            "decision_seq": 1042,
            "clean": true,
            "quarantined_triggers": [],
            "checked_at": "2026-07-17T19:00:00Z"
        });
        assert!(validate("memory.quarantine-check.v1", Some(&payload)).is_ok());
    }

    #[test]
    fn quarantine_check_missing_verdict_fails_closed() {
        let payload = json!({
            "action_id": "aac_1f2e3d4c",
            "chain_root": "u3v9xJ2kQm4Zr8pW1sTnA7bCdEfGhIjKlMnOpQrStUv",
            "decision_seq": 1042
        }); // `clean` missing — the field the whole gate hangs on
        let err = validate("memory.quarantine-check.v1", Some(&payload)).unwrap_err();
        assert_eq!(
            err,
            PredicateError::MissingField {
                suffix: "memory.quarantine-check.v1".into(),
                field: "clean".into()
            }
        );
    }

    #[test]
    fn quarantine_check_stringly_typed_verdict_fails_closed() {
        // A "true" string must not pass for a boolean verdict — a lenient
        // parse here would let a provider bug (or an attacker) launder an
        // ambiguous verdict into a clean one.
        let payload = json!({
            "action_id": "aac_1f2e3d4c",
            "chain_root": "u3v9xJ2kQm4Zr8pW1sTnA7bCdEfGhIjKlMnOpQrStUv",
            "decision_seq": 1042,
            "clean": "true"
        });
        let err = validate("memory.quarantine-check.v1", Some(&payload)).unwrap_err();
        assert_eq!(
            err,
            PredicateError::TypeMismatch {
                suffix: "memory.quarantine-check.v1".into(),
                field: "clean".into(),
                expected: "\"boolean\"".into()
            }
        );
    }

    #[test]
    fn quarantine_check_non_integer_seq_fails_closed() {
        // decision_seq binds the verdict to a ledger state; a non-integer
        // seq breaks chain-root rederivation for Class-2 verifiers.
        let payload = json!({
            "action_id": "aac_1f2e3d4c",
            "chain_root": "u3v9xJ2kQm4Zr8pW1sTnA7bCdEfGhIjKlMnOpQrStUv",
            "decision_seq": "1042",
            "clean": true
        });
        let err = validate("memory.quarantine-check.v1", Some(&payload)).unwrap_err();
        assert_eq!(
            err,
            PredicateError::TypeMismatch {
                suffix: "memory.quarantine-check.v1".into(),
                field: "decision_seq".into(),
                expected: "\"integer\"".into()
            }
        );
    }

    #[test]
    fn unregistered_suffix_is_backward_compatible() {
        // No schema -> attest proceeds as today, even with no payload.
        assert!(validate("custom.kind.v1", None).is_ok());
        assert!(validate("custom.kind.v1", Some(&json!({"anything": 1}))).is_ok());
    }

    #[test]
    fn agent_cert_valid_passes() {
        let payload = json!({
            "agent": "agent://deployer",
            "subject_key_id": "key_abc123",
            "subject_public_key": "vEQfSDqVCz4rtqbu5iuhpFuYrah6QALUSCGJYdOKeCY",
            "issuer": "ship://ship_b49ff5f291a279c7",
            "issued_at": "2026-07-06T12:00:00Z",
            "valid_until": "2027-07-06T12:00:00Z",
            "model": "claude-fable-5",
            "description": null
        });
        assert!(validate("agent_cert.v1", Some(&payload)).is_ok());
    }

    #[test]
    fn agent_cert_missing_subject_key_fails_closed() {
        let payload = json!({
            "agent": "agent://deployer",
            "subject_key_id": "key_abc123",
            "issuer": "ship://ship_x",
            "issued_at": "2026-07-06T12:00:00Z",
            "valid_until": "2027-07-06T12:00:00Z"
        }); // subject_public_key missing — the field the whole chain hangs on
        let err = validate("agent_cert.v1", Some(&payload)).unwrap_err();
        assert_eq!(
            err,
            PredicateError::MissingField {
                suffix: "agent_cert.v1".into(),
                field: "subject_public_key".into()
            }
        );
    }

    #[test]
    fn session_record_valid_passes() {
        let payload = json!({
            "session_id": "ssn_abc123",
            "actor": "agent://hermes",
            "headline": "Fixed keystore hostname-drift bug",
            "outcome": "completed",
            "started_at": "2026-07-06T14:00:00Z",
            "closed_at": "2026-07-06T15:30:00Z",
            "duration_ms": 5400000,
            "harness": "claude-code",
            "attestation_class": "runtime",
            "action_count": 212,
            "approval_count": 2,
            "handoff_count": 0,
            "event_count": 340,
            "tools_exercised": ["Bash(git:*)", "Edit(*)"],
            "receipt_digest": "sha256:deadbeef",
            "receipt_merkle_root": "sha256:cafebabe",
            "report_url": null
        });
        assert!(validate("session.v1", Some(&payload)).is_ok());
    }

    #[test]
    fn session_record_out_of_enum_class_fails_closed() {
        // AUD-06: before enum enforcement, an out-of-vocabulary
        // attestation_class passed on type (string) alone. It must now be
        // rejected against the schema's enum.
        let payload = json!({
            "session_id": "ssn_abc123",
            "actor": "agent://hermes",
            "outcome": "completed",
            "started_at": "2026-07-06T14:00:00Z",
            "closed_at": "2026-07-06T15:30:00Z",
            "attestation_class": "super-trusted",
            "receipt_digest": "sha256:deadbeef"
        });
        let err = validate("session.v1", Some(&payload)).unwrap_err();
        assert!(
            matches!(err, PredicateError::NotInEnum { ref field, .. } if field == "attestation_class"),
            "expected NotInEnum for attestation_class, got {err:?}"
        );
    }

    #[test]
    fn session_record_out_of_enum_outcome_fails_closed() {
        // `outcome` also carries an enum; a bogus value must be rejected.
        let payload = json!({
            "session_id": "ssn_abc123",
            "actor": "agent://hermes",
            "outcome": "totally-shipped",
            "started_at": "2026-07-06T14:00:00Z",
            "closed_at": "2026-07-06T15:30:00Z",
            "attestation_class": "self",
            "receipt_digest": "sha256:deadbeef"
        });
        assert!(matches!(
            validate("session.v1", Some(&payload)).unwrap_err(),
            PredicateError::NotInEnum { .. }
        ));
    }

    #[test]
    fn session_record_missing_required_fails_closed() {
        let payload = json!({
            "session_id": "ssn_abc123",
            "actor": "agent://hermes",
            "outcome": "completed",
            "started_at": "2026-07-06T14:00:00Z",
            "closed_at": "2026-07-06T15:30:00Z",
            "receipt_digest": "sha256:deadbeef"
        }); // attestation_class missing
        let err = validate("session.v1", Some(&payload)).unwrap_err();
        assert_eq!(
            err,
            PredicateError::MissingField {
                suffix: "session.v1".into(),
                field: "attestation_class".into()
            }
        );
    }

    #[test]
    fn session_record_wrong_type_fails_closed() {
        let payload = json!({
            "session_id": "ssn_abc123",
            "actor": "agent://hermes",
            "outcome": "completed",
            "started_at": "2026-07-06T14:00:00Z",
            "closed_at": "2026-07-06T15:30:00Z",
            "attestation_class": "runtime",
            "receipt_digest": "sha256:deadbeef",
            "tools_exercised": "Bash(git:*)"
        }); // tools_exercised must be an array, not a string
        let err = validate("session.v1", Some(&payload)).unwrap_err();
        assert!(matches!(err, PredicateError::TypeMismatch { .. }));
    }

    #[test]
    fn memory_write_valid_passes() {
        let payload = json!({
            "memory_id": "mem_abc",
            "content_hash": "sha256:deadbeef",
            "memory_type": "episodic",
            "scope": "tenant://acme",
            "activegraph_run_id": "run_1",
            "supersedes": null
        });
        assert!(validate("memory.write.v1", Some(&payload)).is_ok());
    }

    #[test]
    fn memory_write_missing_required_fails_closed() {
        let payload = json!({
            "memory_id": "mem_abc",
            "memory_type": "episodic",
            "scope": "tenant://acme"
        }); // content_hash missing
        let err = validate("memory.write.v1", Some(&payload)).unwrap_err();
        assert_eq!(
            err,
            PredicateError::MissingField {
                suffix: "memory.write.v1".into(),
                field: "content_hash".into()
            }
        );
    }

    #[test]
    fn memory_write_wrong_type_fails() {
        let payload = json!({
            "memory_id": "mem_abc",
            "content_hash": 12345, // should be string
            "memory_type": "episodic",
            "scope": "tenant://acme"
        });
        let err = validate("memory.write.v1", Some(&payload)).unwrap_err();
        assert!(
            matches!(err, PredicateError::TypeMismatch { field, .. } if field == "content_hash")
        );
    }

    #[test]
    fn memory_write_nullable_supersedes_accepts_string_and_null() {
        let base = |sup: Value| {
            json!({
                "memory_id": "m", "content_hash": "h", "memory_type": "t", "scope": "s",
                "supersedes": sup
            })
        };
        assert!(validate("memory.write.v1", Some(&base(json!("mem_old")))).is_ok());
        assert!(validate("memory.write.v1", Some(&base(Value::Null))).is_ok());
        // a number is neither string nor null
        assert!(validate("memory.write.v1", Some(&base(json!(7)))).is_err());
    }

    #[test]
    fn registered_predicate_requires_a_payload() {
        let err = validate("memory.write.v1", None).unwrap_err();
        assert!(matches!(err, PredicateError::MissingField { .. }));
    }

    #[test]
    fn memory_read_valid_and_integer_enforced() {
        let ok = json!({
            "zmem_receipt_id": "act_1",
            "trace_sha256": "abcd",
            "query_hash": "qh",
            "retrieval_mode": "semantic",
            "memories_returned": 3
        });
        assert!(validate("memory.read.v1", Some(&ok)).is_ok());

        let bad = json!({
            "zmem_receipt_id": "act_1",
            "trace_sha256": "abcd",
            "query_hash": "qh",
            "retrieval_mode": "semantic",
            "memories_returned": "three" // must be integer
        });
        assert!(matches!(
            validate("memory.read.v1", Some(&bad)).unwrap_err(),
            PredicateError::TypeMismatch { field, .. } if field == "memories_returned"
        ));
    }

    #[test]
    fn memory_read_missing_required_fails() {
        let payload = json!({
            "zmem_receipt_id": "act_1",
            "trace_sha256": "abcd",
            "retrieval_mode": "semantic",
            "memories_returned": 3
        }); // query_hash missing
        assert!(matches!(
            validate("memory.read.v1", Some(&payload)).unwrap_err(),
            PredicateError::MissingField { field, .. } if field == "query_hash"
        ));
    }

    #[test]
    fn boundary_structural_required_fields_enforced() {
        // Structural check: all top-level required present + declared types
        // match. Field shapes mirror schemas/examples/boundary.v1.memory.valid
        // (actor/checker are objects, committed_at is an object, diet an array).
        let valid = json!({
            "schema": "treeship.boundary.v1",
            "subject_ref": "art_aabbccdd11223344",
            "actor": {"uri": "agent://codex", "keyid": "key_aaaa1111"},
            "checker": {"uri": "human://alice", "keyid": "key_bbbb2222"},
            "decision": "allow",
            "policy": {"digest": "sha256:p"},
            "diet_root": "sha256:r",
            "diet": [{"type": "memory_bundle", "digest": "sha256:d"}],
            "committed_at": {"anchor": "merkle://zmem/checkpoint#4821", "ts": "2026-06-06T00:00:00Z"}
        });
        assert!(validate("boundary.v1", Some(&valid)).is_ok());

        // A top-level field with the wrong type is caught structurally too.
        let mut wrong = valid.clone();
        wrong.as_object_mut().unwrap()["committed_at"] = json!("not-an-object");
        assert!(matches!(
            validate("boundary.v1", Some(&wrong)).unwrap_err(),
            PredicateError::TypeMismatch { field, .. } if field == "committed_at"
        ));

        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove("decision");
        assert!(matches!(
            validate("boundary.v1", Some(&missing)).unwrap_err(),
            PredicateError::MissingField { field, .. } if field == "decision"
        ));
    }

    #[test]
    fn agent_card_valid_passes() {
        let card = json!({
            "schema": "agent_card.v1",
            "agent": "agent://deployer",
            "keyid": "key_9f8e7d6c",
            "owner": "human://alice",
            "version": "1.2.0",
            "capabilities": {
                "tools": ["file.read", "file.write", "db.*"],
                "models": ["claude-sonnet-4"],
                "can_delegate": true
            },
            "evidence_anchor": { "receipt_count": 1247, "merkle_root": "mroot_a0be" },
            "supersedes": null
        });
        assert!(validate("agent_card.v1", Some(&card)).is_ok());
    }

    #[test]
    fn agent_card_missing_keyid_fails_closed() {
        // keyid is the binding; a card without it is meaningless.
        let card = json!({
            "schema": "agent_card.v1",
            "agent": "agent://deployer",
            "version": "1.0.0",
            "capabilities": { "tools": ["file.read"] }
        });
        assert!(matches!(
            validate("agent_card.v1", Some(&card)).unwrap_err(),
            PredicateError::MissingField { field, .. } if field == "keyid"
        ));
    }

    #[test]
    fn agent_card_capabilities_must_be_an_object() {
        let card = json!({
            "schema": "agent_card.v1",
            "agent": "agent://deployer",
            "keyid": "key_1",
            "version": "1.0.0",
            "capabilities": ["file.read"] // array, not the required object
        });
        assert!(matches!(
            validate("agent_card.v1", Some(&card)).unwrap_err(),
            PredicateError::TypeMismatch { field, .. } if field == "capabilities"
        ));
    }

    #[test]
    fn agent_card_revocation_valid_passes() {
        let rev = json!({
            "schema": "agent_card_revocation.v1",
            "card": "art_deadbeefdeadbeef",
            "keyid": "key_1",
            "reason": "key-rotation",
            "revoked_at": "2026-06-23T00:00:00Z"
        });
        assert!(validate("agent_card_revocation.v1", Some(&rev)).is_ok());
    }

    #[test]
    fn agent_card_revocation_requires_card_id() {
        let rev = json!({
            "schema": "agent_card_revocation.v1",
            "revoked_at": "2026-06-23T00:00:00Z"
            // missing `card`
        });
        assert!(matches!(
            validate("agent_card_revocation.v1", Some(&rev)).unwrap_err(),
            PredicateError::MissingField { field, .. } if field == "card"
        ));
    }
}
