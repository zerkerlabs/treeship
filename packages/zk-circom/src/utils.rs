use num_bigint::BigUint;
use sha2::{Digest, Sha256};

/// Utilities for working with BN254 field elements used in Circom circuits.
pub struct FieldUtils;

impl FieldUtils {
    /// BN254 field modulus
    const BN254_MODULUS: &'static str =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617";

    /// Convert arbitrary bytes to a BN254 field element string (decimal).
    pub fn bytes_to_field(bytes: &[u8]) -> String {
        let modulus = BigUint::parse_bytes(Self::BN254_MODULUS.as_bytes(), 10).unwrap();
        let value = BigUint::from_bytes_be(bytes);
        let field_element = value % modulus;
        field_element.to_string()
    }

    /// Convert a 32-byte hash to a field element.
    /// Uses only the first 31 bytes so the result is guaranteed to be within BN254.
    pub fn hash_to_field(hash: &[u8; 32]) -> String {
        let mut field_bytes = [0u8; 32];
        field_bytes[1..].copy_from_slice(&hash[..31]);
        Self::bytes_to_field(&field_bytes)
    }

    /// Hash a string with SHA-256 then convert to a field element.
    pub fn string_to_field(data: &str) -> String {
        let hash = Sha256::digest(data.as_bytes());
        Self::hash_to_field(&hash.into())
    }

    /// Hash a list of field element strings using SHA-256 and reduce to a field
    /// element. This is a stand-in for the Poseidon hash used on-circuit; we use
    /// it to compute the expected public input that the circuit will constrain.
    ///
    /// NOTE: In production the off-chain code should use a native Poseidon
    /// implementation (e.g. circomlibjs) so the digest matches exactly. This
    /// SHA-256-based placeholder works for development and tests.
    pub fn poseidon_hash_fields(fields: &[String]) -> String {
        let mut hasher = Sha256::new();
        for f in fields {
            hasher.update(f.as_bytes());
            hasher.update(b",");
        }
        let hash: [u8; 32] = hasher.finalize().into();
        Self::hash_to_field(&hash)
    }

    /// Check whether a decimal string represents a valid BN254 field element.
    pub fn is_valid_field_element(element: &str) -> bool {
        if let Some(value) = BigUint::parse_bytes(element.as_bytes(), 10) {
            let modulus = BigUint::parse_bytes(Self::BN254_MODULUS.as_bytes(), 10).unwrap();
            value < modulus
        } else {
            false
        }
    }
}

/// Helpers for preparing circuit inputs.
pub struct CircuitUtils;

impl CircuitUtils {
    /// Generate a random nonce suitable for circuit inputs (decimal string).
    pub fn generate_nonce() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let nonce: u64 = rng.gen();
        nonce.to_string()
    }

    /// Build a binary mask from a list of allowed actions.
    ///
    /// For each slot up to `mask_size`, the mask is 1 if the corresponding
    /// entry in `allowed_actions` is non-empty, 0 otherwise. Slots beyond
    /// the length of `allowed_actions` are set to 0.
    pub fn policy_to_binary_mask(
        allowed_actions: &[String],
        mask_size: usize,
    ) -> Vec<u8> {
        let mut mask = vec![0u8; mask_size];
        for (i, action) in allowed_actions.iter().enumerate() {
            if i >= mask_size {
                break;
            }
            if !action.is_empty() {
                mask[i] = 1;
            }
        }
        mask
    }

    /// Build a simplified Merkle proof for an API call against a whitelist.
    ///
    /// In production this would use a real Merkle tree; this version produces
    /// deterministic placeholder siblings so the circuit can still be exercised.
    pub fn create_merkle_proof(
        api_call: &str,
        whitelist: &[String],
        tree_depth: usize,
    ) -> Vec<String> {
        let found = whitelist.iter().any(|a| a == api_call);

        if !found {
            return vec!["0".to_string(); tree_depth];
        }

        (0..tree_depth)
            .map(|i| {
                if i % 2 == 0 {
                    FieldUtils::string_to_field(&format!("sibling_{}", i))
                } else {
                    FieldUtils::string_to_field(&format!("path_{}", i))
                }
            })
            .collect()
    }

    /// Validate that a JSON value contains all the required fields for a given circuit.
    pub fn validate_inputs(
        circuit_name: &str,
        inputs: &serde_json::Value,
    ) -> std::result::Result<(), String> {
        let required_fields: Vec<&str> = match circuit_name {
            "input_output_binding" => vec!["artifact_id_hash", "input_hash", "output_hash", "nonce"],
            "prompt_template_binding" => vec!["artifact_id_hash", "template_hash", "parameters_hash"],
            "policy_checker" => vec![
                "artifact_id_hash",
                "policy_digest",
                "action_hash",
                "allowed",
                "n_allowed",
            ],
            _ => return Err(format!("Unknown circuit: {}", circuit_name)),
        };

        let input_obj = inputs.as_object().ok_or("Input must be a JSON object")?;

        for field in required_fields {
            if !input_obj.contains_key(field) {
                return Err(format!("Missing required field: {}", field));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_element_validation() {
        let valid = "12345";
        assert!(FieldUtils::is_valid_field_element(valid));

        // Value larger than the BN254 modulus (78 digits, well above the 77-digit modulus)
        let too_large =
            "999999999999999999999999999999999999999999999999999999999999999999999999999999";
        assert!(!FieldUtils::is_valid_field_element(too_large));
    }

    #[test]
    fn test_bytes_to_field() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8];
        let field_element = FieldUtils::bytes_to_field(&bytes);
        assert!(FieldUtils::is_valid_field_element(&field_element));
    }

    #[test]
    fn test_string_to_field() {
        let data = "test string";
        let field_element = FieldUtils::string_to_field(data);
        assert!(FieldUtils::is_valid_field_element(&field_element));
    }

    #[test]
    fn test_binary_mask_from_actions() {
        let actions = vec![
            "read".to_string(),
            "".to_string(),
            "write".to_string(),
            "".to_string(),
        ];
        let mask = CircuitUtils::policy_to_binary_mask(&actions, 8);
        assert_eq!(mask, vec![1, 0, 1, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_validate_inputs_io_binding() {
        let inputs = serde_json::json!({
            "artifact_id_hash": "999",
            "input_hash": "123",
            "output_hash": "456",
            "nonce": "789",
        });
        assert!(CircuitUtils::validate_inputs("input_output_binding", &inputs).is_ok());
    }

    #[test]
    fn test_validate_inputs_missing_field() {
        let inputs = serde_json::json!({
            "input_hash": "123",
        });
        assert!(CircuitUtils::validate_inputs("input_output_binding", &inputs).is_err());
    }
}
