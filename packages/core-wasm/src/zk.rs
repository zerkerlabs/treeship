//! Real Groth16 verification using ark-groth16 pairing math.
//!
//! Verification keys from the trusted setup are embedded at compile time.
//! Proof verification runs entirely in the browser via WASM -- no server trust.

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{PrimeField, Zero};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use core::str::FromStr;

// Embed verification keys from the trusted setup (committed to repo)
const POLICY_CHECKER_VK: &[u8] =
    include_bytes!("../../zk-circom/zkeys/pc_vk.json");

const INPUT_OUTPUT_BINDING_VK: &[u8] =
    include_bytes!("../../zk-circom/zkeys/iob_vk.json");

const PROMPT_TEMPLATE_VK: &[u8] =
    include_bytes!("../../zk-circom/zkeys/pt_vk.json");

const SPEND_LIMIT_CHECKER_VK: &[u8] =
    include_bytes!("../../zk-circom/zkeys/slc_vk.json");

/// Run actual Groth16 pairing verification on a Circom proof.
pub fn verify_circom_proof(proof_json: &serde_json::Value) -> Result<String, String> {
    let circuit = proof_json.get("circuit")
        .and_then(|c| c.as_str())
        .ok_or("missing circuit field")?;

    // Load the appropriate embedded verification key
    let vk_bytes = match circuit {
        "policy-checker" => POLICY_CHECKER_VK,
        "input-output-binding" => INPUT_OUTPUT_BINDING_VK,
        "prompt-template" => PROMPT_TEMPLATE_VK,
        "spend-limit-checker" => SPEND_LIMIT_CHECKER_VK,
        other => return Err(format!("unknown circuit: {}", other)),
    };

    // Parse verification key from snarkjs JSON format
    let pvk = load_vk(vk_bytes)?;

    // Parse the proof
    let proof_data = proof_json.get("proof")
        .ok_or("missing proof field")?;
    let ark_proof = parse_proof(proof_data)?;

    // Parse public signals
    let public_signals = proof_json.get("public_signals")
        .map(|s| parse_public_signals(s))
        .transpose()?
        .unwrap_or_default();

    // Run actual Groth16 pairing verification
    let valid = Groth16::<Bn254>::verify_proof(&pvk, &ark_proof, &public_signals)
        .unwrap_or(false);

    let artifact_id = proof_json.get("artifact_id")
        .and_then(|a| a.as_str())
        .unwrap_or("unknown");

    Ok(serde_json::json!({
        "valid": valid,
        "system": "circom-groth16",
        "circuit": circuit,
        "artifact_id": artifact_id,
        "public_signals": public_signals.len(),
        "proved_at": proof_json.get("proved_at")
            .and_then(|p| p.as_str())
            .unwrap_or("unknown"),
    }).to_string())
}

/// Parse a snarkjs vk.json into ark-groth16's PreparedVerifyingKey.
fn load_vk(vk_json: &[u8]) -> Result<PreparedVerifyingKey<Bn254>, String> {
    let vk_value: serde_json::Value = serde_json::from_slice(vk_json)
        .map_err(|e| format!("invalid vk JSON: {}", e))?;

    let alpha_g1 = parse_g1(&vk_value["vk_alpha_1"])?;
    let beta_g2 = parse_g2(&vk_value["vk_beta_2"])?;
    let gamma_g2 = parse_g2(&vk_value["vk_gamma_2"])?;
    let delta_g2 = parse_g2(&vk_value["vk_delta_2"])?;

    let ic = vk_value["IC"].as_array()
        .ok_or("missing IC in vk")?
        .iter()
        .map(|p| parse_g1(p))
        .collect::<Result<Vec<G1Affine>, String>>()?;

    let vk = VerifyingKey::<Bn254> {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1: ic,
    };

    Ok(ark_groth16::prepare_verifying_key(&vk))
}

/// Parse a snarkjs Groth16 proof into ark-groth16's Proof type.
fn parse_proof(proof_data: &serde_json::Value) -> Result<Proof<Bn254>, String> {
    let a = parse_g1(&proof_data["pi_a"])?;
    let b = parse_g2(&proof_data["pi_b"])?;
    let c = parse_g1(&proof_data["pi_c"])?;
    Ok(Proof::<Bn254> { a, b, c })
}

/// Parse public signals from snarkjs format.
fn parse_public_signals(signals: &serde_json::Value) -> Result<Vec<Fr>, String> {
    signals.as_array()
        .ok_or("public_signals not array")?
        .iter()
        .map(|s| {
            let val = s.as_str().ok_or("signal not string")?;
            Fr::from_str(val)
                .map_err(|_| format!("invalid Fr: {}", val))
        })
        .collect()
}

/// Parse a G1 point from snarkjs format: ["x", "y", "1"]
fn parse_g1(point: &serde_json::Value) -> Result<G1Affine, String> {
    use ark_ec::AffineRepr;

    let arr = point.as_array().ok_or("G1 point not array")?;
    if arr.len() < 2 {
        return Err("G1 point needs at least 2 coordinates".to_string());
    }

    let x = parse_fq(&arr[0])?;
    let y = parse_fq(&arr[1])?;

    if x.is_zero() && y.is_zero() {
        return Ok(G1Affine::zero());
    }

    Ok(G1Affine::new_unchecked(x, y))
}

/// Parse a G2 point from snarkjs format: [["x1","x2"], ["y1","y2"], ["1","0"]]
fn parse_g2(point: &serde_json::Value) -> Result<G2Affine, String> {
    use ark_ec::AffineRepr;

    let arr = point.as_array().ok_or("G2 point not array")?;
    if arr.len() < 2 {
        return Err("G2 point needs at least 2 coordinates".to_string());
    }

    let x = parse_fq2(&arr[0])?;
    let y = parse_fq2(&arr[1])?;

    if x.is_zero() && y.is_zero() {
        return Ok(G2Affine::zero());
    }

    Ok(G2Affine::new_unchecked(x, y))
}

/// Parse an Fq field element from a decimal string.
fn parse_fq(val: &serde_json::Value) -> Result<ark_bn254::Fq, String> {
    let s = val.as_str().ok_or("Fq not a string")?;
    Fq::from_str(s).map_err(|_| format!("invalid Fq: {}", s))
}

/// Parse an Fq2 element from snarkjs format: ["c0", "c1"]
fn parse_fq2(val: &serde_json::Value) -> Result<ark_bn254::Fq2, String> {
    let arr = val.as_array().ok_or("Fq2 not array")?;
    if arr.len() < 2 {
        return Err("Fq2 needs 2 components".to_string());
    }
    let c0 = parse_fq(&arr[0])?;
    let c1 = parse_fq(&arr[1])?;
    Ok(Fq2::new(c0, c1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vk_loads_from_embedded_bytes() {
        let result = load_vk(POLICY_CHECKER_VK);
        assert!(result.is_ok(), "policy checker vk failed: {:?}", result.err());

        let result = load_vk(INPUT_OUTPUT_BINDING_VK);
        assert!(result.is_ok(), "iob vk failed: {:?}", result.err());

        let result = load_vk(PROMPT_TEMPLATE_VK);
        assert!(result.is_ok(), "prompt template vk failed: {:?}", result.err());

        let result = load_vk(SPEND_LIMIT_CHECKER_VK);
        assert!(result.is_ok(), "spend limit checker vk failed: {:?}", result.err());
    }

    #[test]
    fn g1_parses_from_snarkjs_format() {
        let point = serde_json::json!(["1", "2", "1"]);
        let result = parse_g1(&point);
        assert!(result.is_ok(), "G1 parse failed: {:?}", result.err());
    }

    #[test]
    fn invalid_proof_returns_false() {
        let fake_proof = serde_json::json!({
            "system": "circom-groth16",
            "circuit": "policy-checker",
            "artifact_id": "art_test",
            "proof": {
                "pi_a": ["1", "2", "1"],
                "pi_b": [["1","0"],["1","0"],["1","0"]],
                "pi_c": ["1", "2", "1"],
                "protocol": "groth16",
                "curve": "bn128"
            },
            "public_signals": ["1", "2"],
            "proved_at": "2026-04-02T00:00:00Z"
        });
        let result = verify_circom_proof(&fake_proof);
        assert!(result.is_ok());
        let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        // Fake proof should fail verification, not error
        assert_eq!(json["valid"], false);
    }

    #[test]
    fn unknown_circuit_returns_error() {
        let proof = serde_json::json!({
            "circuit": "nonexistent",
            "proof": {},
            "public_signals": [],
        });
        let result = verify_circom_proof(&proof);
        assert!(result.is_err());
    }
}
