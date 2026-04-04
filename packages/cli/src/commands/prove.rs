use crate::{ctx, printer::Printer};

#[cfg(feature = "zk")]
use treeship_zk_circom::{CircomProver, ZkProof};

/// Available circuit names.
pub const CIRCUITS: &[&str] = &["policy-checker", "input-output-binding", "prompt-template", "spend-limit-checker"];

/// Generate a ZK proof for an artifact using a specific circuit.
#[cfg(feature = "zk")]
pub fn prove_circuit(
    circuit:     &str,
    artifact_id: &str,
    policy_file: Option<&str>,
    config:      Option<&str>,
    printer:     &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    // Resolve "last" keyword
    let artifact_id = if artifact_id == "last" {
        let last_path = std::path::Path::new(&ctx.config.storage_dir).join(".last");
        std::fs::read_to_string(&last_path)
            .map_err(|_| "no recent artifact -- run 'treeship wrap' first")?
            .trim()
            .to_string()
    } else {
        artifact_id.to_string()
    };

    // Load the artifact
    let record = ctx.storage.read(&artifact_id)?;

    // Map circuit name to internal name
    let internal_name = match circuit {
        "policy-checker" => "policy_checker",
        "input-output-binding" => "input_output_binding",
        "prompt-template" => "prompt_template_binding",
        "spend-limit-checker" => "spend_limit_checker",
        _ => return Err(format!("unknown circuit: {}\n  Available: {}", circuit, CIRCUITS.join(", ")).into()),
    };

    // Find circuits directory
    let circuits_dir = find_circuits_dir()?;

    printer.blank();
    printer.info(&format!("Generating {} proof for {}...", circuit, artifact_id));

    let prover = CircomProver::new(&circuits_dir)?;

    let start = std::time::Instant::now();

    let proof = match internal_name {
        "policy_checker" => {
            // Load allowed actions from policy file or declaration
            let allowed = if let Some(path) = policy_file {
                let content = std::fs::read_to_string(path)?;
                let actions: Vec<String> = serde_json::from_str(&content)
                    .map_err(|e| format!("invalid policy file: {e}"))?;
                actions
            } else {
                return Err("--policy required for policy-checker circuit\n  Provide a JSON file with an array of allowed action strings".into());
            };

            // Extract action from the artifact's statement
            let envelope_json = record.envelope.to_json()?;
            let envelope_str = String::from_utf8_lossy(&envelope_json);
            let action = extract_action_from_envelope(&envelope_str)
                .unwrap_or_else(|| "unknown".to_string());

            prover.prove_policy(&action, &allowed, &artifact_id)?
        }
        "input_output_binding" => {
            // Extract input and output digests from artifact metadata
            let envelope_json = record.envelope.to_json()?;
            let envelope_str = String::from_utf8_lossy(&envelope_json);
            let (input_digest, output_digest) = extract_digests_from_envelope(&envelope_str);

            let input_hash = sha256_bytes(&input_digest);
            let output_hash = sha256_bytes(&output_digest);

            prover.prove_io_binding(&input_hash, &output_hash, &artifact_id)?
        }
        "prompt_template_binding" => {
            let envelope_json = record.envelope.to_json()?;
            let envelope_str = String::from_utf8_lossy(&envelope_json);
            let prompt_digest = extract_field_from_envelope(&envelope_str, "system_prompt_digest")
                .unwrap_or_default();
            let template_digest = extract_field_from_envelope(&envelope_str, "template_digest")
                .unwrap_or_default();

            let prompt_hash = sha256_bytes(&prompt_digest);
            let template_hash = sha256_bytes(&template_digest);

            prover.prove_prompt_template(&prompt_hash, &template_hash, &artifact_id)?
        }
        "spend_limit_checker" => {
            // Extract amount and limit from CLI args or artifact meta
            let envelope_json = record.envelope.to_json()?;
            let envelope_str = String::from_utf8_lossy(&envelope_json);

            let amount_cents = extract_field_from_envelope(&envelope_str, "amount_cents")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);

            let max_spend_cents = extract_field_from_envelope(&envelope_str, "max_spend_cents")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);

            if amount_cents == 0 || max_spend_cents == 0 {
                return Err("spend-limit-checker requires amount_cents and max_spend_cents in artifact meta\n  Use --meta '{\"amount_cents\": 4500, \"max_spend_cents\": 100000}'".into());
            }

            prover.prove_spend_limit(&artifact_id, amount_cents, max_spend_cents)?
        }
        _ => unreachable!(),
    };

    let elapsed = start.elapsed();

    // Wrap in ZkProof
    let now = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("{}Z", secs)
    };

    let zk_proof = ZkProof {
        version: 1,
        system: "circom-groth16".to_string(),
        circuit: circuit.to_string(),
        artifact_id: artifact_id.clone(),
        proof: proof.proof,
        public_signals: proof.public_signals,
        proved_at: now,
    };

    // Save proof file
    let proof_filename = format!("{}.{}.zkproof", artifact_id, circuit);
    let proof_json = serde_json::to_vec_pretty(&zk_proof)?;
    std::fs::write(&proof_filename, &proof_json)?;

    printer.success("proof generated", &[
        ("circuit", circuit),
        ("artifact", &artifact_id),
        ("time", &format!("{:.1}s", elapsed.as_secs_f64())),
        ("size", &format!("{} bytes", proof_json.len())),
        ("output", &proof_filename),
    ]);
    printer.blank();

    Ok(())
}

/// Verify a ZK proof file.
#[cfg(feature = "zk")]
pub fn verify_proof(
    proof_file: &str,
    printer:    &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(proof_file)?;
    let zk_proof: ZkProof = serde_json::from_str(&content)
        .map_err(|e| format!("invalid proof file: {e}"))?;

    printer.blank();
    printer.info(&format!("Verifying {} proof...", zk_proof.circuit));

    let circuits_dir = find_circuits_dir()?;
    let prover = CircomProver::new(&circuits_dir)?;

    let internal_name = match zk_proof.circuit.as_str() {
        "policy-checker" => "policy_checker",
        "input-output-binding" => "input_output_binding",
        "prompt-template" => "prompt_template_binding",
        other => other,
    };

    let circom_proof = treeship_zk_circom::CircomProof {
        proof: zk_proof.proof,
        public_signals: zk_proof.public_signals,
        circuit_name: internal_name.to_string(),
    };

    let valid = prover.verify_single_proof(internal_name, &circom_proof)?;

    if valid {
        printer.success("proof verified", &[
            ("circuit", &zk_proof.circuit),
            ("artifact", &zk_proof.artifact_id),
            ("proved_at", &zk_proof.proved_at),
        ]);
    } else {
        printer.warn("proof verification failed", &[
            ("circuit", &zk_proof.circuit),
            ("artifact", &zk_proof.artifact_id),
        ]);
    }
    printer.blank();

    Ok(())
}

/// Show ZK status (which features are available).
pub fn zk_status(printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    printer.blank();
    printer.info("ZK proof status:");
    printer.blank();

    #[cfg(feature = "zk")]
    {
        printer.info(&format!("  {} Circom (groth16)", printer.green("+")));
        printer.info("    circuits: policy-checker, input-output-binding, prompt-template");

        // Check if snarkjs is available
        let snarkjs_available = std::process::Command::new("snarkjs")
            .arg("--version")
            .output()
            .is_ok();

        if snarkjs_available {
            printer.info(&format!("  {} snarkjs available", printer.green("+")));
        } else {
            printer.warn("snarkjs not found", &[]);
            printer.hint("npm install -g snarkjs");
        }

        // Check if circom is available
        let circom_available = std::process::Command::new("circom")
            .arg("--version")
            .output()
            .is_ok();

        if circom_available {
            printer.info(&format!("  {} circom compiler available", printer.green("+")));
        } else {
            printer.dim_info("  - circom compiler not found (not needed for proving, only for circuit development)");
        }

        // Show verification key hashes for transparency
        printer.blank();
        printer.info("  verification key hashes (sha256):");
        for (name, vk_content) in [
            ("policy-checker", include_bytes!("../../../zk-circom/zkeys/pc_vk.json").as_slice()),
            ("input-output-binding", include_bytes!("../../../zk-circom/zkeys/iob_vk.json").as_slice()),
            ("prompt-template", include_bytes!("../../../zk-circom/zkeys/pt_vk.json").as_slice()),
        ] {
            use sha2::{Sha256, Digest};
            let hash = hex::encode(Sha256::digest(vk_content));
            printer.info(&format!("    {} {}", name, &hash[..16]));
        }

        // RISC Zero status
        printer.blank();
        printer.dim_info("  RISC Zero: coming in v0.6.0 (guest compiled, prover not yet wired)");
    }

    #[cfg(not(feature = "zk"))]
    {
        printer.dim_info("  ZK features not enabled in this build");
        printer.hint("rebuild with: cargo build -p treeship-cli --features zk");
    }

    printer.blank();
    Ok(())
}

/// Stub for non-zk builds
#[cfg(not(feature = "zk"))]
pub fn prove_circuit(
    _circuit: &str, _artifact_id: &str, _policy_file: Option<&str>,
    _config: Option<&str>, printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    printer.blank();
    printer.warn("ZK features not enabled in this build", &[]);
    printer.hint("rebuild with: cargo build -p treeship-cli --features zk");
    printer.blank();
    Ok(())
}

/// Stub for non-zk builds
#[cfg(not(feature = "zk"))]
pub fn verify_proof(
    _proof_file: &str, printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    printer.blank();
    printer.warn("ZK features not enabled in this build", &[]);
    printer.hint("rebuild with: cargo build -p treeship-cli --features zk");
    printer.blank();
    Ok(())
}

/// Prove an entire session chain using RISC Zero (background, slow).
#[cfg(feature = "zk")]
pub fn prove_chain(
    session_id: &str,
    config:     Option<&str>,
    printer:    &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    printer.blank();
    printer.info(&format!("Proving chain for session {}...", session_id));
    printer.info("  This may take several minutes (local proving).");
    printer.info("  Consider running in background: treeship daemon handles this automatically.");
    printer.blank();

    // Walk the chain: start from the .last artifact and follow parent_id links
    // back to the root. This gives us exactly the session's chain, not all artifacts.
    let last_path = std::path::Path::new(&ctx.config.storage_dir).join(".last");
    let tip_id = std::fs::read_to_string(&last_path)
        .map(|s| s.trim().to_string())
        .map_err(|_| "no recent artifact -- run 'treeship wrap' first")?;

    let mut chain: Vec<treeship_zk_risc0::ChainArtifact> = Vec::new();
    let mut current_id = Some(tip_id);

    while let Some(id) = current_id {
        match ctx.storage.read(&id) {
            Ok(record) => {
                let envelope_json = record.envelope.to_json()
                    .unwrap_or_default();
                let sig = record.envelope.signatures.first()
                    .map(|s| s.sig.clone())
                    .unwrap_or_default();

                chain.push(treeship_zk_risc0::ChainArtifact {
                    artifact_id: record.artifact_id.clone(),
                    digest: record.digest.clone(),
                    payload_type: record.payload_type.clone(),
                    signed_at: record.signed_at.clone(),
                    parent_id: record.parent_id.clone(),
                    signature: sig,
                    pae_message: envelope_json,
                });

                current_id = record.parent_id.clone();
            }
            Err(_) => {
                // Can't find parent -- chain ends here
                current_id = None;
            }
        }
    }

    // Reverse so chain goes root -> tip (oldest first)
    chain.reverse();
    let artifacts = chain;

    if artifacts.is_empty() {
        return Err("no artifacts found in chain".into());
    }

    printer.info(&format!("  chain: {} artifacts (root -> tip)", artifacts.len()));

    let public_key = ctx.keys.public_key(&ctx.config.default_key_id)?;
    let pub_key_arr: [u8; 32] = public_key.try_into()
        .map_err(|_| "invalid public key length")?;

    let prover = treeship_zk_risc0::RiscZeroProver::new(Default::default());
    let start = std::time::Instant::now();
    let result = prover.prove_chain(&artifacts, pub_key_arr)?;
    let elapsed = start.elapsed();

    // Save proof
    let proof_filename = format!("{}.chain.zkproof", session_id);
    let proof_path = std::path::PathBuf::from(&proof_filename);
    treeship_zk_risc0::RiscZeroProver::save_proof(&result, &proof_path)?;

    printer.success("chain proof generated", &[
        ("session", session_id),
        ("artifacts", &result.artifact_count.to_string()),
        ("digests", if result.all_digests_valid { "all valid" } else { "INVALID" }),
        ("chain", if result.chain_intact { "intact" } else { "BROKEN" }),
        ("time", &format!("{:.1}s", elapsed.as_secs_f64())),
        ("output", &proof_filename),
    ]);
    printer.blank();

    Ok(())
}

/// Stub for non-zk builds
#[cfg(not(feature = "zk"))]
pub fn prove_chain(
    _session_id: &str, _config: Option<&str>, printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    printer.blank();
    printer.warn("ZK features not enabled in this build", &[]);
    printer.hint("rebuild with: cargo build -p treeship-cli --features zk");
    printer.blank();
    Ok(())
}

// -- Helpers ------------------------------------------------------------------

/// Approximate RFC 3339 timestamp (used for proof job metadata).
pub fn now_rfc3339_approx() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}Z", secs)
}

fn find_circuits_dir() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    // Check common locations for circuits
    let candidates = [
        std::path::PathBuf::from(".treeship/circuits"),
        home::home_dir().unwrap_or_default().join(".treeship/circuits"),
        std::path::PathBuf::from("/usr/local/share/treeship/circuits"),
    ];

    for path in &candidates {
        if path.exists() {
            return Ok(path.clone());
        }
    }

    Err("circuits directory not found\n  Install circuits: treeship zk setup\n  Or set TREESHIP_CIRCUITS_DIR".into())
}

fn sha256_bytes(input: &str) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let hash = Sha256::digest(input.as_bytes());
    hash.into()
}

fn extract_action_from_envelope(envelope_str: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(envelope_str).ok()?;
    // DSSE envelope -> payload (base64) -> decode -> parse -> action field
    let payload_b64 = v.get("payload")?.as_str()?;
    let payload_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD, payload_b64
    ).ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    payload.get("action").and_then(|a| a.as_str()).map(|s| s.to_string())
}

fn extract_digests_from_envelope(envelope_str: &str) -> (String, String) {
    let v: serde_json::Value = serde_json::from_str(envelope_str).unwrap_or_default();
    let payload_b64 = v.get("payload").and_then(|p| p.as_str()).unwrap_or("");
    let payload_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD, payload_b64
    ).unwrap_or_default();
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap_or_default();

    let input = payload.get("subject")
        .and_then(|s| s.get("digest"))
        .and_then(|d| d.as_str())
        .unwrap_or("unknown")
        .to_string();

    let output = payload.get("output_digest")
        .or_else(|| payload.get("meta").and_then(|m| m.get("output_digest")))
        .and_then(|d| d.as_str())
        .unwrap_or("unknown")
        .to_string();

    (input, output)
}

fn extract_field_from_envelope(envelope_str: &str, field: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(envelope_str).ok()?;
    let payload_b64 = v.get("payload")?.as_str()?;
    let payload_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD, payload_b64
    ).ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;

    payload.get(field)
        .or_else(|| payload.get("meta").and_then(|m| m.get(field)))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}
