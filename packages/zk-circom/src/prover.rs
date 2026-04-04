use crate::{CircomProof, ProofData};
use crate::utils::FieldUtils;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use serde::de::Error as _;
use serde_json::Value;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CircomError {
    #[error("Circuit compilation failed: {0}")]
    CompilationFailed(String),

    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Circuit not found: {0}")]
    CircuitNotFound(String),
}

pub type Result<T> = std::result::Result<T, CircomError>;

/// Circom proof system integration.
/// Shells out to the circom compiler and snarkjs CLI.
pub struct CircomProver {
    circuits_path: PathBuf,
    compiled_circuits: HashMap<String, CompiledCircuit>,
}

#[derive(Debug, Clone)]
struct CompiledCircuit {
    wasm_path: PathBuf,
    zkey_path: PathBuf,
    vkey_path: PathBuf,
}

impl CircomProver {
    /// Create a new Circom prover pointing at the given circuits directory.
    /// Compiles all known circuits on construction.
    pub fn new<P: AsRef<Path>>(circuits_path: P) -> Result<Self> {
        let circuits_path = circuits_path.as_ref().to_path_buf();

        if !circuits_path.exists() {
            return Err(CircomError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Circuits path does not exist: {}", circuits_path.display()),
            )));
        }

        let mut prover = Self {
            circuits_path,
            compiled_circuits: HashMap::new(),
        };

        prover.compile_all_circuits()?;

        Ok(prover)
    }

    // ---------------------------------------------------------------
    // Public convenience methods for each circuit
    // ---------------------------------------------------------------

    /// Prove that a given action is present in a list of allowed actions.
    /// Returns a policy-checker circuit proof.
    ///
    /// Circuit signals (policy_checker.circom, MAX_ACTIONS=16):
    ///   public:  artifact_id_hash, policy_digest
    ///   private: action_hash, allowed[16], n_allowed
    pub fn prove_policy(
        &self,
        action: &str,
        allowed_actions: &[String],
        artifact_id: &str,
    ) -> Result<CircomProof> {
        const MAX_ACTIONS: usize = 16;

        let artifact_id_hash = FieldUtils::string_to_field(artifact_id);
        let action_hash = FieldUtils::string_to_field(action);

        // Pad allowed list to MAX_ACTIONS with zeros
        let mut allowed: Vec<String> = allowed_actions
            .iter()
            .take(MAX_ACTIONS)
            .map(|a| FieldUtils::string_to_field(a))
            .collect();
        while allowed.len() < MAX_ACTIONS {
            allowed.push("0".to_string());
        }

        let n_allowed = allowed_actions.len().min(MAX_ACTIONS).to_string();

        // policy_digest is computed by the circuit as Poseidon(allowed[0..16]),
        // but we must supply the public input that the circuit will constrain
        // against. Compute it the same way snarkjs would expect it.
        let policy_digest = FieldUtils::poseidon_hash_fields(&allowed);

        let inputs = serde_json::json!({
            "artifact_id_hash": artifact_id_hash,
            "policy_digest": policy_digest,
            "action_hash": action_hash,
            "allowed": allowed,
            "n_allowed": n_allowed,
        });

        self.generate_proof("policy_checker", &inputs)
    }

    /// Prove an input/output binding given two 32-byte digests.
    ///
    /// Circuit signals (input_output_binding.circom):
    ///   public:  artifact_id_hash, input_hash, output_hash
    ///   private: nonce
    pub fn prove_io_binding(
        &self,
        input_digest: &[u8; 32],
        output_digest: &[u8; 32],
        artifact_id: &str,
    ) -> Result<CircomProof> {
        let artifact_id_hash = FieldUtils::string_to_field(artifact_id);
        let input_field = FieldUtils::hash_to_field(input_digest);
        let output_field = FieldUtils::hash_to_field(output_digest);
        let nonce = crate::utils::CircuitUtils::generate_nonce();

        let inputs = serde_json::json!({
            "artifact_id_hash": artifact_id_hash,
            "input_hash": input_field,
            "output_hash": output_field,
            "nonce": nonce,
        });

        self.generate_proof("input_output_binding", &inputs)
    }

    /// Prove a prompt/template binding given two 32-byte digests.
    ///
    /// Circuit signals (prompt_template_binding.circom):
    ///   public:  artifact_id_hash, template_hash
    ///   private: parameters_hash
    pub fn prove_prompt_template(
        &self,
        prompt_digest: &[u8; 32],
        template_digest: &[u8; 32],
        artifact_id: &str,
    ) -> Result<CircomProof> {
        let artifact_id_hash = FieldUtils::string_to_field(artifact_id);
        let template_field = FieldUtils::hash_to_field(template_digest);
        let params_field = FieldUtils::hash_to_field(prompt_digest);

        let inputs = serde_json::json!({
            "artifact_id_hash": artifact_id_hash,
            "template_hash": template_field,
            "parameters_hash": params_field,
        });

        self.generate_proof("prompt_template_binding", &inputs)
    }

    // ---------------------------------------------------------------
    // Verification
    // ---------------------------------------------------------------

    /// Verify all provided proofs against their respective circuits.
    pub fn verify_all_proofs(&self, proofs: &HashMap<String, CircomProof>) -> Result<bool> {
        for (circuit_name, proof) in proofs {
            let is_valid = self.verify_single_proof(circuit_name, proof)?;
            if !is_valid {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Prove a payment amount is within declared spend limit.
    ///
    /// Circuit signals (spend_limit_checker.circom):
    ///   public:  artifact_id[2], limit_digest[2]
    ///   private: actual_amount_cents, max_spend_cents
    pub fn prove_spend_limit(
        &self,
        artifact_id: &str,
        actual_amount_cents: u64,
        max_spend_cents: u64,
    ) -> Result<CircomProof> {
        let artifact_id_hash = FieldUtils::string_to_field(artifact_id);

        // Circuit computes limit_commitment = Poseidon(max_spend_cents, artifact_id[0])
        // as an output. Prover only needs to supply the private values.
        let inputs = serde_json::json!({
            "artifact_id": [artifact_id_hash, "0"],
            "actual_amount_cents": actual_amount_cents.to_string(),
            "max_spend_cents": max_spend_cents.to_string(),
        });

        self.generate_proof("spend_limit_checker", &inputs)
    }

    // ---------------------------------------------------------------
    // Internal proof generation / verification
    // ---------------------------------------------------------------

    fn generate_proof(&self, circuit_name: &str, inputs: &Value) -> Result<CircomProof> {
        let circuit = self
            .compiled_circuits
            .get(circuit_name)
            .ok_or_else(|| CircomError::CircuitNotFound(circuit_name.to_string()))?;

        let temp_dir = tempfile::tempdir()?;
        let input_file = temp_dir.path().join("input.json");
        let witness_file = temp_dir.path().join("witness.wtns");
        let proof_file = temp_dir.path().join("proof.json");
        let public_file = temp_dir.path().join("public.json");

        // Write inputs
        std::fs::write(&input_file, serde_json::to_string_pretty(inputs)?)?;

        // Step 1: generate witness
        let witness_output = Command::new("node")
            .args([
                "generate_witness.js",
                circuit.wasm_path.to_str().unwrap(),
                input_file.to_str().unwrap(),
                witness_file.to_str().unwrap(),
            ])
            .current_dir(&self.circuits_path)
            .output()?;

        if !witness_output.status.success() {
            return Err(CircomError::ProofGenerationFailed(
                String::from_utf8_lossy(&witness_output.stderr).to_string(),
            ));
        }

        // Step 2: generate proof via snarkjs
        let proof_output = Command::new("snarkjs")
            .args([
                "groth16",
                "prove",
                circuit.zkey_path.to_str().unwrap(),
                witness_file.to_str().unwrap(),
                proof_file.to_str().unwrap(),
                public_file.to_str().unwrap(),
            ])
            .output()?;

        if !proof_output.status.success() {
            return Err(CircomError::ProofGenerationFailed(
                String::from_utf8_lossy(&proof_output.stderr).to_string(),
            ));
        }

        // Parse results
        let proof_json: Value = serde_json::from_str(&std::fs::read_to_string(&proof_file)?)?;
        let public_json: Value = serde_json::from_str(&std::fs::read_to_string(&public_file)?)?;

        let proof_data = self.parse_proof_data(&proof_json)?;
        let public_signals = self.parse_public_signals(&public_json)?;

        Ok(CircomProof {
            proof: proof_data,
            public_signals,
            circuit_name: circuit_name.to_string(),
        })
    }

    /// Verify a single proof for a given circuit.
    pub fn verify_single_proof(&self, circuit_name: &str, proof: &CircomProof) -> Result<bool> {
        let circuit = self
            .compiled_circuits
            .get(circuit_name)
            .ok_or_else(|| CircomError::CircuitNotFound(circuit_name.to_string()))?;

        let temp_dir = tempfile::tempdir()?;
        let proof_file = temp_dir.path().join("proof.json");
        let public_file = temp_dir.path().join("public.json");

        let proof_json = self.serialize_proof_data(&proof.proof)?;
        let public_json = serde_json::to_string(&proof.public_signals)?;

        std::fs::write(&proof_file, proof_json)?;
        std::fs::write(&public_file, public_json)?;

        let verify_output = Command::new("snarkjs")
            .args([
                "groth16",
                "verify",
                circuit.vkey_path.to_str().unwrap(),
                public_file.to_str().unwrap(),
                proof_file.to_str().unwrap(),
            ])
            .output()?;

        if !verify_output.status.success() {
            return Ok(false);
        }

        let output_str = String::from_utf8_lossy(&verify_output.stdout);
        Ok(output_str.contains("OK"))
    }

    // ---------------------------------------------------------------
    // Circuit compilation
    // ---------------------------------------------------------------

    fn compile_all_circuits(&mut self) -> Result<()> {
        let circuit_names = [
            "input_output_binding",
            "prompt_template_binding",
            "policy_checker",
            "spend_limit_checker",
        ];

        for circuit_name in &circuit_names {
            self.compile_circuit(circuit_name)?;
        }

        Ok(())
    }

    fn compile_circuit(&mut self, circuit_name: &str) -> Result<()> {
        let circuit_file = self
            .circuits_path
            .join(format!("{}.circom", circuit_name));
        let output_dir = self.circuits_path.join("build").join(circuit_name);

        std::fs::create_dir_all(&output_dir)?;

        // Compile circuit to R1CS and WASM
        let compile_output = Command::new("circom")
            .args([
                circuit_file.to_str().unwrap(),
                "--r1cs",
                "--wasm",
                "--sym",
                "-o",
                output_dir.to_str().unwrap(),
            ])
            .output()?;

        if !compile_output.status.success() {
            return Err(CircomError::CompilationFailed(
                String::from_utf8_lossy(&compile_output.stderr).to_string(),
            ));
        }

        // Generate proving key (simplified; production would use a trusted setup ceremony)
        let r1cs_file = output_dir.join(format!("{}.r1cs", circuit_name));
        let zkey_file = output_dir.join(format!("{}.zkey", circuit_name));
        let vkey_file = output_dir.join(format!("{}_vkey.json", circuit_name));

        let _setup_output = Command::new("snarkjs")
            .args([
                "groth16",
                "setup",
                r1cs_file.to_str().unwrap(),
                "powersOfTau28_hez_final_10.ptau",
                zkey_file.to_str().unwrap(),
            ])
            .current_dir(&self.circuits_path)
            .output()?;

        // Export verification key
        let _vkey_output = Command::new("snarkjs")
            .args([
                "zkey",
                "export",
                "verificationkey",
                zkey_file.to_str().unwrap(),
                vkey_file.to_str().unwrap(),
            ])
            .output()?;

        let compiled_circuit = CompiledCircuit {
            wasm_path: output_dir
                .join(format!("{}_js", circuit_name))
                .join(format!("{}.wasm", circuit_name)),
            zkey_path: zkey_file,
            vkey_path: vkey_file,
        };

        self.compiled_circuits
            .insert(circuit_name.to_string(), compiled_circuit);

        Ok(())
    }

    // ---------------------------------------------------------------
    // Serialization helpers
    // ---------------------------------------------------------------

    fn parse_proof_data(&self, proof_json: &Value) -> Result<ProofData> {
        let proof_obj = proof_json
            .as_object()
            .ok_or_else(|| CircomError::JsonError(serde_json::Error::custom("Expected proof object")))?;

        Ok(ProofData {
            pi_a: [
                proof_obj["pi_a"][0].as_str().unwrap_or("0").to_string(),
                proof_obj["pi_a"][1].as_str().unwrap_or("0").to_string(),
                proof_obj["pi_a"][2].as_str().unwrap_or("1").to_string(),
            ],
            pi_b: [
                [
                    proof_obj["pi_b"][0][0].as_str().unwrap_or("0").to_string(),
                    proof_obj["pi_b"][0][1].as_str().unwrap_or("0").to_string(),
                ],
                [
                    proof_obj["pi_b"][1][0].as_str().unwrap_or("0").to_string(),
                    proof_obj["pi_b"][1][1].as_str().unwrap_or("0").to_string(),
                ],
                [
                    proof_obj["pi_b"][2][0].as_str().unwrap_or("1").to_string(),
                    proof_obj["pi_b"][2][1].as_str().unwrap_or("0").to_string(),
                ],
            ],
            pi_c: [
                proof_obj["pi_c"][0].as_str().unwrap_or("0").to_string(),
                proof_obj["pi_c"][1].as_str().unwrap_or("0").to_string(),
                proof_obj["pi_c"][2].as_str().unwrap_or("1").to_string(),
            ],
            protocol: "groth16".to_string(),
            curve: "bn128".to_string(),
        })
    }

    fn parse_public_signals(&self, public_json: &Value) -> Result<Vec<String>> {
        let signals = public_json
            .as_array()
            .ok_or_else(|| {
                CircomError::JsonError(serde_json::Error::custom(
                    "Expected public signals array",
                ))
            })?;

        Ok(signals
            .iter()
            .map(|v| v.as_str().unwrap_or("0").to_string())
            .collect())
    }

    fn serialize_proof_data(&self, proof_data: &ProofData) -> Result<String> {
        let proof_json = serde_json::json!({
            "pi_a": proof_data.pi_a,
            "pi_b": proof_data.pi_b,
            "pi_c": proof_data.pi_c,
            "protocol": proof_data.protocol,
            "curve": proof_data.curve,
        });

        Ok(serde_json::to_string(&proof_json)?)
    }
}
