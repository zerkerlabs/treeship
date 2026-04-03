//! Native Groth16 proving via ark-circom.
//!
//! This module provides a pure-Rust proving path that reads the same
//! zkey files produced by snarkjs, eliminating the Node.js runtime
//! dependency for proof generation.
//!
//! Status: Scaffolded. The ark-circom API requires careful type
//! alignment between ark-bn254, ark-groth16, and ark-circom versions.
//! Currently the snarkjs shell-out path in prover.rs is the working
//! implementation. This module will replace it once the ark version
//! alignment is resolved.
//!
//! The zkeys committed to the repo are compatible with both snarkjs
//! and ark-circom -- the format is identical.

use crate::{CircomProof, ProofData};
use std::path::PathBuf;

/// Native Circom prover using ark-circom (no Node.js dependency).
///
/// When fully implemented, this replaces the snarkjs shell-out in
/// CircomProver with pure Rust proving via ark-groth16.
pub struct NativeProver {
    pub wasm_path: PathBuf,
    pub zkey_path: PathBuf,
}

impl NativeProver {
    pub fn new(wasm_path: PathBuf, zkey_path: PathBuf) -> Self {
        Self { wasm_path, zkey_path }
    }

    /// Generate a Groth16 proof natively.
    ///
    /// TODO: Wire ark-circom::CircomBuilder + ark-groth16::Groth16::prove
    /// once ark version alignment is resolved. The flow:
    /// 1. CircomConfig::new(wasm_path, r1cs_path)
    /// 2. CircomBuilder::new(config) + push_input() for each witness value
    /// 3. read_zkey(zkey_bytes) to get proving key
    /// 4. Groth16::prove(&pk, circuit, &mut rng)
    /// 5. Serialize proof points to our ProofData format
    pub fn prove(
        &self,
        _inputs: &serde_json::Value,
    ) -> Result<CircomProof, Box<dyn std::error::Error>> {
        // For now, delegate to snarkjs via the existing prover
        Err("native ark-circom proving not yet wired -- use snarkjs path via CircomProver".into())
    }

    /// Check if native proving is available.
    pub fn is_available() -> bool {
        cfg!(feature = "native")
    }
}
