// Circuit metadata and utilities

use std::collections::HashMap;

/// Information about available circuits
pub struct CircuitInfo {
    pub name: String,
    pub description: String,
    pub public_inputs: Vec<String>,
    pub private_inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub constraints: usize,
}

/// Registry of available circuits
pub struct CircuitRegistry {
    circuits: HashMap<String, CircuitInfo>,
}

impl CircuitRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            circuits: HashMap::new(),
        };
        
        registry.register_default_circuits();
        registry
    }
    
    pub fn get_circuit(&self, name: &str) -> Option<&CircuitInfo> {
        self.circuits.get(name)
    }
    
    pub fn list_circuits(&self) -> Vec<&str> {
        self.circuits.keys().map(|s| s.as_str()).collect()
    }
    
    fn register_default_circuits(&mut self) {
        // Input-Output Binding Circuit
        self.circuits.insert("input_output_binding".to_string(), CircuitInfo {
            name: "input_output_binding".to_string(),
            description: "Creates a commitment binding input and output hashes with a nonce".to_string(),
            public_inputs: vec!["input_hash".to_string(), "output_hash".to_string()],
            private_inputs: vec!["nonce".to_string()],
            outputs: vec!["commitment".to_string()],
            constraints: 1000, // Approximate
        });
        
        // Prompt-Template Binding Circuit
        self.circuits.insert("prompt_template_binding".to_string(), CircuitInfo {
            name: "prompt_template_binding".to_string(),
            description: "Verifies prompt was generated from template and parameters".to_string(),
            public_inputs: vec!["template_hash".to_string()],
            private_inputs: vec!["parameters_hash".to_string()],
            outputs: vec!["prompt_hash".to_string(), "verified_template_hash".to_string()],
            constraints: 800, // Approximate
        });
        
        // Policy Checker Circuit
        self.circuits.insert("policy_checker".to_string(), CircuitInfo {
            name: "policy_checker".to_string(),
            description: "Enforces privacy policies and verifies API whitelist compliance".to_string(),
            public_inputs: vec!["api_whitelist_merkle_root".to_string()],
            private_inputs: vec![
                "data_hash".to_string(),
                "privacy_mask".to_string(),
                "api_call_proof".to_string(),
                "api_call_hash".to_string(),
            ],
            outputs: vec!["masked_data_hash".to_string(), "policy_compliance".to_string()],
            constraints: 2500, // Approximate (includes Merkle tree verification)
        });
    }
}

impl Default for CircuitRegistry {
    fn default() -> Self {
        Self::new()
    }
}