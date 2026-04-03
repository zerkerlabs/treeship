pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/switcher.circom";

/**
 * Policy Checker Circuit
 * 
 * This circuit enforces privacy policies by applying a privacy mask to data
 * and verifies API calls against a whitelist using Merkle proofs.
 * 
 * Private inputs: data_hash, privacy_mask, api_call_proof, api_call_hash
 * Public inputs: api_whitelist_merkle_root
 * Public outputs: masked_data_hash, policy_compliance
 */
template PolicyChecker(MASK_SIZE, MERKLE_DEPTH) {
    // Public inputs
    signal input api_whitelist_merkle_root;
    
    // Private inputs
    signal private input data_hash;
    signal private input privacy_mask[MASK_SIZE]; // Binary mask for data sections
    signal private input api_call_proof[MERKLE_DEPTH]; // Merkle proof for API whitelist
    signal private input api_call_hash; // Hash of API call being verified
    
    // Public outputs
    signal output masked_data_hash;
    signal output policy_compliance; // 1 if compliant, 0 if not
    
    // Step 1: Apply privacy mask to data
    component privacy_masker = ApplyPrivacyMask(MASK_SIZE);
    privacy_masker.data_hash <== data_hash;
    for (var i = 0; i < MASK_SIZE; i++) {
        privacy_masker.mask[i] <== privacy_mask[i];
    }
    masked_data_hash <== privacy_masker.masked_hash;
    
    // Step 2: Verify API call against whitelist using Merkle proof
    component merkle_verifier = MerkleProofVerifier(MERKLE_DEPTH);
    merkle_verifier.leaf <== api_call_hash;
    merkle_verifier.root <== api_whitelist_merkle_root;
    for (var i = 0; i < MERKLE_DEPTH; i++) {
        merkle_verifier.proof[i] <== api_call_proof[i];
    }
    
    // Policy compliance is 1 if Merkle proof is valid
    policy_compliance <== merkle_verifier.valid;
    
    // Additional constraints
    component data_range_check = Num2Bits(254);
    data_range_check.in <== data_hash;
    
    // Ensure all mask bits are binary
    for (var i = 0; i < MASK_SIZE; i++) {
        privacy_mask[i] * (privacy_mask[i] - 1) === 0;
    }
}

/**
 * Apply Privacy Mask Template
 * 
 * Applies a binary mask to data sections and computes the masked data hash.
 */
template ApplyPrivacyMask(MASK_SIZE) {
    signal input data_hash;
    signal input mask[MASK_SIZE];
    signal output masked_hash;
    
    // For simplicity, we'll use the mask bits as multipliers
    // In a real implementation, this would involve more complex data sectioning
    component hasher = Poseidon(MASK_SIZE + 1);
    hasher.inputs[0] <== data_hash;
    
    // Include masked sections in the hash
    for (var i = 0; i < MASK_SIZE; i++) {
        hasher.inputs[i + 1] <== mask[i] * data_hash; // Simplified masking
    }
    
    masked_hash <== hasher.out;
}

/**
 * Merkle Proof Verifier Template
 * 
 * Verifies that a leaf is included in a Merkle tree with the given root.
 */
template MerkleProofVerifier(DEPTH) {
    signal input leaf;
    signal input root;
    signal input proof[DEPTH];
    signal output valid;
    
    component hashers[DEPTH];
    component selectors[DEPTH];
    
    signal computed_hash[DEPTH + 1];
    computed_hash[0] <== leaf;
    
    for (var i = 0; i < DEPTH; i++) {
        // Determine if we should hash (computed_hash, proof[i]) or (proof[i], computed_hash)
        // For simplicity, we'll always use (computed_hash, proof[i])
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== computed_hash[i];
        hashers[i].inputs[1] <== proof[i];
        computed_hash[i + 1] <== hashers[i].out;
    }
    
    // Check if computed root matches expected root
    component root_check = IsEqual();
    root_check.in[0] <== computed_hash[DEPTH];
    root_check.in[1] <== root;
    valid <== root_check.out;
}

// Helper templates
template Num2Bits(n) {
    assert(n <= 254);
    signal input in;
    signal output out[n];
    
    var lc1 = 0;
    var e2 = 1;
    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] - 1) === 0;
        lc1 += out[i] * e2;
        e2 = e2 + e2;
    }
    
    lc1 === in;
}

template IsEqual() {
    signal input in[2];
    signal output out;
    
    component isz = IsZero();
    isz.in <== in[1] - in[0];
    out <== isz.out;
}

template IsZero() {
    signal input in;
    signal output out;
    
    signal inv;
    inv <-- in!=0 ? 1/in : 0;
    out <== -in*inv +1;
    in*out === 0;
}

// Instantiate with reasonable defaults: 8-bit privacy mask, 8-level Merkle tree
component main = PolicyChecker(8, 8);