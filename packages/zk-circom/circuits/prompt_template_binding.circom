pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

/**
 * Prompt Template Binding Circuit
 * 
 * This circuit verifies that a prompt was correctly generated from a template
 * and parameters by checking the hash relationships.
 * 
 * Private inputs: parameters_hash
 * Public inputs: template_hash
 * Public outputs: prompt_hash, template_hash (passed through for verification)
 */
template PromptTemplateBinding() {
    // Public inputs
    signal input template_hash;
    
    // Private inputs - parameters used to generate the prompt
    signal private input parameters_hash;
    
    // Public outputs
    signal output prompt_hash;
    signal output verified_template_hash;
    
    // Create Poseidon hash to combine template and parameters
    component prompt_generator = Poseidon(2);
    prompt_generator.inputs[0] <== template_hash;
    prompt_generator.inputs[1] <== parameters_hash;
    
    // The generated prompt hash
    prompt_hash <== prompt_generator.out;
    
    // Pass through template hash for external verification
    verified_template_hash <== template_hash;
    
    // Add constraints to ensure inputs are valid
    component template_range_check = Num2Bits(254);
    template_range_check.in <== template_hash;
    
    component params_range_check = Num2Bits(254);
    params_range_check.in <== parameters_hash;
    
    // Additional constraint: template_hash must be non-zero
    component is_zero = IsZero();
    is_zero.in <== template_hash;
    is_zero.out === 0; // Ensure template_hash is not zero
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

template IsZero() {
    signal input in;
    signal output out;
    
    signal inv;
    
    inv <-- in!=0 ? 1/in : 0;
    
    out <== -in*inv +1;
    in*out === 0;
}

component main = PromptTemplateBinding();