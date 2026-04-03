pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";

/**
 * Input-Output Binding Circuit
 * 
 * This circuit creates a commitment binding input and output hashes together
 * with a nonce for additional security.
 * 
 * Private inputs: nonce
 * Public inputs: input_hash, output_hash
 * Public outputs: commitment
 */
template InputOutputBinding() {
    // Public inputs
    signal input input_hash;
    signal input output_hash;
    
    // Private inputs
    signal private input nonce;
    
    // Public output
    signal output commitment;
    
    // Create Poseidon hash instance for 3 inputs
    component poseidon = Poseidon(3);
    
    // Connect inputs to Poseidon hasher
    poseidon.inputs[0] <== input_hash;
    poseidon.inputs[1] <== output_hash;
    poseidon.inputs[2] <== nonce;
    
    // Output the commitment
    commitment <== poseidon.out;
    
    // Add constraint to ensure input_hash and output_hash are valid field elements
    component range_check_input = Num2Bits(254);
    range_check_input.in <== input_hash;
    
    component range_check_output = Num2Bits(254);
    range_check_output.in <== output_hash;
}

// Helper template for range checking
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

component main = InputOutputBinding();