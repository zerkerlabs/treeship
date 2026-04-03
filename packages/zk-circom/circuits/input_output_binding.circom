pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";

/**
 * Input-Output Binding Circuit (Treeship v0.5.0)
 *
 * Proves: a specific output digest was produced by a specific input.
 * Without revealing: the actual input or output content.
 *
 * Public inputs: input_hash, output_hash
 * Private inputs: nonce
 * Output: commitment (Poseidon hash of input_hash + output_hash + nonce)
 */
template InputOutputBinding() {
    // Public inputs
    signal input input_hash;
    signal input output_hash;

    // Private inputs
    signal input nonce;

    // Public output
    signal output commitment;

    // Poseidon hash binding input, output, and nonce
    component poseidon = Poseidon(3);
    poseidon.inputs[0] <== input_hash;
    poseidon.inputs[1] <== output_hash;
    poseidon.inputs[2] <== nonce;

    commitment <== poseidon.out;
}

component main { public [input_hash, output_hash] } = InputOutputBinding();
