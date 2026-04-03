pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";

/**
 * Input-Output Binding Circuit (Treeship v0.5.0)
 *
 * Proves: a specific output digest was produced by a specific input.
 * Without revealing: the actual input or output content.
 *
 * Public inputs: artifact_id_hash, input_hash, output_hash
 * Private inputs: nonce
 * Output: commitment (Poseidon hash of artifact_id_hash + input_hash + output_hash + nonce)
 */
// TODO: re-run trusted setup after circuit change
template InputOutputBinding() {
    // Public inputs
    signal input artifact_id_hash;
    signal input input_hash;
    signal input output_hash;

    // Private inputs
    signal input nonce;

    // Public output
    signal output commitment;

    // Poseidon hash binding artifact, input, output, and nonce
    component poseidon = Poseidon(4);
    poseidon.inputs[0] <== artifact_id_hash;
    poseidon.inputs[1] <== input_hash;
    poseidon.inputs[2] <== output_hash;
    poseidon.inputs[3] <== nonce;

    commitment <== poseidon.out;
}

component main { public [artifact_id_hash, input_hash, output_hash] } = InputOutputBinding();
