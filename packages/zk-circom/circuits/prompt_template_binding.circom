pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

/**
 * Prompt Template Binding Circuit (Treeship v0.5.0)
 *
 * Proves: a system prompt matched a declared template digest.
 * Without revealing: the system prompt itself.
 *
 * Public inputs: artifact_id_hash, template_hash
 * Private inputs: parameters_hash
 * Output: prompt_hash (Poseidon(template_hash, parameters_hash))
 */
// TODO: re-run trusted setup after circuit change
template PromptTemplateBinding() {
    // Public inputs
    signal input artifact_id_hash;
    signal input template_hash;

    // Private inputs
    signal input parameters_hash;

    // Public outputs
    signal output prompt_hash;
    signal output verified_template_hash;

    // Poseidon hash combining template and parameters
    component prompt_generator = Poseidon(2);
    prompt_generator.inputs[0] <== template_hash;
    prompt_generator.inputs[1] <== parameters_hash;

    prompt_hash <== prompt_generator.out;
    verified_template_hash <== template_hash;
}

component main { public [artifact_id_hash, template_hash] } = PromptTemplateBinding();
