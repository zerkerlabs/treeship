pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

/**
 * Spend Limit Checker Circuit (Treeship v0.6.1)
 *
 * Proves: actual_amount_cents <= max_spend_cents
 * Without revealing: the actual amount or the limit
 *
 * Public inputs: artifact_id[2]
 * Private inputs: actual_amount_cents, max_spend_cents
 * Outputs: valid (1 if amount <= max_spend), limit_commitment
 *
 * The limit_commitment output lets verifiers confirm the proof
 * was generated against a specific declared limit without the
 * prover needing to pre-compute Poseidon.
 */
template SpendLimitChecker() {
    // Public inputs -- bind to a specific artifact
    signal input artifact_id[2];

    // Private inputs -- the actual values being proved
    signal input actual_amount_cents;
    signal input max_spend_cents;

    // Outputs
    signal output valid;
    signal output limit_commitment;

    // Constraint 1: actual_amount_cents <= max_spend_cents
    component lte = LessEqThan(64);
    lte.in[0] <== actual_amount_cents;
    lte.in[1] <== max_spend_cents;
    valid <== lte.out;

    // Constraint 2: commit to the limit value so verifiers can
    // check it matches the declared limit from the declaration
    component limit_hash = Poseidon(2);
    limit_hash.inputs[0] <== max_spend_cents;
    limit_hash.inputs[1] <== artifact_id[0];
    limit_commitment <== limit_hash.out;
}

component main { public [artifact_id] } = SpendLimitChecker();
