pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

/**
 * Spend Limit Checker Circuit (Treeship v0.6.0)
 *
 * Proves: actual_amount_cents <= max_spend_cents
 * Without revealing: the actual amount or the limit
 *
 * Public inputs: artifact_id (2 field elements), limit_digest (2 field elements)
 * Private inputs: actual_amount_cents, max_spend_cents
 * Output: valid (1 if amount <= max_spend, 0 otherwise)
 */
template SpendLimitChecker() {
    // Public inputs
    signal input artifact_id[2];
    signal input limit_digest[2];

    // Private inputs
    signal input actual_amount_cents;
    signal input max_spend_cents;

    // Output
    signal output valid;

    // Constraint 1: actual_amount_cents <= max_spend_cents
    // LessEqThan(64) handles amounts up to 2^64 cents (~$184 trillion)
    component lte = LessEqThan(64);
    lte.in[0] <== actual_amount_cents;
    lte.in[1] <== max_spend_cents;

    // Constraint 2: limit_digest commits to max_spend_cents
    // This binds the public limit_digest to the private limit value
    component limit_hash = Poseidon(1);
    limit_hash.inputs[0] <== max_spend_cents;

    // Verify limit_digest[0] matches hash of max_spend_cents
    limit_digest[0] === limit_hash.out;
    // limit_digest[1] binds proof to this artifact
    limit_digest[1] === artifact_id[0];

    valid <== lte.out;
}

component main { public [artifact_id, limit_digest] } = SpendLimitChecker();
