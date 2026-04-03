pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

/**
 * Policy Checker Circuit (Treeship v0.5.0)
 *
 * Proves: an artifact's action is in a set of allowed actions.
 * Without revealing: the full set of allowed actions (the policy).
 *
 * Public inputs: artifact_id_hash, policy_digest
 * Private inputs: action_hash, allowed[], n_allowed
 * Output: valid (1 if action in allowed set)
 */
template PolicyChecker(MAX_ACTIONS) {
    // Public inputs
    signal input artifact_id_hash;
    signal input policy_digest;

    // Private inputs
    signal input action_hash;
    signal input allowed[MAX_ACTIONS];
    signal input n_allowed;

    // Output
    signal output valid;

    // Check: action_hash appears in allowed[]
    signal match[MAX_ACTIONS];
    signal running[MAX_ACTIONS + 1];
    running[0] <== 0;

    component eq[MAX_ACTIONS];
    for (var i = 0; i < MAX_ACTIONS; i++) {
        eq[i] = IsEqual();
        eq[i].in[0] <== action_hash;
        eq[i].in[1] <== allowed[i];
        match[i] <== eq[i].out;
        running[i + 1] <== running[i] + match[i];
    }

    // valid = 1 if at least one match was found
    component isPositive = GreaterThan(8);
    isPositive.in[0] <== running[MAX_ACTIONS];
    isPositive.in[1] <== 0;
    valid <== isPositive.out;

    // Verify policy digest matches the allowed actions
    component policy_hasher = Poseidon(MAX_ACTIONS);
    for (var i = 0; i < MAX_ACTIONS; i++) {
        policy_hasher.inputs[i] <== allowed[i];
    }
    policy_digest === policy_hasher.out;
}

component main { public [artifact_id_hash, policy_digest] } = PolicyChecker(16);
