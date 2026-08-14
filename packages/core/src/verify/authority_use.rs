//! Granted versus exercised: what a chain was authorized to do, next to what
//! it actually did.
//!
//! # Why this exists
//!
//! Verification checks that every action fell *inside* its mandate's scope --
//! `exercised ⊆ granted`. That is the safety property, and it is the only
//! thing reported. The remainder, `granted \ exercised`, is computed by
//! nobody and shown to nobody.
//!
//! That remainder is the difference between two rooms a reader currently
//! cannot tell apart. An agent that could deploy to staging and deployed to
//! staging, and an agent that could deploy to staging *and production* and
//! deployed to staging, produce receipts that are identical in every
//! reported field. The second was one defect away from a different run, and
//! nothing in the log says so, because nothing happened.
//!
//! Latent authority is the thing that shows up in an incident review as "wait,
//! it could do *what*?". It is free to report -- both sides are already in the
//! signed bytes -- and it is reported nowhere.
//!
//! # What this is not
//!
//! Dormant capability is **not a finding**. A grant scoped to a family
//! (`deploy.*`) will nearly always show dormant members, and narrowing every
//! grant to exactly what was used is only possible in hindsight. This is a
//! number for a reader to weigh, not a rule to fail.
//!
//! `out_of_scope` is different: an action outside every mandate that covered
//! it is a real violation, and the mandate verdict already fails for it. It
//! appears here so the two views cannot disagree silently.

use serde::{Deserialize, Serialize};

use crate::statements::action_in_scope;

/// What a chain was permitted to do, set against what it did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityUse {
    /// Every distinct scope entry across the chain's mandates, sorted.
    pub granted: Vec<String>,
    /// Every distinct action actually performed, sorted.
    pub exercised: Vec<String>,
    /// Granted entries no action matched. Latent capability, not a defect.
    pub dormant: Vec<String>,
    /// Actions matching no granted entry. A violation; the mandate verdict
    /// fails independently, and this makes the two views reconcilable.
    pub out_of_scope: Vec<String>,
}

impl AuthorityUse {
    /// Compute from the chain's mandate scopes and the actions performed.
    ///
    /// Matching uses [`action_in_scope`], the same predicate the verifier
    /// judges with, so this cannot report an action as dormant-adjacent that
    /// the verifier considered in scope, or vice versa. A separate
    /// reimplementation here would eventually disagree, and the disagreement
    /// would be invisible.
    pub fn compute(scopes: &[String], actions: &[String]) -> Self {
        let granted = sorted_unique(scopes);
        let exercised = sorted_unique(actions);

        let dormant = granted
            .iter()
            .filter(|entry| {
                // A scope entry is dormant when no action it covers ran. For a
                // glob this means the whole family went unused, which is the
                // honest reading: `deploy.*` with only `deploy.staging` used
                // is exercised, not dormant, because narrowing it would need
                // hindsight about which members were reachable.
                !exercised
                    .iter()
                    .any(|a| action_in_scope(a, std::slice::from_ref(*entry)))
            })
            .cloned()
            .collect();

        let out_of_scope = exercised
            .iter()
            .filter(|a| !action_in_scope(a, &granted))
            .cloned()
            .collect();

        Self {
            granted,
            exercised,
            dormant,
            out_of_scope,
        }
    }

    /// True when the chain used everything it was given. Rare, and not a goal
    /// -- reported so a reader can see the unusual case rather than infer it.
    pub fn fully_exercised(&self) -> bool {
        !self.granted.is_empty() && self.dormant.is_empty()
    }

    /// One line for humans. Phrased so dormant capability reads as a fact to
    /// weigh, not an accusation, while `out_of_scope` reads as the violation
    /// it is.
    pub fn summary(&self) -> String {
        if self.granted.is_empty() {
            return "no mandate scope on this chain".to_string();
        }
        let mut s = format!(
            "{} of {} granted capabilit{} exercised",
            self.granted.len() - self.dormant.len(),
            self.granted.len(),
            if self.granted.len() == 1 { "y" } else { "ies" }
        );
        if !self.dormant.is_empty() {
            s.push_str(&format!("; dormant: {}", self.dormant.join(", ")));
        }
        if !self.out_of_scope.is_empty() {
            s.push_str(&format!("; OUT OF SCOPE: {}", self.out_of_scope.join(", ")));
        }
        s
    }
}

fn sorted_unique(v: &[String]) -> Vec<String> {
    let mut out: Vec<String> = v.to_vec();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// The case the whole module exists for: two chains whose every other
    /// reported field is identical, distinguished only by what went unused.
    #[test]
    fn narrow_and_broad_grants_are_distinguishable() {
        let narrow = AuthorityUse::compute(&s(&["deploy.staging"]), &s(&["deploy.staging"]));
        let broad = AuthorityUse::compute(
            &s(&["deploy.staging", "deploy.production"]),
            &s(&["deploy.staging"]),
        );

        assert!(narrow.dormant.is_empty());
        assert_eq!(broad.dormant, s(&["deploy.production"]));
        assert_eq!(narrow.exercised, broad.exercised);
        assert_ne!(
            narrow, broad,
            "identical actions under different grants must not compare equal"
        );
        assert!(broad.summary().contains("deploy.production"));
    }

    /// A glob whose family was used is exercised, not dormant. Calling it
    /// dormant would demand hindsight about which members were reachable.
    #[test]
    fn a_used_glob_family_is_not_dormant() {
        let u = AuthorityUse::compute(&s(&["payments.*"]), &s(&["payments.refund"]));
        assert!(u.dormant.is_empty(), "{:?}", u.dormant);
        assert!(u.out_of_scope.is_empty());
    }

    #[test]
    fn an_entirely_unused_glob_family_is_dormant() {
        let u = AuthorityUse::compute(&s(&["payments.*", "read.repo"]), &s(&["read.repo"]));
        assert_eq!(u.dormant, s(&["payments.*"]));
    }

    /// Must agree with the verifier. Reporting an action as in-scope that the
    /// mandate verdict failed -- or the reverse -- would leave two views of
    /// the same chain disagreeing with nobody noticing.
    #[test]
    fn out_of_scope_matches_the_verifier_predicate() {
        let u = AuthorityUse::compute(&s(&["read.*"]), &s(&["read.repo", "deploy.production"]));
        assert_eq!(u.out_of_scope, s(&["deploy.production"]));
        // And confirm directly against the shared predicate.
        assert!(!action_in_scope("deploy.production", &s(&["read.*"])));
        assert!(action_in_scope("read.repo", &s(&["read.*"])));
    }

    /// A bare `*` is deliberately not a wildcard in `action_in_scope`. If this
    /// module treated it as one, it would report a chain as fully exercised
    /// while the verifier rejected every action in it.
    #[test]
    fn bare_star_is_not_treated_as_a_wildcard() {
        let u = AuthorityUse::compute(&s(&["*"]), &s(&["deploy.production"]));
        assert_eq!(u.out_of_scope, s(&["deploy.production"]));
        assert_eq!(u.dormant, s(&["*"]));
    }

    #[test]
    fn duplicates_across_hops_collapse() {
        let u = AuthorityUse::compute(
            &s(&["read.repo", "read.repo", "edit.src"]),
            &s(&["read.repo", "read.repo"]),
        );
        assert_eq!(u.granted, s(&["edit.src", "read.repo"]));
        assert_eq!(u.exercised, s(&["read.repo"]));
        assert_eq!(u.dormant, s(&["edit.src"]));
    }

    /// An empty scope authorizes nothing, so every action is out of scope --
    /// and `fully_exercised` must not read true just because nothing is
    /// dormant when nothing was granted.
    #[test]
    fn empty_scope_authorizes_nothing() {
        let u = AuthorityUse::compute(&[], &s(&["read.repo"]));
        assert!(u.granted.is_empty());
        assert_eq!(u.out_of_scope, s(&["read.repo"]));
        assert!(!u.fully_exercised());
        assert!(u.summary().contains("no mandate scope"));
    }

    #[test]
    fn a_chain_that_used_everything_says_so() {
        let u = AuthorityUse::compute(&s(&["a.one", "b.two"]), &s(&["a.one", "b.two"]));
        assert!(u.fully_exercised());
        assert!(!u.summary().contains("dormant"));
    }
}
