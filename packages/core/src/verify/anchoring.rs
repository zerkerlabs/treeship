//! Anchoring coverage: how much of a claimed timeline had an external witness.
//!
//! # Why this exists
//!
//! A receipt's timestamp comes from `SystemTime::now()` on the signing machine
//! and is signed with that machine's own key. It proves *"this key asserted
//! this"*, never *"this happened then"*. An actor holding its own key and
//! controlling its own clock can emit a chain claiming any timeline it likes.
//!
//! What constrains a timeline is an **anchor**: a record, held by someone
//! other than the actor, that a given digest existed at a given time. A Hub
//! checkpoint, a Rekor entry, an OpenTimestamps attestation. Anchors cannot be
//! obtained retroactively, so work that happened between two anchors is
//! bracketed by them.
//!
//! # What this reports, and why it is not a boolean
//!
//! `anchored: true` would flatten three materially different situations into
//! one word: a session witnessed every few minutes, a session witnessed once
//! at close, and a session witnessed never. Only the first constrains the
//! timeline. That flattening is the same defect as revocation resolving
//! `Unknown` and still reaching a passing exit code -- the honest detail
//! exists and the summary discards it.
//!
//! So the output carries [`AnchorCoverage::unwitnessed_span_seconds`]: the
//! longest stretch of claimed work with no external witness. For an
//! 11-hour session honestly anchored every 15 minutes that number is small.
//! For an 11-hour session fabricated at the end and anchored once, it is the
//! whole session -- whatever the receipts themselves claim.
//!
//! # What this does NOT prove
//!
//! Anchoring bounds *when a claim was made*, never whether the claim is true.
//! A receipt describing work that never happened, anchored punctually, is a
//! punctual lie. And a low coverage score is not evidence of wrongdoing:
//! offline work, air-gapped machines and network failures all produce
//! unanchored sessions. This reports the fact; the policy belongs to the
//! caller.
//!
//! Nor does it detect **omission** -- an actor presenting a shortened chain
//! and discarding the rest. That chain is honestly signed and honestly
//! anchored; catching it requires anchors discoverable by identity, which is
//! the transparency log's property. See `docs/specs/time-anchoring.md`.

use serde::{Deserialize, Serialize};

/// How a claimed timeline relates to its external witnesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Coverage {
    /// No anchors at all. The timeline rests entirely on the actor's own
    /// clock and key. Not an accusation -- offline work looks like this.
    None,
    /// Anchors exist, but none of them falls inside the work. Everything
    /// before the first anchor is unconstrained, which for a
    /// single-anchor-at-close session is the entire timeline.
    EndpointOnly,
    /// Anchors interleave with the work, so stretches between them are
    /// bracketed. `unwitnessed_span_seconds` says how coarsely.
    Periodic,
}

/// One external witness: someone other than the actor recorded that a digest
/// existed at a time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    /// Unix seconds at which the witness recorded the digest. This is the
    /// witness's clock, not the actor's -- that is the entire point.
    pub at: i64,
    /// Which mechanism produced it: "hub", "rekor", "ots", "tsa".
    pub mechanism: String,
}

/// The anchoring picture for one session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorCoverage {
    pub coverage: Coverage,
    /// The longest stretch of claimed work with no external witness. The
    /// number a caller gating on time should read.
    pub unwitnessed_span_seconds: i64,
    /// Total claimed duration, for context: an unwitnessed span of 600s means
    /// something different across a 10-minute session than a 10-hour one.
    pub claimed_span_seconds: i64,
    pub anchor_count: usize,
    /// Distinct mechanisms, sorted. Mechanisms fail differently -- a Hub
    /// anchor needs the Hub trusted, an OTS anchor does not -- so which ones
    /// were used is part of the answer.
    pub mechanisms: Vec<String>,
}

impl AnchorCoverage {
    /// Compute coverage from claimed event times and the anchors witnessing
    /// them. Both are unix seconds; `event_times` need not be sorted.
    ///
    /// The unwitnessed span is the widest gap in the sequence
    /// `[work_start, ..anchors inside the work.., work_end]`. So:
    ///
    /// * no anchors -> the whole session is one unwitnessed span;
    /// * one anchor at close -> everything before it is unwitnessed, which is
    ///   the correct reading: an anchor at the end says nothing about when the
    ///   middle was written;
    /// * anchors every N seconds -> roughly N.
    ///
    /// Anchors outside the work window are counted (they are real witnesses)
    /// but cannot shrink an interior gap, which is why a close-time anchor
    /// does not rescue an unwitnessed session.
    pub fn compute(event_times: &[i64], anchors: &[Anchor]) -> Self {
        let mut mechanisms: Vec<String> = anchors.iter().map(|a| a.mechanism.clone()).collect();
        mechanisms.sort();
        mechanisms.dedup();

        // No events means no claimed timeline to witness. Reporting a
        // confident zero here would be a vacuous pass -- there is nothing to
        // be confident about.
        let (Some(&start), Some(&end)) = (event_times.iter().min(), event_times.iter().max())
        else {
            return Self {
                coverage: Coverage::None,
                unwitnessed_span_seconds: 0,
                claimed_span_seconds: 0,
                anchor_count: anchors.len(),
                mechanisms,
            };
        };

        let claimed = (end - start).max(0);

        if anchors.is_empty() {
            return Self {
                coverage: Coverage::None,
                unwitnessed_span_seconds: claimed,
                claimed_span_seconds: claimed,
                anchor_count: 0,
                mechanisms,
            };
        }

        // Only anchors strictly inside the work window subdivide it. One at or
        // before the start, or at or after the end, brackets the session
        // without constraining anything within it.
        let mut interior: Vec<i64> = anchors
            .iter()
            .map(|a| a.at)
            .filter(|&t| t > start && t < end)
            .collect();
        interior.sort_unstable();

        let coverage = if interior.is_empty() {
            Coverage::EndpointOnly
        } else {
            Coverage::Periodic
        };

        let mut widest = 0i64;
        let mut prev = start;
        for t in &interior {
            widest = widest.max(t - prev);
            prev = *t;
        }
        widest = widest.max(end - prev);

        Self {
            coverage,
            unwitnessed_span_seconds: widest,
            claimed_span_seconds: claimed,
            anchor_count: anchors.len(),
            mechanisms,
        }
    }

    /// Whether this satisfies a caller's maximum tolerated unwitnessed span.
    ///
    /// A session with no claimed work cannot violate a bound -- there is no
    /// timeline to have fabricated.
    pub fn within(&self, max_unwitnessed_seconds: i64) -> bool {
        self.claimed_span_seconds == 0 || self.unwitnessed_span_seconds <= max_unwitnessed_seconds
    }

    /// One line for humans, phrased so it cannot be misread as a guarantee.
    pub fn summary(&self) -> String {
        match self.coverage {
            Coverage::None if self.claimed_span_seconds == 0 => "no timeline to anchor".to_string(),
            Coverage::None => format!(
                "UNWITNESSED — {} of claimed work with no external anchor; \
                 the timeline rests on the signer's own clock",
                human(self.claimed_span_seconds)
            ),
            Coverage::EndpointOnly => format!(
                "endpoint-only — {} anchor(s), none during the work; \
                 {} unwitnessed",
                self.anchor_count,
                human(self.unwitnessed_span_seconds)
            ),
            Coverage::Periodic => format!(
                "anchored — {} anchor(s) via {}; longest unwitnessed span {}",
                self.anchor_count,
                self.mechanisms.join("+"),
                human(self.unwitnessed_span_seconds)
            ),
        }
    }
}

fn human(secs: i64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s => format!("{}h{:02}m", s / 3600, (s % 3600) / 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor(at: i64) -> Anchor {
        Anchor {
            at,
            mechanism: "hub".into(),
        }
    }

    const H: i64 = 3600;

    /// The scenario the spec is written around: 11 hours of work presented as
    /// 4. Whichever way it is told, coverage is what distinguishes the honest
    /// session from the fabricated one -- not the receipts, which are equally
    /// well signed in both.
    #[test]
    fn fabricated_session_reports_the_whole_span_unwitnessed() {
        // Eleven hours of claimed work, one anchor when it was all over.
        let events: Vec<i64> = (0..=11).map(|h| h * H).collect();
        let c = AnchorCoverage::compute(&events, &[anchor(11 * H)]);

        assert_eq!(c.coverage, Coverage::EndpointOnly);
        assert_eq!(c.unwitnessed_span_seconds, 11 * H);
        assert!(!c.within(H), "an 11h unwitnessed span must fail a 1h bound");
    }

    #[test]
    fn honest_session_anchored_throughout_reports_the_interval() {
        let events: Vec<i64> = (0..=11).map(|h| h * H).collect();
        // Anchored every hour, including one after close.
        let anchors: Vec<Anchor> = (1..=11).map(|h| anchor(h * H)).collect();
        let c = AnchorCoverage::compute(&events, &anchors);

        assert_eq!(c.coverage, Coverage::Periodic);
        assert_eq!(c.unwitnessed_span_seconds, H);
        assert!(c.within(2 * H));
        assert!(!c.within(H / 2));
    }

    /// An anchor at close must not rescue the session. This is the case a
    /// boolean `anchored: true` would get wrong, and the reason this module
    /// reports a span instead.
    #[test]
    fn closing_anchor_does_not_shrink_the_interior_gap() {
        let events = vec![0, 4 * H];
        let with = AnchorCoverage::compute(&events, &[anchor(4 * H)]);
        let without = AnchorCoverage::compute(&events, &[]);

        assert_eq!(
            with.unwitnessed_span_seconds, without.unwitnessed_span_seconds,
            "an anchor at close constrains nothing inside the session"
        );
        // It is still a real witness, so it is still counted and still
        // changes the classification.
        assert_eq!(with.anchor_count, 1);
        assert_eq!(with.coverage, Coverage::EndpointOnly);
        assert_eq!(without.coverage, Coverage::None);
    }

    #[test]
    fn no_anchors_reports_the_entire_claimed_span() {
        let c = AnchorCoverage::compute(&[0, 4 * H], &[]);
        assert_eq!(c.coverage, Coverage::None);
        assert_eq!(c.unwitnessed_span_seconds, 4 * H);
        assert!(c.summary().contains("UNWITNESSED"));
    }

    /// An empty timeline has nothing to fabricate, so it must not be reported
    /// as a violation -- but it must not be reported as *proven* either.
    #[test]
    fn empty_timeline_is_neither_a_pass_nor_a_violation() {
        let c = AnchorCoverage::compute(&[], &[]);
        assert_eq!(c.claimed_span_seconds, 0);
        assert!(c.within(0));
        assert_eq!(c.coverage, Coverage::None);
        assert!(!c.summary().contains("UNWITNESSED"));
    }

    #[test]
    fn unsorted_events_are_handled() {
        let jumbled = vec![3 * H, 0, 2 * H, H];
        let ordered = vec![0, H, 2 * H, 3 * H];
        assert_eq!(
            AnchorCoverage::compute(&jumbled, &[anchor(90 * 60)]),
            AnchorCoverage::compute(&ordered, &[anchor(90 * 60)]),
        );
    }

    #[test]
    fn mechanisms_are_deduped_and_sorted() {
        let events = vec![0, 4 * H];
        let anchors = vec![
            Anchor {
                at: H,
                mechanism: "rekor".into(),
            },
            Anchor {
                at: 2 * H,
                mechanism: "hub".into(),
            },
            Anchor {
                at: 3 * H,
                mechanism: "rekor".into(),
            },
        ];
        let c = AnchorCoverage::compute(&events, &anchors);
        assert_eq!(c.mechanisms, vec!["hub", "rekor"]);
        assert_eq!(c.anchor_count, 3);
    }

    /// A single instant of work is a degenerate timeline, not a fabricated
    /// one. Reporting a negative or nonsense span here would be worse than
    /// reporting zero.
    #[test]
    fn single_event_has_no_span_to_fabricate() {
        let c = AnchorCoverage::compute(&[1000], &[]);
        assert_eq!(c.claimed_span_seconds, 0);
        assert_eq!(c.unwitnessed_span_seconds, 0);
        assert!(c.within(0));
    }
}
