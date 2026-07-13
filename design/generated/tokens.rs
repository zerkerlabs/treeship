// GENERATED from design/tokens.json by scripts/gen-design-tokens.py. DO NOT EDIT.
#![allow(dead_code)]

// Colors (hex string literals; parse at the render boundary).
pub const PAPER: &str = "#F1F0EA";
pub const PANEL: &str = "#EBEAE1";
pub const INK: &str = "#1F2329";
pub const MUTED: &str = "#5F646B";
pub const FAINT: &str = "#9B9B93";
pub const HAIR: &str = "#DAD8CD";
pub const HAIR_COOL: &str = "#CBCED0";
pub const STEEL: &str = "#37454F";
pub const BRONZE: &str = "#856733";
pub const BRONZE_HI: &str = "#C6A972";
pub const BRONZE_LO: &str = "#5E4923";
pub const VERDICT_PASS: &str = "#3B6A4E";
pub const VERDICT_FAIL: &str = "#9F4230";
pub const VERDICT_WARN: &str = "#8F5E1F";

/// A trust verdict. Each variant has exactly one word, color, and glyph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    FullPass,
    StructuralPass,
    Countersigned,
    Permitted,
    Anchored,
    Declared,
    SelfAsserted,
    Pending,
    Revoked,
    Unverified,
}

impl Verdict {
    pub const fn word(self) -> &'static str {
        match self {
            Verdict::FullPass => "full pass",
            Verdict::StructuralPass => "structural pass",
            Verdict::Countersigned => "countersigned",
            Verdict::Permitted => "permitted",
            Verdict::Anchored => "anchored",
            Verdict::Declared => "declared",
            Verdict::SelfAsserted => "self-asserted",
            Verdict::Pending => "pending",
            Verdict::Revoked => "revoked",
            Verdict::Unverified => "unverified",
        }
    }
    pub const fn glyph(self) -> &'static str {
        match self {
            Verdict::FullPass => "△",
            Verdict::StructuralPass => "△",
            Verdict::Countersigned => "△",
            Verdict::Permitted => "○",
            Verdict::Anchored => "◇",
            Verdict::Declared => "△",
            Verdict::SelfAsserted => "△",
            Verdict::Pending => "·",
            Verdict::Revoked => "✕",
            Verdict::Unverified => "✕",
        }
    }
    pub const fn color_hex(self) -> &'static str {
        match self {
            Verdict::FullPass => "#3B6A4E",
            Verdict::StructuralPass => "#3B6A4E",
            Verdict::Countersigned => "#3B6A4E",
            Verdict::Permitted => "#3B6A4E",
            Verdict::Anchored => "#3B6A4E",
            Verdict::Declared => "#8F5E1F",
            Verdict::SelfAsserted => "#8F5E1F",
            Verdict::Pending => "#5F646B",
            Verdict::Revoked => "#9F4230",
            Verdict::Unverified => "#9F4230",
        }
    }
}
