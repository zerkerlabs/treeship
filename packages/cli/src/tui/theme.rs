//! Central TUI palette + brand accents, grounded in design/tokens.json and
//! /DESIGN.md.
//!
//! Every view used to redefine the same color consts locally; this is the one
//! place they live now, so `treeship ui` stays consistent and can be themed
//! from a single seam.
//!
//! Trust-state colors keep vivid, terminal-legible values on purpose: a dim
//! `revoked` is a legibility bug, not a subtlety. Their hues track the verdict
//! families in design/tokens.json (pass / fail / warn). Brand accents come
//! straight from the tokens: bronze is the seal metal, used for the TREESHIP
//! wordmark; steel is the cool accent, brightened so it reads on a dark
//! terminal background (the token value #37454F is near-invisible there).

use ratatui::style::Color;

// --- Trust states (semantically load-bearing) ---
pub const PASS: Color = Color::Rgb(34, 197, 94);
pub const FAIL: Color = Color::Rgb(239, 68, 68);
pub const WARN: Color = Color::Rgb(250, 204, 21);
pub const INFO: Color = Color::Rgb(147, 197, 253);

// --- Text tiers ---
pub const TEXT: Color = Color::White;
pub const KEY: Color = Color::Rgb(180, 180, 180);
pub const DIM: Color = Color::Rgb(100, 100, 100);

// --- Brand accents (design/tokens.json) ---
/// The seal metal (#C6A972). Used for the TREESHIP wordmark.
pub const BRONZE: Color = Color::Rgb(198, 169, 114);
/// The cool accent (#37454F), brightened for legibility on a dark terminal.
pub const STEEL: Color = Color::Rgb(122, 148, 163);

// --- Aliases matching the names the views read at call sites ---
pub const GREEN: Color = PASS;
pub const RED: Color = FAIL;
pub const YELLOW: Color = WARN;
pub const BLUE: Color = INFO;
pub const WHITE: Color = TEXT;
pub const KEY_COLOR: Color = KEY;
