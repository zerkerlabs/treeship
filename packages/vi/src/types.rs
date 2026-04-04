//! Core Verifiable Intent types.
//!
//! These map to the VI credential chain: L1 (Issuer) -> L2 (User) -> L3 (Agent).
//! All types are data-only with Serialize/Deserialize. Logic comes later.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// L1: Issuer Credential (SD-JWT from the issuing bank or payment network)
// ---------------------------------------------------------------------------

/// L1 issuer credential. Represents the bank or payment network's assertion
/// that a user holds a valid account or instrument.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L1Credential {
    /// Credential identifier (e.g. SD-JWT `jti`)
    pub id: String,
    /// Issuer identifier (e.g. bank DID or URL)
    pub issuer: String,
    /// Subject identifier (the user)
    pub subject: String,
    /// Payment instrument this credential covers
    pub instrument: PaymentInstrument,
    /// Issuance timestamp (seconds since epoch)
    pub issued_at: u64,
    /// Expiry timestamp (seconds since epoch)
    pub expires_at: u64,
    /// Raw SD-JWT (opaque to Treeship, passed through)
    pub raw_sdjwt: Option<String>,
}

// ---------------------------------------------------------------------------
// L2: User Mandate
// ---------------------------------------------------------------------------

/// L2 user mandate. The user creates this to delegate bounded authority
/// to an agent for checkout and/or payment operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2Mandate {
    /// Mandate identifier
    pub id: String,
    /// Reference to the L1 credential this mandate is rooted in
    pub l1_credential_id: String,
    /// The user (delegator) identifier
    pub user: String,
    /// The agent (delegatee) identifier
    pub agent: String,
    /// Confirmation method binding the agent's key to this mandate
    pub cnf: AgentKeyBinding,
    /// Checkout constraints (what the agent may check out)
    pub checkout: Option<CheckoutConstraint>,
    /// Payment constraints (spending limits and allowed methods)
    pub payment: Option<PaymentConstraint>,
    /// Issuance timestamp
    pub issued_at: u64,
    /// Expiry timestamp
    pub expires_at: u64,
}

// ---------------------------------------------------------------------------
// L3a: Agent Payment Credential
// ---------------------------------------------------------------------------

/// L3a credential issued by an agent (or Treeship on behalf of an agent)
/// to execute a payment within the bounds of the L2 mandate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L3aPayment {
    /// Credential identifier
    pub id: String,
    /// Reference to the L2 mandate
    pub mandate_id: String,
    /// Agent identifier
    pub agent: String,
    /// Payment amount in minor units (e.g. cents)
    pub amount_minor: u64,
    /// ISO 4217 currency code
    pub currency: String,
    /// Recipient or merchant identifier
    pub recipient: String,
    /// Treeship attestation for this credential
    pub agent_attestation: Option<AgentAttestation>,
    /// Issuance timestamp
    pub issued_at: u64,
}

// ---------------------------------------------------------------------------
// L3b: Agent Checkout Credential
// ---------------------------------------------------------------------------

/// L3b credential for checkout operations (cart assembly, address selection,
/// shipping choice) within the bounds of the L2 mandate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L3bCheckout {
    /// Credential identifier
    pub id: String,
    /// Reference to the L2 mandate
    pub mandate_id: String,
    /// Agent identifier
    pub agent: String,
    /// Merchant or platform identifier
    pub merchant: String,
    /// Cart items (opaque JSON blobs for now)
    pub cart_items: Vec<serde_json::Value>,
    /// Shipping address hash (privacy-preserving)
    pub shipping_address_hash: Option<String>,
    /// Treeship attestation for this credential
    pub agent_attestation: Option<AgentAttestation>,
    /// Issuance timestamp
    pub issued_at: u64,
}

// ---------------------------------------------------------------------------
// Constraints
// ---------------------------------------------------------------------------

/// Checkout constraints define what an agent is allowed to purchase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutConstraint {
    /// Allowed merchant identifiers (empty means any)
    pub allowed_merchants: Vec<String>,
    /// Allowed product categories (empty means any)
    pub allowed_categories: Vec<String>,
    /// Maximum number of items per checkout
    pub max_items: Option<u32>,
}

/// Payment constraints define how much and how an agent may spend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentConstraint {
    /// Maximum amount in minor units per transaction
    pub max_amount_minor: u64,
    /// ISO 4217 currency code
    pub currency: String,
    /// Allowed payment methods (e.g. "card", "lobster_cash", "x402")
    pub allowed_methods: Vec<String>,
    /// Maximum number of transactions under this mandate
    pub max_transactions: Option<u32>,
}

// ---------------------------------------------------------------------------
// Agent Key Binding
// ---------------------------------------------------------------------------

/// Binds an agent's public key to a mandate so only that agent can use it.
/// Follows the `cnf` (confirmation) pattern from SD-JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentKeyBinding {
    /// Key identifier
    pub kid: String,
    /// JWK thumbprint of the agent's public key
    pub jwk_thumbprint: String,
    /// Algorithm (e.g. "ES256" for P-256)
    pub alg: String,
}

// ---------------------------------------------------------------------------
// Agent Attestation (Treeship extension)
// ---------------------------------------------------------------------------

/// Treeship's attestation embedded in every L3 credential.
/// This is how Treeship plugs into the VI chain: the agent runtime
/// attests that it verified constraints and operated within bounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAttestation {
    /// Treeship attestation ID (links to the Treeship receipt store)
    pub attestation_id: String,
    /// Treeship session ID
    pub session_id: String,
    /// The agent that produced this credential
    pub agent_id: String,
    /// Hash of the L2 mandate that was verified
    pub mandate_hash: String,
    /// Hash of the L3 credential body (before attestation was attached)
    pub credential_hash: String,
    /// Whether all constraints were satisfied
    pub constraints_satisfied: bool,
    /// ZK proof reference (if a zero-knowledge proof of constraint
    /// satisfaction was generated)
    pub zk_proof_ref: Option<String>,
    /// Treeship signature over the attestation fields
    pub signature: String,
    /// Timestamp
    pub attested_at: u64,
    /// Additional metadata
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Payment Instrument
// ---------------------------------------------------------------------------

/// A payment instrument referenced by an L1 credential.
/// Details are intentionally minimal; the real instrument data
/// lives in the issuer's SD-JWT selective disclosures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentInstrument {
    /// Instrument type (e.g. "card", "account", "lobster_cash")
    pub instrument_type: String,
    /// Last four digits or truncated identifier (for display only)
    pub display_suffix: Option<String>,
    /// Network (e.g. "visa", "mastercard", "base", "solana")
    pub network: Option<String>,
}
