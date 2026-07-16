export interface ActionParams {
  actor: string;
  action: string;
  parentId?: string;
  approvalNonce?: string;
  meta?: Record<string, unknown>;
}

export interface ApprovalParams {
  approver: string;
  description: string;
  /** ISO-8601 timestamp when the approval expires (e.g. "2026-12-31T00:00:00Z"). */
  expires?: string;
  /** Maps to the CLI --subject flag. Identifies what this approval covers. */
  subject?: string;
}

export interface HandoffParams {
  from: string;
  to: string;
  artifacts: string[];
  approvals?: string[];
  obligations?: string[];
}

export interface DecisionParams {
  actor: string;
  model?: string;
  modelVersion?: string;
  tokensIn?: number;
  tokensOut?: number;
  promptDigest?: string;
  summary?: string;
  confidence?: number;
  parentId?: string;
}

export interface ActionResult {
  artifactId: string;
}

export interface ApprovalResult {
  artifactId: string;
  nonce: string;
}

export interface VerifyCheck {
  step: string;
  status: "pass" | "fail" | "warn";
  detail: string;
}

export interface VerifyReceiptResult {
  outcome: "pass" | "fail" | "error";
  checks: VerifyCheck[];
  session: {
    id: string;
    ship_id?: string;
    schema_version?: string;
    agent: string;
    duration_ms?: number;
    actions: number;
  };
  error_code?: string;
  message?: string;
}

export interface VerifyCertificateResult {
  outcome: "pass" | "fail" | "error";
  signature_valid: boolean;
  validity: "valid" | "expired" | "not_yet_valid" | "not_checked";
  certificate: {
    ship_id: string;
    agent_name: string;
    issued_at: string;
    valid_until: string;
    schema_version?: string;
  };
  error_code?: string;
  message?: string;
}

export interface CrossVerifyResult {
  outcome: "pass" | "fail" | "error";
  ok: boolean;
  ship_id_status: "match" | "mismatch" | "unknown";
  certificate_status: "valid" | "expired" | "not_yet_valid";
  certificate_signature_valid: boolean;
  authorized_tool_calls: string[];
  unauthorized_tool_calls: string[];
  authorized_tools_never_called: string[];
  error_code?: string;
  message?: string;
}

/**
 * Legacy VerifyResult shape (pre-v0.9.1). Preserved for backwards
 * compatibility with callers of the old VerifyModule.verify(artifactId)
 * path, which ships legacy-formatted chain counts. New code should prefer
 * VerifyReceiptResult.
 */
export interface VerifyResult {
  outcome: "pass" | "fail" | "error";
  chain: number;
  target: string;
}

export interface PushResult {
  hubUrl: string;
  rekorIndex?: number;
}

/** One certificate in a resolution bundle's chain. */
export interface ResolutionCert {
  artifact_id: string;
  /** An `agent_cert.v1` DSSE envelope object. */
  envelope: Record<string, unknown>;
}

/**
 * A resolution bundle: the signed bytes needed to decide whether an agent's
 * current card is trustworthy — the same shape the Hub serves and the CLI
 * re-verifies.
 */
export interface ResolutionBundleInput {
  agent: string;
  /** The agent's current `agent_card.v1` DSSE envelope object. */
  card: Record<string, unknown>;
  certs?: ResolutionCert[];
  /** `agent_card_revocation.v1` DSSE envelope objects. */
  revocations?: Record<string, unknown>[];
}

/** Result of `VerifyModule.verifyResolution`. Mirrors the WASM JSON output. */
export interface ResolutionVerdict {
  /** Card signature verified against your roots (directly or via the chain). */
  sig_ok: boolean;
  /** Card is key-bound: signer pinned under AgentCert, or chain-certified. */
  key_bound: boolean;
  /** If verified via the certificate chain, the cert artifact that vouched. */
  chain_cert_id: string | null;
  /** An authorized, verifying revocation was found. */
  revoked: boolean;
  revocation_reason: string | null;
  error_code?: string;
  message?: string;
}

/** The challenge-response outcome within a presentation. */
export interface PresentationChallenge {
  outcome:
    | "not_requested"
    | "present_but_unchecked"
    | "no_response"
    | "no_established_key"
    | "verified"
    | "failed";
  signed_at: string | null;
  reason: string | null;
}

/** The staple portion of a presentation verdict. */
export interface PresentationStaple {
  verified: boolean;
  status:
    | "no_staple"
    | "unparseable"
    | "signer_not_trusted"
    | "inclusion_invalid"
    | "verified";
  checkpoint_index: number | null;
  age_secs: number | null;
}

/** Result of `VerifyModule.verifyPresentation`. Mirrors the WASM JSON output. */
export interface PresentationVerdict {
  agent: string;
  card_id: string;
  sig_ok: boolean;
  key_bound: boolean;
  via_chain: boolean;
  revoked: string | null;
  challenge: PresentationChallenge;
  challenge_ok: boolean;
  staple: PresentationStaple;
  /** Roll-up: not revoked, key-bound, and (if requested) challenge verified. */
  ok: boolean;
  error_code?: string;
  message?: string;
}

export class TreeshipError extends Error {
  constructor(message: string, public readonly args: string[]) {
    super(message);
    this.name = "TreeshipError";
  }
}
