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
  // "unverified" (AUD-01): the receipt is internally consistent (Merkle root,
  // inclusion proofs, timeline) but no signature was verified against a trust
  // root — structural checks alone cannot establish authenticity.
  outcome: "pass" | "fail" | "error" | "unverified";
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

// Compile-time regression guard (AUD-01): core-wasm's verify_receipt emits
// "unverified" for a receipt whose signature was not verified against a trust
// root. If the union above ever drops that member, this fails to compile.
type _AssertTrue<T extends true> = T;
type _Aud01ReceiptOutcomeHasUnverified = _AssertTrue<
  "unverified" extends VerifyReceiptResult["outcome"] ? true : false
>;

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

export class TreeshipError extends Error {
  constructor(message: string, public readonly args: string[]) {
    super(message);
    this.name = "TreeshipError";
  }
}
