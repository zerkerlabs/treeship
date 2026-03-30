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
  expiresIn?: string;  // "1h", "30m"
  scope?: string;
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
