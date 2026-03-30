import { runTreeship } from "./exec.js";
import type { ActionParams, ApprovalParams, HandoffParams, DecisionParams, ActionResult, ApprovalResult } from "./types.js";

export class AttestModule {
  async action(params: ActionParams): Promise<ActionResult> {
    const args = ["attest", "action", "--actor", params.actor, "--action", params.action, "--format", "json"];
    if (params.parentId) args.push("--parent", params.parentId);
    if (params.approvalNonce) args.push("--approval-nonce", params.approvalNonce);
    if (params.meta) args.push("--meta", JSON.stringify(params.meta));
    const result = await runTreeship(args);
    return { artifactId: (result.id || result.artifact_id) as string };
  }

  async approval(params: ApprovalParams): Promise<ApprovalResult> {
    const args = ["attest", "approval", "--approver", params.approver, "--description", params.description, "--format", "json"];
    if (params.expiresIn) args.push("--expires", params.expiresIn);
    const result = await runTreeship(args);
    return { artifactId: (result.id || result.artifact_id) as string, nonce: result.nonce as string };
  }

  async handoff(params: HandoffParams): Promise<ActionResult> {
    const args = ["attest", "handoff", "--from", params.from, "--to", params.to, "--artifacts", params.artifacts.join(","), "--format", "json"];
    if (params.approvals?.length) args.push("--approvals", params.approvals.join(","));
    if (params.obligations?.length) args.push("--obligations", params.obligations.join(","));
    const result = await runTreeship(args);
    return { artifactId: (result.id || result.artifact_id) as string };
  }

  async decision(params: DecisionParams): Promise<ActionResult> {
    const args = ["attest", "decision", "--actor", params.actor, "--format", "json"];
    if (params.model) args.push("--model", params.model);
    if (params.tokensIn) args.push("--tokens-in", String(params.tokensIn));
    if (params.tokensOut) args.push("--tokens-out", String(params.tokensOut));
    if (params.promptDigest) args.push("--prompt-digest", params.promptDigest);
    if (params.summary) args.push("--summary", params.summary);
    if (params.confidence) args.push("--confidence", String(params.confidence));
    if (params.parentId) args.push("--parent", params.parentId);
    const result = await runTreeship(args);
    return { artifactId: (result.id || result.artifact_id) as string };
  }
}
