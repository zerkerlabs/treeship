import {
  attestAction,
  attestHandoff,
  attestReceipt,
  currentSessionId,
  provisionAgentKey,
} from './attest.js';
import { gateInbound, mintChallenge } from './gate.js';
import type { GateResultLike } from './gate.js';
import { hashPayload, stableStringify } from './utils.js';
import type {
  AdmitTaskContext,
  HandoffContext,
  TaskAttestationResult,
  TaskCompletedContext,
  TaskReceivedContext,
  TreeshipA2AOptions,
} from './types.js';

/**
 * Framework-agnostic Treeship middleware for A2A servers.
 *
 * The middleware is intentionally hook-based — it does not import any
 * particular A2A SDK. Wire `onTaskReceived`, `onTaskCompleted`, and
 * `onHandoff` into whichever A2A server you run, then call
 * `decorateArtifact()` on the artifact you return to the caller.
 *
 * Failures never throw. Treeship attestation must never break the agent path.
 */
/**
 * Thrown when a task from another agent reaches `onTaskReceived` without
 * having passed `admitTask` first.
 *
 * This is the one error this package raises on purpose. Everything else here
 * swallows failures because attestation must never break the agent path; a
 * task from a foreign actor that was never gated is not an attestation
 * problem, it is unverified work about to run.
 */
export class ForeignWorkNotGatedError extends Error {
  readonly taskId: string;
  readonly fromAgent: string;

  constructor(taskId: string, fromAgent: string) {
    super(
      `refusing task ${taskId} from ${fromAgent}: call admitTask() first. ` +
        'Mint a nonce with mintTaskChallenge(), have the sender answer it with ' +
        '`treeship present <actor> --challenge <nonce>`, then pass the presentation ' +
        'to admitTask(). To accept unverified foreign work, set TREESHIP_A2A_UNVERIFIED=1 ' +
        '(the receipt will record that the gate was skipped).',
    );
    this.name = 'ForeignWorkNotGatedError';
    this.taskId = taskId;
    this.fromAgent = fromAgent;
  }
}

export class TreeshipA2AMiddleware {
  readonly shipId: string;
  readonly actor: string;
  readonly receiptBaseUrl: string;
  private readonly attestComplete: boolean;
  private readonly attestHandoffs: boolean;
  private readonly publishReceipt: boolean;

  /** intentId per active task — used to chain receipts. */
  private readonly intents = new Map<string, string>();

  /** Nonce this ship minted per task. Never a caller-supplied value. */
  private readonly challenges = new Map<string, string>();

  /** Gate outcome per task, so the intent artifact can record it. */
  private readonly gateStatus = new Map<string, 'verified' | 'unverified'>();

  constructor(opts: TreeshipA2AOptions) {
    if (!opts.shipId) throw new Error('TreeshipA2AMiddleware: shipId is required');
    this.shipId = opts.shipId;
    this.actor = opts.actor ?? `agent://a2a-${opts.shipId}`;
    this.receiptBaseUrl = (opts.receiptBaseUrl ?? 'https://treeship.dev/receipt').replace(/\/$/, '');
    this.attestComplete = opts.attestOnTaskComplete ?? true;
    this.attestHandoffs = opts.attestOnHandoff ?? true;
    this.publishReceipt = opts.publishReceipt ?? true;

    // Provision this agent's per-agent key so its receipts are key-bound and
    // its actor verifies as `proven` rather than `asserted`. Fire-and-forget:
    // it must not make the constructor async or block agent setup, and it is
    // idempotent + best-effort (a missing/uninitialized CLI is swallowed). The
    // key is needed before the first attestation; provisioning is fast and the
    // worst case (a race on the very first task) is one `asserted` receipt.
    void provisionAgentKey(this.actor);
  }

  /**
   * Mint the challenge nonce this ship will require for one inbound task.
   *
   * Hand the returned nonce to the calling agent; it must produce a
   * presentation answering *this* nonce. Returns null when the CLI cannot
   * mint one, which `admitTask` treats as a refusal rather than inventing a
   * nonce whose freshness this process guessed at.
   */
  async mintTaskChallenge(taskId: string): Promise<string | null> {
    const nonce = await mintChallenge();
    if (nonce) this.challenges.set(taskId, nonce);
    return nonce;
  }

  /**
   * Decide whether inbound foreign work runs at all. Call this BEFORE
   * executing the task, and do not execute when `allowed` is false.
   *
   * Unlike every other method on this class, this one is allowed to withhold
   * the agent path. Attestation must never break the work; the gate exists to
   * break it. A gate that could not run refuses.
   */
  async admitTask(ctx: AdmitTaskContext): Promise<GateResultLike> {
    const result = await gateInbound({
      presentationPath: ctx.presentationPath,
      challenge: this.challenges.get(ctx.taskId),
      maxStapleAge: ctx.maxStapleAge,
    });

    if (result.allowed) {
      this.gateStatus.set(ctx.taskId, result.unverified ? 'unverified' : 'verified');
      if (result.unverified) {
        // The opt-out fired. Record the skip as its own signed action: a
        // skipped gate that leaves no artifact reads exactly like a gate that
        // passed, which is the failure this whole path exists to prevent.
        await attestAction({
          actor: this.actor,
          action: 'a2a.gate.skipped',
          meta: {
            a2a_task_id: ctx.taskId,
            ship_id: this.shipId,
            session_id: currentSessionId(),
            reason: result.reason,
          },
        });
      }
      return result;
    }

    // Refusals are evidence too. Without this, "refused the work" and "never
    // received the work" are the same silence in the log.
    await attestAction({
      actor: this.actor,
      action: 'a2a.gate.refused',
      meta: {
        a2a_task_id: ctx.taskId,
        ship_id: this.shipId,
        session_id: currentSessionId(),
        refusal: result.refusal,
        detail: result.message,
      },
    });
    this.challenges.delete(ctx.taskId);
    return result;
  }

  /**
   * Call when an A2A task arrives. Records an intent artifact so the eventual
   * receipt can chain back to it. Awaited — proof of what was about to happen.
   */
  async onTaskReceived(ctx: TaskReceivedContext): Promise<string | undefined> {
    // Foreign work that was never gated must not slip through as `not_gated`.
    // An integration that forgets to call `admitTask` would otherwise get
    // exactly today's behaviour, which is the failure this whole path exists
    // to remove: the gate has to be the default, not an available option.
    if (ctx.fromAgent && !this.gateStatus.has(ctx.taskId)) {
      throw new ForeignWorkNotGatedError(ctx.taskId, ctx.fromAgent);
    }
    const intentId = await attestAction({
      actor: this.actor,
      action: `a2a.task.${ctx.skill ?? 'unknown'}.intent`,
      meta: {
        a2a_task_id: ctx.taskId,
        a2a_skill: ctx.skill,
        a2a_message_id: ctx.messageId,
        from_agent: ctx.fromAgent,
        ship_id: this.shipId,
        session_id: currentSessionId(),
        gate_status: ctx.gateStatus ?? this.gateStatus.get(ctx.taskId) ?? 'not_gated',
      },
    });
    if (intentId) this.intents.set(ctx.taskId, intentId);
    return intentId;
  }

  /**
   * Call when an A2A task finishes. Returns IDs the caller can stamp into
   * artifact metadata. Fire-and-forget at the call site is fine — failures
   * are swallowed internally.
   */
  async onTaskCompleted(ctx: TaskCompletedContext): Promise<TaskAttestationResult> {
    if (!this.attestComplete) {
      return { shipId: this.shipId };
    }

    const intentId = this.intents.get(ctx.taskId);
    this.intents.delete(ctx.taskId);

    const receiptId = await attestReceipt({
      system: this.actor,
      kind: 'a2a.task.result',
      subject: intentId,
      payload: {
        a2a_task_id: ctx.taskId,
        elapsed_ms: ctx.elapsedMs,
        status: ctx.status,
        artifact_digest: ctx.artifactDigest,
        tokens_used: ctx.tokensUsed,
        cost_usd: ctx.costUsd,
        error: ctx.error,
        ship_id: this.shipId,
        session_id: currentSessionId(),
      },
    });

    return {
      intentId,
      receiptId,
      receiptUrl: receiptId ? `${this.receiptBaseUrl}/${receiptId}` : undefined,
      shipId: this.shipId,
    };
  }

  /**
   * Call when delegating a task to another A2A agent. Records a signed
   * handoff so the parent session shows the full delegation graph.
   */
  async onHandoff(ctx: HandoffContext): Promise<string | undefined> {
    if (!this.attestHandoffs) return undefined;
    return attestHandoff({
      from: this.actor,
      to: ctx.toAgent,
      taskId: ctx.taskId,
      context: ctx.context,
      messageId: ctx.messageId,
    });
  }

  /**
   * Stamp Treeship attestation IDs into an A2A artifact's metadata so the
   * receiving agent can fetch and verify the receipt before trusting the work.
   *
   * Returns a new metadata object (does not mutate the input).
   */
  decorateArtifact<T extends { metadata?: Record<string, unknown> } | undefined>(
    artifact: T,
    result: TaskAttestationResult,
  ): T {
    if (!artifact || !this.publishReceipt) return artifact;

    const meta: Record<string, unknown> = {
      treeship_artifact_id: result.receiptId,
      treeship_receipt_url: result.receiptUrl,
      treeship_session_id: currentSessionId(),
      treeship_ship_id: result.shipId,
    };

    return {
      ...artifact,
      metadata: { ...(artifact.metadata ?? {}), ...stripUndefined(meta) },
    } as T;
  }

  /** Compute the SHA-256 digest of an artifact's parts for the receipt payload. */
  static digestArtifact(artifact: unknown): string {
    return hashPayload(stableStringify(artifact));
  }
}

function stripUndefined<T extends Record<string, unknown>>(obj: T): Partial<T> {
  const out: Partial<T> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined && v !== null) (out as Record<string, unknown>)[k] = v;
  }
  return out;
}
