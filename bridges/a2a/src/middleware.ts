import { attestAction, attestHandoff, attestReceipt, currentSessionId } from './attest.js';
import { hashPayload, stableStringify } from './utils.js';
import type {
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
export class TreeshipA2AMiddleware {
  readonly shipId: string;
  readonly actor: string;
  readonly receiptBaseUrl: string;
  private readonly attestComplete: boolean;
  private readonly attestHandoffs: boolean;
  private readonly publishReceipt: boolean;

  /** intentId per active task — used to chain receipts. */
  private readonly intents = new Map<string, string>();

  constructor(opts: TreeshipA2AOptions) {
    if (!opts.shipId) throw new Error('TreeshipA2AMiddleware: shipId is required');
    this.shipId = opts.shipId;
    this.actor = opts.actor ?? `agent://a2a-${opts.shipId}`;
    this.receiptBaseUrl = (opts.receiptBaseUrl ?? 'https://treeship.dev/receipt').replace(/\/$/, '');
    this.attestComplete = opts.attestOnTaskComplete ?? true;
    this.attestHandoffs = opts.attestOnHandoff ?? true;
    this.publishReceipt = opts.publishReceipt ?? true;
  }

  /**
   * Call when an A2A task arrives. Records an intent artifact so the eventual
   * receipt can chain back to it. Awaited — proof of what was about to happen.
   */
  async onTaskReceived(ctx: TaskReceivedContext): Promise<string | undefined> {
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
