import { runTreeship } from "./exec.js";
import type { SessionEventParams, SessionEventResult } from "./types.js";

/**
 * Session module: append structured events to the active session's event log.
 *
 * Where `attest.*` signs a tamper-evident artifact (the proof chain), a session
 * event is what populates the receipt's **timeline**, **side-effect ledger**,
 * and **activity-density chart**. Wraps `treeship session event`, so it requires
 * an active session (`treeship session start`). Pass `artifactId` to link the
 * timeline entry to the signed artifact it references.
 */
export class SessionModule {
  async event(params: SessionEventParams): Promise<SessionEventResult> {
    const args = ["session", "event", "--type", params.type, "--format", "json"];
    if (params.tool) args.push("--tool", params.tool);
    if (params.file) args.push("--file", params.file);
    if (params.destination) args.push("--destination", params.destination);
    if (params.actor) args.push("--actor", params.actor);
    if (params.agentName) args.push("--agent-name", params.agentName);
    if (params.durationMs !== undefined) args.push("--duration-ms", String(params.durationMs));
    if (params.exitCode !== undefined) args.push("--exit-code", String(params.exitCode));
    if (params.artifactId) args.push("--artifact-id", params.artifactId);
    if (params.model) args.push("--model", params.model);
    if (params.provider) args.push("--provider", params.provider);
    if (params.tokensIn !== undefined) args.push("--tokens-in", String(params.tokensIn));
    if (params.tokensOut !== undefined) args.push("--tokens-out", String(params.tokensOut));
    if (params.meta) args.push("--meta", JSON.stringify(params.meta));
    const result = await runTreeship(args);
    return { eventId: (result.event_id || result.id) as string };
  }
}
