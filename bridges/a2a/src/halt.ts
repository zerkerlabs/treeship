import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const exec = promisify(execFile);

/**
 * The kill switch, honoured by the bridge.
 *
 * `treeship halt <actor>` (or `*`) leaves a signed `halt.v1` in the workspace
 * and a marker `treeship halt list` reads. The Claude Code plugin's gate
 * refused every tool call under a standing halt from 0.31.6; a tool call
 * through this bridge did not look, so an operator who threw the switch
 * stopped one harness and not the other. The bridge now asks before every
 * call, the way the plugin does, and refuses with a signed `blocked.v1`.
 *
 * Only a halt the local ship signed is obeyed (`honoured: true` in the
 * listing). A marker anyone could drop into the directory is not an order.
 */
export type HaltCheck =
  | { halted: false; checked: true }
  /** The check could not run (no CLI on PATH, a CLI without `halt`). */
  | { halted: false; checked: false; reason: string }
  | { halted: true; halt: string; actor: string; reason?: string };

type HaltRow = { actor?: unknown; halt?: unknown; honoured?: unknown; reason?: unknown };

export async function checkHalt(actor: string, timeoutMs = 5000): Promise<HaltCheck> {
  let stdout: string;
  try {
    ({ stdout } = await exec('treeship', ['halt', 'list', '--format', 'json'], { timeout: timeoutMs }));
  } catch (err) {
    const e = err as { stderr?: string; message?: string } | undefined;
    const reason = (e?.stderr || e?.message || String(err)).toString().trim().split('\n')[0];
    return { halted: false, checked: false, reason };
  }
  let rows: HaltRow[];
  try {
    const parsed = JSON.parse(stdout) as { halts?: unknown };
    rows = Array.isArray(parsed?.halts) ? (parsed.halts as HaltRow[]) : [];
  } catch {
    return { halted: false, checked: false, reason: 'halt list returned something that is not JSON' };
  }
  for (const r of rows) {
    if (r.honoured !== true) continue;
    if (r.actor !== actor && r.actor !== '*') continue;
    if (typeof r.halt !== 'string' || r.halt.length === 0) continue;
    return {
      halted: true,
      halt: r.halt,
      actor: r.actor,
      reason: typeof r.reason === 'string' ? r.reason : undefined,
    };
  }
  return { halted: false, checked: true };
}

/** Thrown by `onTaskReceived` when this actor is halted. The task never ran. */
export class TreeshipHaltedError extends Error {
  readonly halt: string;
  readonly actor: string;
  /** The signed `blocked.v1` refusal, when it could be minted. */
  readonly blocked?: string;
  constructor(actor: string, halt: string, tool: string, blocked?: string) {
    super(
      `Treeship halt: ${actor} is halted (${halt}); ${tool} refused. ` +
        `Every tool call is refused until an operator runs \`treeship halt --lift ${actor}\`.` +
        (blocked ? ` Refusal signed as ${blocked}.` : ''),
    );
    this.name = 'TreeshipHaltedError';
    this.actor = actor;
    this.halt = halt;
    this.blocked = blocked;
  }
}
