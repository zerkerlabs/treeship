import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type {
  CallToolRequest,
  CallToolResultSchema,
  CompatibilityCallToolResultSchema,
  Implementation,
} from '@modelcontextprotocol/sdk/types.js';
import type { RequestOptions } from '@modelcontextprotocol/sdk/shared/protocol.js';
import type { ClientOptions } from '@modelcontextprotocol/sdk/client/index.js';
import { attestAction, attestReceipt, emitSessionEvent } from './attest.js';
import { hashPayload } from './utils.js';
import type { ToolReceipt } from './types.js';

// ---------------------------------------------------------------------------
// Tool-input sanitization for session events
//
// Codex finding #3: the receipt's MCP promotion logic
// (packages/core/src/session/side_effects.rs::promote_mcp_called_tool)
// looks for `meta.tool_input.{file_path,path,notebook_path,target_file,
// command,cmd}` to lift a generic agent.called_tool into a specialized
// files_read / files_written / processes side effect. Without those
// fields in meta, every MCP-routed file write in a session shows up as
// "tool_invocations: 1" with no file appearing in files_written -- the
// trust-fabric "files changed" guarantee silently breaks for the entire
// MCP path (Cursor, Codex, Cline, all custom MCP file-op servers).
//
// Whitelist-only by design. The bridge does NOT pass through arbitrary
// caller-supplied keys. Passing the whole arguments object would leak
// content/text/body/password/token/secret/api_key fields and any
// caller-defined sensitive payload into the (signed, eventually
// shareable) session log. Only the small set of path/command keys we
// know are safe to publish make it through; everything else stays in
// the args_digest in the intent attestation, where the operator can
// audit it locally without the digest leaving their machine.
// ---------------------------------------------------------------------------

/// Field names whose values are safe to include in meta.tool_input.
/// All are paths or commands -- they describe WHICH file or process, not
/// the contents thereof. If a future MCP tool needs a new safe field,
/// add it here explicitly. Do not switch to a denylist.
const SAFE_TOOL_INPUT_KEYS = [
  'file_path',
  'path',
  'notebook_path',
  'target_file',
  'command',
  'cmd',
] as const;

/**
 * Extract only the whitelisted keys from a tool's raw arguments.
 * Returns undefined when no whitelisted keys are present (so the meta
 * field is omitted entirely rather than serialized as `{}`).
 *
 * Exported (named `__sanitizeToolInput`) only so the regression suite
 * can pin the whitelist behavior. The underscore prefix signals
 * internal use; callers in this package should not import it.
 */
export function __sanitizeToolInput(
  args: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (!args || typeof args !== 'object') return undefined;
  const out: Record<string, unknown> = {};
  for (const key of SAFE_TOOL_INPUT_KEYS) {
    const v = (args as Record<string, unknown>)[key];
    if (typeof v === 'string' && v.length > 0) {
      out[key] = v;
    }
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

export class TreeshipMCPClient extends Client {
  private _actor: string;
  private _disabled: boolean;

  constructor(clientInfo: Implementation, options?: ClientOptions) {
    super(clientInfo, options);
    this._actor = process.env.TREESHIP_ACTOR ?? `agent://mcp-${clientInfo?.name ?? 'unknown'}`;
    this._disabled = process.env.TREESHIP_DISABLE === '1';
  }

  async callTool(
    params: CallToolRequest['params'],
    resultSchema?: typeof CallToolResultSchema | typeof CompatibilityCallToolResultSchema,
    options?: RequestOptions,
  ): Promise<any> {
    if (this._disabled) {
      return super.callTool(params, resultSchema, options);
    }

    // Attest INTENT before the call (awaited -- proof of what was about to happen)
    const intentId = await this._attestIntent(params).catch(() => undefined);

    const startMs = Date.now();
    let result: any;
    let error: Error | undefined;

    try {
      result = await super.callTool(params, resultSchema, options);
    } catch (e) {
      error = e as Error;
      throw e;
    } finally {
      const elapsedMs = Date.now() - startMs;

      // Always attest + emit session event, even on failure.
      // A thrown tool call that did side effects must not vanish from
      // the audit trail. The receipt and session event fire regardless
      // of whether result exists.
      const receipt = { resolve: (_id: string | undefined) => {} };
      const receiptPromise = new Promise<string | undefined>(r => { receipt.resolve = r; });

      if (result) {
        result._treeship = {
          intent: intentId,
          receipt: undefined,
          receiptReady: receiptPromise,
          tool: params.name,
          actor: this._actor,
        } as ToolReceipt;
      }

      this._attestReceipt(params, result, intentId, elapsedMs, error)
        .then(id => {
          if (result) {
            result._treeship.receipt = id;
          }
          receipt.resolve(id);
        })
        .catch(() => receipt.resolve(undefined));
    }

    return result;
  }

  private async _attestIntent(params: CallToolRequest['params']): Promise<string | undefined> {
    return attestAction({
      actor: this._actor,
      action: `mcp.tool.${params.name}.intent`,
      approvalNonce: process.env.TREESHIP_APPROVAL_NONCE || undefined,
      meta: {
        tool: params.name,
        server: 'mcp',
        args_digest: hashPayload(JSON.stringify(params.arguments ?? {})),
      },
    });
  }

  private async _attestReceipt(
    params: CallToolRequest['params'],
    result: any | undefined,
    intentId: string | undefined,
    elapsedMs: number,
    error?: Error,
  ): Promise<string | undefined> {
    try {
      const receiptId = await attestReceipt({
        system: this._actor,
        kind: 'tool.result',
        subject: intentId,
        payload: {
          tool: params.name,
          elapsed_ms: elapsedMs,
          exit_code: error ? 1 : 0,
          is_error: result?.isError ?? !!error,
          output_digest: result
            ? hashPayload(JSON.stringify(result.content ?? result))
            : undefined,
          error_message: error?.message,
        },
      });

      // Emit a session event so this tool call appears in the receipt
      // timeline, side effects, and agent graph. The signed artifact
      // (above) is the cryptographic proof; the session event is what
      // makes it human-readable in the receipt.
      //
      // Sanitized tool_input is included in meta so the core's MCP
      // promotion logic (packages/core/src/session/side_effects.rs)
      // can lift file/process side effects into files_read /
      // files_written / processes. Without this, an agent writing a
      // file via @treeship/mcp shows up as "tool_invocations: 1" with
      // no promoted side effect -- the file change vanishes from the
      // receipt's "Files changed" section. Codex adversarial review
      // finding #3.
      emitSessionEvent({
        type: 'agent.called_tool',
        tool: params.name,
        actor: this._actor,
        agentName: this._actor.replace('agent://', ''),
        durationMs: elapsedMs,
        exitCode: error ? 1 : 0,
        artifactId: receiptId,
        meta: {
          source: 'mcp-bridge',
          is_error: result?.isError ?? !!error,
          tool_input: __sanitizeToolInput(params.arguments),
        },
      }).catch(() => {}); // best-effort, never block

      return receiptId;
    } catch (e) {
      process.stderr.write(
        `[treeship] attestReceipt failed for ${params.name}: ${(e as Error).message}\n`,
      );
      return undefined;
    }
  }
}
