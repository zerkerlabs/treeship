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
