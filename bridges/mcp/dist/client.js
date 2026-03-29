import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { attestAction } from './attest.js';
import { hashPayload } from './utils.js';
export class TreeshipMCPClient extends Client {
    _actor;
    _disabled;
    constructor(clientInfo, options) {
        super(clientInfo, options);
        this._actor = process.env.TREESHIP_ACTOR ?? `agent://mcp-${clientInfo?.name ?? 'unknown'}`;
        this._disabled = process.env.TREESHIP_DISABLE === '1';
    }
    async callTool(params, resultSchema, options) {
        if (this._disabled) {
            return super.callTool(params, resultSchema, options);
        }
        // Attest INTENT before the call (awaited -- proof of what was about to happen)
        const intentId = await this._attestIntent(params).catch(() => undefined);
        const startMs = Date.now();
        let result;
        let error;
        try {
            result = await super.callTool(params, resultSchema, options);
        }
        catch (e) {
            error = e;
            throw e;
        }
        finally {
            const elapsedMs = Date.now() - startMs;
            // Attest RECEIPT after the call (fire-and-forget -- never blocks response)
            this._attestReceipt(params, result, intentId, elapsedMs, error).catch(() => { });
        }
        // Attach treeship metadata to result
        if (intentId && result) {
            result._treeship = {
                intent: intentId,
                tool: params.name,
                actor: this._actor,
            };
        }
        return result;
    }
    async _attestIntent(params) {
        return attestAction({
            actor: this._actor,
            action: `mcp.tool.${params.name}.intent`,
            meta: {
                tool: params.name,
                server: 'mcp',
                args_digest: hashPayload(JSON.stringify(params.arguments ?? {})),
                approval_nonce: process.env.TREESHIP_APPROVAL_NONCE || undefined,
            },
        });
    }
    async _attestReceipt(params, result, intentId, elapsedMs, error) {
        await attestAction({
            actor: this._actor,
            action: `mcp.tool.${params.name}.receipt`,
            parentId: intentId,
            meta: {
                tool: params.name,
                elapsed_ms: elapsedMs,
                exit_code: error ? 1 : 0,
                is_error: result?.isError ?? !!error,
                output_digest: result
                    ? hashPayload(JSON.stringify(result.content ?? result))
                    : undefined,
                error_message: error?.message,
            },
        }).catch(() => { });
    }
}
