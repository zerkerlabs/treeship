import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { CallToolRequest, CallToolResultSchema, CompatibilityCallToolResultSchema, Implementation } from '@modelcontextprotocol/sdk/types.js';
import type { RequestOptions } from '@modelcontextprotocol/sdk/shared/protocol.js';
import type { ClientOptions } from '@modelcontextprotocol/sdk/client/index.js';
export declare class TreeshipMCPClient extends Client {
    private _actor;
    private _disabled;
    constructor(clientInfo: Implementation, options?: ClientOptions);
    callTool(params: CallToolRequest['params'], resultSchema?: typeof CallToolResultSchema | typeof CompatibilityCallToolResultSchema, options?: RequestOptions): Promise<any>;
    private _attestIntent;
    private _attestReceipt;
}
