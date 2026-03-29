export interface ToolReceipt {
    intent?: string;
    receipt?: string;
    tool: string;
    actor: string;
}
export interface AttestParams {
    actor: string;
    action: string;
    parentId?: string;
    meta?: Record<string, unknown>;
}
