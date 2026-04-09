import type { AgentCard, TreeshipExtensionParams } from './types.js';
import { TREESHIP_EXTENSION_URI } from './types.js';

/**
 * Build an AgentCard with the Treeship extension attached.
 *
 * Use this when serving `/.well-known/agent.json`. Any A2A peer that reads
 * the card learns the agent's ship ID, where to fetch receipts, and the
 * Ed25519 verification key for offline proof checking.
 */
export function buildAgentCard(
  base: AgentCard,
  treeship: TreeshipExtensionParams & { required?: boolean },
): AgentCard {
  const ext = {
    uri: TREESHIP_EXTENSION_URI,
    required: treeship.required ?? false,
    params: {
      ship_id: treeship.ship_id,
      receipt_endpoint: treeship.receipt_endpoint ?? 'https://treeship.dev/receipt',
      ...(treeship.verification_key ? { verification_key: treeship.verification_key } : {}),
    },
  };

  return {
    ...base,
    extensions: [...(base.extensions ?? []).filter((e) => e.uri !== TREESHIP_EXTENSION_URI), ext],
  };
}

/**
 * Returns true if the given AgentCard publishes a Treeship attestation extension.
 */
export function hasTreeshipExtension(card: AgentCard | null | undefined): boolean {
  if (!card?.extensions) return false;
  return card.extensions.some((e) => e.uri === TREESHIP_EXTENSION_URI);
}

/**
 * Extract the Treeship extension params from an AgentCard, or undefined if absent.
 */
export function getTreeshipExtension(
  card: AgentCard | null | undefined,
): TreeshipExtensionParams | undefined {
  if (!card?.extensions) return undefined;
  const ext = card.extensions.find((e) => e.uri === TREESHIP_EXTENSION_URI);
  if (!ext?.params) return undefined;
  const params = ext.params as Record<string, unknown>;
  if (typeof params.ship_id !== 'string') return undefined;
  return {
    ship_id: params.ship_id,
    receipt_endpoint:
      typeof params.receipt_endpoint === 'string' ? params.receipt_endpoint : undefined,
    verification_key:
      typeof params.verification_key === 'string' ? params.verification_key : undefined,
  };
}

/**
 * Fetch a remote AgentCard from `<url>/.well-known/agent.json`.
 * Returns null on error.
 */
export async function fetchAgentCard(agentBaseUrl: string): Promise<AgentCard | null> {
  const url = agentBaseUrl.replace(/\/$/, '') + '/.well-known/agent.json';
  try {
    const res = await fetch(url);
    if (!res.ok) return null;
    return (await res.json()) as AgentCard;
  } catch {
    return null;
  }
}
