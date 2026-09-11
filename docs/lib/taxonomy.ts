// The blog's two sorting axes. A post has exactly one category and any number
// of systems. Both are closed lists so the index, the listing routes and the
// chips on a post agree, and so a typo in frontmatter fails the build instead
// of minting a new bucket.

export const CATEGORIES = {
  release: {
    label: 'Releases',
    singular: 'Release',
    blurb: 'What each version added, in the order it shipped.',
  },
  integration: {
    label: 'Integrations',
    singular: 'Integration',
    blurb: 'Treeship inside another system: a harness, a protocol, a product, a standard.',
  },
  guide: {
    label: 'Guides',
    singular: 'Guide',
    blurb: 'Worked examples, start to finish, with real ids.',
  },
  engineering: {
    label: 'Engineering',
    singular: 'Engineering',
    blurb: 'How the pieces are built and why they are built that way.',
  },
  security: {
    label: 'Security',
    singular: 'Security',
    blurb: 'Attack classes, advisories, and what a verifier can and cannot conclude.',
  },
  perspective: {
    label: 'Perspectives',
    singular: 'Perspective',
    blurb: 'Where we think this is going.',
  },
  announcement: {
    label: 'Announcements',
    singular: 'Announcement',
    blurb: 'Company and project news.',
  },
} as const;

export type Category = keyof typeof CATEGORIES;
export const CATEGORY_ORDER: Category[] = [
  'release',
  'integration',
  'guide',
  'engineering',
  'security',
  'perspective',
  'announcement',
];

export type SystemGroup = 'harness' | 'protocol' | 'framework' | 'standard' | 'product' | 'partner' | 'surface';

export const SYSTEM_GROUPS: Record<SystemGroup, string> = {
  harness: 'Agent harnesses',
  protocol: 'Protocols',
  framework: 'Frameworks',
  standard: 'Standards',
  product: 'Zerker products',
  partner: 'Partners',
  surface: 'Treeship surfaces',
};

export interface SystemInfo {
  label: string;
  vendor?: string;
  group: SystemGroup;
  /** Docs path (this site) or an absolute URL. */
  docs?: string;
}

export const SYSTEMS: Record<string, SystemInfo> = {
  'claude-code': { label: 'Claude Code', vendor: 'Anthropic', group: 'harness', docs: '/integrations/claude-code' },
  codex: { label: 'Codex CLI', vendor: 'OpenAI', group: 'harness', docs: '/integrations/codex' },
  cursor: { label: 'Cursor', vendor: 'Anysphere', group: 'harness', docs: '/integrations/cursor' },
  hermes: { label: 'Hermes', vendor: 'Nous Research', group: 'harness', docs: '/integrations/hermes' },
  openclaw: { label: 'OpenClaw', vendor: 'OpenClaw', group: 'harness', docs: '/integrations/openclaw' },
  kimi: { label: 'Kimi Code CLI', vendor: 'Moonshot AI', group: 'harness', docs: '/integrations/agent-skills' },
  perplexity: { label: 'Perplexity Computer', vendor: 'Perplexity', group: 'harness', docs: '/integrations' },
  'grok-bot': { label: 'Grok Bot', vendor: 'xAI', group: 'harness', docs: '/integrations' },
  mcp: { label: '@treeship/mcp', vendor: 'Model Context Protocol', group: 'protocol', docs: '/integrations/mcp' },
  a2a: { label: '@treeship/a2a', vendor: 'Agent2Agent', group: 'protocol', docs: '/integrations/a2a' },
  'commerce-agents': { label: 'Claude Commerce Agents', vendor: 'Anthropic', group: 'framework', docs: '/commerce/commerce-agents' },
  langchain: { label: 'LangChain', group: 'framework', docs: '/integrations/langchain' },
  rig: { label: 'Rig', group: 'framework', docs: 'https://github.com/zerkerlabs/rig-treeship' },
  'verifiable-intent': { label: 'Verifiable Intent', vendor: 'Mastercard', group: 'standard', docs: '/integrations/verifiable-intent' },
  'zerker-reason': { label: 'Zerker Reason', vendor: 'Zerker Labs', group: 'product', docs: '/integrations/zerker-reason' },
  'zerker-gateway': { label: 'Zerker Gateway', vendor: 'Zerker Labs', group: 'product', docs: 'https://docs.zerker.ai' },
  'memory-providers': { label: 'Memory providers', group: 'product', docs: '/integrations/memory-proofs' },
  'lobster-cash': { label: 'Lobster Cash', group: 'partner', docs: '/integrations/lobster-cash' },
  robinhood: { label: 'Robinhood Agentic Trading', vendor: 'Robinhood', group: 'partner', docs: '/integrations/robinhood-agentic-trading' },
  ninjatech: { label: 'NinjaTech / SuperNinja', vendor: 'NinjaTech AI', group: 'partner', docs: '/integrations/ninjatech' },
  cli: { label: 'Treeship CLI', group: 'surface', docs: '/cli/overview' },
  hub: { label: 'Treeship Hub', group: 'surface', docs: '/api/overview' },
  'python-sdk': { label: 'Python SDK', group: 'surface', docs: '/sdk/python' },
  'typescript-sdk': { label: 'TypeScript SDK', group: 'surface', docs: '/sdk/typescript' },
  'wasm-verifier': { label: '@treeship/verify', group: 'surface', docs: '/sdk/verify' },
  'go-client': { label: 'Go hub client', group: 'surface', docs: '/api/overview' },
  'claude-code-plugin': { label: 'Claude Code plugin', vendor: 'Anthropic', group: 'harness', docs: '/integrations/claude-code' },
};

export function isCategory(value: string): value is Category {
  return value in CATEGORIES;
}

export function systemInfo(id: string): SystemInfo {
  const info = SYSTEMS[id];
  if (!info) throw new Error(`unknown blog system "${id}"; add it to lib/taxonomy.ts`);
  return info;
}

/** URL-safe tag slug: lowercase, spaces and slashes to hyphens. */
export function tagSlug(tag: string): string {
  return tag.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}
