import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { TreeshipA2AMiddleware } from '../src/middleware.js';
import {
  buildAgentCard,
  getTreeshipExtension,
  hasTreeshipExtension,
} from '../src/agent-card.js';
import { TREESHIP_EXTENSION_URI } from '../src/types.js';
import { attestAction, attestHandoff, __resetCliMissingWarning } from '../src/attest.js';

describe('@treeship/a2a', () => {
  describe('TreeshipA2AMiddleware', () => {
    let mw: TreeshipA2AMiddleware;

    beforeEach(() => {
      // Force the CLI to be missing so attestations return undefined cleanly.
      process.env.PATH = '/nonexistent';
      mw = new TreeshipA2AMiddleware({
        shipId: 'shp_test',
        receiptBaseUrl: 'https://treeship.dev/receipt',
      });
    });

    it('throws if shipId is missing', () => {
      // @ts-expect-error -- intentionally invalid
      expect(() => new TreeshipA2AMiddleware({})).toThrow(/shipId/);
    });

    it('exposes the configured ship ID and a default actor', () => {
      expect(mw.shipId).toBe('shp_test');
      expect(mw.actor).toBe('agent://a2a-shp_test');
    });

    it('decorateArtifact injects treeship metadata fields', () => {
      const decorated = mw.decorateArtifact(
        { metadata: { existing: true } } as { metadata?: Record<string, unknown> },
        {
          shipId: 'shp_test',
          receiptId: 'art_abc',
          receiptUrl: 'https://treeship.dev/receipt/art_abc',
        },
      );
      expect(decorated?.metadata).toMatchObject({
        existing: true,
        treeship_artifact_id: 'art_abc',
        treeship_receipt_url: 'https://treeship.dev/receipt/art_abc',
        treeship_ship_id: 'shp_test',
      });
    });

    it('decorateArtifact is a no-op when publishReceipt is false', () => {
      const off = new TreeshipA2AMiddleware({ shipId: 'shp_x', publishReceipt: false });
      const input = { metadata: {} };
      const out = off.decorateArtifact(input, { shipId: 'shp_x', receiptId: 'art_y' });
      expect(out).toBe(input);
    });

    it('digestArtifact returns a stable sha256 prefix', () => {
      const a = TreeshipA2AMiddleware.digestArtifact({ b: 1, a: 2 });
      const b = TreeshipA2AMiddleware.digestArtifact({ a: 2, b: 1 });
      expect(a).toBe(b);
      expect(a.startsWith('sha256:')).toBe(true);
    });

    it('onTaskReceived returns undefined gracefully when CLI is missing', async () => {
      const id = await mw.onTaskReceived({
        taskId: 'task_1',
        skill: 'web-research',
        fromAgent: 'agent://claude-code',
      });
      expect(id).toBeUndefined();
    });

    it('onTaskCompleted returns a result with shipId even on attestation failure', async () => {
      const result = await mw.onTaskCompleted({
        taskId: 'task_1',
        elapsedMs: 12,
        status: 'completed',
      });
      expect(result.shipId).toBe('shp_test');
      expect(result.receiptId).toBeUndefined();
    });
  });

  describe('CLI-missing handling', () => {
    let writes: string[];
    let writeSpy: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
      __resetCliMissingWarning();
      delete process.env.TREESHIP_DISABLE;
      process.env.PATH = '/nonexistent';
      writes = [];
      writeSpy = vi
        .spyOn(process.stderr, 'write')
        .mockImplementation((chunk: string | Uint8Array) => {
          writes.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
          return true;
        });
    });

    afterEach(() => {
      writeSpy.mockRestore();
    });

    it('prints an actionable warning when the treeship CLI is missing', async () => {
      const id = await attestAction({ actor: 'agent://test', action: 'a2a.task.test.intent' });
      expect(id).toBeUndefined();

      const combined = writes.join('');
      expect(combined).toContain('treeship CLI not found on PATH');
      expect(combined).toContain('treeship.dev/install');
      expect(combined).toContain('npm install -g treeship');
      expect(combined).toContain('treeship init');
      expect(combined).toContain('TREESHIP_DISABLE=1');
    });

    it('prints the CLI-missing warning exactly once per process', async () => {
      await attestAction({ actor: 'agent://test', action: 'a' });
      await attestAction({ actor: 'agent://test', action: 'b' });
      await attestHandoff({ from: 'agent://x', to: 'agent://y', taskId: 't1' });

      const warnings = writes.filter((w) => w.includes('treeship CLI not found'));
      expect(warnings).toHaveLength(1);
    });

    it('does not throw when the CLI is missing', async () => {
      await expect(
        attestAction({ actor: 'agent://test', action: 'never-throws' }),
      ).resolves.toBeUndefined();
    });

    it('TREESHIP_DISABLE=1 silences the warning entirely', async () => {
      process.env.TREESHIP_DISABLE = '1';
      const id = await attestAction({ actor: 'agent://test', action: 'silenced' });
      expect(id).toBeUndefined();
      expect(writes.join('')).not.toContain('treeship CLI not found');
    });
  });

  describe('buildAgentCard', () => {
    const base = {
      name: 'OpenClaw Research Agent',
      version: '1.2.0',
      url: 'https://openclaw.example/a2a',
      skills: [{ id: 'web-research', name: 'Web Research' }],
    };

    it('attaches a Treeship extension to the AgentCard', () => {
      const card = buildAgentCard(base, { ship_id: 'shp_4a9f' });
      expect(hasTreeshipExtension(card)).toBe(true);
      const ext = getTreeshipExtension(card);
      expect(ext?.ship_id).toBe('shp_4a9f');
      expect(ext?.receipt_endpoint).toBe('https://treeship.dev/receipt');
    });

    it('uses the canonical extension URI', () => {
      const card = buildAgentCard(base, { ship_id: 'shp_x' });
      expect(card.extensions?.[0].uri).toBe(TREESHIP_EXTENSION_URI);
      expect(TREESHIP_EXTENSION_URI).toBe('treeship.dev/extensions/attestation/v1');
    });

    it('replaces an existing Treeship extension instead of duplicating', () => {
      const first = buildAgentCard(base, { ship_id: 'shp_old' });
      const second = buildAgentCard(first, { ship_id: 'shp_new' });
      const exts = second.extensions ?? [];
      expect(exts.filter((e) => e.uri === TREESHIP_EXTENSION_URI)).toHaveLength(1);
      expect(getTreeshipExtension(second)?.ship_id).toBe('shp_new');
    });

    it('hasTreeshipExtension returns false for cards without the extension', () => {
      expect(hasTreeshipExtension(base)).toBe(false);
      expect(hasTreeshipExtension(undefined)).toBe(false);
    });
  });
});
