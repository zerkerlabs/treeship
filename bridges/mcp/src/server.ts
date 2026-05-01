#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { z } from 'zod';

const exec = promisify(execFile);

const TREESHIP_BIN = process.env.TREESHIP_BIN || 'treeship';
const ACTOR = process.env.TREESHIP_ACTOR || 'agent://mcp';
const TIMEOUT_MS = 10_000;

type ExecResult = { stdout: string; stderr: string; code: number };

async function runTreeship(args: string[]): Promise<ExecResult> {
  try {
    const { stdout, stderr } = await exec(TREESHIP_BIN, args, { timeout: TIMEOUT_MS });
    return { stdout, stderr, code: 0 };
  } catch (e: any) {
    return {
      stdout: e?.stdout ?? '',
      stderr: e?.stderr ?? String(e?.message ?? e),
      code: typeof e?.code === 'number' ? e.code : 1,
    };
  }
}

function textResult(text: string, isError = false) {
  return {
    content: [{ type: 'text' as const, text }],
    isError,
  };
}

function formatExec({ stdout, stderr, code }: ExecResult): { content: any[]; isError: boolean } {
  if (code === 0) {
    return textResult(stdout.trim() || stderr.trim() || 'ok');
  }
  const msg = (stderr || stdout || `treeship exited with code ${code}`).trim();
  return textResult(msg, true);
}

const server = new McpServer(
  { name: 'treeship', version: '0.10.0' },
  { capabilities: { tools: {} } },
);

server.registerTool(
  'treeship_session_status',
  {
    title: 'Treeship session status',
    description:
      'Show the active Treeship session: id, name, started_at, event count, and the current actor. Returns JSON.',
    inputSchema: {},
  },
  async () => formatExec(await runTreeship(['session', 'status', '--format', 'json'])),
);

server.registerTool(
  'treeship_session_event',
  {
    title: 'Append a session event',
    description:
      'Append a structured event to the active Treeship session. Use type=agent.note for free-form notes the agent wants on the receipt timeline.',
    inputSchema: {
      type: z.string().describe('Event type, e.g. agent.note, agent.decision, agent.handoff'),
      tool: z.string().optional().describe('Tool name, when applicable'),
      durationMs: z.number().int().optional(),
      exitCode: z.number().int().optional(),
      meta: z.record(z.unknown()).optional().describe('Free-form metadata (no secrets)'),
    },
  },
  async ({ type, tool, durationMs, exitCode, meta }) => {
    const args = [
      'session', 'event',
      '--type', type,
      '--actor', ACTOR,
      '--agent-name', ACTOR.replace(/^agent:\/\//, ''),
    ];
    if (tool) args.push('--tool', tool);
    if (durationMs != null) args.push('--duration-ms', String(durationMs));
    if (exitCode != null) args.push('--exit-code', String(exitCode));
    if (meta && Object.keys(meta).length > 0) {
      args.push('--meta', JSON.stringify(meta));
    }
    return formatExec(await runTreeship(args));
  },
);

server.registerTool(
  'treeship_attest_action',
  {
    title: 'Sign an action attestation',
    description:
      'Sign a Treeship action artifact recording that the agent is about to do something. Returns the artifact id as JSON.',
    inputSchema: {
      action: z.string().describe('Action label, e.g. mcp.fetch.intent or git.commit.intent'),
      parentId: z.string().optional().describe('Parent artifact id for chaining'),
      meta: z.record(z.unknown()).optional(),
    },
  },
  async ({ action, parentId, meta }) => {
    const args = [
      'attest', 'action',
      '--actor', ACTOR,
      '--action', action,
      '--format', 'json',
    ];
    if (parentId) args.push('--parent', parentId);
    if (meta && Object.keys(meta).length > 0) {
      args.push('--meta', JSON.stringify(meta));
    }
    return formatExec(await runTreeship(args));
  },
);

server.registerTool(
  'treeship_verify',
  {
    title: 'Verify an artifact or chain',
    description:
      'Verify a Treeship artifact id and its parent chain. Returns the verification result.',
    inputSchema: {
      artifactId: z.string().describe('Artifact id (e.g. art_...) or path to a .treeship file'),
      chain: z.boolean().optional().describe('Walk the full parent chain (default true)'),
    },
  },
  async ({ artifactId, chain }) => {
    const args = ['verify', artifactId];
    if (chain !== false) args.push('--chain');
    return formatExec(await runTreeship(args));
  },
);

server.registerTool(
  'treeship_session_report',
  {
    title: 'Publish session report',
    description:
      'Close-and-publish the active session as a shareable report on the configured hub. Returns the report URL.',
    inputSchema: {
      summary: z.string().optional().describe('Headline summary for the report'),
    },
  },
  async ({ summary }) => {
    const args = ['session', 'report'];
    if (summary) args.push('--summary', summary);
    return formatExec(await runTreeship(args));
  },
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(err => {
  process.stderr.write(`[treeship-mcp] fatal: ${err?.stack ?? err}\n`);
  process.exit(1);
});
