#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { promisify } from 'node:util';
import { z } from 'zod';
import {
  attestHandoffArgs,
  mintChallengeArgs,
  presentArgs,
  sessionReportCommands,
  verifyArgs,
  verifyPresentationArgs,
} from './cli-args.js';

const exec = promisify(execFile);

// The version clients see in the MCP handshake. Read from the package
// manifest so it rides the release train instead of drifting (it was
// hardcoded at 0.10.0 seven releases past that).
const PKG_VERSION: string =
  createRequire(import.meta.url)('../package.json').version ?? '0.0.0';

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
  { name: 'treeship', version: PKG_VERSION },
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
    // The CLI walks the parent chain by DEFAULT; the only flag is `--no-chain`
    // to opt out. There is no `--chain` flag — passing it makes clap reject the
    // whole invocation, which previously broke every default verify call.
    return formatExec(await runTreeship(verifyArgs(artifactId, chain)));
  },
);

server.registerTool(
  'treeship_session_report',
  {
    title: 'Publish session report',
    description:
      'Publish the latest closed session as a shareable report. When summary is provided, close the active session with that summary first.',
    inputSchema: {
      summary: z.string().optional().describe('Headline summary for the report'),
    },
  },
  async ({ summary }) => {
    const commands = sessionReportCommands(summary);
    for (const command of commands) {
      const result = await runTreeship(command);
      if (result.code !== 0 || command === commands.at(-1)) return formatExec(result);
    }
    return textResult('ok');
  },
);

/**
 * Provision a per-agent signing key for this bridge's actor on startup.
 *
 * This is what makes the receipts the bridge already emits *provable*: once the
 * agent has its own key pinned under AgentCert, `attest action --actor <agent>`
 * (which every tool below already calls) signs with that key, so the actor
 * reads `proven (key-bound)` instead of `asserted`. Without it, the bridge
 * still works -- receipts are just signed by the shared ship key.
 *
 * Idempotent and best-effort: `agent register --own-key` reuses an existing
 * per-agent key (no key pile-up across restarts), `--quiet` skips the on-disk
 * .agent package so nothing is dropped into the user's working directory, and
 * any failure (CLI missing, no `treeship init`) is logged and swallowed so it
 * never blocks the MCP server from starting.
 */
async function provisionAgentKey(): Promise<void> {
  const name = ACTOR.replace(/^agent:\/\//, '');
  if (!name) return;
  const { code, stderr } = await runTreeship([
    'agent', 'register', '--own-key', '--quiet', '--name', name,
  ]);
  if (code !== 0) {
    process.stderr.write(
      `[treeship-mcp] per-agent key not provisioned for ${ACTOR}; ` +
        `receipts will be signed by the shared key (actor asserted). ` +
        `${stderr.trim()}\n`,
    );
  }
}

// ---------------------------------------------------------------------------
// The handshake.
//
// Everything above this line records what THIS agent did. These four let it
// decide whether to act on what ANOTHER agent hands it, which is the half that
// was missing: the bridge exposed five tools and none of them could check a
// counterparty.
//
// The shape is deliberate. `mint_challenge` and `verify_presentation` belong to
// the receiver, `present` belongs to the sender, and the receiver never accepts
// a nonce the sender chose. A presentation answering a challenge the sender
// picked shows a document exists; it does not show the sender holds the key.
// ---------------------------------------------------------------------------

server.registerTool(
  'treeship_mint_challenge',
  {
    title: 'Mint a challenge nonce',
    description:
      'Mint a 128-bit challenge nonce to hand to another agent. YOU are the receiver: run this before accepting any work from another agent, then require that agent to answer THIS nonce with treeship_present. Never accept a nonce the other party generated — a nonce they chose can be pre-signed, which proves only that a document exists.',
    inputSchema: {},
  },
  async () => formatExec(await runTreeship(mintChallengeArgs())),
);

server.registerTool(
  'treeship_present',
  {
    title: 'Present this agent’s proof',
    description:
      'Package this agent’s card, certificate chain, known revocations, and a Merkle staple into a presentation file, answering a challenge nonce the counterparty minted. Use when another agent or a human asks you to prove who you are. Presenting without a challenge is not proof of identity and this tool requires one.',
    inputSchema: {
      challenge: z
        .string()
        .min(32)
        .describe('The nonce the COUNTERPARTY minted. At least 32 characters; a shorter nonce can be guessed and pre-answered.'),
      actor: z.string().optional().describe('Actor URI to present (defaults to this bridge’s actor)'),
    },
  },
  async ({ challenge, actor }) => formatExec(await runTreeship(presentArgs(actor ?? ACTOR, challenge))),
);

server.registerTool(
  'treeship_verify_presentation',
  {
    title: 'Verify another agent’s presentation',
    description:
      'Verify a counterparty presentation against YOUR pinned trust roots, fully offline. Run this BEFORE doing work another agent asked for, and do not proceed if it fails. Read the structured fields rather than the verdict line: an unpinned issuer and a replayed nonce both print CHALLENGE FAILED, but key_bound=false with signature "UNVERIFIED (key not in your trust roots)" means you never pinned them — your side to fix, not theirs.',
    inputSchema: {
      file: z.string().describe('Path to the presentation file the counterparty gave you'),
      challenge: z.string().min(32).describe('The nonce YOU minted for this exchange'),
      maxStapleAge: z
        .string()
        .optional()
        .describe('Reject a staple older than this, e.g. "1h". Freshness is reported as an explicit bound, never as "current".'),
    },
  },
  async ({ file, challenge, maxStapleAge }) =>
    formatExec(await runTreeship(verifyPresentationArgs(file, challenge, maxStapleAge))),
);

server.registerTool(
  'treeship_attest_handoff',
  {
    title: 'Record a handoff to another agent',
    description:
      'Sign a record that custody of some artifacts passed from one agent to another. Note the current limit: the handoff does not yet reference the presentation or nonce you verified, so custody here is asserted. Run treeship_verify_presentation first regardless — the check is what makes the handoff trustworthy, even while the record cannot cite it.',
    inputSchema: {
      to: z.string().describe('Receiving actor URI, e.g. agent://claude-code'),
      artifacts: z.array(z.string()).min(1).describe('Artifact ids being handed over'),
      from: z.string().optional().describe('Sending actor URI (defaults to this bridge’s actor)'),
    },
  },
  async ({ to, artifacts, from }) =>
    formatExec(await runTreeship(attestHandoffArgs(from ?? ACTOR, to, artifacts))),
);

async function main() {
  await provisionAgentKey();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(err => {
  process.stderr.write(`[treeship-mcp] fatal: ${err?.stack ?? err}\n`);
  process.exit(1);
});
