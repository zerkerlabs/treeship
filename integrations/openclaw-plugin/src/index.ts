// Treeship -- official OpenClaw plugin.
//
// Architecture: this plugin runs in the OpenClaw Gateway process, NOT in the
// agent's tool-calling context. Every hook fires before/after a tool runs,
// regardless of what the agent says, remembers, or has been prompt-injected
// to do. The receipt is built by infrastructure, not instruction.
//
// Without this plugin, OpenClaw + Treeship would still work via @treeship/mcp
// + the universal SKILL.md, but capture depends on the agent calling MCP tools
// after each action. With this plugin, capture is automatic and bypass-proof.
//
// Mirrors the Claude Code plugin design (integrations/claude-code-plugin/):
//   SessionStart hook        -> auto open treeship session
//   PostToolUse hook         -> typed agent.* event per tool
//   SessionEnd hook          -> close session, surface report URL
//
// OpenClaw exposes richer hooks than Claude Code:
//   before_tool_call         -> agent.called_tool (intent, can block)
//   after_tool_call          -> typed result events (with exit code)
//
// That gives OpenClaw receipts a tighter timeline than Claude Code today --
// every tool call is paired (intent, result) rather than result-only.

import { execFile, execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { homedir } from "node:os";

// ---------------------------------------------------------------------------
// OpenClaw SDK types (best-effort). The real types live in `openclaw`'s
// definePluginEntry signature; if the names below drift from the runtime
// SDK after this is published, update this block to match what the OpenClaw
// types package actually exports. The hook handler signatures are
// (event, ctx) -- OpenClaw passes the event payload first and a context
// object second, whose shapes vary per hook -- so we keep the types loose
// with `unknown` and narrow inside each handler.
// ---------------------------------------------------------------------------

type Hook =
  | "before_tool_call"
  | "after_tool_call"
  | "before_session_start"
  | "after_session_end"
  | "session_start"
  | "session_end";

interface PluginApi {
  registerHook(
    hook: Hook,
    handler: (event: unknown, ctx: unknown) => unknown | Promise<unknown>,
    opts?: { name?: string; description?: string }
  ): void;
}

// The OpenClaw entry point. If `openclaw` exports `definePluginEntry`, prefer
// that; otherwise this module's default export IS the entry and OpenClaw
// will invoke it with the api object.
type PluginEntry = (api: PluginApi) => void;

// ---------------------------------------------------------------------------
// CLI wrapper. Mirrors the Claude Code plugin's shell-out pattern -- the
// `treeship` CLI is the authority. Same fail-open semantics: any error
// returns silently so a broken Treeship install never blocks OpenClaw.
//
// `runSync` is used inside hooks that need to block until the event is
// recorded (anything where downstream reasoning depends on the receipt
// being up to date). `runAsync` is fire-and-forget for events where the
// hook's return must not be delayed by a CLI call (after_tool_call on
// hot paths).
// ---------------------------------------------------------------------------

const TIMEOUT_MS = 2000;

function treeshipAvailable(): boolean {
  try {
    execFileSync("treeship", ["--version"], { stdio: "ignore", timeout: TIMEOUT_MS });
    return true;
  } catch {
    return false;
  }
}

function projectInitialized(): boolean {
  // Check multiple locations: process.env.TREESHIP_PROJECT_ROOT, then
  // homedir/.treeship, then current working dir for backward compat.
  if (process.env.TREESHIP_PROJECT_ROOT && existsSync(process.env.TREESHIP_PROJECT_ROOT)) {
    return true;
  }
  const homeDir = homedir();
  if (existsSync(homeDir + "/.treeship")) {
    return true;
  }
  return existsSync("./.treeship");
}

function sessionActive(): boolean {
  try {
    execFileSync("treeship", ["session", "status", "--check"], {
      stdio: "ignore",
      timeout: TIMEOUT_MS,
    });
    return true;
  } catch {
    return false;
  }
}

function runSync(args: string[]): { ok: boolean; stdout: string; stderr: string } {
  try {
    const stdout = execFileSync("treeship", args, {
      stdio: ["ignore", "pipe", "pipe"],
      timeout: TIMEOUT_MS,
      encoding: "utf8",
    });
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: Buffer | string; stderr?: Buffer | string };
    return {
      ok: false,
      stdout: e.stdout ? e.stdout.toString() : "",
      stderr: e.stderr ? e.stderr.toString() : String(err),
    };
  }
}

function runAsync(args: string[]): void {
  // Fire-and-forget. Errors are swallowed -- the receipt either records the
  // event or it doesn't; either way the agent's tool call should not block
  // on Treeship.
  const child = execFile("treeship", args, { timeout: TIMEOUT_MS }, (err, stdout, stderr) => {
    if (err || (stderr && stderr.length > 0)) {
      console.error(`[treeship] event failed: treeship ${args.join(" ")} — ${stderr || err?.message || "unknown error"}`);
    } else {
      console.log(`[treeship] event ok: treeship ${args.join(" ")} — ${stdout?.trim() || "ok"}`);
    }
  });
  child.on("error", (err) => {
    console.error(`[treeship] spawn error: treeship ${args.join(" ")} — ${err.message}`);
  });
  child.unref();
}

// ---------------------------------------------------------------------------
// Tool-name -> Treeship event dispatch. Mirrors the Claude Code plugin's
// PostToolUse dispatch table, retargeted to OpenClaw's tool taxonomy.
//
// If you discover OpenClaw tool names that aren't covered here, add a case
// rather than relying on the generic fall-through -- typed events populate
// the receipt's side-effects buckets (files_read[], files_written[],
// processes[], network_connections[]). Without a typed mapping, every tool
// lands in agent.called_tool[] only, which is what makes a skill-only
// integration's receipts look thin.
// ---------------------------------------------------------------------------

const READ_TOOLS = new Set([
  "read",
  "read_file",
  "view",
  "view_file",
  "cat",
  "open",
]);

const WRITE_TOOLS = new Set([
  "write",
  "write_file",
  "edit",
  "edit_file",
  "create",
  "create_file",
  "patch",
  "multi_edit",
  "notebook_edit",
]);

const BASH_TOOLS = new Set([
  "bash",
  "shell",
  "exec",
  "execFile",
  "run",
  "run_command",
  "terminal",
]);

const NETWORK_TOOLS = new Set([
  "fetch",
  "web_fetch",
  "http",
  "curl",
  "request",
]);

function classify(toolName: string): "read" | "write" | "bash" | "network" | "other" {
  const n = toolName.toLowerCase();
  if (READ_TOOLS.has(n)) return "read";
  if (WRITE_TOOLS.has(n)) return "write";
  if (BASH_TOOLS.has(n)) return "bash";
  if (NETWORK_TOOLS.has(n)) return "network";
  return "other";
}

// Pull the first string field that matches any of the candidate paths from a
// dotted-key context object. Returns "" when nothing matches. Keeps the
// dispatch resilient when OpenClaw renames a field or different tools use
// slightly different argument shapes.
function pickString(ctx: unknown, paths: string[]): string {
  if (!ctx || typeof ctx !== "object") return "";
  for (const path of paths) {
    let v: unknown = ctx;
    for (const k of path.split(".")) {
      if (v && typeof v === "object" && k in (v as Record<string, unknown>)) {
        v = (v as Record<string, unknown>)[k];
      } else {
        v = undefined;
        break;
      }
    }
    if (typeof v === "string" && v.length > 0) return v;
    if (typeof v === "number") return String(v);
  }
  return "";
}

function pickNumber(ctx: unknown, paths: string[]): number | null {
  if (!ctx || typeof ctx !== "object") return null;
  for (const path of paths) {
    let v: unknown = ctx;
    for (const k of path.split(".")) {
      if (v && typeof v === "object" && k in (v as Record<string, unknown>)) {
        v = (v as Record<string, unknown>)[k];
      } else {
        v = undefined;
        break;
      }
    }
    if (typeof v === "number" && Number.isFinite(v)) return v;
    if (typeof v === "string" && v.length > 0) {
      const n = Number(v);
      if (Number.isFinite(n)) return n;
    }
  }
  return null;
}

function hostFromUrl(url: string): string {
  // Strip scheme + path -> just host. Same as the CC plugin's sed pipeline,
  // done without spawning a subshell.
  let s = url.replace(/^https?:\/\//, "");
  const slash = s.indexOf("/");
  if (slash !== -1) s = s.slice(0, slash);
  const colon = s.indexOf(":");
  if (colon !== -1) s = s.slice(0, colon);
  return s;
}

// ---------------------------------------------------------------------------
// Hook handlers
// ---------------------------------------------------------------------------

function onBeforeToolCall(event: unknown, _ctx: unknown): void {
  if (!treeshipAvailable() || !projectInitialized() || !sessionActive()) return;

  const toolName =
    pickString(event, ["toolName", "tool.name", "tool_name", "name"]) || "unknown";

  // Record intent as agent.called_tool with phase metadata.
  runAsync([
    "session",
    "event",
    "--type",
    "agent.called_tool",
    "--tool",
    toolName,
    "--meta",
    '{"phase":"intent"}',
    "--agent-name",
    "openclaw",
  ]);
}

function onAfterToolCall(event: unknown, _ctx: unknown): void {
  if (!treeshipAvailable() || !projectInitialized() || !sessionActive()) return;

  // OpenClaw event shape: { toolName, params, runId, toolCallId, result, error?, durationMs }
  const toolName =
    pickString(event, ["toolName", "tool.name", "tool_name", "name"]) || "unknown";
  const kind = classify(toolName);

  // Tool params are in event.params
  const params = (event && typeof event === "object" && "params" in event)
    ? (event as Record<string, unknown>).params
    : {};

  switch (kind) {
    case "read": {
      const file = pickString(params, [
        "file_path",
        "path",
        "file",
      ]);
      if (file) {
        runAsync([
          "session",
          "event",
          "--type",
          "agent.read_file",
          "--file",
          file,
          "--agent-name",
          "openclaw",
        ]);
        return;
      }
      break;
    }
    case "write": {
      const file = pickString(params, [
        "file_path",
        "path",
        "notebook_path",
        "file",
      ]);
      if (file) {
        runAsync([
          "session",
          "event",
          "--type",
          "agent.wrote_file",
          "--file",
          file,
          "--agent-name",
          "openclaw",
        ]);
        return;
      }
      break;
    }
    case "bash": {
      const cmd = pickString(params, ["command", "cmd", "shell"]);
      if (cmd) {
        runAsync([
          "session",
          "event",
          "--type",
          "agent.called_tool",
          "--tool",
          "bash",
          "--meta",
          JSON.stringify({ command: cmd, phase: "result" }),
          "--agent-name",
          "openclaw",
        ]);
        return;
      }
      break;
    }
    case "network": {
      const url = pickString(params, ["url", "href", "endpoint"]);
      if (url) {
        runAsync([
          "session",
          "event",
          "--type",
          "agent.connected_network",
          "--destination",
          hostFromUrl(url),
          "--agent-name",
          "openclaw",
        ]);
        return;
      }
      break;
    }
    case "other":
      break;
  }

  // Generic fallback. Tools that don't match a typed bucket still get a
  // line in the receipt -- agent.called_tool -- so the timeline stays
  // complete even when the dispatch doesn't recognize the call.
  runAsync([
    "session",
    "event",
    "--type",
    "agent.called_tool",
    "--tool",
    toolName,
    "--agent-name",
    "openclaw",
  ]);
}

function onSessionStart(_ctx: unknown): void {
  if (!treeshipAvailable() || !projectInitialized()) return;
  if (sessionActive()) return;

  const project = basename(process.cwd());
  const ts = new Date()
    .toISOString()
    .replace(/[-:T]/g, "")
    .replace(/\..*$/, "");
  const sessionName = `${project}-openclaw-${ts}`;

  const startResult = runSync(["session", "start", "--name", sessionName]);
  if (!startResult.ok) return;

  // Mirror the Claude Code plugin's model attribution: emit one
  // agent.decision event so the receipt records WHICH model the agent
  // was running on. Detection priority:
  //   1. TREESHIP_MODEL env var
  //   2. ~/.openclaw/config.json `.model` (if it exists)
  //   3. fallback to "openclaw" generic
  let model = process.env.TREESHIP_MODEL || "";
  if (!model) {
    const cfg = `${homedir()}/.openclaw/config.json`;
    if (existsSync(cfg)) {
      try {
        const parsed = JSON.parse(readFileSync(cfg, "utf8")) as { model?: string };
        if (parsed.model) model = parsed.model;
      } catch {
        /* swallow */
      }
    }
  }
  if (!model) model = "openclaw";

  // OpenClaw is provider-agnostic (it runs whatever model the user picked).
  // TREESHIP_PROVIDER can override; default is best-effort from the model
  // string itself.
  const provider =
    process.env.TREESHIP_PROVIDER ||
    inferProviderFromModel(model) ||
    "openclaw";

  runAsync([
    "session",
    "event",
    "--type",
    "agent.decision",
    "--model",
    model,
    "--provider",
    provider,
    "--agent-name",
    "openclaw",
  ]);
}

function onSessionEnd(_ctx: unknown): void {
  if (!treeshipAvailable() || !projectInitialized() || !sessionActive()) return;

  // Generic auto-headline. If the agent (or a higher-priority skill) closed
  // with a real headline earlier, `session status --check` returns 1 and
  // we never reach here.
  const close = runSync([
    "session",
    "close",
    "--headline",
    "OpenClaw session",
  ]);
  if (!close.ok) return;

  // Best-effort publish. URL goes nowhere productive from a Gateway-side
  // process, but we trigger the publish so the agent can read the URL out
  // of the local receipt on its next session-status check.
  runAsync(["session", "report"]);
}

function inferProviderFromModel(model: string): string | null {
  const m = model.toLowerCase();
  if (m.includes("claude")) return "anthropic";
  if (m.includes("gpt") || m.includes("o1") || m.includes("o3") || m.includes("o4")) return "openai";
  if (m.includes("kimi")) return "moonshot";
  if (m.includes("deepseek")) return "deepseek";
  if (m.includes("gemini")) return "google";
  if (m.includes("llama")) return "meta";
  if (m.includes("mistral") || m.includes("mixtral")) return "mistral";
  return null;
}

// ---------------------------------------------------------------------------
// Entry point. OpenClaw discovers plugins by importing this module and
// invoking the default export with an api object. Some SDK versions wrap
// the entry in `definePluginEntry`; both shapes are supported by exporting
// both the raw function AND a wrapped form when the runtime helper exists.
// ---------------------------------------------------------------------------

const entry: PluginEntry = (api: PluginApi) => {
  // Tool-call hooks: register with both snake_case and camelCase names
  // via both registerHook and api.on for maximum runtime compatibility.
  const beforeNames = ["before_tool_call", "beforeToolCall"];
  for (const name of beforeNames) {
    if (typeof api.registerHook === "function") {
      try { api.registerHook(name as any, onBeforeToolCall, { name: `treeship-before-${name}` }); } catch (e) {}
    }
    if (typeof (api as any).on === "function") {
      try { (api as any).on(name, onBeforeToolCall, { name: `treeship-before-${name}` }); } catch (e) {}
    }
  }
  const afterNames = ["after_tool_call", "afterToolCall"];
  for (const name of afterNames) {
    if (typeof api.registerHook === "function") {
      try { api.registerHook(name as any, onAfterToolCall, { name: `treeship-after-${name}` }); } catch (e) {}
    }
    if (typeof (api as any).on === "function") {
      try { (api as any).on(name, onAfterToolCall, { name: `treeship-after-${name}` }); } catch (e) {}
    }
  }
  // Session-lifecycle hooks
  const sessionNames = ["session_start", "sessionStart", "before_session_start", "beforeSessionStart"];
  for (const name of sessionNames) {
    if (typeof api.registerHook === "function") {
      try { api.registerHook(name as any, onSessionStart, { name: `treeship-${name}` }); } catch (e) {}
    }
    if (typeof (api as any).on === "function") {
      try { (api as any).on(name, onSessionStart, { name: `treeship-${name}` }); } catch (e) {}
    }
  }
  const endNames = ["session_end", "sessionEnd", "after_session_end", "afterSessionEnd"];
  for (const name of endNames) {
    if (typeof api.registerHook === "function") {
      try { api.registerHook(name as any, onSessionEnd, { name: `treeship-${name}` }); } catch (e) {}
    }
    if (typeof (api as any).on === "function") {
      try { (api as any).on(name, onSessionEnd, { name: `treeship-${name}` }); } catch (e) {}
    }
  }
};

export default entry;

// Some OpenClaw versions look for a named export `register` instead of the
// default export. Provide both so the plugin is discoverable either way.
export const register = entry;

// Re-export under definePluginEntry-style if the SDK helper is present at
// runtime. Static import would create a hard dep on `openclaw`; we resolve
// it lazily so the plugin is usable in environments where the SDK module
// resolution is non-standard (vendored builds, test harnesses, etc.).
try {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const sdk = require("openclaw") as { definePluginEntry?: (opts: { id: string; name: string; description: string; register: PluginEntry }) => unknown };
  if (sdk && typeof sdk.definePluginEntry === "function") {
    module.exports = sdk.definePluginEntry({
      id: "treeship",
      name: "Treeship",
      description: "Auto-capture OpenClaw tool calls into Treeship receipts",
      register: entry
    });
    // Preserve named exports so `import { register }` still works.
    (module.exports as { register: PluginEntry }).register = entry;
    (module.exports as { default: PluginEntry }).default = entry;
  }
} catch {
  // openclaw not resolvable at load time -- default export is the contract.
}
