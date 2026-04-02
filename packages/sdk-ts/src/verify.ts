import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { VerifyResult } from "./types.js";

const exec = promisify(execFile);

export class VerifyModule {
  async verify(id: string): Promise<VerifyResult> {
    let stdout = "";
    let stderr = "";

    try {
      const result = await exec("treeship", ["verify", id, "--format", "json"], {
        timeout: 10_000,
        env: { ...process.env },
      });
      stdout = result.stdout;
    } catch (err: unknown) {
      // Binary not found -- re-throw as operational error
      if (err instanceof Error && (err.message.includes("ENOENT") || err.message.includes("not found"))) {
        throw err;
      }

      // Non-zero exit: try to parse stdout/stderr for structured output.
      // The CLI writes JSON to stdout even on verification failure.
      const execErr = err as { stdout?: string; stderr?: string };
      stdout = execErr.stdout || "";
      stderr = execErr.stderr || "";

      if (!stdout) {
        // No JSON output at all -- this is an operational error, not a verification failure.
        throw new Error(
          `treeship verify failed: ${stderr || (err instanceof Error ? err.message : String(err))}`
        );
      }
    }

    // Parse the JSON output from the CLI.
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(stdout);
    } catch {
      throw new Error(`treeship verify returned invalid JSON: ${stdout.slice(0, 200)}`);
    }

    const outcome = parsed.outcome as string;
    if (outcome === "pass") {
      return {
        outcome: "pass",
        chain: (parsed.passed || parsed.total || 1) as number,
        target: id,
      };
    } else if (outcome === "fail") {
      return {
        outcome: "fail",
        chain: (parsed.failed || 0) as number,
        target: id,
      };
    } else {
      // outcome: "error" or unknown -- propagate as operational error
      throw new Error(`treeship verify error: ${parsed.message || JSON.stringify(parsed)}`);
    }
  }
}
