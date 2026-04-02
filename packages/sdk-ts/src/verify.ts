import { runTreeship } from "./exec.js";
import { TreeshipError, type VerifyResult } from "./types.js";

export class VerifyModule {
  async verify(id: string): Promise<VerifyResult> {
    try {
      const result = await runTreeship(["verify", id, "--format", "json"]);
      return {
        outcome: (result.outcome as string) === "pass" ? "pass" : (result.outcome as string) === "error" ? "error" : "fail",
        chain: (result.total || result.chain || 1) as number,
        target: id,
      };
    } catch (err: unknown) {
      // Non-zero exit from the CLI means verification failure, not a
      // transport/runtime error.  Only re-throw when the binary itself
      // is missing or some other OS-level problem occurred.
      if (isBinaryNotFound(err)) {
        throw err;
      }

      // The CLI exited non-zero -- treat as a verification "fail".
      return { outcome: "fail", target: id, chain: 0 };
    }
  }
}

/** Returns true when the error indicates the treeship binary is not on PATH. */
function isBinaryNotFound(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const msg = err.message;
  // Node's child_process surfaces ENOENT when the binary doesn't exist.
  return msg.includes("ENOENT") || msg.includes("not found");
}
