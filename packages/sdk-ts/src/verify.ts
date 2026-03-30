import { runTreeship } from "./exec.js";
import type { VerifyResult } from "./types.js";

export class VerifyModule {
  async verify(id: string): Promise<VerifyResult> {
    const result = await runTreeship(["verify", id, "--format", "json"]);
    return {
      outcome: (result.outcome as string) === "pass" ? "pass" : (result.outcome as string) === "error" ? "error" : "fail",
      chain: (result.total || result.chain || 1) as number,
      target: id,
    };
  }
}
