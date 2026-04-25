import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { AttestModule } from "./attest.js";
import { VerifyModule } from "./verify.js";
import { HubModule } from "./hub.js";

const exec = promisify(execFile);

/**
 * Main entry point for the Treeship TypeScript SDK.
 *
 * This SDK shells out to the `treeship` CLI binary, which must be installed
 * and available on your PATH.  Use {@link Ship.checkCli} to verify the
 * binary is reachable before calling other methods.
 */
export class Ship {
  readonly attest = new AttestModule();
  readonly verify = new VerifyModule();
  readonly hub = new HubModule();

  /**
   * Checks that the `treeship` CLI binary is available and returns its
   * version string (e.g. "0.4.1").
   *
   * Throws a descriptive error if the binary is not found on PATH.
   */
  static async checkCli(): Promise<string> {
    try {
      const { stdout } = await exec("treeship", ["version"], {
        timeout: 5_000,
        env: { ...process.env },
      });
      return stdout.trim();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("ENOENT") || msg.includes("not found")) {
        throw new Error(
          "treeship CLI binary not found on PATH. " +
          "Install it from https://treeship.dev/docs/install before using the SDK.",
        );
      }
      throw new Error(`Failed to run 'treeship version': ${msg}`);
    }
  }
}
