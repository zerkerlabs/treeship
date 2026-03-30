import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { TreeshipError } from "./types.js";

const exec = promisify(execFile);

export async function runTreeship(args: string[]): Promise<Record<string, unknown>> {
  try {
    const { stdout } = await exec("treeship", args, {
      timeout: 10_000,
      env: { ...process.env },
    });
    return JSON.parse(stdout);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new TreeshipError(`treeship ${args.slice(0, 2).join(" ")} failed: ${msg}`, args);
  }
}
