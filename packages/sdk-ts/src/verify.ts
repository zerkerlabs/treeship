import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type {
  CrossVerifyResult,
  VerifyCertificateResult,
  VerifyReceiptResult,
  VerifyResult,
} from "./types.js";

const exec = promisify(execFile);

// Lazy WASM load. Keeps the SDK's module graph resolvable even in
// environments where @treeship/core-wasm hasn't been installed yet (for
// example during early bootstrap CI, before the release pipeline has
// published core-wasm). The first verification call pays the load cost;
// subsequent calls reuse the cached bindings.
type WasmBindings = {
  verify_receipt: (json: string) => string;
  verify_certificate: (json: string, now: string) => string;
  cross_verify: (receipt: string, cert: string, now: string) => string;
};

let wasmBindings: WasmBindings | null = null;

async function loadWasm(): Promise<WasmBindings> {
  if (wasmBindings) return wasmBindings;
  const mod = (await import("@treeship/core-wasm")) as unknown as WasmBindings;
  wasmBindings = mod;
  return mod;
}

/**
 * A verifiable target: either a parsed object, a JSON string, a URL string,
 * or a URL object. The SDK normalizes all four forms into a JSON string
 * before handing off to WASM.
 */
export type VerifyTarget = string | URL | Record<string, unknown>;

async function normalizeToJson(target: VerifyTarget): Promise<string> {
  if (typeof target === "object" && !(target instanceof URL)) {
    return JSON.stringify(target);
  }
  const raw = target instanceof URL ? target.toString() : target;
  if (raw.startsWith("http://") || raw.startsWith("https://")) {
    // Accept both the Hub JSON API path and the human-readable mirror.
    const apiUrl = raw.replace("/receipt/", "/v1/receipt/");
    const res = await fetch(apiUrl, { headers: { accept: "application/json" } });
    if (!res.ok) {
      throw new Error(`fetch ${apiUrl} returned HTTP ${res.status}`);
    }
    return await res.text();
  }
  return raw;
}

export class VerifyModule {
  /**
   * Legacy artifact-ID verify path. Shells out to the CLI because this
   * walks the local storage chain (which lives under .treeship/), something
   * WASM in an arbitrary runtime has no access to. Kept for backwards
   * compatibility; new callers should prefer verifyReceipt / verifyCertificate /
   * crossVerify below.
   */
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
      if (
        err instanceof Error &&
        (err.message.includes("ENOENT") || err.message.includes("not found"))
      ) {
        throw err;
      }
      const execErr = err as { stdout?: string; stderr?: string };
      stdout = execErr.stdout || "";
      stderr = execErr.stderr || "";
      if (!stdout) {
        throw new Error(
          `treeship verify failed: ${stderr || (err instanceof Error ? err.message : String(err))}`
        );
      }
    }

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
      throw new Error(`treeship verify error: ${parsed.message || JSON.stringify(parsed)}`);
    }
  }

  /**
   * Verify a Session Receipt directly via WebAssembly. Accepts a parsed
   * receipt object, a JSON string, or a URL (fetched with global fetch).
   * Returns the full check-by-check result.
   *
   * Runs anywhere WASM + fetch are available: Node 18+, browser, Vercel
   * Edge, Cloudflare Workers, AWS Lambda, Deno.
   */
  async verifyReceipt(target: VerifyTarget): Promise<VerifyReceiptResult> {
    const json = await normalizeToJson(target);
    const wasm = await loadWasm();
    return JSON.parse(wasm.verify_receipt(json));
  }

  /**
   * Verify an Agent Certificate directly via WebAssembly. Checks the
   * embedded Ed25519 signature and (if `now` is supplied) classifies the
   * validity window.
   *
   * Supply `now` as a Date or RFC 3339 string. Omit to defer validity
   * classification (signature-only check).
   */
  async verifyCertificate(
    target: VerifyTarget,
    now?: Date | string
  ): Promise<VerifyCertificateResult> {
    const json = await normalizeToJson(target);
    const nowStr =
      now === undefined
        ? ""
        : now instanceof Date
          ? now.toISOString()
          : now;
    const wasm = await loadWasm();
    return JSON.parse(wasm.verify_certificate(json, nowStr));
  }

  /**
   * Cross-verify a Session Receipt against an Agent Certificate. Same
   * semantics as `treeship verify --certificate` from the CLI: ship IDs
   * match, certificate valid at `now`, zero unauthorized tool calls.
   */
  async crossVerify(
    receipt: VerifyTarget,
    certificate: VerifyTarget,
    now?: Date | string
  ): Promise<CrossVerifyResult> {
    const [receiptJson, certJson] = await Promise.all([
      normalizeToJson(receipt),
      normalizeToJson(certificate),
    ]);
    const nowStr =
      now === undefined
        ? new Date().toISOString()
        : now instanceof Date
          ? now.toISOString()
          : now;
    const wasm = await loadWasm();
    return JSON.parse(wasm.cross_verify(receiptJson, certJson, nowStr));
  }
}
