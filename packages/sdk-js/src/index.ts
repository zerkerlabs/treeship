/**
 * Treeship JavaScript/TypeScript SDK
 *
 * @example
 * ```typescript
 * import { TreshipClient } from '@treeship/sdk';
 *
 * const client = new TreshipClient();
 * const result = await client.attest({
 *   action: 'Document processed',
 *   inputs: { doc_id: '123' }
 * });
 * console.log(result.url);
 * ```
 */

import { createHash } from "crypto";
import * as ed from "@noble/ed25519";

export interface AttestOptions {
  action: string;
  inputs?: Record<string, unknown>;
  agent?: string;
  metadata?: Record<string, unknown>;
}

export interface AttestResult {
  attested: boolean;
  id?: string;
  url?: string;
  timestamp?: string;
  signature?: string;
  error?: string;
}

export interface VerifyResult {
  valid: boolean;
  signatureValid: boolean;
  keyMatches: boolean;
  attestation?: Record<string, unknown>;
  error?: string;
}

export interface TreshipClientOptions {
  apiKey?: string;
  apiUrl?: string;
  agent?: string;
  timeout?: number;
}

function hashInputs(inputs: Record<string, unknown> | undefined): string {
  const data = inputs || {};
  const canonical = JSON.stringify(data, Object.keys(data).sort());
  return createHash("sha256").update(canonical).digest("hex");
}

function base64urlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padding = "=".repeat((4 - (base64.length % 4)) % 4);
  return Uint8Array.from(Buffer.from(base64 + padding, "base64"));
}

export class TreshipClient {
  private apiKey: string;
  private apiUrl: string;
  private agent: string;
  private timeout: number;

  constructor(options: TreshipClientOptions = {}) {
    this.apiKey = options.apiKey || process.env.TREESHIP_API_KEY || "";
    this.apiUrl = (
      options.apiUrl ||
      process.env.TREESHIP_API_URL ||
      "https://api.treeship.dev"
    ).replace(/\/$/, "");
    this.agent = options.agent || process.env.TREESHIP_AGENT || "js-agent";
    this.timeout = options.timeout || 10000;
  }

  async attest(options: AttestOptions): Promise<AttestResult> {
    try {
      const inputsHash = hashInputs(options.inputs);

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeout);

      const response = await fetch(`${this.apiUrl}/v1/attest`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          "Content-Type": "application/json",
          "User-Agent": "treeship-sdk-js/1.0.0",
        },
        body: JSON.stringify({
          agent_slug: options.agent || this.agent,
          action: options.action.slice(0, 500),
          inputs_hash: inputsHash,
          metadata: options.metadata,
        }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        const data = await response.json();
        return {
          attested: true,
          id: data.attestation_id,
          url: data.public_url,
          timestamp: data.timestamp,
          signature: data.signature,
        };
      } else {
        return {
          attested: false,
          error: `API error: ${response.status}`,
        };
      }
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        return { attested: false, error: "Timeout" };
      }
      return {
        attested: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  async verify(attestationId: string): Promise<VerifyResult> {
    try {
      const [attestationRes, pubkeyRes] = await Promise.all([
        fetch(`${this.apiUrl}/v1/verify/${attestationId}`),
        fetch(`${this.apiUrl}/v1/pubkey`),
      ]);

      if (!attestationRes.ok) {
        return { valid: false, signatureValid: false, keyMatches: false, error: "Not found" };
      }

      const attestationData = await attestationRes.json();
      const pubkeyData = await pubkeyRes.json();

      const attestation = attestationData.attestation || attestationData;
      const expectedKey = pubkeyData.public_key;

      // Verify signature
      const canonical = JSON.stringify({
        action: attestation.action,
        agent: attestation.agent_slug || attestation.agent,
        id: attestation.id,
        inputs_hash: attestation.inputs_hash,
        timestamp: attestation.timestamp,
        version: "1.0",
      });

      const payload = new TextEncoder().encode(canonical);
      const signature = base64urlDecode(attestation.signature);
      const publicKey = base64urlDecode(attestation.public_key);

      const signatureValid = await ed.verifyAsync(signature, payload, publicKey);
      const keyMatches = !expectedKey || attestation.public_key === expectedKey;

      return {
        valid: signatureValid && keyMatches,
        signatureValid,
        keyMatches,
        attestation,
      };
    } catch (error) {
      return {
        valid: false,
        signatureValid: false,
        keyMatches: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }
}

export default TreshipClient;
