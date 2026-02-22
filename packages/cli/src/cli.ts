#!/usr/bin/env node
/**
 * Treeship CLI — cryptographic verification for AI agents
 */
import { Command } from "commander";
import Conf from "conf";
import ora from "ora";
import { createHash } from "crypto";
import * as ed from "@noble/ed25519";

const config = new Conf({ projectName: "treeship" });

const API_URL = process.env.TREESHIP_API_URL || "https://api.treeship.dev";

interface AttestResponse {
  attestation_id: string;
  public_url: string;
  timestamp: string;
  signature: string;
  public_key: string;
}

interface VerifyResponse {
  valid: boolean;
  attestation: {
    id: string;
    agent_slug: string;
    action: string;
    inputs_hash: string;
    timestamp: string;
    signature: string;
    public_key: string;
  };
}

interface PubKeyResponse {
  key_id: string;
  algorithm: string;
  public_key: string;
  public_key_pem: string;
}

async function getApiKey(): Promise<string> {
  const key = process.env.TREESHIP_API_KEY || (config.get("apiKey") as string);
  if (!key) {
    console.error("Error: No API key found.");
    console.error("Run 'treeship init' to configure, or set TREESHIP_API_KEY env var.");
    process.exit(1);
  }
  return key;
}

function hashInputs(inputs: Record<string, unknown>): string {
  const canonical = JSON.stringify(inputs, Object.keys(inputs).sort());
  return createHash("sha256").update(canonical).digest("hex");
}

function base64urlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padding = "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = Buffer.from(base64 + padding, "base64");
  return new Uint8Array(binary);
}

async function verifySignature(
  attestation: VerifyResponse["attestation"],
  expectedPublicKey?: string
): Promise<{ valid: boolean; keyMatch: boolean }> {
  const canonical = JSON.stringify({
    action: attestation.action,
    agent: attestation.agent_slug,
    id: attestation.id,
    inputs_hash: attestation.inputs_hash,
    timestamp: attestation.timestamp,
    version: "1.0",
  });

  const payload = new TextEncoder().encode(canonical);
  const signature = base64urlDecode(attestation.signature);
  const publicKey = base64urlDecode(attestation.public_key);

  const valid = await ed.verifyAsync(signature, payload, publicKey);
  const keyMatch = expectedPublicKey ? attestation.public_key === expectedPublicKey : true;

  return { valid, keyMatch };
}

const program = new Command()
  .name("treeship")
  .description("Cryptographic verification for AI agents")
  .version("1.0.0");

// treeship init
program
  .command("init")
  .description("Configure Treeship CLI")
  .action(async () => {
    const readline = await import("readline");
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    const question = (q: string): Promise<string> =>
      new Promise((resolve) => rl.question(q, resolve));

    console.log("\n🌳 Treeship Setup\n");
    console.log("Get your free API key at: https://treeship.dev/api-keys\n");

    const apiKey = await question("Enter your API key: ");
    config.set("apiKey", apiKey.trim());

    const agentSlug = await question("Default agent slug (e.g., my-agent): ");
    if (agentSlug.trim()) {
      config.set("defaultAgent", agentSlug.trim());
    }

    rl.close();

    console.log("\n✓ Configuration saved to ~/.config/treeship/config.json");
    console.log("\nTest it: treeship attest --action 'Test attestation'");
  });

// treeship attest
program
  .command("attest")
  .description("Create a new attestation")
  .requiredOption("-a, --action <action>", "Action description")
  .option("-g, --agent <agent>", "Agent slug")
  .option("-i, --inputs <json>", "Inputs as JSON (will be hashed)")
  .option("--inputs-hash <hash>", "Pre-computed inputs hash")
  .option("-j, --json", "Output as JSON")
  .action(async (opts) => {
    const apiKey = await getApiKey();
    const agent = opts.agent || (config.get("defaultAgent") as string) || "cli-agent";

    let inputsHash: string;
    if (opts.inputsHash) {
      inputsHash = opts.inputsHash;
    } else if (opts.inputs) {
      const inputs = JSON.parse(opts.inputs);
      inputsHash = hashInputs(inputs);
    } else {
      inputsHash = hashInputs({});
    }

    const spinner = opts.json ? null : ora("Creating attestation...").start();

    try {
      const response = await fetch(`${API_URL}/v1/attest`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
          "User-Agent": "treeship-cli/1.0.0",
        },
        body: JSON.stringify({
          agent_slug: agent,
          action: opts.action,
          inputs_hash: inputsHash,
        }),
      });

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`API error: ${response.status} ${error}`);
      }

      const data = (await response.json()) as AttestResponse;

      spinner?.stop();

      if (opts.json) {
        console.log(JSON.stringify(data, null, 2));
      } else {
        console.log(`\n✓ Attestation created`);
        console.log(`  ID: ${data.attestation_id}`);
        console.log(`  URL: ${data.public_url}`);
        console.log(`  Time: ${data.timestamp}`);
      }
    } catch (error) {
      spinner?.fail("Failed to create attestation");
      console.error(error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// treeship verify
program
  .command("verify <id>")
  .description("Verify an attestation")
  .option("-j, --json", "Output as JSON")
  .option("--local-only", "Verify signature locally without fetching from API")
  .action(async (id: string, opts) => {
    const spinner = opts.json ? null : ora("Verifying...").start();

    try {
      // Fetch attestation
      const attestationResponse = await fetch(`${API_URL}/v1/verify/${id}`);
      if (!attestationResponse.ok) {
        throw new Error(`Attestation not found: ${id}`);
      }
      const data = (await attestationResponse.json()) as VerifyResponse;

      // Fetch expected public key
      const pubkeyResponse = await fetch(`${API_URL}/v1/pubkey`);
      const pubkeyData = (await pubkeyResponse.json()) as PubKeyResponse;

      // Verify signature locally
      const { valid, keyMatch } = await verifySignature(
        data.attestation,
        pubkeyData.public_key
      );

      spinner?.stop();

      if (opts.json) {
        console.log(
          JSON.stringify(
            {
              ...data,
              local_verification: { signature_valid: valid, key_matches_treeship: keyMatch },
            },
            null,
            2
          )
        );
      } else {
        if (valid && keyMatch) {
          console.log(`\n✓ Signature valid`);
          console.log(`  Agent: ${data.attestation.agent_slug}`);
          console.log(`  Action: ${data.attestation.action}`);
          console.log(`  Time: ${data.attestation.timestamp}`);
          console.log(`  Inputs hash: ${data.attestation.inputs_hash.slice(0, 16)}...`);
        } else if (valid && !keyMatch) {
          console.log(`\n⚠ Signature valid but key doesn't match Treeship production key`);
          console.log(`  This may be from a self-hosted Treeship instance.`);
        } else {
          console.log(`\n✗ Signature INVALID`);
          console.log(`  This attestation may have been tampered with.`);
          process.exit(1);
        }
      }
    } catch (error) {
      spinner?.fail("Verification failed");
      console.error(error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// treeship pubkey
program
  .command("pubkey")
  .description("Get Treeship public key for manual verification")
  .option("-j, --json", "Output as JSON")
  .action(async (opts) => {
    try {
      const response = await fetch(`${API_URL}/v1/pubkey`);
      const data = (await response.json()) as PubKeyResponse;

      if (opts.json) {
        console.log(JSON.stringify(data, null, 2));
      } else {
        console.log(`\nTreeship Public Key`);
        console.log(`  Key ID: ${data.key_id}`);
        console.log(`  Algorithm: ${data.algorithm}`);
        console.log(`\n${data.public_key_pem}`);
      }
    } catch (error) {
      console.error("Failed to fetch public key");
      console.error(error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// treeship agent <slug>
program
  .command("agent <slug>")
  .description("View agent attestation feed")
  .option("-n, --limit <n>", "Number of attestations to show", "10")
  .option("-j, --json", "Output as JSON")
  .action(async (slug: string, opts) => {
    const spinner = opts.json ? null : ora("Fetching agent feed...").start();

    try {
      const response = await fetch(`${API_URL}/v1/agent/${slug}?limit=${opts.limit}`);
      if (!response.ok) {
        throw new Error(`Agent not found: ${slug}`);
      }
      const data = await response.json();

      spinner?.stop();

      if (opts.json) {
        console.log(JSON.stringify(data, null, 2));
      } else {
        console.log(`\nAgent: ${slug}`);
        console.log(`Total attestations: ${data.total}\n`);

        for (const att of data.attestations || []) {
          console.log(`  ${att.timestamp}`);
          console.log(`    ${att.action}`);
          console.log(`    ${att.public_url}\n`);
        }
      }
    } catch (error) {
      spinner?.fail("Failed to fetch agent feed");
      console.error(error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

program.parse();
