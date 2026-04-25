import { describe, it, expect } from "vitest";
import { ship } from "../src/index.js";

describe("@treeship/sdk", () => {
  it("exports ship factory", () => {
    expect(ship).toBeDefined();
    expect(typeof ship).toBe("function");
  });

  it("ship has attest, verify, hub modules", () => {
    const s = ship();
    expect(s.attest).toBeDefined();
    expect(s.verify).toBeDefined();
    expect(s.hub).toBeDefined();
  });

  it("attest module has action, approval, handoff, decision", () => {
    const s = ship();
    expect(typeof s.attest.action).toBe("function");
    expect(typeof s.attest.approval).toBe("function");
    expect(typeof s.attest.handoff).toBe("function");
    expect(typeof s.attest.decision).toBe("function");
  });

  it("verify module has legacy artifact-ID verify method", () => {
    const s = ship();
    expect(typeof s.verify.verify).toBe("function");
  });

  it("verify module has WASM-backed receipt / certificate / cross verifiers", () => {
    const s = ship();
    expect(typeof s.verify.verifyReceipt).toBe("function");
    expect(typeof s.verify.verifyCertificate).toBe("function");
    expect(typeof s.verify.crossVerify).toBe("function");
  });

  it("hub module has push, pull, status methods", () => {
    const s = ship();
    expect(typeof s.hub.push).toBe("function");
    expect(typeof s.hub.pull).toBe("function");
    expect(typeof s.hub.status).toBe("function");
  });
});
