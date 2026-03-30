import { describe, it, expect } from "vitest";
import { ship } from "../src/index.js";

describe("@treeship/sdk", () => {
  it("exports ship factory", () => {
    expect(ship).toBeDefined();
    expect(typeof ship).toBe("function");
  });

  it("ship has attest, verify, dock modules", () => {
    const s = ship();
    expect(s.attest).toBeDefined();
    expect(s.verify).toBeDefined();
    expect(s.dock).toBeDefined();
  });

  it("attest module has action, approval, handoff, decision", () => {
    const s = ship();
    expect(typeof s.attest.action).toBe("function");
    expect(typeof s.attest.approval).toBe("function");
    expect(typeof s.attest.handoff).toBe("function");
    expect(typeof s.attest.decision).toBe("function");
  });

  it("verify module has verify method", () => {
    const s = ship();
    expect(typeof s.verify.verify).toBe("function");
  });

  it("dock module has push, pull, status methods", () => {
    const s = ship();
    expect(typeof s.dock.push).toBe("function");
    expect(typeof s.dock.pull).toBe("function");
    expect(typeof s.dock.status).toBe("function");
  });
});
