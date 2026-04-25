import { Ship } from "./ship.js";

export function ship(): Ship {
  return new Ship();
}

export { Ship } from "./ship.js";
export { AttestModule } from "./attest.js";
export { VerifyModule } from "./verify.js";
export { HubModule } from "./hub.js";
export * from "./types.js";
