import { AttestModule } from "./attest.js";
import { VerifyModule } from "./verify.js";
import { DockModule } from "./dock.js";

export class Ship {
  readonly attest = new AttestModule();
  readonly verify = new VerifyModule();
  readonly dock = new DockModule();
}
