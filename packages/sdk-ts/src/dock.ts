import { runTreeship } from "./exec.js";
import type { PushResult } from "./types.js";

export class DockModule {
  async push(id: string): Promise<PushResult> {
    const result = await runTreeship(["dock", "push", id, "--format", "json"]);
    return {
      hubUrl: (result.hub_url || result.url || "") as string,
      rekorIndex: result.rekor_index as number | undefined,
    };
  }

  async pull(id: string): Promise<void> {
    await runTreeship(["dock", "pull", id]);
  }

  async status(): Promise<{ docked: boolean; endpoint?: string; dockId?: string }> {
    try {
      const result = await runTreeship(["dock", "status", "--format", "json"]);
      return {
        docked: result.status === "docked",
        endpoint: result.endpoint as string | undefined,
        dockId: result.dock_id as string | undefined,
      };
    } catch {
      return { docked: false };
    }
  }
}
