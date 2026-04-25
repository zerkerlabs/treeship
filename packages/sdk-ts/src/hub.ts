import { runTreeship } from "./exec.js";
import type { PushResult } from "./types.js";

export class HubModule {
  async push(id: string): Promise<PushResult> {
    const result = await runTreeship(["hub", "push", id, "--format", "json"]);
    return {
      hubUrl: (result.hub_url || result.url || "") as string,
      rekorIndex: result.rekor_index as number | undefined,
    };
  }

  async pull(id: string): Promise<void> {
    await runTreeship(["hub", "pull", id]);
  }

  async status(): Promise<{ connected: boolean; endpoint?: string; hubId?: string }> {
    try {
      const result = await runTreeship(["hub", "status", "--format", "json"]);
      return {
        connected: result.status === "active" || result.status === "attached" || result.status === "connected",
        endpoint: result.endpoint as string | undefined,
        hubId: (result.hub_id || result.dock_id) as string | undefined,
      };
    } catch {
      return { connected: false };
    }
  }
}
