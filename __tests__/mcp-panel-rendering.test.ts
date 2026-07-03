import { describe, expect, it, vi } from "vitest";
import { createMcpPanel } from "../mcp-panel.ts";
import { computeServerHash, type MetadataCache } from "../metadata-cache.ts";
import type { McpConfig, McpPanelCallbacks, McpPanelResult } from "../types.ts";

function stripAnsi(input: string): string {
  return input.replace(/\x1b\[[0-9;]*m/g, "");
}

function createCallbacks(): McpPanelCallbacks {
  return {
    reconnect: async () => true,
    canAuthenticate: () => false,
    authenticate: async () => ({ ok: false }),
    getConnectionStatus: () => "idle",
    refreshCacheAfterReconnect: () => null,
  };
}

function createConfig(): McpConfig {
  return {
    mcpServers: {
      atlassian: { command: "npx", args: ["-y", "atlassian-mcp"] },
    },
  };
}

function createCache(config: McpConfig): MetadataCache {
  return {
    version: 1,
    servers: {
      atlassian: {
        configHash: computeServerHash(config.mcpServers.atlassian),
        cachedAt: Date.now(),
        tools: [
          {
            name: "search\u0007issues",
            description: "Search\r\n\x1b[31missues\x1b[0m\tby query\u0000now",
          },
          { name: "list_projects", description: "List projects" },
        ],
        resources: [],
      },
    },
  };
}

describe("mcp-panel rendering", () => {
  it("renders MCP metadata as single-line display text", () => {
    const config = createConfig();
    const panel = createMcpPanel(
      config,
      createCache(config),
      new Map(),
      createCallbacks(),
      { requestRender: () => {} },
      () => {},
    );

    panel.handleInput("\r");

    const lines = panel.render(120);
    const output = stripAnsi(lines.join("\n"));

    expect(output).toContain("search issues");
    expect(output).toContain("Search issues by query now");
    expect(lines.some((line) => /[\r\n\u0000-\u001f\u007f-\u009f]/.test(stripAnsi(line)))).toBe(false);
    expect(output).not.toContain("[31m");
    panel.dispose();
  });

  it("keeps dirty changes and closes when Keep & Close is confirmed", () => {
    const config = createConfig();
    const done = vi.fn<(result: McpPanelResult) => void>();
    const panel = createMcpPanel(
      config,
      createCache(config),
      new Map(),
      createCallbacks(),
      { requestRender: () => {} },
      done,
    );

    panel.handleInput("\r");
    panel.handleInput("\x1b[B");
    panel.handleInput("\r");
    panel.handleInput("\x1b");

    expect(stripAnsi(panel.render(120).join("\n"))).toContain("Keep & Close");

    panel.handleInput("\r");

    expect(done).toHaveBeenCalledTimes(1);
    const result = done.mock.calls[0][0];
    expect(result.cancelled).toBe(false);
    expect(result.changes.get("atlassian")).toEqual(["search\u0007issues"]);
    panel.dispose();
  });
});
