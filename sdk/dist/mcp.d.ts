export declare class McpPreflightRefused extends Error {
    stage: any;
    why: any;
    receipt: any;
    lock: any;
    verification: any;
    constructor(stage: any, why: any, detail: any);
}
/** The server URL a transport will talk to, if it can be read (Streamable HTTP and SSE transports keep it as _url or url). */
export declare function transportUrl(transport: any): string | null;
/**
 * The two hooks. cc is a CrawlCheck client (from this SDK). opts: template (default safe_mcp_tool), policy, agent,
 * confirm(receipt) for require_confirmation, allowWarn, lock (an approved McpLock), confirmDestructive, maxAgeMs for a
 * cached connect receipt (default: until the receipt's expires_at).
 */
export declare function mcpPreflight(cc: any, opts?: {}): {
    state: {
        url: null;
        host: null;
        receipt: null;
        verification: null;
        decidedAt: number;
        lockCheck: null;
        approved: null;
        continuity: null;
        records: never[];
        pausedTools: null;
    };
    /** Before initialize. url: the server URL (a stdio/local server has none and is not decided; pass opts.local = "allow" | "refuse", default allow). */
    beforeConnect(url: any): Promise<{
        local: boolean;
        receipt: null;
        host?: undefined;
        verification?: undefined;
    } | {
        local: boolean;
        host: string;
        receipt: any;
        verification: any;
    }>;
    /** After initialize, with the tools the server lists. Refuses (and the wrapper closes the client) when they differ from the approved lockfile. */
    afterConnect(tools: any, meta: any): Promise<any>;
    /** Before tools/call. */
    beforeToolCall(name: any, annotations: any, tool: any): Promise<{
        receipt: any;
        tool_receipt: any;
    }>;
};
/**
 * Wrap an MCP client in place: client.connect and client.callTool run the hooks first. Returns the same client, with
 * client.preflight (the hooks and their state). Works on @modelcontextprotocol/sdk's Client and on anything with the same
 * two methods; listTools() is used for the lockfile check when present.
 */
export declare function withPreflight(client: any, cc: any, opts?: {}): any;
