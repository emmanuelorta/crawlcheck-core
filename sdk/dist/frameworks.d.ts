export declare class ContinuityRefused extends Error {
    why: any;
    record: any;
    tool: any;
    constructor(why: any, record?: null, tool?: null);
}
/** The shared gate. lock: an approved mcp-lockfile (with lock.parts so a change can be named). */
export declare function continuityGate(lock: any, opts?: {}): {
    mode: any;
    records: never[];
    record: null;
    paused: Set<any>;
    keepRecord(rec: any): Promise<any>;
    ask(req: any): Promise<boolean>;
    /** Compare the offered tools with the lock and apply the mode. Returns the record; throws ContinuityRefused. */
    check(tools: any, meta?: {}): Promise<any>;
    /** Record a check that could not compare anything. Throws ContinuityRefused outside observe. */
    fail(cls: any, detail: any): Promise<any>;
    /** The tools the agent may see: all of them in observe mode, else without the paused ones. */
    allowed(tools: any, nameOf?: (t: any) => any): any;
    /** Refuse a call to a paused tool (a framework that cached an earlier list could still try it). */
    callOk(name: any): boolean;
};
/**
 * OpenAI Agents SDK (@openai/agents): wrap an MCP server (MCPServerStdio, MCPServerStreamableHttp, MCPServerSSE or your
 * own MCPServer) so every listTools() the SDK makes is checked against lock. Everything else is the server's own.
 *   const guarded = withContinuity(server, lock, { mode: "observe" });  new Agent({ name, instructions, mcpServers: [guarded] })
 * The records are at guarded.continuity.records.
 */
export declare function withContinuity(server: any, lock: any, opts?: {}): any;
/**
 * LangChain (@langchain/mcp-adapters): loadMcpTools with the continuity check.
 *   const tools = await loadMcpToolsWithContinuity("shop", client, lock, { mode: "observe" })
 * client: a MultiServerMCPClient (its connection for serverName is used) or a connected MCP SDK Client. The list is read
 * once (every page) and the LangChain tools are converted from exactly the definitions that were compared.
 * opts.adapters: the @langchain/mcp-adapters module (default: imported on first use); opts.loadOptions: its
 * LoadMcpToolsOptions. The gate (records) is opts.gate, or read them from opts.onRecord.
 */
export declare function loadMcpToolsWithContinuity(serverName: any, client: any, lock: any, opts?: {}): Promise<any>;
