// Tool-interface continuity for agent frameworks (1.12.0, https://crawlcheck.io/spec/continuity). The same contract as the
// Python package's continuity_gate.py and its openai_agents / langchain / crewai adapters.
//
// The check runs where the framework fetches an MCP server's tool list, against the lockfile the operator approved:
//   observe  every difference is recorded (gate.records, onRecord, console.warn unless log: false) and the tools pass
//            through unchanged. Nothing is blocked.
//   review   any difference pauses the whole server until confirm() says yes; integrity failures are denied.
//   enforce  the policy applies: by default a changed or new tool is withheld from the agent (pause_tool) until confirm()
//            re-approves it; a whole-server pause or refresh asks confirm() once; deny throws ContinuityRefused.
// confirm(request) may return a promise; request is { continuity: record } for the server or { tool, continuity } for one
// tool. A yes is remembered for that exact definition, so a framework that lists tools every turn does not ask twice.
// No framework is a dependency of this package: each adapter imports its framework only when called.
// 1.13.0 signed baseline: when the gate is created it checks the lockfile's signature (verifyLockBaseline) before trusting
// it. opts.operatorKeys, keyPolicy, publishedKids, trustedKids, requireSignedBaseline. A bad or forged signature, or an
// unsigned lockfile when requireSignedBaseline, is recorded as baseline_untrusted; outside observe every check then throws.
// await gate.ready (or use openContinuityGate) to fail at startup.
import { continuityCheck, continuityFailure, verifyLockBaseline, baselineRefusal } from "./continuity.js";
import { canon } from "./verify.js";
export class ContinuityRefused extends Error {
    constructor(why, record = null, tool = null) {
        super("CrawlCheck continuity refused" + (tool ? " tool " + tool : "") + ": " + why);
        this.name = "ContinuityRefused";
        this.why = why;
        this.record = record;
        this.tool = tool;
    }
}
const pick = (t) => ({ name: t?.name, description: t?.description, inputSchema: t?.inputSchema ?? t?.input_schema, annotations: t?.annotations });
/** The shared gate. lock: an approved mcp-lockfile (with lock.parts so a change can be named). */
export function continuityGate(lock, opts = {}) {
    const mode = opts.mode || "observe";
    if (["observe", "review", "enforce"].indexOf(mode) < 0)
        throw new Error("mode must be observe, review or enforce");
    if (!lock || !Array.isArray(lock.tools))
        throw new Error("lock must be an approved mcp-lockfile (an object with a tools array); see https://crawlcheck.io/spec/mcp-lockfile");
    const keep = opts.keep ?? 50, okTools = new Set(), okLists = new Set();
    let lastKey = null, base = lock, refused = null;
    const co = { mode, policy: opts.policy, exceptions: opts.exceptions, server: opts.server ?? undefined, serverIdentity: opts.serverIdentity, expectPolicySha256: opts.expectPolicySha256 };
    const requireSigned = opts.requireSignedBaseline ?? !!(opts.operatorKeys && opts.operatorKeys.length);
    const gate = {
        mode, records: [], record: null, paused: new Set(), baseline: null, ready: null,
        get refused() { return refused; },
        async keepRecord(rec) {
            gate.record = rec;
            gate.records = gate.records.concat([rec]).slice(-keep);
            const changed = rec.events.some((e) => e.class !== "unchanged");
            if (changed && opts.log !== false)
                (opts.logger || console).warn("crawlcheck continuity " + rec.mode + " " + (rec.server || "-") + ": would " + rec.would + ", outcome " + rec.outcome + ": " + rec.why.join("; "));
            if (opts.onRecord) {
                try {
                    await opts.onRecord(rec);
                }
                catch (e) { /* recording never breaks the agent */ }
            }
            return rec;
        },
        async ask(req) {
            if (!opts.confirm)
                return false;
            try {
                return !!(await opts.confirm(req));
            }
            catch {
                return false;
            }
        },
        /** Compare the offered tools with the lock and apply the mode. Returns the record; throws ContinuityRefused. */
        async check(tools, meta = {}) {
            await gate.ready;
            if (refused)
                throw refused;
            const complete = meta.complete !== false;
            const rows = Array.isArray(tools) ? tools.map(pick) : tools;
            let rec = await continuityCheck(base, rows, Object.assign({}, co, { complete, baselineTrust: gate.baseline && gate.baseline.trust }));
            const key = (rec.observed?.tools_sha256 ?? "") + "|" + complete;
            if (lastKey === key && gate.record)
                rec = gate.record;
            else {
                lastKey = key;
                await gate.keepRecord(rec);
            }
            if (mode === "observe") {
                gate.paused = new Set();
                return rec;
            }
            if (rec.outcome === "deny")
                throw new ContinuityRefused(rec.why.join("; "), rec);
            if (rec.outcome === "pause" || rec.outcome === "refresh") {
                if (!okLists.has(key)) {
                    if (!(await gate.ask({ continuity: rec })))
                        throw new ContinuityRefused(rec.why.join("; "), rec);
                    okLists.add(key);
                }
                gate.paused = new Set();
                return rec;
            }
            const byName = {};
            for (const r of Array.isArray(rows) ? rows : [])
                byName[String(r.name ?? "").slice(0, 120)] = canon(r);
            const paused = new Set();
            for (const n of rec.paused_tools) {
                const k = n + "\n" + (byName[n] ?? "");
                if (okTools.has(k) || (await gate.ask({ tool: n, continuity: rec })))
                    okTools.add(k);
                else
                    paused.add(n);
            }
            gate.paused = paused;
            return rec;
        },
        /** Record a check that could not compare anything. Throws ContinuityRefused outside observe. */
        async fail(cls, detail) {
            await gate.ready;
            if (refused)
                throw refused;
            const rec = await continuityFailure(cls, Object.assign({}, co, { detail: detail ? String(detail).slice(0, 300) : undefined }));
            lastKey = null;
            await gate.keepRecord(rec);
            if (mode !== "observe" && rec.outcome !== "proceed")
                throw new ContinuityRefused(rec.why.join("; "), rec);
            return rec;
        },
        /** The tools the agent may see: all of them in observe mode, else without the paused ones. */
        allowed(tools, nameOf = (t) => t?.name) { return mode === "observe" || !gate.paused.size ? tools.slice() : tools.filter((t) => !gate.paused.has(nameOf(t))); },
        /** Refuse a call to a paused tool (a framework that cached an earlier list could still try it). */
        callOk(name) { if (mode !== "observe" && gate.paused.has(name))
            throw new ContinuityRefused("tool " + name + " changed since it was approved (or is new) and no person re-approved it", gate.record, name); return true; },
    };
    gate.ready = (async () => {
        let b;
        try {
            b = await verifyLockBaseline(lock, opts);
        }
        catch (e) {
            b = { trust: "invalid", signer: null, kid: null, why: "the baseline could not be checked: " + (e && e.message || e), parts_used: false, lock };
        }
        gate.baseline = { trust: b.trust, signer: b.signer, kid: b.kid, why: b.why, parts_used: b.parts_used };
        base = b.lock || lock;
        const bad = baselineRefusal(b, requireSigned);
        if (bad) {
            const rec = await continuityFailure("baseline_untrusted", Object.assign({}, co, { detail: String(bad).slice(0, 300) }));
            await gate.keepRecord(rec);
            if (mode !== "observe" && rec.outcome !== "proceed")
                refused = new ContinuityRefused(rec.why.join("; ") + ": " + bad, rec);
        }
        return gate.baseline;
    })();
    gate.ready.catch(() => { }); // a bad policy is thrown by check(), which awaits ready
    return gate;
}
/** continuityGate, checked at startup: resolves to the gate once the baseline verifies, throws ContinuityRefused when it does not (outside observe). */
export async function openContinuityGate(lock, opts = {}) {
    const g = continuityGate(lock, opts);
    await g.ready;
    if (g.refused)
        throw g.refused;
    return g;
}
const urlOf = (s) => {
    for (const p of [s && s.params, s && s.underlying && s.underlying.params, s && s.options])
        if (p && typeof p.url === "string" && p.url)
            return p.url;
    return null;
};
/**
 * OpenAI Agents SDK (@openai/agents): wrap an MCP server (MCPServerStdio, MCPServerStreamableHttp, MCPServerSSE or your
 * own MCPServer) so every listTools() the SDK makes is checked against lock. Everything else is the server's own.
 *   const guarded = withContinuity(server, lock, { mode: "observe" });  new Agent({ name, instructions, mcpServers: [guarded] })
 * The records are at guarded.continuity.records.
 */
export function withContinuity(server, lock, opts = {}) {
    const gate = opts.gate || continuityGate(lock, Object.assign({ server: opts.serverUrl ?? urlOf(server) ?? undefined }, opts));
    const listTools = async (...a) => {
        let tools;
        try {
            tools = await server.listTools(...a);
        }
        catch (e) {
            await gate.fail("server_unavailable", e && e.message);
            throw e;
        }
        await gate.check(tools, { complete: true }); // the Agents SDK reads every page or throws
        return gate.allowed(tools);
    };
    const callTool = async (name, ...a) => { gate.callOk(name); return server.callTool(name, ...a); };
    const callToolResult = server.callToolResult ? async (name, ...a) => { gate.callOk(name); return server.callToolResult(name, ...a); } : undefined;
    return new Proxy(server, {
        get(target, k) {
            if (k === "listTools")
                return listTools;
            if (k === "callTool")
                return callTool;
            if (k === "callToolResult" && callToolResult)
                return callToolResult;
            if (k === "continuity")
                return gate;
            const v = Reflect.get(target, k, target);
            return typeof v === "function" ? v.bind(target) : v; // bound: the servers keep private (#) state
        },
    });
}
async function listAll(client) {
    const out = [];
    let cursor, pages = 0;
    for (;;) {
        const r = await client.listTools(cursor ? { cursor } : undefined);
        out.push(...(r?.tools ?? []));
        const next = r?.nextCursor;
        if (!next)
            return { tools: out, complete: true };
        if (++pages >= 1000 || next === cursor)
            return { tools: out, complete: false };
        cursor = next;
    }
}
/**
 * LangChain (@langchain/mcp-adapters): loadMcpTools with the continuity check.
 *   const tools = await loadMcpToolsWithContinuity("shop", client, lock, { mode: "observe" })
 * client: a MultiServerMCPClient (its connection for serverName is used) or a connected MCP SDK Client. The list is read
 * once (every page) and the LangChain tools are converted from exactly the definitions that were compared.
 * opts.adapters: the @langchain/mcp-adapters module (default: imported on first use); opts.loadOptions: its
 * LoadMcpToolsOptions. The gate (records) is opts.gate, or read them from opts.onRecord.
 */
export async function loadMcpToolsWithContinuity(serverName, client, lock, opts = {}) {
    const lc = opts.adapters || (await import("@langchain/mcp-adapters"));
    let mcp = client;
    if (client && typeof client.getClient === "function" && typeof client.callTool !== "function") {
        mcp = await client.getClient(serverName);
        if (!mcp)
            throw new Error("no connected MCP server named " + serverName);
    }
    let conn = null;
    try {
        const c = client && client !== mcp ? client.config : null;
        conn = c ? ((c.servers || c.mcpServers || {})[serverName] ?? null) : null;
    }
    catch {
        conn = null;
    }
    const gate = opts.gate || continuityGate(lock, Object.assign({ server: opts.serverUrl ?? (conn && conn.url) ?? undefined }, opts));
    await gate.ready;
    if (gate.refused)
        throw gate.refused; // 1.13.0: an untrusted baseline fails before the server is read
    let listed;
    try {
        listed = await listAll(mcp);
    }
    catch (e) {
        await gate.fail("server_unavailable", e && e.message);
        throw e;
    }
    await gate.check(structuredClone(listed.tools), { complete: listed.complete });
    const allowed = gate.allowed(listed.tools);
    const pinned = new Proxy(mcp, {
        get(target, k) {
            if (k === "listTools")
                return async () => ({ tools: allowed });
            if (k === "callTool")
                return async (params, ...a) => { gate.callOk(params && params.name); return target.callTool(params, ...a); };
            const v = Reflect.get(target, k, target);
            return typeof v === "function" ? v.bind(target) : v;
        },
    });
    const tools = await lc.loadMcpTools(serverName, pinned, opts.loadOptions);
    Object.defineProperty(tools, "continuity", { value: gate, enumerable: false });
    return tools;
}
