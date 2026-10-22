// Preflight as an MCP client extension (https://crawlcheck.io/spec/mcp-preflight). Reference middleware: the check runs
// in the protocol path, before `initialize` reaches a server and before every `tools/call`, instead of being a call the
// agent remembers to make. It wraps any MCP client object that has connect(transport) and callTool(params) (the official
// @modelcontextprotocol/sdk Client does), or is used as two bare hooks for other client stacks.
//
//   connect:   the server's host is resolved and the "connect" action decided (template safe_mcp_tool). block, unsupported
//              and an unverifiable receipt refuse the connect before a byte is sent; require_confirmation asks opts.confirm.
//              With opts.lock, the tools the server lists after connecting must match the approved lockfile, or the client
//              is closed again.
//   tools/call: the connect receipt must still be unexpired (else the host is decided again); a tool outside the approved
//              lockfile is refused; a tool annotated destructive (destructiveHint true, or readOnlyHint false with
//              openWorldHint true) asks opts.confirm when opts.confirmDestructive is set.
//   per call:  (1.4.0) a tool call gets a receipt of its own, scoped to that tool (name, digest of its definition, opts.scopes),
//              so a connect receipt never stands in for a call to a tool that changed. opts.toolReceipts: "write" (default:
//              every tool not annotated readOnlyHint), "all", or "none".
// Nothing here calls a tool, reads arguments or alters the request; a refused call throws McpPreflightRefused and the
// request is never sent.
import { normalizeDomain } from "./index.js";
import { checkLock, toolOperation } from "./index.js";
export class McpPreflightRefused extends Error {
    constructor(stage, why, detail) { super("MCP preflight refused " + stage + ": " + why); this.name = "McpPreflightRefused"; this.stage = stage; this.why = why; this.receipt = detail && detail.receipt || null; this.lock = detail && detail.lock || null; this.verification = detail && detail.verification || null; }
}
/** The server URL a transport will talk to, if it can be read (Streamable HTTP and SSE transports keep it as _url or url). */
export function transportUrl(transport) {
    if (!transport)
        return null;
    for (const k of ["_url", "url", "endpoint", "_endpoint"]) {
        const v = transport[k];
        if (v instanceof URL)
            return v.toString();
        if (typeof v === "string" && /^https?:\/\//i.test(v))
            return v;
    }
    return null;
}
function hostOf(url) { try {
    return normalizeDomain(new URL(url).hostname);
}
catch (e) {
    return null;
} }
function destructive(ann) { if (!ann || typeof ann !== "object")
    return false; if (ann.destructiveHint === true)
    return true; return ann.readOnlyHint === false && ann.openWorldHint === true; }
/**
 * The two hooks. cc is a CrawlCheck client (from this SDK). opts: template (default safe_mcp_tool), policy, agent,
 * confirm(receipt) for require_confirmation, allowWarn, lock (an approved McpLock), confirmDestructive, maxAgeMs for a
 * cached connect receipt (default: until the receipt's expires_at).
 */
export function mcpPreflight(cc, opts = {}) {
    const template = opts.template || "safe_mcp_tool";
    const state = { url: null, host: null, receipt: null, verification: null, decidedAt: 0, lockCheck: null, approved: null };
    const fresh = function () {
        if (!state.receipt)
            return false;
        const exp = Date.parse(state.receipt.expires_at || "");
        if (isFinite(exp) && Date.now() > exp)
            return false;
        if (opts.maxAgeMs && Date.now() - state.decidedAt > opts.maxAgeMs)
            return false;
        return true;
    };
    // tscope1: send the server URL and, with a lockfile, its approved tools_sha256, so CrawlCheck reads the live tools from its own
    // vantage and the signed receipt names the endpoint and tool state it covered (a changed list comes back as block).
    const mcpScope = function () { if (!state.url || !/^https:/i.test(state.url))
        return undefined; const h = opts.lock && typeof opts.lock.tools_sha256 === "string" ? opts.lock.tools_sha256 : null; return h ? { url: state.url, tools_sha256: h } : { url: state.url }; };
    const decide = async function (host) {
        const g = await cc.guard(host, "connect", { template, policy: opts.policy, agent: opts.agent, confirm: opts.confirm, allowWarn: !!opts.allowWarn, onlineKeys: opts.onlineKeys, mcp: mcpScope() });
        state.receipt = g.receipt;
        state.verification = g.verification;
        state.decidedAt = Date.now();
        if (!g.proceed) {
            const d = g.receipt && g.receipt.decision;
            const decisionOnly = (g.why || []).every(function (w) { return /^decision is|a human did not confirm|no confirm\(\) was given|allowWarn is not set/.test(w); });
            const why = g.split_view ? "the transparency log showed two histories; no answer is trusted" : !g.verification ? ((g.why || []).join("; ") || "no decision") : !g.verification.verified ? "the decision receipt did not verify" : g.verification.accepted === false ? "the receipt was signed with a key CrawlCheck does not publish" : !decisionOnly ? g.why.join("; ") : !g.verification.verified ? "the decision receipt did not verify" : g.verification.accepted === false ? "the receipt was signed with a key CrawlCheck does not publish" : d === "require_confirmation" ? "a human must confirm and none did" : d === "warn" ? "warn without allowWarn" : d === "unsupported" ? "nothing vouches for a connection to " + host + " (" + ((g.receipt.steps || [])[0] || {}).why + ")" : "decision " + d + (g.receipt.steps && g.receipt.steps[0] ? " (" + g.receipt.steps[0].why + ")" : "");
            throw new McpPreflightRefused("connect", why, { receipt: g.receipt, verification: g.verification });
        }
        return g;
    };
    return {
        state,
        /** Before initialize. url: the server URL (a stdio/local server has none and is not decided; pass opts.local = "allow" | "refuse", default allow). */
        async beforeConnect(url) {
            if (!url) {
                if (opts.local === "refuse")
                    throw new McpPreflightRefused("connect", "a local (stdio) server cannot be resolved and opts.local is refuse");
                state.url = null;
                state.host = null;
                return { local: true, receipt: null };
            }
            const host = hostOf(url);
            if (!host)
                throw new McpPreflightRefused("connect", "not a server URL: " + url);
            state.url = url;
            state.host = host;
            const g = await decide(host);
            return { local: false, host, receipt: g.receipt, verification: g.verification };
        },
        /** After initialize, with the tools the server lists. Refuses (and the wrapper closes the client) when they differ from the approved lockfile. */
        async afterConnect(tools) {
            if (!opts.lock) {
                state.approved = null;
                return null;
            }
            const lc = await checkLock(opts.lock, tools || []);
            state.lockCheck = lc;
            state.approved = new Set((opts.lock.tools || []).map(function (t) { return t.name; }));
            if (lc.decision !== "connect")
                throw new McpPreflightRefused("connect", "the server's tools differ from the approved lockfile (added " + lc.added.length + ", removed " + lc.removed.length + ", modified " + lc.modified.length + ")", { lock: lc });
            return lc;
        },
        /** Before tools/call. */
        async beforeToolCall(name, annotations, tool) {
            if (state.host && !fresh())
                await decide(state.host);
            if (state.approved && !state.approved.has(name))
                throw new McpPreflightRefused("tools/call", "tool " + name + " is not in the approved lockfile", { lock: state.lockCheck, receipt: state.receipt });
            if (opts.confirmDestructive && destructive(annotations)) {
                const ok = opts.confirm ? await opts.confirm(Object.assign({}, state.receipt || {}, { tool: name, annotations })) : false;
                if (!ok)
                    throw new McpPreflightRefused("tools/call", "tool " + name + " is annotated destructive and no human confirmed", { receipt: state.receipt });
            }
            const mode = opts.toolReceipts || "write", ro = !!(annotations && annotations.readOnlyHint === true);
            let callReceipt = null;
            if (state.host && (mode === "all" || (mode === "write" && !ro))) { // op1/mcp: a receipt for this exact tool call
                const op = tool ? await toolOperation(tool, opts.scopes) : Object.assign({ tool: String(name) }, opts.scopes && opts.scopes.length ? { scopes: opts.scopes.slice() } : {});
                const g = await cc.guard(state.host, "connect", { template, policy: opts.policy, agent: opts.agent, confirm: opts.confirm, allowWarn: !!opts.allowWarn, onlineKeys: opts.onlineKeys, operation: op });
                if (!g.proceed)
                    throw new McpPreflightRefused("tools/call", "no receipt for tool " + name + ": " + ((g.why || []).join("; ") || "refused"), { receipt: g.receipt, verification: g.verification });
                callReceipt = g.receipt;
            }
            return { receipt: callReceipt || state.receipt, tool_receipt: callReceipt };
        }
    };
}
/**
 * Wrap an MCP client in place: client.connect and client.callTool run the hooks first. Returns the same client, with
 * client.preflight (the hooks and their state). Works on @modelcontextprotocol/sdk's Client and on anything with the same
 * two methods; listTools() is used for the lockfile check when present.
 */
export function withPreflight(client, cc, opts = {}) {
    const pf = mcpPreflight(cc, opts);
    const connect = client.connect.bind(client), callTool = client.callTool.bind(client);
    const tools = {};
    client.connect = async function (transport, ...rest) {
        await pf.beforeConnect(opts.serverUrl || transportUrl(transport));
        const r = await connect(transport, ...rest);
        if (opts.lock || opts.confirmDestructive || (opts.toolReceipts || "write") !== "none") {
            let list = [];
            try {
                const t = typeof client.listTools === "function" ? await client.listTools() : null;
                list = (t && t.tools) || [];
            }
            catch (e) {
                list = [];
            }
            list.forEach(function (t) { if (t && t.name)
                tools[t.name] = t; });
            if (opts.lock || opts.confirmDestructive)
                try {
                    await pf.afterConnect(list);
                }
                catch (e) {
                    try {
                        if (typeof client.close === "function")
                            await client.close();
                    }
                    catch (e2) { }
                    throw e;
                }
        }
        return r;
    };
    client.callTool = async function (params, ...rest) {
        const name = params && params.name;
        await pf.beforeToolCall(name, tools[name] && tools[name].annotations, tools[name]);
        return callTool(params, ...rest);
    };
    client.preflight = pf;
    return client;
}
