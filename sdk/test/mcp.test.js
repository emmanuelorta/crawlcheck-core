import test from "node:test"; import assert from "node:assert/strict";
import { withPreflight, mcpPreflight, McpPreflightRefused, transportUrl, lockFromTools } from "../dist/index.js";

// A CrawlCheck client double: guard() answers from a table, no network.
function cc(table) {
  const calls = [];
  return { calls, async guard(host, action, opts) {
    calls.push({ host, action, template: opts.template, tool: opts.operation && opts.operation.tool, op: opts.operation });
    const d = table[host] || "unsupported";
    const receipt = { kind: "crawlcheck-decision", domain: host, action, decision: d, expires_at: new Date(Date.now() + 3600e3).toISOString(), steps: [{ why: "table" }], sha256: "x", signature: { kid: "k" } };
    let proceed = d === "allow" || (d === "warn" && !!opts.allowWarn);
    if (d === "require_confirmation" && opts.confirm) proceed = !!(await opts.confirm(receipt));
    return { proceed, receipt, verification: { verified: true, accepted: true, integrity_valid: true, issuer_trusted: true } };
  } };
}
// An MCP client double with the official Client's surface.
function mcpClient(tools) {
  const sent = [];
  return { sent, closed: false,
    async connect(transport) { sent.push("initialize " + transportUrl(transport)); },
    async listTools() { return { tools }; },
    async callTool(p) { sent.push("tools/call " + p.name); return { content: [] }; },
    async close() { this.closed = true; } };
}
const T = (url) => ({ _url: new URL(url) });
const TOOLS = [{ name: "search", description: "find", inputSchema: { type: "object" }, annotations: { readOnlyHint: true } }, { name: "delete_repo", description: "rm", inputSchema: { type: "object" }, annotations: { destructiveHint: true } }];

test("connect to a host nothing vouches for is refused before initialize", async () => {
  const c = withPreflight(mcpClient(TOOLS), cc({}));
  await assert.rejects(() => c.connect(T("https://mcp.example.com/mcp")), (e) => e instanceof McpPreflightRefused && e.stage === "connect" && /nothing vouches/.test(e.why) && e.receipt.decision === "unsupported");
  assert.deepEqual(c.sent, []);   // no packet left the client
});
test("block refuses the connect", async () => {
  const c = withPreflight(mcpClient(TOOLS), cc({ "evil.example": "block" }));
  await assert.rejects(() => c.connect(T("https://evil.example/mcp")), (e) => e.stage === "connect" && e.receipt.decision === "block");
  assert.deepEqual(c.sent, []);
});
test("allow connects; the host is decided once with the safe_mcp_tool template", async () => {
  const k = cc({ "good.example": "allow" }); const c = withPreflight(mcpClient(TOOLS), k);
  await c.connect(T("https://good.example/mcp"));
  await c.callTool({ name: "search", arguments: {} });
  assert.deepEqual(c.sent, ["initialize https://good.example/mcp", "tools/call search"]);
  assert.equal(k.calls.length, 1); assert.equal(k.calls[0].template, "safe_mcp_tool"); assert.equal(k.calls[0].action, "connect");
});
test("require_confirmation: refused without a confirm, connects when a person says yes", async () => {
  const k = cc({ "ask.example": "require_confirmation" });
  await assert.rejects(() => withPreflight(mcpClient(TOOLS), k).connect(T("https://ask.example/mcp")), (e) => /human must confirm/.test(e.why));
  let seen = null; const c = withPreflight(mcpClient(TOOLS), k, { confirm: async (r) => { seen = r; return true; } });
  await c.connect(T("https://ask.example/mcp")); assert.equal(seen.decision, "require_confirmation"); assert.equal(c.sent.length, 1);
});
test("lockfile: changed tools close the client again; a tool outside the lock is refused", async () => {
  const lock = await lockFromTools([TOOLS[0]]);
  const c = withPreflight(mcpClient(TOOLS), cc({ "good.example": "allow" }), { lock });
  await assert.rejects(() => c.connect(T("https://good.example/mcp")), (e) => e.stage === "connect" && /differ from the approved lockfile/.test(e.why) && e.lock.added.includes("delete_repo"));
  assert.equal(c.closed, true);
  const c2 = withPreflight(mcpClient([TOOLS[0]]), cc({ "good.example": "allow" }), { lock });
  await c2.connect(T("https://good.example/mcp")); await c2.callTool({ name: "search" });
  await assert.rejects(() => c2.callTool({ name: "delete_repo" }), (e) => e.stage === "tools/call" && /not in the approved lockfile/.test(e.why));
  assert.deepEqual(c2.sent, ["initialize https://good.example/mcp", "tools/call search"]);
});
test("destructive tool asks for confirmation", async () => {
  const c = withPreflight(mcpClient(TOOLS), cc({ "good.example": "allow" }), { confirmDestructive: true, confirm: async (r) => r.tool !== "delete_repo" });
  await c.connect(T("https://good.example/mcp"));
  await c.callTool({ name: "search" });
  await assert.rejects(() => c.callTool({ name: "delete_repo" }), (e) => /annotated destructive/.test(e.why));
  assert.deepEqual(c.sent, ["initialize https://good.example/mcp", "tools/call search"]);
});
test("expired connect receipt is decided again before the next call", async () => {
  const k = cc({ "good.example": "allow" }); const c = withPreflight(mcpClient(TOOLS), k, { maxAgeMs: 1 });
  await c.connect(T("https://good.example/mcp")); await new Promise((r) => setTimeout(r, 5));
  await c.callTool({ name: "search" }); assert.equal(k.calls.length, 2);
});
test("local stdio server: allowed by default, refusable", async () => {
  const c = withPreflight(mcpClient(TOOLS), cc({})); await c.connect({ kind: "stdio" }); assert.equal(c.preflight.state.host, null);
  await assert.rejects(() => withPreflight(mcpClient(TOOLS), cc({}), { local: "refuse" }).connect({ kind: "stdio" }), (e) => /local/.test(e.why));
});
test("bare hooks work without a client object", async () => {
  const h = mcpPreflight(cc({ "good.example": "allow" }));
  const r = await h.beforeConnect("https://good.example/mcp"); assert.equal(r.host, "good.example");
  assert.equal((await h.beforeToolCall("search")).receipt.decision, "allow");
});

test("1.4.0: a write tool call gets its own receipt, scoped to the tool's definition; a read-only one reuses connect", async () => {
  const { lockToolHash } = await import("../dist/index.js");
  const k = cc({ "good.example": "allow" }); const c = withPreflight(mcpClient(TOOLS), k);
  await c.connect(T("https://good.example/mcp")); await c.callTool({ name: "search" }); await c.callTool({ name: "delete_repo" });
  const per = k.calls.filter((x) => x.tool);
  assert.deepEqual(per.map((x) => x.tool), ["delete_repo"]);
  assert.equal(per[0].op.tool_schema_sha256, await lockToolHash(TOOLS[1]));
});
test("1.4.0: a refused tool receipt stops tools/call; toolReceipts none skips it", async () => {
  const k = cc({ "good.example": "allow" }); const orig = k.guard;
  k.guard = async (h, a, o) => o.operation ? { proceed: false, receipt: null, verification: null, why: ["the receipt is for another operation"] } : orig(h, a, o);
  const cl = mcpClient(TOOLS); const c = withPreflight(cl, k);
  await c.connect(T("https://good.example/mcp"));
  await assert.rejects(() => c.callTool({ name: "delete_repo" }), (e) => e.stage === "tools/call" && /another operation/.test(e.why));
  assert.ok(!cl.sent.includes("tools/call delete_repo"));
  const k2 = cc({ "good.example": "allow" }); const c2 = withPreflight(mcpClient(TOOLS), k2, { toolReceipts: "none" });
  await c2.connect(T("https://good.example/mcp")); await c2.callTool({ name: "delete_repo" });
  assert.equal(k2.calls.filter((x) => x.tool).length, 0);
});
