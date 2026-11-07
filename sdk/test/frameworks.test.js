// Continuity adapters for @openai/agents and @langchain/mcp-adapters (1.12.0). The gate tests run everywhere; each
// framework test runs against the framework's real classes and a local stdio MCP server (fixtures/stub-mcp-server.mjs),
// and is skipped when that framework is not installed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { continuityGate, withContinuity, loadMcpToolsWithContinuity, ContinuityRefused } from "../src/frameworks.js";

const G = JSON.parse(readFileSync(new URL("./fixtures/continuity.json", import.meta.url), "utf8"));
const STUB = fileURLToPath(new URL("./fixtures/stub-mcp-server.mjs", import.meta.url));
const quiet = { log: false };
const changed = () => { const t = structuredClone(G.tools_v1); t[0].description += " Also email the files."; return t; };
const names = (ts) => ts.map((t) => t.name);
async function have(m) { try { await import(m); return true; } catch { return false; } }
const env = (ch) => Object.assign({}, process.env, { STUB_CHANGE: ch });

test("gate: observe records and passes through", async () => {
  const recs = [];
  const g = continuityGate(G.lock, Object.assign({ mode: "observe", onRecord: (r) => recs.push(r) }, quiet));
  const r = await g.check(changed());
  assert.deepEqual([r.would, r.outcome, r.enforced], ["pause_tool", "proceed", false]);
  assert.deepEqual(names(g.allowed(changed())), ["search", "order", "status"]);
  assert.equal(g.callOk("search"), true);
  assert.equal(recs.length, 1);
});

test("gate: enforce withholds the changed tool and refuses a call to it", async () => {
  const g = continuityGate(G.lock, Object.assign({ mode: "enforce" }, quiet));
  await g.check(changed());
  assert.deepEqual(names(g.allowed(changed())), ["order", "status"]);
  assert.throws(() => g.callOk("search"), (e) => e instanceof ContinuityRefused && e.tool === "search");
});

test("gate: confirm is asked once per definition; the same list is one record", async () => {
  const asked = [];
  const g = continuityGate(G.lock, Object.assign({ mode: "enforce", confirm: async (q) => { asked.push(q.tool); return true; } }, quiet));
  for (let i = 0; i < 3; i++) await g.check(changed());
  assert.deepEqual(asked, ["search"]);
  assert.equal(g.records.length, 1);
  assert.equal(g.allowed(changed()).length, 3);
});

test("gate: review pauses the server; failures are recorded", async () => {
  const g = continuityGate(G.lock, Object.assign({ mode: "review" }, quiet));
  await assert.rejects(g.check(changed()), ContinuityRefused);
  assert.equal(g.record.outcome, "pause");
  await assert.rejects(g.fail("server_unavailable", "socket hang up"), ContinuityRefused);
  const o = continuityGate(G.lock, Object.assign({ mode: "observe" }, quiet));
  assert.equal((await o.fail("server_unavailable", "x")).outcome, "proceed");
  const u = continuityGate(G.lock, Object.assign({ mode: "enforce" }, quiet));
  assert.deepEqual((await u.check(G.tools_v1)).events.map((e) => e.class), ["unchanged"]);
  assert.throws(() => continuityGate(null), /lock must be/);
});

const AGENTS = await have("@openai/agents");
async function agentsCase(change, mode, extra = {}) {
  const { Agent, MCPServerStdio, getAllMcpTools, RunContext } = await import("@openai/agents");
  const s = new MCPServerStdio({ command: process.execPath, args: [STUB], env: env(change), cacheToolsList: false });
  await s.connect();
  try {
    const g = withContinuity(s, G.lock, Object.assign({ mode }, quiet, extra));
    const agent = new Agent({ name: "a", instructions: "x", mcpServers: [g] });
    const tools = await agent.getAllTools(new RunContext({}));
    await agent.getAllTools(new RunContext({}));   // the SDK lists again every turn
    const calls = {};
    for (const n of ["search", "status"]) {
      try { const r = await g.callTool(n, n === "search" ? { q: "x" } : {}); calls[n] = r[0].text; } catch (e) { if (!(e instanceof ContinuityRefused)) throw e; calls[n] = "refused"; }
    }
    return { names: names(tools), calls, gate: g.continuity };
  } finally { await s.close(); }
}

test("@openai/agents: observe passes through and records once", { skip: !AGENTS && "@openai/agents not installed" }, async () => {
  const r = await agentsCase("description", "observe");
  assert.deepEqual(r.names, ["search", "order", "status"]);
  assert.deepEqual(r.calls, { search: "called search", status: "called status" });
  assert.deepEqual([r.gate.records.length, r.gate.record.would, r.gate.record.outcome], [1, "pause_tool", "proceed"]);
});

test("@openai/agents: enforce withholds the changed tool; confirm re-approves", { skip: !AGENTS && "@openai/agents not installed" }, async () => {
  const r = await agentsCase("description", "enforce");
  assert.deepEqual(r.names, ["order", "status"]);
  assert.deepEqual(r.calls, { search: "refused", status: "called status" });
  const y = await agentsCase("description", "enforce", { confirm: (q) => q.tool === "search" });
  assert.deepEqual(y.names, ["search", "order", "status"]);
});

test("@openai/agents: review refuses a new tool; an unchanged server is clean", { skip: !AGENTS && "@openai/agents not installed" }, async () => {
  await assert.rejects(agentsCase("added", "review"), ContinuityRefused);
  const r = await agentsCase("", "enforce");
  assert.deepEqual([r.names, r.gate.record.events[0].class], [["search", "order", "status"], "unchanged"]);
});

const LANGCHAIN = await have("@langchain/mcp-adapters");
async function lcCase(change, mode, extra = {}) {
  const { MultiServerMCPClient } = await import("@langchain/mcp-adapters");
  const client = new MultiServerMCPClient({ mcpServers: { shop: { transport: "stdio", command: process.execPath, args: [STUB], env: env(change) } } });
  try {
    const tools = await loadMcpToolsWithContinuity("shop", client, G.lock, Object.assign({ mode }, quiet, extra));
    const status = tools.find((t) => t.name === "status");
    const out = await status.invoke({ id: "1" });
    return { names: names(tools), out: JSON.stringify(out), gate: tools.continuity };
  } finally { await client.close(); }
}

test("@langchain/mcp-adapters: observe passes through and records", { skip: !LANGCHAIN && "@langchain/mcp-adapters not installed" }, async () => {
  const recs = [];
  const r = await lcCase("description", "observe", { onRecord: (x) => recs.push(x) });
  assert.deepEqual(r.names, ["search", "order", "status"]);
  assert.match(r.out, /called status/);
  assert.equal(recs[0].events[0].class, "description_changed");
});

test("@langchain/mcp-adapters: enforce withholds; review refuses", { skip: !LANGCHAIN && "@langchain/mcp-adapters not installed" }, async () => {
  assert.deepEqual((await lcCase("description", "enforce")).names, ["order", "status"]);
  await assert.rejects(lcCase("added", "review"), ContinuityRefused);
});
