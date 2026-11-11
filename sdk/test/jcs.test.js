// jcs-v1 (1.14.0): the digests must equal what CrawlCheck's lockfile endpoint signs, for the spec's vectors, for edge
// cases (empty and absent fields, numbers, UTF-16 key order, unpaired surrogates, depth, size limits, unnamed tools) and
// for a live lockfile. The golden file is shared with the Python SDK (tests/fixtures/jcs-v1.json).
import test from "node:test"; import assert from "node:assert/strict"; import fs from "node:fs"; import zlib from "node:zlib";
import { jcsV1, jcsCanon, jcsContract, lockFromTools, checkLock, continuityCheck, LOCK_V1_MAX_TOOLS, withPreflight } from "../dist/index.js";
const G = JSON.parse(fs.readFileSync(new URL("./fixtures/jcs-v1.json", import.meta.url), "utf8"));
const toolsOf = (c) => JSON.parse(c.tools_json ?? zlib.inflateSync(Buffer.from(c.tools_json_deflate_b64, "base64")).toString("utf8"));
for (const c of G.cases) test("jcs-v1 golden (endpoint's answer): " + c.name, async () => { assert.deepEqual(await jcsV1(toolsOf(c)), c.expect); });
test("jcs-v1: the live lockfile of crawlcheck.io/mcp", async () => { assert.deepEqual(await jcsV1(G.live.tools), G.live.lock_jcs_v1); });
test("jcs-v1: the spec's test vectors", async () => {
  const V = G.spec_vectors, t = toolsOf(G.cases.find((c) => c.name === "spec_read_file"));
  assert.equal((await jcsV1([])).tools_sha256, V.empty_list_tools_sha256);
  assert.equal(jcsCanon(jcsContract(t[0])), V.read_file.canonical_contract);
  const r = await jcsV1(t); assert.equal(r.tools[0].contract, V.read_file.contract); assert.equal(r.tools[0].extras, V.read_file.extras); assert.equal(r.tools_sha256, V.read_file.tools_sha256); assert.equal(r.extras_sha256, V.read_file.extras_sha256);
});
test("jcs-v1: a missing description, an empty one and a null one are the same contract", async () => {
  const d = (n) => G.cases.find((c) => c.name === n).expect.tools_sha256;
  assert.equal(d("description_absent"), d("description_empty")); assert.equal(d("description_absent"), d("description_null")); assert.equal(d("inputschema_absent"), d("inputschema_empty"));
  assert.notEqual(d("outputschema_empty"), d("inputschema_empty"));
});
test("jcs-v1: a partial list is not digested", async () => { assert.equal((await jcsV1([{ name: "a" }], { partial: true })).tools_sha256, null); });
const many = (n) => Array.from({ length: n }, (_, i) => ({ name: "t" + String(i).padStart(3, "0"), description: "Tool " + i + ".", inputSchema: { type: "object" } }));
test("lockFromTools: past LOCK_V1_MAX_TOOLS the v1 hash is marked incomplete, never cut silently; jcs_v1 covers every tool", async () => {
  assert.equal(LOCK_V1_MAX_TOOLS, 300);
  const a = await lockFromTools(many(300)); assert.equal(a.complete, true); assert.equal(a.offered, undefined);
  const b = await lockFromTools(many(301)); assert.equal(b.complete, false); assert.equal(b.offered, 301); assert.equal(b.count, 300); assert.equal(b.jcs_v1.count, 301); assert.equal(b.jcs_v1.tools.length, 301);
  const lock = Object.assign({}, b); const c = await checkLock(lock, many(301));
  assert.equal(c.verdict, "incomplete"); assert.equal(c.decision, "block"); assert.equal(c.jcs_v1.contract_unchanged, true);
});
test("checkLock reports the jcs-v1 comparison beside the v1 verdict", async () => {
  const t = many(3), lk = await lockFromTools(t); const t2 = JSON.parse(JSON.stringify(t)); t2[1].title = "New title";
  const c = await checkLock(lk, t2); assert.equal(c.verdict, "unchanged"); assert.equal(c.jcs_v1.contract_unchanged, true); assert.equal(c.jcs_v1.extras_unchanged, false);
});
test("continuityCheck: a CrawlCheck lockfile's jcs_v1 is what the comparison uses (title change is seen, digest lk-v1 opts out)", async () => {
  const t = many(3), lk = await lockFromTools(t), lock = { tools_sha256: lk.tools_sha256, tools: lk.tools, jcs_v1: lk.jcs_v1 };
  const t2 = JSON.parse(JSON.stringify(t)); t2[0].title = "Renamed";
  const r = await continuityCheck(lock, t2, { now: Date.parse("2026-11-11T00:00:00Z") });
  assert.equal(r.baseline.alg, "jcs-v1"); assert.deepEqual(r.events.map((e) => [e.class, e.tool]), [["tool_changed", "t000"]]); assert.deepEqual(r.paused_tools, ["t000"]);
  const r2 = await continuityCheck(lock, t2, { now: Date.parse("2026-11-11T00:00:00Z"), digest: "lk-v1" }); assert.equal(r2.events[0].class, "unchanged"); assert.equal(r2.baseline.alg, undefined);
});
const T = { _url: new URL("https://mcp.example.com/mcp") };
const cc = { guard: async () => ({ proceed: true, receipt: { decision: "allow" }, verification: {}, why: [] }), preflight: async () => ({}) };
const client = (pages) => ({ async connect() { }, async close() { }, async callTool() { return {}; }, async listTools(p) { const i = Number((p && p.cursor) || 0); return { tools: pages[i], nextCursor: i + 1 < pages.length ? String(i + 1) : undefined }; } });
test("withPreflight reads every page of tools/list (nextCursor followed)", async () => {
  const t = many(5), lk = await lockFromTools(t), lock = { tools_sha256: lk.tools_sha256, tools: lk.tools };
  const c = withPreflight(client([t.slice(0, 2), t.slice(2, 4), t.slice(4)]), cc, { lock, toolReceipts: "none", publishedKids: [], onlineKeys: false, local: "allow" });
  await c.connect(T); assert.equal(c.preflight.state.lockCheck.verdict, "unchanged");
});
test("withPreflight with a v1 lockfile refuses a list it could not read in full", async () => {
  const t = many(2), lk = await lockFromTools(t), lock = { tools_sha256: lk.tools_sha256, tools: lk.tools };
  const loop = { async connect() { }, async close() { }, async callTool() { return {}; }, async listTools() { return { tools: t, nextCursor: "same" }; } };
  const c = withPreflight(loop, cc, { lock, toolReceipts: "none", onlineKeys: false, local: "allow" });
  await assert.rejects(() => c.connect(T), /could not be read in full/);
});
