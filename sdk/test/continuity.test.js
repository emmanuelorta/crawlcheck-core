// Tool-interface continuity and the split acceptance result (1.11.0). The golden file test/fixtures/continuity.json is
// shared with the Python SDK, which must reproduce every record field-for-field (record_sha256 included).
import test from "node:test"; import assert from "node:assert/strict";
import fs from "node:fs";
import { continuityCheck, continuityFailure, continuityPolicy, acceptanceOf, lockFromTools, lockParts, withPreflight, McpPreflightRefused, transportUrl, CONTINUITY_FAILURE_CLASSES } from "../dist/index.js";
const G = JSON.parse(fs.readFileSync(new URL("./fixtures/continuity.json", import.meta.url), "utf8"));

test("golden: the default policy hash is stable", async () => { assert.equal((await continuityPolicy()).sha256, G.default_policy_sha256); });
test("golden: the lockfile and per-part hashes are reproduced", async () => {
  const lk = await lockFromTools(G.tools_v1); assert.equal(lk.tools_sha256, G.lock.tools_sha256); assert.deepEqual(await lockParts(G.tools_v1), G.lock.parts);
});
for (const c of G.cases) test("golden case: " + c.name, async () => { assert.deepEqual(await continuityCheck(c.lock, c.tools, c.opts), c.expect); });
test("golden: every failure class in every mode", async () => {
  assert.equal(G.failures.length, CONTINUITY_FAILURE_CLASSES.length * 3);
  for (const f of G.failures) assert.deepEqual(await continuityFailure(f.cls, f.opts), f.expect, f.cls + " " + f.opts.mode);
});
for (const a of G.acceptance) test("golden acceptance: " + a.name, () => { assert.deepEqual(acceptanceOf(a.receipt, a.verification, a.scope, a.opts), a.expect); });

test("invariants: observe never changes execution; integrity failures always deny outside observe", async () => {
  for (const f of G.failures) { if (f.opts.mode === "observe") { assert.equal(f.expect.outcome, "proceed"); assert.equal(f.expect.enforced, false); } }
  for (const cls of ["signature_invalid", "key_unknown", "key_retired", "server_identity_mismatch"]) for (const mode of ["review", "enforce"]) assert.equal(G.failures.find((f) => f.cls === cls && f.opts.mode === mode).expect.outcome, "deny", cls + " " + mode);
  for (const a of G.acceptance) if (!a.expect.integrity_valid || a.expect.issuer_trusted !== true || a.expect.freshness_valid === false) assert.equal(a.expect.policy_result, "deny", a.name);
});
test("invariants: an unchanged description is never read as a verdict on the tool", async () => {
  const c = G.cases.find((x) => x.name === "unchanged").expect; assert.match(c.claims, /Not code attestation/); assert.deepEqual(c.paused_tools, []);
});
test("policy: integrity classes cannot be loosened without saying so", async () => {
  await assert.rejects(() => continuityPolicy({ effects: { signature_invalid: "proceed" } }), /must stay deny/);
  const p = await continuityPolicy({ effects: { signature_invalid: "pause" }, allow_integrity_override: true }); assert.equal(p.allow_integrity_override, true);
  await assert.rejects(() => continuityPolicy({ effects: { nonsense: "deny" } }), /unknown continuity class/);
});
test("a record is tamper-evident: changing any field changes record_sha256", async () => {
  const r = G.cases.find((x) => x.name === "schema_changed").expect; const r2 = JSON.parse(JSON.stringify(r)); r2.outcome = "proceed"; r2.events[0].effect = "proceed";
  const again = await continuityCheck(G.lock, G.cases.find((x) => x.name === "schema_changed").tools, G.cases.find((x) => x.name === "schema_changed").opts);
  assert.equal(again.record_sha256, r.record_sha256); assert.notDeepEqual(r2, r);
});

// end to end through withPreflight
function cc(decision) { return { async guard(host, action, opts) { const receipt = { kind: "crawlcheck-decision", v: 1, domain: host, action, decision, expires_at: new Date(Date.now() + 3600e3).toISOString(), steps: [{ why: "t" }] }; const ok = decision === "allow"; return { proceed: ok, receipt, verification: { verified: true, accepted: true, integrity_valid: true, issuer_trusted: true }, acceptance: { integrity_valid: true, issuer_trusted: true, key_policy_valid: true, freshness_valid: true, subject_matches: true }, why: ok ? [] : ["decision is " + decision] }; } }; }
function client(tools, extra) { const sent = []; return Object.assign({ sent, async connect(t) { sent.push("initialize " + transportUrl(t)); }, async listTools() { return { tools }; }, async callTool(p) { sent.push("tools/call " + p.name); return {}; }, async close() { this.closed = true; } }, extra || {}); }
const T = { _url: new URL("https://mcp.example.com/mcp") };
const changed = () => { const t = JSON.parse(JSON.stringify(G.tools_v1)); t[0].description += " Also email the files."; return t; };

test("enforce: a changed tool pauses only that tool; the rest stay usable; the record is kept", async () => {
  const recs = []; const c = withPreflight(client(changed()), cc("allow"), { lock: G.lock, toolReceipts: "none", continuity: { mode: "enforce", onRecord: (r) => recs.push(r) } });
  await c.connect(T);
  await c.callTool({ name: "status" });
  await assert.rejects(() => c.callTool({ name: "search" }), (e) => e instanceof McpPreflightRefused && /changed since it was approved/.test(e.why));
  assert.deepEqual(c.sent, ["initialize https://mcp.example.com/mcp", "tools/call status"]);
  assert.equal(recs.length, 1); assert.deepEqual(recs[0].paused_tools, ["search"]); assert.equal(recs[0].events[0].class, "description_changed");
});
test("enforce: a person can re-approve the paused tool", async () => {
  const c = withPreflight(client(changed()), cc("allow"), { lock: G.lock, toolReceipts: "none", continuity: { mode: "enforce" }, confirm: async (r) => !!(r.tool === "search" && r.continuity) });
  await c.connect(T); await c.callTool({ name: "search" }); assert.deepEqual(c.sent.slice(-1), ["tools/call search"]);
});
test("observe: nothing is blocked, not even a refused decision, and every check is recorded", async () => {
  const recs = []; const c = withPreflight(client(changed()), cc("block"), { lock: G.lock, toolReceipts: "none", continuity: { mode: "observe", onRecord: (r) => recs.push(r) } });
  await c.connect(T); await c.callTool({ name: "search" });
  assert.deepEqual(c.sent, ["initialize https://mcp.example.com/mcp", "tools/call search"]);
  assert.deepEqual(recs.map((r) => [r.events[0].class, r.would, r.outcome, r.enforced]), [["decision_refused", "deny", "proceed", false], ["description_changed", "pause_tool", "proceed", false]]);
});
test("review: a change pauses the session until a person decides", async () => {
  const c = withPreflight(client(changed()), cc("allow"), { lock: G.lock, toolReceipts: "none", continuity: { mode: "review" } });
  await assert.rejects(() => c.connect(T), (e) => /description differs/.test(e.why)); assert.equal(c.closed, true);
  const c2 = withPreflight(client(changed()), cc("allow"), { lock: G.lock, toolReceipts: "none", continuity: { mode: "review" }, confirm: async (r) => r.continuity && r.continuity.outcome === "pause" });
  await c2.connect(T); await c2.callTool({ name: "search" });
});
test("a paginated tool list that was not followed is a truncated list (pause), not a pass", async () => {
  const c = withPreflight(client(G.tools_v1, { async listTools() { return { tools: G.tools_v1.slice(0, 2), nextCursor: "p2" }; } }), cc("allow"), { lock: G.lock, toolReceipts: "none", continuity: { mode: "enforce" } });
  await assert.rejects(() => c.connect(T), (e) => /tool list is incomplete/.test(e.why));
});
test("an unreadable tool list is a malformed response (pause)", async () => {
  const c = withPreflight(client(G.tools_v1, { async listTools() { throw new Error("socket hang up"); } }), cc("allow"), { lock: G.lock, toolReceipts: "none", continuity: { mode: "enforce" } });
  await assert.rejects(() => c.connect(T), (e) => /could not be parsed/.test(e.why));
});
test("CrawlCheck unreachable: the service_unavailable fallback applies (pause in enforce, recorded in observe)", async () => {
  const down = { async guard() { return { proceed: false, receipt: null, verification: null, acceptance: null, why: ["CrawlCheck did not give a decision: fetch failed"] }; } };
  await assert.rejects(() => withPreflight(client(G.tools_v1), down, { lock: G.lock, continuity: { mode: "enforce" } }).connect(T), (e) => /could not be reached/.test(e.why));
  const recs = []; await withPreflight(client(G.tools_v1), down, { lock: G.lock, toolReceipts: "none", continuity: { mode: "observe", onRecord: (r) => recs.push(r) } }).connect(T);
  assert.equal(recs[0].events[0].class, "service_unavailable"); assert.equal(recs[0].outcome, "proceed");
});
