// Signed baseline (1.13.0): the lockfile's signature is checked once, when a gate is created, before anything is compared
// against it. The cases are in the shared golden file (baseline_cases); the Python SDK must reproduce each one exactly.
import test from "node:test"; import assert from "node:assert/strict";
import fs from "node:fs";
import { verifyLockBaseline, signLock, newOperatorKey, keyPolicyFrom, continuityGate, openContinuityGate, ContinuityRefused, withPreflight, McpPreflightRefused, CONTINUITY_FAILURE_CLASSES, CONTINUITY_DEFAULT_POLICY, canon } from "../dist/index.js";
const G = JSON.parse(fs.readFileSync(new URL("./fixtures/continuity.json", import.meta.url), "utf8"));
const keyDir = G.key_directory;
const sha = async (s) => Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))).toString("hex");
const B = (n) => G.baseline_cases.find((c) => c.name === n);
const quiet = { log: false };
const opts = async (o) => { const x = Object.assign({}, o); if (x.keyPolicyDirectory) { delete x.keyPolicyDirectory; x.keyPolicy = await keyPolicyFrom(keyDir); } return x; };

for (const c of G.baseline_cases) test("golden baseline: " + c.name, async () => {
  const r = await verifyLockBaseline(c.lock, await opts(c.opts)); const { lock, ...rest } = r;
  assert.deepEqual(rest, c.expect); assert.equal(await sha(canon(lock)), c.used_sha256);
});
test("golden: signLock is deterministic and matches the fixture", async () => {
  assert.deepEqual(await signLock(G.lock, G.operator.privateKey), G.operator.signed_lock);
});
test("baseline_untrusted is the 14th failure class, deny by default, and an integrity class", async () => {
  assert.equal(CONTINUITY_FAILURE_CLASSES.length, 14); assert.equal(CONTINUITY_FAILURE_CLASSES[13], "baseline_untrusted");
  assert.equal(CONTINUITY_DEFAULT_POLICY.effects.baseline_untrusted, "deny");
  for (const m of ["review", "enforce"]) assert.equal(G.failures.find((f) => f.cls === "baseline_untrusted" && f.opts.mode === m).expect.outcome, "deny");
  assert.equal(G.failures.find((f) => f.cls === "baseline_untrusted" && f.opts.mode === "observe").expect.outcome, "proceed");
});

test("gate, enforce: a lockfile edited after CrawlCheck signed it fails at startup", async () => {
  const L = B("edited_after_signing").lock;
  await assert.rejects(() => openContinuityGate(L, Object.assign({ mode: "enforce" }, quiet)), (e) => e instanceof ContinuityRefused && /baseline_untrusted|not trusted/.test(e.message) && e.record.events[0].class === "baseline_untrusted");
  const g = continuityGate(L, Object.assign({ mode: "enforce" }, quiet)); await g.ready;
  assert.equal(g.baseline.trust, "invalid"); assert.equal(g.records.length, 1);
  await assert.rejects(() => g.check(G.tools_v1), ContinuityRefused);
});
test("gate, enforce: a lockfile re-signed with a foreign key fails at startup", async () => {
  await assert.rejects(() => openContinuityGate(B("forged_foreign_key").lock, Object.assign({ mode: "enforce" }, quiet)), /not a CrawlCheck key/);
});
test("gate, observe: an untrusted baseline is recorded and passes", async () => {
  const g = await openContinuityGate(B("edited_after_signing").lock, Object.assign({ mode: "observe" }, quiet));
  assert.equal(g.records[0].events[0].class, "baseline_untrusted"); assert.equal(g.records[0].outcome, "proceed");
  const r = await g.check([]); assert.equal(r.outcome, "proceed"); assert.equal(r.baseline.trust, "invalid");
});
test("gate: a CrawlCheck-signed lockfile is verified and named in every record", async () => {
  const L = B("crawlcheck_signed").lock;
  const g = await openContinuityGate(L, Object.assign({ mode: "enforce" }, quiet));
  assert.equal(g.baseline.trust, "verified"); assert.equal(g.records.length, 0);
  const r = await g.check([]); assert.equal(r.baseline.trust, "verified"); assert.equal(r.baseline.per_part, true);
});
test("gate: parts added after signing are not used for the comparison", async () => {
  const g = await openContinuityGate(B("parts_added_after_signing").lock, Object.assign({ mode: "enforce" }, quiet));
  assert.equal(g.baseline.trust, "verified"); assert.equal(g.baseline.parts_used, false);
  const r = await g.check([]); assert.equal(r.baseline.per_part, false);
});
test("gate: unsigned passes unless a signed baseline is required; operator keys require one by default", async () => {
  const g = await openContinuityGate(G.lock, Object.assign({ mode: "enforce" }, quiet)); assert.equal(g.baseline.trust, "unsigned");
  await assert.rejects(() => openContinuityGate(G.lock, Object.assign({ mode: "enforce", requireSignedBaseline: true }, quiet)), /unsigned and a signed one is required/);
  await assert.rejects(() => openContinuityGate(G.lock, Object.assign({ mode: "enforce", operatorKeys: [G.operator.publicKey] }, quiet)), /unsigned/);
  await openContinuityGate(G.lock, Object.assign({ mode: "enforce", operatorKeys: [G.operator.publicKey], requireSignedBaseline: false }, quiet));
});
test("gate: an operator-signed lockfile with the operator key is operator_signed; with another key it is refused", async () => {
  const g = await openContinuityGate(G.operator.signed_lock, Object.assign({ mode: "enforce", operatorKeys: [G.operator.publicKey] }, quiet));
  assert.equal(g.baseline.trust, "operator_signed"); const r = await g.check(G.tools_v1); assert.equal(r.outcome, "proceed"); assert.equal(r.baseline.trust, "operator_signed");
  await assert.rejects(() => openContinuityGate(G.operator.signed_lock, Object.assign({ mode: "enforce", operatorKeys: [G.operator.other_publicKey] }, quiet)), /not one of the operator keys/);
});
test("gate: an attacker who edits the operator-signed baseline to approve a new tool is refused at startup", async () => {
  const L = structuredClone(G.operator.signed_lock); L.tools.push({ name: "export", sha256: "e".repeat(64) });
  await assert.rejects(() => openContinuityGate(L, Object.assign({ mode: "enforce", operatorKeys: [G.operator.publicKey] }, quiet)), /changed after the operator signed it/);
  const R = structuredClone(L); delete R.operator_signature;   // stripping the signature instead: unsigned, refused because a key is configured
  await assert.rejects(() => openContinuityGate(R, Object.assign({ mode: "enforce", operatorKeys: [G.operator.publicKey] }, quiet)), /unsigned/);
});
test("verified at startup, not per call: check() does not verify again", async () => {
  let calls = 0; const g = continuityGate(B("crawlcheck_signed").lock, Object.assign({ mode: "enforce" }, quiet)); await g.ready;
  const orig = crypto.subtle.verify; crypto.subtle.verify = async (...a) => { calls++; return orig.apply(crypto.subtle, a); };
  try { for (let i = 0; i < 3; i++) await g.check([]); } finally { crypto.subtle.verify = orig; }
  assert.equal(calls, 0);
});
test("newOperatorKey + signLock round trip", async () => {
  const k = await newOperatorKey(); const s = await signLock(G.lock, k.privateKey);
  assert.equal((await verifyLockBaseline(s, { operatorKeys: [k.publicKey] })).trust, "operator_signed");
  assert.equal(s.operator_signature.kid, k.kid);
});
function cc() { return { async guard(host, action) { return { proceed: true, receipt: { kind: "crawlcheck-decision", decision: "allow", expires_at: new Date(Date.now() + 3600e3).toISOString() }, verification: { verified: true }, why: [] }; } }; }
test("withPreflight: an untrusted baseline refuses the connect before a byte is sent", async () => {
  const sent = []; const c = { async connect() { sent.push("initialize"); }, async listTools() { return { tools: G.tools_v1 }; }, async callTool() { sent.push("call"); } };
  withPreflight(c, cc(), { lock: B("edited_after_signing").lock, continuity: { mode: "enforce" } });
  await assert.rejects(() => c.connect({ url: "https://mcp.example.com/mcp" }), (e) => e instanceof McpPreflightRefused && /baseline/.test(e.message));
  assert.deepEqual(sent, []);
  const c2 = { async connect() { sent.push("initialize"); }, async listTools() { return { tools: G.tools_v1 }; }, async callTool() { } };
  withPreflight(c2, cc(), { lock: B("forged_foreign_key").lock });   // without continuity too
  await assert.rejects(() => c2.connect({ url: "https://mcp.example.com/mcp" }), /lockfile is not trusted/);
  const c3 = { async connect() { sent.push("initialize"); }, async listTools() { return { tools: G.tools_v1 }; }, async callTool() { } };
  withPreflight(c3, cc(), { lock: G.operator.signed_lock, continuity: { mode: "enforce", operatorKeys: [G.operator.publicKey] }, toolReceipts: "none" });
  await c3.connect({ url: "https://mcp.example.com/mcp" }); assert.equal(c3.preflight.state.baseline.trust, "operator_signed");
});
