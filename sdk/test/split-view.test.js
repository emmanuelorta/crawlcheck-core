// Split-view detection: a forced fork of the Resolve transparency log (one signing key, two histories, made by the
// Worker's own log code in a test harness) must be detected offline, and the live log must check out consistent.
import test from "node:test"; import assert from "node:assert/strict"; import fs from "node:fs";
import { CrawlCheck, newLogStore, logObserve, logGossip, logHeads, verifyWitnessToken, verifyDocument } from "../dist/index.js";
import { walkHeads } from "../src/log.js";
const F = JSON.parse(fs.readFileSync(new URL("./fixtures/split-view.json", import.meta.url), "utf8"));

test("a forked log is detected by gossip: two signed heads for one batch", async () => {
  const a = newLogStore(), b = newLogStore();
  for (const s of F.A) assert.equal((await logObserve(a, s, { publishedKids: [F.kid] })).state, "new");
  for (const s of F.B) await logObserve(b, s, { publishedKids: [F.kid] });
  assert.equal(a.forks.length + b.forks.length, 0, "each history alone is consistent");
  const g = await logGossip(a, logHeads(b), { publishedKids: [F.kid] });
  assert.deepEqual(g.forks.map((f) => f.kind + "@" + f.batch).sort(), ["two_heads_for_one_batch@1", "two_heads_for_one_batch@2"]);
  assert.ok((await verifyDocument(g.forks[0].a)).verified && (await verifyDocument(g.forks[0].b)).verified, "both heads of the proof verify on their own");
});
test("a head that does not chain to one held is a fork", async () => {
  const c = newLogStore(); await logObserve(c, F.A[1]);
  const r = await logObserve(c, F.B[2]);
  assert.equal(r.state, "fork"); assert.equal(r.fork.kind, "chain_break");
});
test("a tampered head proves nothing (invalid, not a fork)", async () => {
  const s = Object.assign({}, F.B[1], { batch_root: "0".repeat(64) });
  assert.equal((await logObserve(newLogStore(), s)).state, "invalid");
});
test("the witness token binds one head: valid for it, refused for the forked head", async () => {
  assert.equal((await verifyWitnessToken(F.witness.token, F.A[2].sha256, F.jwks)).ok, true);
  assert.equal((await verifyWitnessToken(F.witness.token, F.B[2].sha256, F.jwks)).ok, false);
});
test("1.9.0: the chain walk reads 200 heads per request, and falls back to one per batch on an older server", async () => {
  const calls = [];
  const batched = async (p) => { calls.push(p); const m = /sths\?to=(\d+)&n=(\d+)/.exec(p); if (!m) throw new Error("404");
    const to = +m[1], n = +m[2]; return { sths: Array.from({ length: n }, (_, i) => ({ kind: "crawlcheck-log-sth", batch: to - i })) }; };
  let r = await walkHeads(batched, 449, 0);
  assert.equal(r.length, 450); assert.deepEqual(r.slice(0, 2).map((x) => x.batch), [449, 448]); assert.equal(r[449].batch, 0);
  assert.deepEqual(calls, ["/api/v1/log/sths?to=449&n=200", "/api/v1/log/sths?to=249&n=200", "/api/v1/log/sths?to=49&n=50"]);
  calls.length = 0;
  const old = async (p) => { calls.push(p); const m = /sth\/(\d+)$/.exec(p); if (!m) throw new Error("404"); return { sth: { kind: "crawlcheck-log-sth", batch: +m[1] } }; };
  r = await walkHeads(old, 4, 2);
  assert.deepEqual(r.map((x) => x.batch), [4, 3, 2]); assert.equal(calls.length, 4, "one refused batched call, then one per head");
  assert.deepEqual(await walkHeads(batched, 3, 4), []);
});
test("live: the production log is consistent and GitHub's witness co-signature verifies", async () => {
  const c = new CrawlCheck(); await c.resolve("github.com");
  const r = await c.logCheck({ report: false });
  assert.equal(r.consistent, true, r.summary);
  assert.ok(r.witnessed && r.witnessed.token === true, JSON.stringify(r.witnessed));
});
