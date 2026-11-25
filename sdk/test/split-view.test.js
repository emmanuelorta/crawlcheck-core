// Split-view detection: a forced fork of the Resolve transparency log (one signing key, two histories, made by the
// service's own log code in a test harness) must be detected offline, and the live log must check out consistent.
import test from "node:test"; import assert from "node:assert/strict"; import fs from "node:fs";
import { CrawlCheck, newLogStore, logObserve, logGossip, logHeads, verifyWitnessToken, verifyDocument, keyPolicyFrom, GITHUB_OIDC_JWKS } from "../dist/index.js";
import { walkHeads } from "../src/log.js";
const F = JSON.parse(fs.readFileSync(new URL("./fixtures/split-view.json", import.meta.url), "utf8"));

test("a forked log is detected by gossip: two signed heads for one batch", async () => {
  const a = newLogStore(), b = newLogStore();
  // The harness key is not one a release ships, so its id alone does not say it signs log heads: the policy does.
  const keyPolicy = await keyPolicyFrom({ keys: [Object.assign({}, F.A[0].signature.key.jwk, { crawlcheck_purpose: "log heads", crawlcheck_signs_from: "2026-10-01T00:00:00Z" })] });
  assert.deepEqual(keyPolicy.kids, [F.kid]);
  assert.equal((await logObserve(newLogStore(), F.A[0], { publishedKids: [F.kid] })).state, "invalid", "key ids alone: a listed key of unknown purpose signs no log head");
  for (const s of F.A) assert.equal((await logObserve(a, s, { keyPolicy })).state, "new");
  for (const s of F.B) await logObserve(b, s, { keyPolicy });
  assert.equal(a.forks.length + b.forks.length, 0, "each history alone is consistent");
  const g = await logGossip(a, logHeads(b), { keyPolicy });
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
  // The fixture's token is synthetic and issued to an example repository: its signature holds, and it is not the witness.
  const fx = await verifyWitnessToken(F.witness.token, F.A[2].sha256, F.jwks);
  assert.equal(fx.ok, false); assert.match(fx.why, /not the witness workflow/);
  // The witness's own token is read from the live log with the keys GitHub publishes: valid for its head, refused for another.
  const get = async (u) => (await fetch(u, { headers: { "user-agent": "crawlcheck-selftest sdk-js-tests" } })).json();
  const w = await get("https://crawlcheck.io/api/v1/log/witness/latest"), jwks = await get(GITHUB_OIDC_JWKS);
  assert.equal((await verifyWitnessToken(w.token, w.sth_sha256, jwks)).ok, true);
  assert.equal((await verifyWitnessToken(w.token, F.B[2].sha256, jwks)).ok, false);
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
  const c = new CrawlCheck({ headers: { "user-agent": "crawlcheck-selftest sdk-js-tests" } }); await c.resolve("github.com");
  const r = await c.logCheck({ report: false });
  assert.equal(r.consistent, true, r.summary);
  assert.ok(r.witnessed && r.witnessed.token === true, JSON.stringify(r.witnessed));
});
