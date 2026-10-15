// Offline revocations (rvd1): the client syncs the signed list and its ?since= delta, and guard() refuses a listed
// domain for a listed action with the network cut. Fixtures are signed by the Worker's own code with a throwaway key.
import test from "node:test"; import assert from "node:assert/strict"; import fs from "node:fs";
import { CrawlCheck, newRevocationStore, applyRevocations, revokedFor } from "../dist/index.js";
const F = JSON.parse(fs.readFileSync(new URL("./fixtures/revocations.json", import.meta.url), "utf8"));

function fakeFetch(state) {
  return async (u) => {
    const url = new URL(String(u));
    if (state.cut) throw new TypeError("fetch failed (network cut)");
    state.calls.push(url.pathname + url.search);
    const body = url.pathname === "/.well-known/http-message-signatures-directory" ? F.directory
      : url.pathname === "/api/v1/revocations" ? (url.searchParams.get("since") ? (state.delta || F.delta) : F.full) : null;
    return new Response(body ? JSON.stringify(body) : "{}", { status: body ? 200 : 404, headers: { "content-type": "application/json" } });
  };
}

test("sync: the full list, then the delta (added, lifted), then guard refuses offline", async () => {
  const state = { calls: [], cut: false };
  const cc = new CrawlCheck({ fetch: fakeFetch(state) });
  const a = await cc.syncRevocations();
  assert.equal(a.applied, true, a.reason); assert.equal(a.full, true); assert.equal(a.total, 2);
  assert.ok(revokedFor(cc.revocations, "shop.example", "transact"));
  assert.equal(revokedFor(cc.revocations, "shop.example", "connect"), null, "a high-risk field change revokes transact only");
  const b = await cc.syncRevocations();
  assert.equal(b.applied, true, b.reason); assert.equal(b.full, false); assert.equal(b.added, 1); assert.equal(b.removed, 1);
  assert.ok(state.calls.some((c) => c.startsWith("/api/v1/revocations?since=")), "the second sync asked for a delta");
  assert.equal(revokedFor(cc.revocations, "shop.example", "transact"), null, "lifted");
  assert.ok(revokedFor(cc.revocations, "paypa1.com", "connect"));
  state.cut = true; const n = state.calls.length;
  const g = await cc.guard("checkout.paypa1.com", "transact");
  assert.equal(g.proceed, false); assert.equal(g.revoked.domain, "paypa1.com"); assert.match(g.why[0], /revocation list/);
  const g2 = await cc.guard("xn--pple-43d.com", "connect");
  assert.equal(g2.proceed, false); assert.deepEqual(g2.revoked.causes, ["impersonation_suspected"]);
  assert.equal(state.calls.length, n, "no request was made for a revoked domain");
  const g3 = await cc.guard("paypa1.com", "read");
  assert.equal(g3.proceed, false); assert.equal(g3.revoked, undefined, "read is never revoked by the list; with the network cut guard still fails closed");
});

test("a tampered list is never applied", async () => {
  const bad = JSON.parse(JSON.stringify(F.full)); bad.revoked = [];
  const state = { calls: [], cut: false };
  const cc = new CrawlCheck({ fetch: async (u) => { const p = new URL(String(u)).pathname; return new Response(JSON.stringify(p === "/api/v1/revocations" ? bad : F.directory), { status: 200 }); } });
  const r = await cc.syncRevocations();
  assert.equal(r.applied, false); assert.match(r.reason, /did not verify/); assert.equal(r.total, 0);
});

test("a delta that does not reach back is refused; a store persists as JSON", () => {
  const st = newRevocationStore();
  assert.equal(applyRevocations(st, F.full).applied, true);
  const copy = JSON.parse(JSON.stringify(st));
  assert.ok(revokedFor(copy, "www.shop.example", "transact"), "parent-domain and www match");
  const inc = Object.assign({}, F.delta, { delta_complete: false });
  assert.equal(applyRevocations(copy, inc).applied, false);
  const late = Object.assign({}, F.delta, { since: "2999-01-01T00:00:00.000Z", generated_at: "2999-01-02T00:00:00.000Z" });
  assert.match(applyRevocations(copy, late).reason, /starts after/);
  const old = Object.assign({}, F.full, { generated_at: "2000-01-01T00:00:00.000Z" });
  assert.match(applyRevocations(copy, old).reason, /older/);
});

test("private mode: resolve sends only a hash prefix, verifies the bucket's answer, and never names the domain", async () => {
  const crypto = await import("node:crypto");
  const h = crypto.createHash("sha256").update("example-shop.com").digest("hex");
  const calls = [];
  const bucket = { kind: "crawlcheck-resolve-prefix", prefix: h.slice(0, 2), in_bucket: 2, answers: [{ domain_sha256: "0".repeat(64), answer: {} }, { domain_sha256: h, answer: F.resolve }] };
  const cc = new CrawlCheck({ privateLookups: true, fetch: async (u) => { const p = new URL(String(u)); calls.push(p.pathname + p.search);
    const b = p.pathname === "/.well-known/http-message-signatures-directory" ? F.directory : p.pathname.startsWith("/api/v1/resolve-prefix/") ? bucket : null;
    return new Response(JSON.stringify(b || {}), { status: b ? 200 : 404 }); } });
  const a = await cc.resolve("example-shop.com");
  assert.equal(a.domain, "example-shop.com");
  assert.ok(calls.includes("/api/v1/resolve-prefix/" + h.slice(0, 2)));
  assert.ok(calls.every((c) => !c.includes("example-shop")), "the domain never left the process: " + calls.join(" "));
  const v = await cc.resolveFor("example-shop.com");
  assert.equal(v.source, "network"); assert.ok(v.decisions.read);
  await assert.rejects(cc.resolve("not-in-bucket.com"), (e) => e.status === 404 && /never sent/.test(e.message));
  assert.ok(calls.every((c) => !c.includes("not-in-bucket")));
});
