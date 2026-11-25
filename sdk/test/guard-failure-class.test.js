// failure_class on guard() and guardedFetch() results, and observe mode, over the acceptance suite's signed cases
// (https://crawlcheck.io/spec/guard). CC_SDK=<path or package name> runs it against another build.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
const here = new URL(".", import.meta.url);
const CASES = process.env.CC_GUARD_CASES || [new URL("../../spec/guard-acceptance/cases.json", here), new URL("./fixtures/guard-acceptance.json", here)].find((u) => existsSync(u));
const suite = JSON.parse(readFileSync(CASES, "utf8"));
const { CrawlCheck, GUARD_FAILURE_CLASSES, CONTINUITY_FAILURE_CLASSES, guardFailureClassOf, continuityClassOf, newRevocationStore } = await import(process.env.CC_SDK || "../dist/index.js");
const BASE = "https://cc.test";

function fakeFetch(c, log) {
  return async (url, init = {}) => {
    url = String(url);
    if (url.startsWith(BASE)) {
      const p = new URL(url).pathname, cc = c.crawlcheck;
      if (cc.unreachable) throw new TypeError("fetch failed");
      if (cc.timeout) throw new DOMException("The operation was aborted due to timeout", "TimeoutError");   // not in the suite: set by a test here
      if (p === "/.well-known/http-message-signatures-directory") return new Response(JSON.stringify(suite.directory), { headers: { "content-type": "application/json" } });
      if (p === "/.well-known/security-key-rotation.json") { const rot = cc.rotation || suite.rotation; return rot ? new Response(JSON.stringify(rot), { headers: { "content-type": "application/json" } }) : new Response("{}", { status: 404 }); }
      if (p === "/api/v1/preflight") {
        const b = JSON.parse(init.body || "{}"); log.asked.push(b.domain);
        if (cc.by_op) { const o = b.operation || {}; const r = cc.by_op[o.method + " " + o.url]; return r ? new Response(JSON.stringify(r), { headers: { "content-type": "application/json" } }) : new Response("{\"error\":\"none\"}", { status: 404 }); }
        if (cc.by_domain) { const r = cc.by_domain[b.domain]; return r ? new Response(JSON.stringify(r), { headers: { "content-type": "application/json" } }) : new Response("{\"error\":\"none\"}", { status: 404 }); }
        return new Response(cc.text !== undefined ? cc.text : JSON.stringify(cc.body), { status: cc.status || 200, headers: { "content-type": "application/json" } });
      }
      return new Response("{}", { status: 404 });
    }
    log.fetched.push(url);
    const h = new Headers(init.headers || {}); if (h.get("crawlcheck-receipt")) log.header_to.push(new URL(url).hostname);
    const s = (c.sites || {})[url];
    if (!s) return new Response("not in fixture", { status: 404 });
    return new Response(s.body ?? null, { status: s.status, headers: s.location ? { location: s.location } : {} });
  };
}
const byId = Object.fromEntries(suite.cases.map((c) => [c.id, c]));
async function run(c, extra = {}) {
  const log = { fetched: [], header_to: [], asked: [] };
  const cc = new CrawlCheck({ base: BASE, fetch: fakeFetch(c, log) });
  const q = c.request, opts = Object.assign({ nonce: q.nonce, now: Date.parse(q.now), allowWarn: q.allow_warn }, extra);
  if (q.operation) opts.operation = q.operation;
  if (q.confirm !== null) opts.confirm = async () => q.confirm;
  const r = q.url ? await cc.guardedFetch(q.url, Object.assign(opts, { action: q.action, maxHops: q.max_hops })) : await cc.guard(q.domain, q.action, opts);
  return { r, log, cc };
}

// The class every case in the suite gets. null: the case proceeds.
const EXPECT = {
  "allow": null, "warn-default": "decision_refused", "warn-allowed": null, "confirm-missing": "server_identity_mismatch", "confirm-no": "decision_refused", "confirm-yes": null,
  "block": "decision_refused", "unsupported": "decision_refused", "decision-unknown": "signature_invalid", "other-domain": "server_identity_mismatch", "subdomain": "server_identity_mismatch",
  "www-same": null, "other-action": "server_identity_mismatch", "expired": "evidence_expired", "expired-in-skew": null, "skew-inflated": "evidence_expired", "future": "evidence_expired",
  "lifetime-transact": "evidence_expired", "lifetime-connect": "evidence_expired", "no-expiry": "evidence_expired", "nonce-other": "replay_mismatch", "nonce-missing": "replay_mismatch",
  "op-match": null, "op-other-url": "operation_mismatch", "op-other-method": "operation_mismatch", "op-missing": "operation_mismatch", "op-tool-schema": "operation_mismatch", "op-scopes": "operation_mismatch",
  "purpose-key-decision": null, "kp-decision-key-early": "key_retired", "kp-document-key-after-switch": "key_retired", "kp-request-key-unbound": "key_retired", "kp-request-key-bound": null,
  "kp-request-key-bound-after-switch": "key_retired", "kp-retired": "key_unknown", "kp-compromised-in-directory": "key_unknown", "kp-compromised-answer": "key_unknown", "kp-fallback": null,
  "kp-fallback-compromised-key": "key_unknown", "resolve-key-foreign": "key_unknown", "tampered": "signature_invalid", "tampered-unsigned-field": "signature_invalid", "unknown-signed-field": null,
  "foreign-key": "key_unknown", "kid-mismatch": "signature_invalid", "unsigned": "signature_invalid", "resolve-unbound": "signature_invalid", "wrong-kind": "response_malformed",
  "wrong-version": "response_malformed", "malformed-empty": "response_malformed", "malformed-array": "response_malformed", "malformed-text": "response_malformed", "http-500": "service_unavailable",
  "http-429": "service_unavailable", "unreachable": "service_unavailable", "fetch-ok": null, "fetch-blocked": "decision_refused", "redirect-to-blocked": "decision_refused", "redirect-to-allowed": null,
  "redirect-relative": null, "redirect-scheme": "fetch_refused", "redirect-loop": "fetch_refused", "redirect-ip": "service_unavailable", "fetch-receipt-reuse": null
};

test("the table names every case in the suite", () => { assert.deepEqual(Object.keys(EXPECT).sort(), suite.cases.map((c) => c.id).sort()); });
test("GUARD_FAILURE_CLASSES: the eleven guard classes, the two split out, and guardedFetch's own", () => {
  for (const k of ["service_unavailable", "check_timeout", "response_malformed", "signature_invalid", "key_unknown", "key_retired", "server_identity_mismatch", "evidence_expired", "operation_mismatch", "replay_mismatch", "decision_refused", "revoked", "split_view", "fetch_refused"]) assert.ok(GUARD_FAILURE_CLASSES.includes(k), k);
  assert.equal(GUARD_FAILURE_CLASSES.length, 14);
  for (const k of ["operation_mismatch", "replay_mismatch", "revoked", "split_view", "fetch_refused"]) assert.equal(CONTINUITY_FAILURE_CLASSES.includes(k), false, k + " must not enter the continuity policy (its sha256 would change)");
});

for (const c of suite.cases) {
  test("enforce " + c.id + ": failure_class " + EXPECT[c.id], async () => {
    const { r } = await run(c);
    assert.equal(r.proceed, c.expect.proceed);
    assert.equal(r.failure_class, EXPECT[c.id], "why: " + r.why.join(" | "));
    assert.equal(r.failure_class === null, r.proceed, "failure_class is null exactly when the result proceeds");
    if (r.failure_class !== null) assert.ok(GUARD_FAILURE_CLASSES.includes(r.failure_class));
    assert.equal(r.mode, "enforce"); assert.equal(r.enforced, true); assert.equal(r.would_proceed, r.proceed);
    if (!c.request.url && !r.proceed && r.receipt) assert.equal(guardFailureClassOf(Object.assign({}, r, { failure_class: undefined })), r.failure_class, "with a receipt, the class can be told from the rest of the result");
  });
  test("observe " + c.id + ": reported, not refused", async () => {
    const seen = [];
    const { r, log } = await run(c, { mode: "observe", onRecord: (g) => { seen.push(g); } });
    assert.equal(r.mode, "observe"); assert.equal(r.enforced, false);
    assert.equal(r.would_proceed, c.expect.proceed, "would_proceed is what enforce returns");
    assert.equal(r.failure_class, EXPECT[c.id]);
    if (EXPECT[c.id] === "fetch_refused") { assert.equal(r.proceed, false, "a URL that cannot be checked is refused in observe too"); return; }
    assert.equal(r.proceed, true, "observe never refuses a decision");
    if (c.request.url) {
      assert.ok(r.response, "the request went out");
      assert.equal(seen.length, r.hops.length, "onRecord saw every hop's check");
      for (const h of r.hops) if (h.would_proceed === false) assert.equal(log.header_to.includes(h.domain), false, "no receipt header goes to a hop the guard would refuse");
    } else {
      assert.equal(seen.length, 1); assert.equal(seen[0], r);
      assert.equal(!!r.header, c.expect.proceed, "a receipt header only for a receipt that was accepted");
      if (!c.expect.proceed) assert.ok(r.why.length > 0, "the reasons are kept");
    }
  });
}

test("operation and replay are no longer server_identity_mismatch on the result; continuityClassOf is unchanged", async () => {
  for (const [id, cls] of [["op-other-url", "operation_mismatch"], ["nonce-other", "replay_mismatch"]]) {
    const { r } = await run(byId[id]);
    assert.equal(r.failure_class, cls); assert.equal(guardFailureClassOf(r), cls);
    assert.equal(continuityClassOf(r), "server_identity_mismatch", "continuity records and policies keep their class");
  }
});
test("require_confirmation with no confirm(): decision_refused", async () => {
  const c = JSON.parse(JSON.stringify(byId["confirm-no"])); c.request.confirm = null;
  const { r } = await run(c);
  assert.equal(r.proceed, false); assert.equal(r.failure_class, "decision_refused"); assert.match(r.why.join(" "), /no confirm\(\) was given/);
});
test("a timeout is check_timeout", async () => {
  const c = JSON.parse(JSON.stringify(byId["allow"])); c.crawlcheck.timeout = true;
  const { r } = await run(c);
  assert.equal(r.proceed, false); assert.equal(r.failure_class, "check_timeout");
});
test("revoked: refused offline with its own class; observe reports it and proceeds", async () => {
  const c = byId["allow"], q = c.request;
  for (const mode of ["enforce", "observe"]) {
    const log = { fetched: [], header_to: [], asked: [] };
    const store = newRevocationStore(); store.generated_at = "2026-10-10T00:00:00.000Z";
    store.revoked[q.domain] = { domain: q.domain, actions: ["transact"], causes: ["test"], state: "revoked", since: "2026-10-09T00:00:00.000Z" };
    const cc = new CrawlCheck({ base: BASE, fetch: fakeFetch(c, log), revocationStore: store });
    const r = await cc.guard(q.domain, "transact", { nonce: q.nonce, now: Date.parse(q.now), mode });
    assert.ok(r.revoked, "the fixture entry matched"); assert.deepEqual(log.asked, [], "no request");
    assert.equal(r.failure_class, "revoked"); assert.equal(r.would_proceed, false); assert.equal(r.proceed, mode === "observe"); assert.equal(r.header, null);
    assert.equal(continuityClassOf(r), "service_unavailable", "unchanged");
  }
});
test("split view: its own class", async () => {
  const c = byId["allow"], q = c.request, log = { fetched: [], header_to: [], asked: [] };
  const cc = new CrawlCheck({ base: BASE, fetch: fakeFetch(c, log) });
  cc.log.forks.push({ kind: "two_heads_for_one_batch", batch: 1, why: "test" });
  const r = await cc.guard(q.domain, "read", { nonce: q.nonce, now: Date.parse(q.now) });
  assert.equal(r.proceed, false); assert.equal(r.failure_class, "split_view");
});
test("onlineKeys false with nothing pinned: key_unknown", async () => {
  const c = byId["allow"], q = c.request, log = { fetched: [], header_to: [], asked: [] };
  const cc = new CrawlCheck({ base: BASE, fetch: fakeFetch(c, log) });
  const r = await cc.guard(q.domain, "read", { nonce: q.nonce, now: Date.parse(q.now), onlineKeys: false });
  assert.equal(r.proceed, false); assert.equal(r.failure_class, "key_unknown");
});
test("mode: only enforce and observe; anything else throws before any request", async () => {
  const c = byId["allow"], q = c.request, log = { fetched: [], header_to: [], asked: [] };
  const cc = new CrawlCheck({ base: BASE, fetch: fakeFetch(c, log) });
  await assert.rejects(cc.guard(q.domain, "read", { mode: "review" }), /mode must be enforce or observe/);
  await assert.rejects(cc.guardedFetch("https://good.example/", { mode: "off" }), /mode must be enforce or observe/);
  assert.deepEqual(log.asked, []); assert.deepEqual(log.fetched, []);
});
test("onRecord: called in enforce mode too, and a throwing recorder changes nothing", async () => {
  const seen = [];
  const a = await run(byId["block"], { onRecord: (g) => { seen.push(g.failure_class); throw new Error("recorder down"); } });
  assert.equal(a.r.proceed, false); assert.deepEqual(seen, ["decision_refused"]);
  const b = await run(byId["allow"], { onRecord: async () => { throw new Error("recorder down"); } });
  assert.equal(b.r.proceed, true);
});
test("guardedFetch: a refused hop carries the class; observe follows the redirect enforce would have stopped", async () => {
  const c = byId["redirect-to-blocked"];
  const e = await run(c);
  assert.equal(e.r.proceed, false); assert.equal(e.r.failure_class, "decision_refused"); assert.equal(e.r.would_proceed, false);
  assert.deepEqual(e.r.hops.map((h) => h.failure_class), [null, "decision_refused"]); assert.deepEqual(e.log.fetched, ["https://good.example/go"]);
  const o = await run(c, { mode: "observe" });
  assert.equal(o.r.proceed, true); assert.equal(o.r.would_proceed, false); assert.equal(o.r.enforced, false); assert.equal(o.r.failure_class, "decision_refused");
  assert.deepEqual(o.log.fetched, ["https://good.example/go", "https://evil.example/x"]);
  assert.deepEqual(o.r.hops.map((h) => [h.proceed, h.would_proceed]), [[true, true], [true, false]]);
  assert.deepEqual(o.log.header_to, ["good.example"], "the receipt header went only where a receipt was accepted");
});
test("guardedFetch: a URL that is not one is fetch_refused in both modes", async () => {
  const cc = new CrawlCheck({ base: BASE, fetch: fakeFetch(byId["allow"], { fetched: [], header_to: [], asked: [] }) });
  for (const mode of ["enforce", "observe"]) for (const u of ["not a url", "ftp://good.example/x"]) {
    const r = await cc.guardedFetch(u, { mode });
    assert.equal(r.proceed, false); assert.equal(r.failure_class, "fetch_refused"); assert.equal(r.would_proceed, false);
  }
});
test("guardedFetch over a replaced guard() that returns no failure_class: the hop still gets one", async () => {
  const cc = new CrawlCheck({ base: BASE, fetch: async () => { throw new Error("requested"); } });
  cc.guard = async () => ({ proceed: false, why: ["decision is block"], receipt: { kind: "crawlcheck-decision", v: 1, decision: "block" }, verification: null, header: null, acceptance: null });
  const r = await cc.guardedFetch("https://good.example/");
  assert.equal(r.proceed, false); assert.equal(r.would_proceed, false); assert.ok(GUARD_FAILURE_CLASSES.includes(r.failure_class)); assert.equal(r.hops[0].failure_class, r.failure_class);
});
test("agent tools carry the class", async () => {
  const { agentTools } = await import(process.env.CC_SDK || "../dist/index.js");
  const c = byId["block"], cc = new CrawlCheck({ base: BASE, fetch: fakeFetch(c, { fetched: [], header_to: [], asked: [] }) });
  const tools = Object.fromEntries(agentTools(cc, { nonce: c.request.nonce, now: Date.parse(c.request.now) }).map((t) => [t.name, t.execute]));
  const out = await tools.crawlcheck_check_site({ site: c.request.domain });
  assert.equal(out.proceed, false); assert.equal(out.failure_class, "decision_refused");
});
