// The guard() acceptance suite (https://crawlcheck.io/spec/guard) against this SDK.
// CC_SDK=<path or package name> runs it against another build (CI uses the copy installed from npm).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
const here = new URL(".", import.meta.url);
const CASES = process.env.CC_GUARD_CASES || [new URL("../../spec/guard-acceptance/cases.json", here), new URL("./fixtures/guard-acceptance.json", here)].find((u) => existsSync(u));
const suite = JSON.parse(readFileSync(CASES, "utf8"));
const { CrawlCheck } = await import(process.env.CC_SDK || "../dist/index.js");
const BASE = "https://cc.test";

function fakeFetch(c, log) {
  return async (url, init = {}) => {
    url = String(url);
    if (url.startsWith(BASE)) {
      const p = new URL(url).pathname, cc = c.crawlcheck;
      if (cc.unreachable) throw new TypeError("fetch failed");
      if (p === "/.well-known/http-message-signatures-directory") return new Response(JSON.stringify(suite.directory), { headers: { "content-type": "application/json" } });
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

for (const c of suite.cases) {
  test(c.id + ": " + c.title, async () => {
    const log = { fetched: [], header_to: [], asked: [] };
    const cc = new CrawlCheck({ base: BASE, fetch: fakeFetch(c, log) });
    const q = c.request, opts = { nonce: q.nonce, now: Date.parse(q.now), allowWarn: q.allow_warn };
    if (q.operation) opts.operation = q.operation;
    if (q.confirm !== null) opts.confirm = async () => q.confirm;
    if (q.url) {
      assert.equal(typeof cc.guardedFetch, "function", "this SDK has no guarded fetch, so nothing re-checks redirects");
      const r = await cc.guardedFetch(q.url, Object.assign(opts, { action: q.action, maxHops: q.max_hops }));
      assert.equal(r.proceed, c.expect.proceed, "proceed; why: " + r.why.join(" | "));
      if (c.expect.fetched) assert.deepEqual(log.fetched, c.expect.fetched);
      if (c.expect.fetched_count !== undefined) assert.equal(log.fetched.length, c.expect.fetched_count);
      if (c.expect.receipt_header_to) assert.deepEqual(log.header_to, c.expect.receipt_header_to);
    } else {
      let r; try { r = await cc.guard(q.domain, q.action, opts); } catch (e) { r = { proceed: false, header: null, threw: String(e && e.message || e) }; }   // a throw is a refusal: the caller cannot act on it
      assert.equal(r.proceed, c.expect.proceed, "proceed; why: " + (r.threw || (r.why || []).join(" | ")));
      assert.equal(!!r.header, c.expect.proceed, "the receipt header is given only when it proceeds");
      if (!r.proceed) assert.ok(r.threw || (r.why && r.why.length > 0), "a refusal says why");
    }
  });
}
