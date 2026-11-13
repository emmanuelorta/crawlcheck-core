// hdr1: caller headers stay on the origin the caller named; after a redirect to another origin only the allowlist travels.
import test from "node:test"; import assert from "node:assert/strict";
import { CrawlCheck, GUARDED_SAFE_HEADERS } from "../dist/index.js";
function client() { const cc = new CrawlCheck(); cc.guard = async () => ({ proceed: true, why: [], receipt: { decision: "allow" }, header: { "crawlcheck-receipt": "r" } }); return cc; }
function recorder(map) { const seen = []; const f = async (u, init) => { seen.push({ url: String(u), headers: Object.fromEntries(new Headers(init.headers).entries()) }); const to = map[String(u)]; return to ? new Response(null, { status: 302, headers: { location: to } }) : new Response("ok", { status: 200 }); }; return { f, seen }; }
const H = { authorization: "Bearer secret", cookie: "sid=1", "x-api-key": "k", accept: "text/html", "user-agent": "t/1" };
test("another host: Authorization, Cookie and custom headers are dropped; the allowlist and the receipt stay", async () => {
  const { f, seen } = recorder({ "https://a.example/x": "https://b.example/y" });
  const r = await client().guardedFetch("https://a.example/x", { init: { headers: H }, fetch: f });
  assert.equal(r.proceed, true); assert.equal(seen.length, 2);
  assert.equal(seen[0].headers.authorization, "Bearer secret"); assert.equal(seen[0].headers.cookie, "sid=1");
  for (const k of ["authorization", "cookie", "x-api-key"]) assert.equal(seen[1].headers[k], undefined, k + " crossed origins");
  assert.equal(seen[1].headers.accept, "text/html"); assert.equal(seen[1].headers["user-agent"], "t/1"); assert.equal(seen[1].headers["crawlcheck-receipt"], "r");
});
test("same origin: every caller header is kept", async () => {
  const { f, seen } = recorder({ "https://a.example/x": "https://a.example/y" });
  await client().guardedFetch("https://a.example/x", { init: { headers: H }, fetch: f });
  assert.equal(seen[1].headers.authorization, "Bearer secret"); assert.equal(seen[1].headers["x-api-key"], "k");
});
test("scheme downgrade and port change count as another origin", async () => {
  for (const to of ["http://a.example/y", "https://a.example:8443/y"]) {
    const { f, seen } = recorder({ "https://a.example/x": to });
    await client().guardedFetch("https://a.example/x", { init: { headers: H }, fetch: f });
    assert.equal(seen[1].headers.authorization, undefined, to); assert.equal(seen[1].headers.cookie, undefined, to);
  }
});
test("back to the first origin: headers return", async () => {
  const { f, seen } = recorder({ "https://a.example/x": "https://b.example/y", "https://b.example/y": "https://a.example/z" });
  await client().guardedFetch("https://a.example/x", { init: { headers: H }, fetch: f });
  assert.equal(seen[1].headers.authorization, undefined); assert.equal(seen[2].headers.authorization, "Bearer secret");
});
test("the allowlist holds no credential header", () => { for (const k of ["authorization", "cookie", "proxy-authorization"]) assert.equal(GUARDED_SAFE_HEADERS.includes(k), false); });
