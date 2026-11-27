// Safe transport (outside audit F5/F6, 2026-11-22): the probes must not reach private addresses directly or through a
// redirect, and must not buffer an unbounded body. Offline: global fetch is replaced; nothing leaves the machine.
import { test } from "node:test";
import assert from "node:assert/strict";
import { grab, safeFetch, isPublicHost, readCapped, agentsMd } from "../src/surfaces.js";

function withFetch(handler) { const real = globalThis.fetch; const calls = []; globalThis.fetch = async (u, o) => { calls.push(String(u)); return handler(String(u), o); }; return { calls, restore: () => { globalThis.fetch = real; } }; }

test("private and loopback hosts are refused before any request", async () => {
  for (const h of ["localhost", "127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1", "172.16.0.1", "100.64.0.1", "[::1]", "[fd00::1]", "[::ffff:127.0.0.1]", "2130706433", "0x7f000001", "box.internal", "printer.local"]) assert.equal(isPublicHost(h.replace(/^\[|\]$/g, "")), false, h);
  for (const h of ["example.com", "93.184.216.34", "crawlcheck.io"]) assert.equal(isPublicHost(h), true, h);
  const f = withFetch(() => new Response("secret"));
  try { const g = await grab("http://127.0.0.1:8080/"); assert.equal(g.status, null); assert.match(g.error, /blocked/); assert.equal(f.calls.length, 0); } finally { f.restore(); }
});

test("a redirect to a private address is refused at the hop", async () => {
  const f = withFetch((u) => u.startsWith("https://example.test/") ? new Response(null, { status: 302, headers: { location: "http://169.254.169.254/latest/meta-data/" } }) : new Response("metadata"));
  try { const g = await grab("https://example.test/"); assert.equal(g.status, null); assert.match(g.error, /non-public/); assert.deepEqual(f.calls, ["https://example.test/"]); } finally { f.restore(); }
});

test("public redirects are followed by hand, with a hop limit", async () => {
  let n = 0; const f = withFetch((u) => new Response(null, { status: 301, headers: { location: "https://example.test/" + (++n) } }));
  try { const g = await grab("https://example.test/"); assert.match(g.error, /redirects/); assert.equal(f.calls.length, 6); } finally { f.restore(); }
  const f2 = withFetch((u) => u.endsWith("/a") ? new Response(null, { status: 302, headers: { location: "/b" } }) : new Response("ok"));
  try { const g = await grab("https://example.test/a"); assert.equal(g.status, 200); assert.equal(g.body, "ok"); assert.equal(g.finalUrl, "https://example.test/b"); } finally { f2.restore(); }
});

test("bodies are cut at the ceiling while streaming and say so", async () => {
  let pulled = 0; const chunk = new Uint8Array(65536).fill(97);
  const stream = () => new ReadableStream({ pull(c) { pulled += chunk.byteLength; c.enqueue(chunk); if (pulled > 64 * 1024 * 1024) c.close(); } });
  const f = withFetch(() => new Response(stream(), { headers: { "content-type": "text/html" } }));
  try {
    const g = await grab("https://example.test/", { ceiling: 300000 });
    assert.equal(g.bytes, 300000); assert.equal(g.truncated, true); assert.equal(g.body.length, 60000);
    assert.ok(pulled < 2 * 1024 * 1024, "stopped reading near the ceiling, pulled " + pulled);
    const a = await agentsMd("example.test"); assert.ok(a.bytes <= 300000);
  } finally { f.restore(); }
  const r = await readCapped(new Response("abc"), 10); assert.equal(r.bytes, 3); assert.equal(r.truncated, false);
});

test("trustedNetwork turns the address check off on purpose", async () => {
  const f = withFetch(() => new Response("mine"));
  try { const r = await safeFetch("http://127.0.0.1/", {}, { trustedNetwork: true }); assert.equal(await r.text(), "mine"); } finally { f.restore(); }
});


test("cross-origin redirect strips credentials, cookies, custom headers, and request body", async () => {
  const seen = [];
  const f = withFetch((u, opts) => {
    seen.push({url:u, method:opts.method, headers:Object.fromEntries(new Headers(opts.headers)), body:opts.body});
    if (u === "https://one.example/start") return new Response(null,{status:302,headers:{location:"https://two.example/next"}});
    if (u === "https://two.example/next") return new Response(null,{status:302,headers:{location:"https://two.example/final"}});
    return new Response("ok");
  });
  try {
    const r = await safeFetch("https://one.example/start", { method:"POST", headers:{authorization:"Bearer private", cookie:"session=private", "x-api-key":"private", accept:"application/json"}, body:"sensitive=1" });
    assert.equal(await r.text(),"ok");
    assert.equal(seen.length,3);
    assert.equal(seen[0].headers.authorization,"Bearer private");
    for(const s of seen.slice(1)){
      assert.equal(s.method,"GET");
      assert.equal(s.body,undefined);
      assert.equal(s.headers.authorization,undefined);
      assert.equal(s.headers.cookie,undefined);
      assert.equal(s.headers["x-api-key"],undefined);
      assert.equal(s.headers.accept,"application/json");
    }
  } finally { f.restore(); }
});
test("same-origin redirects retain explicitly supplied headers", async () => {
  const seen=[];
  const f=withFetch((u,o)=>{seen.push(o);return u.endsWith("/a") ? new Response(null,{status:302,headers:{location:"/b"}}):new Response("ok");});
  try{
    await safeFetch("https://example.test/a",{headers:{authorization:"Bearer local"}});
    assert.equal(new Headers(seen[1].headers).get("authorization"),"Bearer local");
  } finally {f.restore();}
});
