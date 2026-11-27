import { test } from "node:test";
import assert from "node:assert/strict";
import { fetchOne } from "../action/observe.mjs";

const identity = { id: "test-agent", headers: { "user-agent": "CrawlCheck-test" } };
const root = "https://93.184.216.34/";

test("observer stops at redirected private target before sending a request", async () => {
  const calls = [];
  const f = async (url, init) => {
    calls.push(String(url));
    assert.equal(init.redirect, "manual");
    return new Response(null, { status: 302, headers: { location: "http://169.254.169.254/latest/meta-data/" } });
  };
  const { row } = await fetchOne(root, identity, 4000, f);
  assert.deepEqual(calls, [root]);
  assert.equal(row.status, null);
  assert.match(row.error, /blocked: non-public address/);
});

test("observer follows safe public redirects with bounded manual hops", async () => {
  const calls = [];
  const f = async (url, init) => {
    calls.push(String(url));
    assert.equal(init.redirect, "manual");
    return calls.length === 1
      ? new Response(null, { status: 302, headers: { location: "/final" } })
      : new Response("verified", { status: 200, headers: { "content-type": "text/plain" } });
  };
  const { row, buf } = await fetchOne(root, identity, 4000, f);
  assert.deepEqual(calls, [root, root + "final"]);
  assert.equal(row.status, 200);
  assert.equal(row.url_final, root + "final");
  assert.equal(buf.toString("utf8"), "verified");
  assert.equal(row.sha256.length, 64);
});

test("observer refuses an unbounded redirect loop", async () => {
  let hits = 0;
  const f = async () => { hits++; return new Response(null, { status: 301, headers: {location: root} }); };
  const {row} = await fetchOne(root,identity,4000,f);
  assert.equal(hits,6);
  assert.match(row.error,/more than 5 redirects/);
  assert.equal(row.sha256,null);
});
