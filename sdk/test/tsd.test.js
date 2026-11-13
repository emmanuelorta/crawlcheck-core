// mcp-tool-set-digest/1: the 68 published vectors (github.com/alexar76/mcp-tool-set-digest, Apache-2.0 OR MIT), every
// canonical text they carry, and the equal / differ pairs. Then the relation to jcs-v1: equal in the ordinary case.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { toolSetDigest, tsdCanonical, ToolSetDigestError, jcsV1, TSD_SPEC } from "../dist/index.js";
const V = JSON.parse(fs.readFileSync(new URL("./fixtures/tool-set-digest-vectors.json", import.meta.url), "utf8"));
const key = (side) => (side.error ? "E:" + side.error : String(side.digest));
const got = {};
test("the fixture is the published set", () => { assert.equal(V.vectors.length, 68); assert.equal(TSD_SPEC, "mcp-tool-set-digest/1"); });
for (const v of V.vectors) test("vector " + v.id, async () => {
  const r = (got[v.id] = await toolSetDigest(JSON.parse(v.tools)));
  for (const k of ["contract", "extras"]) {
    assert.equal(key(r[k]), key(v[k]), k);
    if (v[k].canonical !== undefined) assert.equal(r[k].canonical, v[k].canonical, k + " canonical text");
  }
});
test("equal and differ pairs", async () => {
  for (const v of V.vectors) if (!got[v.id]) got[v.id] = await toolSetDigest(JSON.parse(v.tools));
  for (const p of V.equal) assert.equal(key(got[p.ids[0]][p.digest]), key(got[p.ids[1]][p.digest]), p.ids.join(" = "));
  for (const p of V.differ) assert.notEqual(key(got[p.ids[0]][p.digest]), key(got[p.ids[1]][p.digest]), p.ids.join(" != "));
});
test("a member outside the contract cannot take the contract digest away", async () => {
  const r = await toolSetDigest([{ name: "a", title: "\ud800" }]);
  assert.ok(r.contract.digest); assert.deepEqual(r.extras, { error: "TSD-TEXT", tool: "a" });
});
test("a partial list has neither digest", async () => { const r = await toolSetDigest([{ name: "a" }], { partial: true }); assert.deepEqual([r.contract, r.extras], [{ error: "TSD-PAGE" }, { error: "TSD-PAGE" }]); });
test("nothing is repaired: tsdCanonical refuses what RFC 8785 refuses", () => {
  assert.throws(() => tsdCanonical("\udc00"), (e) => e instanceof ToolSetDigestError && e.code === "TSD-TEXT");
  assert.throws(() => tsdCanonical({ a: Infinity }), (e) => e.code === "TSD-NUMBER");
  assert.equal(tsdCanonical({ b: 1.0, a: -0, c: 1e21 }), '{"a":0,"b":1,"c":1e+21}');
});
test("equals jcs-v1 wherever jcs-v1 neither repairs nor bounds", async () => {
  const tools = [{ name: "read_file", title: "Read file", description: "Read a file from disk.", inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] }, annotations: { readOnlyHint: true } }, { name: "b", description: "x" }];
  const t = await toolSetDigest(tools, { perTool: true }), j = await jcsV1(tools);
  assert.equal(t.contract.digest, j.tools_sha256); assert.equal(t.extras.digest, j.extras_sha256);
  assert.deepEqual(t.tools.map((x) => [x.name, x.contract, x.extras]).sort(), j.tools.map((x) => [x.name, x.contract, x.extras]).sort());
});
