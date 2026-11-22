// TSD-DEPTH (1.15.3): a reader limit of 512 levels of arrays and objects, the tools array being level 1. Before it,
// this SDK gave a digest to about 3,000 levels while the Python SDK raised RecursionError from about 500.
import test from "node:test";
import assert from "node:assert/strict";
import { toolSetDigest, tsdCanonical } from "../dist/index.js";

const nested = (n) => { let v = []; for (let i = 0; i < n - 1; i++) v = [v]; return v; };

test("contract side: 509 nested arrays under inputSchema pass, 510 give TSD-DEPTH", async () => {
  const ok = await toolSetDigest([{ name: "a", inputSchema: { x: nested(509) } }]);
  assert.match(ok.contract.digest, /^sha256-/);
  const over = await toolSetDigest([{ name: "a", inputSchema: { x: nested(510) } }]);
  assert.deepEqual(over.contract, { error: "TSD-DEPTH", tool: "a" });
  assert.deepEqual(over.extras, { digest: null });
});

test("extras side: the depth error stays on the digest covering it", async () => {
  const ok = await toolSetDigest([{ name: "a", x: nested(510) }]);
  assert.match(ok.extras.digest, /^sha256-/);
  const over = await toolSetDigest([{ name: "a", x: nested(511) }]);
  assert.deepEqual(over.extras, { error: "TSD-DEPTH", tool: "a" });
  assert.match(over.contract.digest, /^sha256-/);
});

test("no stack exhaustion at 100,000 levels", async () => {
  const r = await toolSetDigest([{ name: "a", inputSchema: { x: nested(100000) } }]);
  assert.equal(r.contract.error, "TSD-DEPTH");
});

test("canonical text, level and document order", () => {
  assert.equal(tsdCanonical({ b: [1, { d: null, c: true }], a: "x" }), '{"a":"x","b":[1,{"c":true,"d":null}]}');
  assert.throws(() => tsdCanonical(nested(513)), (e) => e.code === "TSD-DEPTH");
  assert.equal(tsdCanonical(nested(512)), "[".repeat(512) + "]".repeat(512));
  assert.throws(() => tsdCanonical({ a: Infinity, b: "\ud800" }), (e) => e.code === "TSD-NUMBER");
});
