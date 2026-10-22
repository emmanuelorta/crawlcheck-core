// The signing-policy suite (https://crawlcheck.io/keys#policy) against this SDK. Same cases as the Python package and
// crawlcheck-verify.mjs (spec/key-policy/run.mjs runs all three). CC_SDK=<path or package name> runs another build.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
const here = new URL(".", import.meta.url);
const suite = JSON.parse(readFileSync([new URL("../../spec/key-policy/cases.json", here), new URL("./fixtures/key-policy.json", here)].find((u) => existsSync(u)), "utf8"));
const S = await import(process.env.CC_SDK || "../dist/index.js");

test("KEY_POLICY is the published policy", () => {
  for (const k of ["object_purpose", "chains", "starts", "bound", "purpose_aliases"]) assert.deepEqual(S.KEY_POLICY[k], suite.policy[k], k);
});
for (const c of suite.cases) {
  test(c.id + ": " + c.title, async () => {
    const kp = await S.keyPolicyFrom(suite.directory, c.keys === "directory" ? null : suite.rotation);
    const r = S.applyKeyPolicy(await S.verifyDocument(c.doc), c.doc, kp);
    const why = (r.checks.find((x) => x.id === "key_purpose") || {}).why;
    for (const [k, v] of Object.entries(c.expect)) assert.equal(r[k], v, k + ": " + why);
  });
}
