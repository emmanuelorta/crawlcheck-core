// Release audit additions to the fail-closed verifier: a document whose signed body states no time, and a listed key id
// this release does not ship. Offline only: every key here is generated inside the test and thrown away.
import { test } from "node:test";
import assert from "node:assert/strict";
const S = await import(process.env.CC_SDK || "../dist/index.js");

const { subtle } = globalThis.crypto, enc = new TextEncoder();
const hex = (u) => Array.from(new Uint8Array(u), (b) => b.toString(16).padStart(2, "0")).join("");
const b64u = (u) => Buffer.from(u).toString("base64url");
async function mk() {
  const k = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const x = (await subtle.exportKey("jwk", k.publicKey)).x;
  return { priv: k.privateKey, jwk: { kty: "OKP", crv: "Ed25519", x }, kid: b64u(await subtle.digest("SHA-256", enc.encode(JSON.stringify({ crv: "Ed25519", kty: "OKP", x })))) };
}
// o.signed_at: the (unsigned) signature.signed_at; null leaves it out.
async function sign(body, key, o = {}) {
  const sha = hex(await subtle.digest("SHA-256", enc.encode(S.canon(body)))), msg = "crawlcheck-data-v1\n" + sha;
  const signature = { v: 1, alg: "Ed25519", kid: key.kid, message: msg, key: { jwk: key.jwk }, sig: b64u(await subtle.sign({ name: "Ed25519" }, key.priv, enc.encode(msg))) };
  if (o.signed_at !== null) signature.signed_at = o.signed_at || new Date().toISOString();
  return Object.assign({}, body, { sha256: sha, signature });
}
const docKey = await mk(), decisionKey = await mk(), logKey = await mk(), retiredDoc = await mk(), retiredLog = await mk(), fifth = await mk();
const DIRECTORY = { keys: [
  { kty: "OKP", crv: "Ed25519", x: docKey.jwk.x, crawlcheck_purpose: "documents", crawlcheck_signs_from: "2026-10-11T00:00:00Z" },
  { kty: "OKP", crv: "Ed25519", x: decisionKey.jwk.x, crawlcheck_purpose: "decisions", crawlcheck_signs_from: "2026-11-09T17:00:00Z" },
  { kty: "OKP", crv: "Ed25519", x: logKey.jwk.x, crawlcheck_purpose: "log heads", crawlcheck_signs_from: "2026-11-09T17:00:00Z" }] };
const ROTATION = { retired: [
  { thumbprint: retiredDoc.kid, purpose: "documents", crawlcheck_signs_from: "2026-10-11T00:00:00Z", stopped_signing_at: "2026-11-01T00:00:00Z" },
  { thumbprint: retiredLog.kid, purpose: "log heads", crawlcheck_signs_from: "2026-10-11T00:00:00Z", stopped_signing_at: "2026-11-01T00:00:00Z" }], compromised: [] };
const kp = await S.keyPolicyFrom(DIRECTORY, ROTATION);
const BACK = "2026-10-20T00:00:00Z";   // inside both retired keys' signing windows
const policy = async (doc) => S.applyKeyPolicy(await S.verifyDocument(doc), doc, kp);
const claims = (o = {}) => Object.assign({ kind: "crawlcheck-claims", v: 1, domain: "site.example" }, o);
const answer = (o = {}) => Object.assign({ kind: "crawlcheck-resolve", v: 1, domain: "site.example", status: "measured", actions: { read: { decision: "allow", doubts: [] } } }, o);
const decision = (o = {}) => Object.assign({ kind: "crawlcheck-decision", v: 1, domain: "site.example", action: "read", decision: "allow", expires_at: "2099-01-01T00:00:00Z", resolve: { sha256: "a".repeat(64), kid: docKey.kid } }, o);
const head = (key, batch, o = {}) => { const b = { kind: "crawlcheck-log-sth", v: 1, log_id: "crawlcheck-resolve-log-v1", batch, first_index: batch, batch_size: 1, tree_size: batch + 1, batch_root: "a".repeat(64), prev_sth_sha256: batch ? "c".repeat(64) : null };
  if (o.created_at !== null) b.created_at = o.created_at || new Date().toISOString(); return sign(b, key, o); };
const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } });
const client = (extra = {}) => new S.CrawlCheck({ base: "https://cc.test", fetch: async (url, init) => {
  const p = new URL(String(url)).pathname;
  if (p in extra) return json(typeof extra[p] === "function" ? await extra[p](init) : extra[p]);
  if (p === "/.well-known/http-message-signatures-directory") return json(DIRECTORY);
  if (p === "/.well-known/security-key-rotation.json") return json(ROTATION);
  return json({}, 404);
} });

test("no time in the signed body: a key the policy does not accept now is refused, whatever signature.signed_at says or omits", async () => {
  // signed_at set back into the key's window, and signed_at left out: neither may carry the document
  for (const signed_at of [BACK, null]) {
    for (const [label, doc] of [
      ["a document under a retired key", await sign(claims(), retiredDoc, { signed_at })],
      ["a Resolve answer under a retired key", await sign(answer(), retiredDoc, { signed_at })],
      ["a decision under a retired key", await sign(decision(), retiredDoc, { signed_at })],
      ["a decision under the documents key", await sign(decision(), docKey, { signed_at })],
      ["a document under the log-head key", await sign(claims(), logKey, { signed_at })],
      ["a document under the decisions key", await sign(claims(), decisionKey, { signed_at })]]) {
      const v = await policy(doc), w = await client().verifyDocument(doc), at = " (signed_at " + signed_at + ")";
      assert.equal(v.accepted, false, label + at); assert.equal(v.key_policy_valid, false, label + at);
      assert.equal(w.accepted, false, label + ", through the client" + at);
    }
    // log heads: the library with a key policy, and the client's default path
    for (const [label, key] of [["a retired log-head key", retiredLog], ["a retired documents key", retiredDoc], ["the documents key", docKey], ["the decisions key", decisionKey]]) {
      const h = await head(key, 40, { created_at: null, signed_at }), st = S.newLogStore();
      assert.equal((await S.logObserve(st, h, { keyPolicy: kp })).state, "invalid", "a head with no created_at under " + label); assert.equal(Object.keys(st.heads).length, 0);
      const cc = client(); assert.equal((await cc.logGossip([h])).results[0].state, "invalid"); assert.equal(Object.keys(cc.log.heads).length, 0, "the client keeps nothing"); assert.equal(cc.logIgnored.length, 1);
    }
    // lockfiles
    const lock = await sign({ kind: "crawlcheck-mcp-lock", v: 1, server: { url: "https://mcp.site.example/mcp" }, tools: [{ name: "a", sha256: "b".repeat(64) }], tools_sha256: "c".repeat(64) }, retiredDoc, { signed_at });
    assert.equal((await S.verifyLockBaseline(lock, { keyPolicy: kp })).trust, "invalid");
  }
  // controls: nothing changes for a key the policy accepts now, nor for a retired key whose document states its time in the body
  let v = await policy(await sign(claims(), docKey)); assert.equal(v.accepted, true); assert.equal(v.key_policy_valid, true);
  v = await policy(await sign(claims(), docKey, { signed_at: null })); assert.equal(v.accepted, true, "a live key of the right purpose, no time anywhere: accepted, partial"); assert.equal(v.accepted_strict, false);
  v = await policy(await sign(claims({ generated_at: BACK }), retiredDoc, { signed_at: BACK })); assert.equal(v.accepted, true, "a retired key, body time inside its window"); assert.equal(v.key_policy_code, "ok");
  const st = S.newLogStore(); assert.equal((await S.logObserve(st, await head(logKey, 5), { keyPolicy: kp })).state, "new");
  // and a decision the service really makes (decided_at inside the body) still passes guard
  const cc = client({ "/api/v1/preflight": async (init) => { const q = JSON.parse(init.body); return sign(decision({ domain: q.domain, action: q.action, nonce: q.nonce, decided_at: new Date(Date.now() - 2000).toISOString(), expires_at: new Date(Date.now() + 120000).toISOString(), steps: [] }), decisionKey); } });
  assert.equal((await cc.guard("site.example", "read")).proceed, true);
});

test("key ids only: a listed id this release does not ship is never treated as a key of known purpose", async () => {
  const kids = [...S.CRAWLCHECK_KEY_IDS, fifth.kid];
  const d = await sign(decision({ decided_at: new Date(Date.now() - 2000).toISOString(), resolve: { sha256: "a".repeat(64), kid: S.CRAWLCHECK_KEY_IDS[1] } }), fifth);
  const v = await S.verifyDocument(d, { publishedKids: kids });
  assert.equal(v.accepted, true, "the caller listed the key: accepted"); assert.equal(v.accepted_strict, false, "but never strict"); assert.equal(v.assurance, "partial");
  assert.equal(v.key_policy_valid, null); assert.equal(v.key_policy_code, "purpose_unknown"); assert.ok(v.unavailable.includes("key_purpose"));
  const c = v.checks.find((x) => x.id === "key_purpose"); assert.ok(c && c.ok === null && /keyPolicy/.test(c.why));
  assert.equal((await S.verifyDocument(d, { publishedKids: [...S.CRAWLCHECK_KEY_IDS] })).accepted, false, "not on the list: refused as before");
  // a log head under such a key is not kept on its id alone
  const st = S.newLogStore(), r = await S.logObserve(st, await head(fifth, 3), { publishedKids: kids });
  assert.equal(r.state, "invalid"); assert.match(r.why, /keyPolicy/); assert.equal(Object.keys(st.heads).length, 0);
  // guard with key ids only does not act on a decision under such a key; with a policy that names it a decision key it does
  const preflight = async (init) => { const q = JSON.parse(init.body); return sign(decision({ domain: q.domain, action: q.action, nonce: q.nonce, decided_at: new Date(Date.now() - 2000).toISOString(), expires_at: new Date(Date.now() + 120000).toISOString(), resolve: { sha256: "a".repeat(64), kid: S.CRAWLCHECK_KEY_IDS[1] }, steps: [] }), fifth); };
  const cc = client({ "/api/v1/preflight": preflight });
  const g = await cc.guard("site.example", "read", { onlineKeys: false, publishedKids: kids });
  assert.equal(g.proceed, false); assert.match(g.why.join(" "), /purpose this release does not know/);
  const named = S.pinnedKeyPolicy(); named.keys[fifth.kid] = { purpose: "decisions", start: 0 }; named.kids.push(fifth.kid);
  assert.equal((await cc.guard("site.example", "read", { onlineKeys: false, keyPolicy: named })).proceed, true, "control: the policy says what the key signs");
});

test("canonical form: member names sort by UTF-16 code unit (the same bytes as the Python package)", () => {
  assert.equal(S.canon(JSON.parse('{"\\uffff":1,"\\ud83d\\ude00":2,"a":3}')), '{"a":3,"😀":2,"￿":1}');
});
