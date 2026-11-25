// Forged signed documents must be refused: every acceptance field fails closed when the signature was not actually
// checked against a key CrawlCheck publishes. Offline only: every key here is generated inside the test and thrown away.
// CC_SDK=<path or package name> runs it against another build.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdtempSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
const here = new URL(".", import.meta.url);
const S = await import(process.env.CC_SDK || "../dist/index.js");
const V = await import(process.env.CC_SDK_VERIFY || "../dist/verify.js");
const VERIFY_CLI = fileURLToPath(new URL("../dist/verify.js", here));
const guardSuite = JSON.parse(readFileSync([new URL("../../spec/guard-acceptance/cases.json", here), new URL("./fixtures/guard-acceptance.json", here)].find((u) => existsSync(u)), "utf8"));

const { subtle } = globalThis.crypto, enc = new TextEncoder();
const hex = (u) => Array.from(new Uint8Array(u), (b) => b.toString(16).padStart(2, "0")).join("");
const b64u = (u) => Buffer.from(u).toString("base64url");
const clone = (o) => JSON.parse(JSON.stringify(o));
const shaHex = async (s) => hex(await subtle.digest("SHA-256", enc.encode(s)));
async function mk() {
  const k = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const x = (await subtle.exportKey("jwk", k.publicKey)).x;
  return { priv: k.privateKey, jwk: { kty: "OKP", crv: "Ed25519", x }, kid: b64u(await subtle.digest("SHA-256", enc.encode(JSON.stringify({ crv: "Ed25519", kty: "OKP", x })))) };
}
// A document in the crawlcheck-data-v1 scheme. o.kid: the key id it claims; o.key: false leaves the public key out;
// o.sig: a string to put in place of the signature, false to leave it out.
async function sign(body, key, o = {}) {
  const sha = await shaHex(S.canon(body)), msg = "crawlcheck-data-v1\n" + sha;
  const signature = { v: 1, alg: "Ed25519", kid: o.kid || key.kid, message: msg, signed_at: o.signed_at || "2026-11-20T00:00:00Z" };
  if (o.key !== false) signature.key = { jwk: o.key || key.jwk };
  if (o.sig !== false) signature.sig = typeof o.sig === "string" ? o.sig : b64u(await subtle.sign({ name: "Ed25519" }, key.priv, enc.encode(msg)));
  return Object.assign({}, body, { sha256: sha, signature });
}
const real = await mk(), evil = await mk(), decisionKey = await mk(), logKey = await mk(), retired = await mk(), burnt = await mk();
const DIRECTORY = { keys: [
  { kty: "OKP", crv: "Ed25519", x: real.jwk.x, crawlcheck_purpose: "documents", crawlcheck_signs_from: "2026-10-11T00:00:00Z" },
  { kty: "OKP", crv: "Ed25519", x: decisionKey.jwk.x, crawlcheck_purpose: "decisions", crawlcheck_signs_from: "2026-11-09T17:00:00Z" },
  { kty: "OKP", crv: "Ed25519", x: logKey.jwk.x, crawlcheck_purpose: "log heads", crawlcheck_signs_from: "2026-11-09T17:00:00Z" },
  { kty: "OKP", crv: "Ed25519", x: burnt.jwk.x, crawlcheck_purpose: "documents", crawlcheck_signs_from: "2026-10-11T00:00:00Z" }] };
const ROTATION = { retired: [{ thumbprint: retired.kid, purpose: "documents", crawlcheck_signs_from: "2026-10-11T00:00:00Z", stopped_signing_at: "2026-11-01T00:00:00Z" }],
  compromised: [{ thumbprint: burnt.kid, compromised_since: "2026-11-15T00:00:00Z" }] };
const KIDS = [real.kid, decisionKey.kid, logKey.kid];
const kp = await S.keyPolicyFrom(DIRECTORY, ROTATION);
const answer = (domain = "victim.example") => ({ kind: "crawlcheck-resolve", v: 1, domain, status: "measured", actions: { read: { decision: "allow", doubts: [] }, transact: { decision: "allow", doubts: [] } },
  freshness: { observed_at: "2026-11-20T00:00:00Z", fresh_until: "2099-01-01T00:00:00Z" } });
const BASE = "https://cc.test";
const client = (extra = {}) => new S.CrawlCheck({ base: BASE, fetch: async (url) => {
  const p = new URL(String(url)).pathname;
  if (p === "/.well-known/http-message-signatures-directory") return new Response(JSON.stringify(DIRECTORY), { headers: { "content-type": "application/json" } });
  if (p === "/.well-known/security-key-rotation.json") return new Response(JSON.stringify(ROTATION), { headers: { "content-type": "application/json" } });
  if (extra[p]) return new Response(JSON.stringify(extra[p]), { headers: { "content-type": "application/json" } });
  return new Response("{}", { status: 404 });
} });
// Every way this SDK can be asked "is this document CrawlCheck's?".
async function everyPath(doc) {
  return {
    offline: await S.verifyDocument(doc),
    kids: await V.verifyDataDoc(doc, { publishedKids: KIDS }),
    policy: S.applyKeyPolicy(await S.verifyDocument(doc), doc, kp),
    client: await client().verifyDocument(doc)
  };
}
const refused = (r, label) => {
  for (const [path, v] of Object.entries(r)) {
    assert.notEqual(v.accepted, true, label + " / " + path + ": accepted");
    assert.notEqual(v.accepted_strict, true, label + " / " + path + ": accepted_strict");
    if (path !== "offline") assert.equal(v.verified, false, label + " / " + path + ": verified");
  }
};

test("control: a genuine answer is accepted with the published keys, and never offline", async () => {
  const r = await everyPath(await sign(answer(), real));
  assert.equal(r.offline.verified, true); assert.equal(r.offline.accepted, false); assert.equal(r.offline.issuer_trusted, null);
  for (const p of ["kids", "policy", "client"]) { assert.equal(r[p].verified, true, p); assert.equal(r[p].accepted, true, p); assert.equal(r[p].integrity_valid, true, p); assert.equal(r[p].issuer_trusted, true, p); }
  assert.equal(r.client.key_policy_valid, true);
});

test("forged: signed by a foreign key, transparency proof removed - refused offline and online", async () => {
  const doc = await sign(answer(), evil);   // self-consistent: the foreign key, its own key id, no transparency field
  assert.equal("transparency" in doc, false);
  const r = await everyPath(doc); refused(r, "foreign key");
  assert.equal(r.offline.accepted, false, "offline is never accepted");
  assert.equal(r.offline.issuer_pinned, false, "offline, the key is not one this release knows as CrawlCheck's");
  assert.equal(r.kids.issuer_trusted, false); assert.equal(r.client.issuer_trusted, false);
  // the command line refuses it too, offline, with a failing exit status
  const f = join(mkdtempSync(join(tmpdir(), "cc-forged-")), "answer.json"); writeFileSync(f, JSON.stringify(doc));
  const run = spawnSync(process.execPath, [VERIFY_CLI, f], { encoding: "utf8" });
  assert.equal(run.status, 1, run.stdout + run.stderr);
  assert.match(run.stdout, /NOT ACCEPTED/);
});

test("forged: the document names a published key id but carries no key (signature never checked)", async () => {
  const doc = await sign(answer(), evil, { kid: real.kid, key: false });
  const r = await everyPath(doc); refused(r, "no key");
  for (const p of ["kids", "policy", "client"]) assert.equal(r[p].integrity_valid, false, p + ": integrity_valid");
  assert.equal(r.offline.verified, false, "nothing was verified");
});

test("forged: a published key id, no key and no signature at all", async () => {
  const doc = await sign(answer(), evil, { kid: real.kid, key: false, sig: false });
  const r = await everyPath(doc); refused(r, "no key, no sig");
  assert.equal(r.offline.verified, false); assert.equal(r.client.integrity_valid, false);
});

test("forged: the real public key is attached, the signature is missing, empty or not base64", async () => {
  for (const sig of [false, "", "!!!not-base64!!!", "AAAA"]) {
    const doc = await sign(answer(), evil, { kid: real.kid, key: real.jwk, sig });
    const r = await everyPath(doc); refused(r, "sig " + JSON.stringify(sig));
    for (const p of ["offline", "kids", "policy", "client"]) { assert.equal(r[p].verified, false, p + " verified, sig " + JSON.stringify(sig)); assert.equal(r[p].integrity_valid, false, p + " integrity_valid, sig " + JSON.stringify(sig)); }
  }
});

test("forged: wrong key (a foreign key under a published key id)", async () => {
  const r = await everyPath(await sign(answer(), evil, { kid: real.kid })); refused(r, "wrong key");
  assert.equal(r.offline.checks.find((c) => c.id === "key_id").ok, false);
});

test("forged: an unknown key id is refused wherever published keys are known", async () => {
  const r = await everyPath(await sign(answer(), evil)); refused(r, "unknown kid");
  assert.equal(r.client.checks.find((c) => c.id === "key_published").ok, false);
});

test("forged: a tampered payload under a genuine signature", async () => {
  const doc = await sign(answer(), real); doc.actions.transact.decision = "block"; doc.actions.read.doubts = ["x"];
  const r = await everyPath(doc); refused(r, "tampered");
  assert.equal(r.offline.verified, false); assert.equal(r.offline.checks.find((c) => c.id === "document_hash").ok, false);
});

test("forged: a genuine signature replayed on an answer for another domain", async () => {
  const a = await sign(answer("good.example"), real), b = Object.assign(answer("victim.example"), { sha256: a.sha256, signature: a.signature });
  refused(await everyPath(b), "replay, stated digest kept");
  const c = Object.assign(answer("victim.example"), { signature: a.signature }); c.sha256 = await shaHex(S.canon(answer("victim.example")));
  const r = await everyPath(c); refused(r, "replay, digest recomputed");
  assert.equal(r.offline.verified, false);
});

test("forged: wrong key purpose (a log-head key signing a decision, a decision key signing an answer)", async () => {
  const decision = { kind: "crawlcheck-decision", v: 1, domain: "victim.example", action: "read", decision: "allow", decided_at: "2026-11-20T00:00:00Z", resolve: { sha256: "b".repeat(64), kid: real.kid } };
  for (const [doc, label] of [[await sign(decision, logKey), "log-head key on a decision"], [await sign(decision, real), "document key on a decision"], [await sign(answer(), decisionKey), "decision key on an answer"]]) {
    for (const v of [S.applyKeyPolicy(await S.verifyDocument(doc), doc, kp), await client().verifyDocument(doc)]) {
      assert.equal(v.accepted, false, label); assert.equal(v.key_policy_valid, false, label); assert.equal(v.key_policy_code, "key_wrong_purpose", label);
    }
  }
  const ok = await sign(decision, decisionKey);
  assert.equal((await client().verifyDocument(ok)).accepted, true, "control: the decision key signs a decision");
});

test("forged: a retired key signing after it stopped, and a key listed as compromised", async () => {
  const late = await sign(answer(), retired, { signed_at: "2026-11-20T00:00:00Z" }), early = await sign(Object.assign(answer(), { answered_at: "2026-10-20T00:00:00Z" }), retired, { signed_at: "2026-10-20T00:00:00Z" });   // the time is inside the signed body: signed_at alone places nothing
  const vl = await client().verifyDocument(late);
  assert.equal(vl.accepted, false); assert.equal(vl.key_policy_code, "key_retired");
  assert.equal((await client().verifyDocument(early)).accepted, true, "control: signed inside the retired key's window");
  for (const at of ["2026-11-20T00:00:00Z", "2026-11-01T00:00:00Z"]) {
    const v = await client().verifyDocument(await sign(answer(), burnt, { signed_at: at }));
    assert.equal(v.accepted, false, at); assert.equal(v.key_policy_code, "key_compromised", at);
  }
});

test("a missing transparency proof lowers the assurance; it never counts as a check that passed", async () => {
  const v = await client().verifyDocument(await sign(answer(), real));
  assert.equal(v.accepted, true);
  assert.equal(v.accepted_strict, false, "no proof of the answer's place in the log");
  assert.equal(v.assurance, "partial"); assert.ok(v.unavailable.includes("log_inclusion"), JSON.stringify(v.unavailable));
  const c = v.checks.find((x) => x.id === "log_inclusion"); assert.ok(c && c.ok === null, "log_inclusion is reported as not run");
  for (const t of [null, false, 0, "", {}]) {   // a transparency field that says nothing is the same as none
    const w = await V.verifyDataDoc(await sign(Object.assign(answer(), { transparency: t }), real), { publishedKids: KIDS });
    assert.notEqual(w.accepted_strict, true, "transparency " + JSON.stringify(t));
  }
});

test("forged: a transparency proof whose log head names a published key but was never signed", async () => {
  const body = answer(); const leaf = hex(await subtle.digest("SHA-256", Buffer.concat([Buffer.from([0]), Buffer.from(S.canon({ log: "crawlcheck-resolve-log-v1", domain: body.domain, status: body.status,
    actions: { read: { decision: "allow", doubts: [] }, transact: { decision: "allow", doubts: [] } }, report: null, observed_at: body.freshness.observed_at, incident: null, impersonation: null, high_risk_pending: [] }))])));
  const head = (key, o) => sign({ kind: "crawlcheck-log-sth", v: 1, log_id: "crawlcheck-resolve-log-v1", batch: 0, first_index: 0, batch_size: 1, tree_size: 1, batch_root: leaf, prev_sth_sha256: null, created_at: "2026-11-20T00:00:00Z" }, key, o);
  const withHead = async (sth) => sign(Object.assign(answer(), { transparency: { log: "crawlcheck-resolve-log-v1", state: "included", leaf_hash: leaf, index: 0, batch: 0, batch_size: 1, path: [], sth } }), real);
  const good = await client().verifyDocument(await withHead(await head(logKey)));
  assert.equal(good.accepted, true, JSON.stringify(good.checks)); assert.equal(good.accepted_strict, true, "control: a complete proof under the log key");
  for (const [sth, label] of [[await head(evil, { kid: logKey.kid, key: false }), "head without a key"], [await head(evil, { kid: logKey.kid, key: false, sig: false }), "head without key or signature"], [await head(evil), "head under a foreign key"]]) {
    const v = await client().verifyDocument(await withHead(sth));
    assert.equal(v.accepted, false, label); assert.equal(v.verified, false, label);
  }
});

test("forged: an unsigned log head naming a published key is not a head (and cannot plant a fork)", async () => {
  const mkHead = (root) => sign({ kind: "crawlcheck-log-sth", v: 1, log_id: "crawlcheck-resolve-log-v1", batch: 0, first_index: 0, batch_size: 1, tree_size: 1, batch_root: root, prev_sth_sha256: null, created_at: "2026-11-20T00:00:00Z" }, evil, { kid: logKey.kid, key: false });
  const store = S.newLogStore();
  assert.equal((await S.logObserve(store, await mkHead("a".repeat(64)), { publishedKids: KIDS })).state, "invalid");
  assert.equal((await S.logObserve(store, await mkHead("b".repeat(64)), { publishedKids: KIDS })).state, "invalid");
  assert.equal(store.forks.length, 0);
  const bare = S.newLogStore();
  assert.equal((await S.logObserve(bare, await mkHead("a".repeat(64)))).state, "invalid", "without a key list either");
});

test("forged: guard() refuses a receipt that names a published key but was never signed", async () => {
  const c = guardSuite.cases.find((x) => x.id === "block"), q = c.request;
  const forge = async (o) => { const body = clone(c.crawlcheck.body); const sg = body.signature; delete body.sha256; delete body.signature; body.decision = "allow"; body.base_decision = "allow";
    const sha = await shaHex(S.canon(body)); const signature = Object.assign({}, sg, { message: "crawlcheck-data-v1\n" + sha }); if (o.key === false) delete signature.key; if (o.sig === false) delete signature.sig; else if (typeof o.sig === "string") signature.sig = o.sig;
    return Object.assign(body, { sha256: sha, signature }); };
  for (const [o, label] of [[{ key: false }, "key removed"], [{ key: false, sig: false }, "key and signature removed"], [{ sig: "!!!" }, "signature not base64"], [{ sig: false }, "signature removed"]]) {
    const receipt = await forge(o);
    const cc = new S.CrawlCheck({ base: BASE, fetch: async (url) => { const p = new URL(String(url)).pathname;
      if (p === "/.well-known/http-message-signatures-directory") return new Response(JSON.stringify(guardSuite.directory), { headers: { "content-type": "application/json" } });
      if (p === "/.well-known/security-key-rotation.json") return new Response(JSON.stringify(guardSuite.rotation), { headers: { "content-type": "application/json" } });
      if (p === "/api/v1/preflight") return new Response(JSON.stringify(receipt), { headers: { "content-type": "application/json" } });
      return new Response("{}", { status: 404 }); } });
    const g = await cc.guard(q.domain, q.action, { nonce: q.nonce, now: Date.parse(q.now), allowWarn: true });
    assert.equal(g.proceed, false, label + ": " + JSON.stringify(g.why)); assert.equal(g.header, null, label);
    assert.notEqual(g.acceptance && g.acceptance.accepted, true, label);
  }
});

test("forged: an evidence bundle and a remediation receipt that name a published key but carry none", async () => {
  const body = JSON.stringify({ v: 2, experiences: [] });
  const bundle = { kind: "crawlcheck-evidence-bundle", report: { id: "r1", domain: "victim.example" }, manifest: { body, sha256: await shaHex(body), signature: { kid: real.kid, sig: "AAAA" } }, record: {}, seal: {} };
  const vb = await V.verifyBundle(bundle, { publishedKids: KIDS });
  assert.equal(vb.accepted, false, JSON.stringify(vb.checks)); assert.equal(vb.accepted_strict, false);
  const rb = { kind: "crawlcheck-remediation-receipt", subject: { domain: "victim.example" }, before: { scanned_at: "2026-11-01T00:00:00Z" }, after: { scanned_at: "2026-11-02T00:00:00Z" }, verification: { verdict: "fixed" } };
  const sha = await shaHex(S.canon(rb));
  const rc = Object.assign({}, rb, { receipt_id: "rc1:" + sha, signature: { kid: real.kid, receipt_sha256: sha, message: "crawlcheck-receipt-v1\n" + sha } });
  const vr = await V.verifyReceipt(rc, { publishedKids: KIDS });
  assert.equal(vr.accepted, false, JSON.stringify(vr.checks)); assert.equal(vr.verified, false);
});

test("the key ids this release pins are the published ones", async () => {
  const d = JSON.parse(readFileSync(new URL("./fixtures/key-directory-20261107.json", here), "utf8"));
  const kids = (await S.keyPolicyFrom(d, null)).kids;
  assert.deepEqual([...S.CRAWLCHECK_KEY_IDS].sort(), kids.slice().sort());
  for (const k of S.CRAWLCHECK_LOCK_KIDS) assert.ok(S.CRAWLCHECK_KEY_IDS.includes(k));
  const pinnedDoc = await sign(answer(), evil); pinnedDoc.signature.kid = S.CRAWLCHECK_KEY_IDS[0];   // a pinned id, a foreign key
  const v = await S.verifyDocument(pinnedDoc); assert.equal(v.verified, false); assert.equal(v.accepted, false);
});
