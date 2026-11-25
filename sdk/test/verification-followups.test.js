// Follow-ups to the fail-closed verifier: the time the signing policy reads, which log heads a client keeps, the command
// line's exit status, documents and tool lists with unusual member names, and what "pinned" means.
// Offline except the outside-witness test (it reads the live log): every key here is generated inside the test and thrown away. CC_SDK=<path or package> runs another build.
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
const fixture = (n) => JSON.parse(readFileSync(new URL("./fixtures/" + n, here), "utf8"));

const { subtle } = globalThis.crypto, enc = new TextEncoder();
const hex = (u) => Array.from(new Uint8Array(u), (b) => b.toString(16).padStart(2, "0")).join("");
const b64u = (u) => Buffer.from(u).toString("base64url");
const shaHex = async (s) => hex(await subtle.digest("SHA-256", enc.encode(s)));
async function mk() {
  const k = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const x = (await subtle.exportKey("jwk", k.publicKey)).x;
  return { priv: k.privateKey, jwk: { kty: "OKP", crv: "Ed25519", x }, kid: b64u(await subtle.digest("SHA-256", enc.encode(JSON.stringify({ crv: "Ed25519", kty: "OKP", x })))) };
}
// A document in the crawlcheck-data-v1 scheme. o.signed_at: the (unsigned) signature.signed_at, null to leave it out.
async function sign(body, key, o = {}) {
  const sha = await shaHex(S.canon(body)), msg = "crawlcheck-data-v1\n" + sha;
  const signature = { v: 1, alg: "Ed25519", kid: o.kid || key.kid, message: msg, key: { jwk: key.jwk }, sig: b64u(await subtle.sign({ name: "Ed25519" }, key.priv, enc.encode(msg))) };
  if (o.signed_at !== null) signature.signed_at = o.signed_at || "2026-11-20T00:00:00Z";
  return Object.assign({}, body, { sha256: sha, signature });
}
const docKey = await mk(), decisionKey = await mk(), logKey = await mk(), retired = await mk(), evil = await mk();
const DIRECTORY = { keys: [
  { kty: "OKP", crv: "Ed25519", x: docKey.jwk.x, crawlcheck_purpose: "documents", crawlcheck_signs_from: "2026-10-11T00:00:00Z" },
  { kty: "OKP", crv: "Ed25519", x: decisionKey.jwk.x, crawlcheck_purpose: "decisions", crawlcheck_signs_from: "2026-11-09T17:00:00Z" },
  { kty: "OKP", crv: "Ed25519", x: logKey.jwk.x, crawlcheck_purpose: "log heads", crawlcheck_signs_from: "2026-11-09T17:00:00Z" }] };
const ROTATION = { retired: [{ thumbprint: retired.kid, purpose: "documents", crawlcheck_signs_from: "2026-10-11T00:00:00Z", stopped_signing_at: "2026-11-01T00:00:00Z" }], compromised: [] };
const kp = await S.keyPolicyFrom(DIRECTORY, ROTATION);
const answer = (o = {}) => Object.assign({ kind: "crawlcheck-resolve", v: 1, domain: "site.example", status: "measured", actions: { read: { decision: "allow", doubts: [] } } }, o);
const decision = (o = {}) => Object.assign({ kind: "crawlcheck-decision", v: 1, domain: "site.example", action: "read", decision: "allow", expires_at: "2099-01-01T00:00:00Z", resolve: { sha256: "a".repeat(64), kid: docKey.kid } }, o);
const policy = async (doc) => S.applyKeyPolicy(await S.verifyDocument(doc), doc, kp);
const head = (key, batch, root, o = {}) => sign(Object.assign({ kind: "crawlcheck-log-sth", v: 1, log_id: "crawlcheck-resolve-log-v1", batch, first_index: batch, batch_size: 1, tree_size: batch + 1, batch_root: root, prev_sth_sha256: batch ? "c".repeat(64) : null, created_at: "2026-11-20T00:00:00Z" }, o.body || {}), key, o);
const BASE = "https://cc.test";
const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } });
const client = (extra = {}, opts = {}) => new S.CrawlCheck(Object.assign({ base: BASE, fetch: async (url) => {
  const p = new URL(String(url)).pathname;
  if (p in extra) return extra[p] === null ? json({}, 503) : json(extra[p]);
  if (p === "/.well-known/http-message-signatures-directory") return json(DIRECTORY);
  if (p === "/.well-known/security-key-rotation.json") return json(ROTATION);
  return json({}, 404);
} }, opts));

test("signing policy: signature.signed_at cannot move a document to an earlier time than its signed body states", async () => {
  // control: a retired key, inside its window, honestly dated
  let v = await policy(await sign(answer({ answered_at: "2026-10-20T00:00:00Z" }), retired, { signed_at: "2026-10-20T00:00:00Z" }));
  assert.equal(v.accepted, true); assert.equal(v.key_policy_code, "ok");
  // the same key after it stopped signing, with the unsigned field set back into its window
  v = await policy(await sign(answer({ answered_at: "2026-11-20T00:00:00Z" }), retired, { signed_at: "2026-10-20T00:00:00Z" }));
  assert.equal(v.accepted, false, "a retired key must not be accepted for a body dated after it stopped"); assert.equal(v.key_policy_code, "key_retired");
  // a documents key on a decision made after the decisions key took over, with the unsigned field set back before the switch
  v = await policy(await sign(decision({ decided_at: "2026-11-20T00:00:00Z" }), docKey, { signed_at: "2026-11-01T00:00:00Z" }));
  assert.equal(v.accepted, false); assert.equal(v.key_policy_code, "key_wrong_purpose");
  // control: the decisions key on the same decision, and signed_at a moment later than the body time
  v = await policy(await sign(decision({ decided_at: "2026-11-20T00:00:00Z" }), decisionKey, { signed_at: "2026-11-20T00:00:03Z" }));
  assert.equal(v.accepted, true, JSON.stringify(v.checks.filter((c) => c.ok === false)));
  assert.equal(V.signedAtOf({ answered_at: "2026-11-20T00:00:00Z", signature: { signed_at: "2026-10-20T00:00:00Z" } }), Date.parse("2026-11-20T00:00:00Z"));
  assert.equal(V.signedAtOf({ generated_at: "2026-11-20T00:00:00Z", signature: { signed_at: "2026-11-20T00:00:05Z" } }), Date.parse("2026-11-20T00:00:05Z"), "later is allowed (signing follows the content)");
});

test("signing policy: a pass that rests only on the unsigned signing time is not a pass", async () => {
  // a decision with decided_at left out, signed by a documents key, signed_at set before the decisions key existed
  let v = await policy(await sign(decision(), docKey, { signed_at: "2026-11-01T00:00:00Z" }));
  assert.equal(v.key_policy_valid, false); assert.equal(v.key_policy_code, "no_signing_time"); assert.equal(v.accepted, false);
  // another kind with no time in its body, under a retired key: not accepted, whatever signed_at says
  v = await policy(await sign({ kind: "crawlcheck-claims", v: 1, domain: "site.example" }, retired, { signed_at: "2026-10-20T00:00:00Z" }));
  assert.equal(v.key_policy_valid, false); assert.equal(v.key_policy_code, "no_signing_time"); assert.equal(v.accepted, false); assert.equal(v.accepted_strict, false);
  // control: the same document under the live documents key passes now as well, so nothing depends on the unsigned time
  v = await policy(await sign({ kind: "crawlcheck-claims", v: 1, domain: "site.example" }, docKey, { signed_at: "2026-11-20T00:00:00Z" }));
  assert.equal(v.key_policy_valid, true); assert.equal(v.accepted, true);
  // created_at and approved_at are inside the signed bytes: a log head and a lockfile are dated by them
  v = await policy(await head(docKey, 3, "d".repeat(64), { body: { created_at: "2026-11-01T00:00:00Z" }, signed_at: "2026-11-01T00:00:00Z" }));
  assert.equal(v.key_policy_valid, true, "a documents key signed log heads before the log-head key started");
  v = await policy(await head(docKey, 3, "d".repeat(64), { body: { created_at: "2026-11-20T00:00:00Z" }, signed_at: "2026-11-01T00:00:00Z" }));
  assert.equal(v.key_policy_valid, false, "and not after, whatever signed_at says"); assert.equal(v.key_policy_code, "key_wrong_purpose");
});

test("log heads: the client keeps a head only when a published log key signed it; anything else is ignored and reported", async () => {
  const cc = client();
  const forgedA = await head(evil, 7, "a".repeat(64)), forgedB = await head(evil, 7, "b".repeat(64));
  const g = await cc.logGossip([forgedA, forgedB]);
  assert.deepEqual(g.results.map((r) => r.state), ["invalid", "invalid"]);
  assert.equal(g.forks.length, 0); assert.equal(cc.log.forks.length, 0, "two self-signed heads are not a fork"); assert.equal(Object.keys(cc.log.heads).length, 0, "and neither is kept");
  assert.equal(cc.logIgnored.length, 2); assert.equal(cc.logIgnored[0].batch, 7); assert.match(cc.logIgnored[0].why, /does not verify|not signed by a key/);
  // the head inside a Resolve answer goes through the same check
  const withHead = (sth) => answer({ answered_at: "2026-11-20T00:00:00Z", transparency: { state: "included", sth } });
  const c2 = client({ "/api/v1/resolve": await sign(withHead(forgedA), docKey) });
  await c2.resolve("site.example");
  assert.equal(Object.keys(c2.log.heads).length, 0, "resolve() must not keep a head from an unknown key"); assert.equal(c2.logIgnored.length, 1);
  // a head the log key signed is kept; a self-signed head for the same batch afterwards changes nothing
  const good = await head(logKey, 7, "e".repeat(64));
  const c3 = client({ "/api/v1/resolve": await sign(withHead(good), docKey) });
  await c3.resolve("site.example");
  assert.equal(c3.log.heads[7].sha256, good.sha256); assert.equal(c3.log.heads[7].issuer_checked, true);
  await c3.logGossip([forgedA]);
  assert.equal(c3.log.forks.length, 0); assert.equal(c3.log.heads[7].sha256, good.sha256);
  // a head signed by a published key of another purpose is not a log head either
  assert.equal((await c3.logGossip([await head(decisionKey, 9, "f".repeat(64))])).results[0].state, "invalid");
  // two heads the log key really signed for one batch are still a fork, and say they were checked
  const g2 = await c3.logGossip([await head(logKey, 7, "9".repeat(64))]);
  assert.equal(g2.forks.length, 1); assert.equal(g2.forks[0].kind, "two_heads_for_one_batch"); assert.equal(g2.forks[0].issuer_checked, true);
  // when the key directory cannot be read the client falls back to the ids this release ships, never to "any key"
  const c4 = client({ "/.well-known/http-message-signatures-directory": null });
  assert.equal((await c4.logGossip([good])).results[0].state, "invalid"); assert.equal(Object.keys(c4.log.heads).length, 0);
});

test("log heads: unchecked heads have no standing against checked ones, and a saved store is re-checked", async () => {
  const A = await head(evil, 4, "a".repeat(64)), B = await head(evil, 4, "b".repeat(64)), real = await head(logKey, 4, "e".repeat(64));
  // without a key list two self-signed heads still collide, but the record says what it is worth
  const bare = S.newLogStore();
  await S.logObserve(bare, A); const f = await S.logObserve(bare, B);
  assert.equal(f.state, "fork"); assert.equal(f.fork.issuer_checked, false); assert.match(f.fork.proof, /NOT checked/);
  assert.doesNotMatch(f.fork.proof, /carry CrawlCheck's own signature/);
  // a checked head replaces an unchecked one for the same batch; no fork
  const mixed = S.newLogStore(); await S.logObserve(mixed, A);
  assert.equal((await S.logObserve(mixed, real, { keyPolicy: kp })).state, "new"); assert.equal(mixed.forks.length, 0); assert.equal(mixed.heads[4].sha256, real.sha256);
  // and an unchecked head that contradicts a checked one is ignored
  const r = await S.logObserve(mixed, B); assert.equal(r.state, "invalid"); assert.equal(mixed.forks.length, 0);
  // logPrune: forks and heads that no published key signed are dropped; a real fork stays
  const pruned = await S.logPrune(bare, { keyPolicy: kp });
  assert.deepEqual(pruned, { forks_dropped: 1, heads_dropped: 1 }); assert.equal(bare.forks.length, 0);
  const two = S.newLogStore(); await S.logObserve(two, real); await S.logObserve(two, await head(logKey, 4, "9".repeat(64)));
  assert.equal(two.forks.length, 1); await S.logPrune(two, { keyPolicy: kp }); assert.equal(two.forks.length, 1); assert.equal(two.forks[0].issuer_checked, true);
  await assert.rejects(() => S.logPrune(S.newLogStore(), {}), /publishedKids or keyPolicy/);
  // guard(): a store saved with a planted fork no longer refuses every genuine answer
  const planted = S.newLogStore(); await S.logObserve(planted, A); await S.logObserve(planted, B); assert.equal(planted.forks.length, 1);
  const c = guardSuite.cases.find((x) => x.id === "allow"), q = c.request;
  const cc = new S.CrawlCheck({ base: BASE, logStore: planted, fetch: async (url) => { const p = new URL(String(url)).pathname;
    if (p === "/.well-known/http-message-signatures-directory") return json(guardSuite.directory);
    if (p === "/.well-known/security-key-rotation.json") return json(guardSuite.rotation);
    if (p === "/api/v1/preflight") return json(c.crawlcheck.body);
    return json({}, 404); } });
  const g = await cc.guard(q.domain, q.action, { nonce: q.nonce, now: Date.parse(q.now) });
  assert.equal(g.proceed, true, JSON.stringify(g.why)); assert.equal(planted.forks.length, 0);
});

test("command line: the exit status is 0 only when the document is ACCEPTED", async () => {
  const dir = mkdtempSync(join(tmpdir(), "cc-followups-"));
  const run = (name, doc, ...args) => { const f = join(dir, name); writeFileSync(f, JSON.stringify(doc)); return spawnSync(process.execPath, [VERIFY_CLI, ...args, f], { encoding: "utf8" }); };
  // an evidence bundle that names a key this release ships and carries no key: nothing checks the signature
  const body = JSON.stringify({ v: 2, experiences: [] });
  const bundle = { kind: "crawlcheck-evidence-bundle", report: { id: "r1", domain: "site.example" }, manifest: { body, sha256: await shaHex(body), signature: { kid: S.CRAWLCHECK_KEY_IDS[1], sig: "AAAA" } }, record: {}, seal: {} };
  let r = run("bundle.json", bundle);
  assert.match(r.stdout, /NOT ACCEPTED/); assert.notEqual(r.status, 0, "NOT ACCEPTED must not exit 0");
  // a genuine document read offline is intact but its issuer was not checked: NOT ACCEPTED, exit 3
  r = run("lock.json", fixture("lock-signed.json"));
  assert.match(r.stdout, /NOT ACCEPTED/); assert.equal(r.status, 3);
  // a document under an unknown key: exit 1
  r = run("foreign.json", await sign(answer({ answered_at: "2026-11-20T00:00:00Z" }), evil));
  assert.equal(r.status, 1);
});

test("canonical form: every own member is hashed, whatever its name", async () => {
  const signed = await sign(answer({ answered_at: "2026-11-20T00:00:00Z" }), docKey);
  const kids = { publishedKids: kp.kids };
  assert.equal((await V.verifyDataDoc(signed, kids)).accepted, true);
  const text = JSON.stringify(signed);
  const inject = (member) => JSON.parse("{" + member + "," + text.slice(1));
  for (const [member, label] of [['"__proto__":{"admin":true}', "__proto__"], ['"constructor":{"prototype":{"x":1}}', "constructor"], ['"toString":"x"', "toString"], ['"hasOwnProperty":1', "hasOwnProperty"]]) {
    const v = await V.verifyDataDoc(inject(member), kids);
    assert.equal((v.checks.find((c) => c.id === "document_hash") || {}).ok, false, label + " added after signing must change the hash"); assert.equal(v.accepted, false, label);
  }
  // duplicate members: the parser keeps the last one, and that is the one that is hashed
  assert.equal((await V.verifyDataDoc(JSON.parse(text.slice(0, -1) + ',"domain":"other.example"}'), kids)).accepted, false, "a duplicate that changes the value read");
  assert.equal((await V.verifyDataDoc(JSON.parse('{"domain":"other.example",' + text.slice(1)), kids)).accepted, true, "a shadowed duplicate reads as the signed value");
  // a document signed WITH such members verifies, and changing them is detected (top level and nested)
  const odd = JSON.parse('{"kind":"crawlcheck-claims","v":1,"domain":"site.example","generated_at":"2026-11-20T00:00:00Z","__proto__":{"a":1},"constructor":"c","nested":{"__proto__":{"b":2},"constructor":{"d":3}}}');
  const sha = await shaHex(S.canon(odd)), msg = "crawlcheck-data-v1\n" + sha;
  const sigText = JSON.stringify({ v: 1, alg: "Ed25519", kid: docKey.kid, message: msg, key: { jwk: docKey.jwk }, sig: b64u(await subtle.sign({ name: "Ed25519" }, docKey.priv, enc.encode(msg))), signed_at: "2026-11-20T00:00:00Z" });
  const oddText = '{"kind":"crawlcheck-claims","v":1,"domain":"site.example","generated_at":"2026-11-20T00:00:00Z","__proto__":{"a":1},"constructor":"c","nested":{"__proto__":{"b":2},"constructor":{"d":3}},"sha256":"' + sha + '","signature":' + sigText + "}";
  assert.equal((await V.verifyDataDoc(JSON.parse(oddText), kids)).accepted, true, "members with special names are ordinary members");
  assert.equal((await V.verifyDataDoc(JSON.parse(oddText.replace('"__proto__":{"a":1}', '"__proto__":{"a":2}')), kids)).accepted, false, "top-level __proto__ value changed");
  assert.equal((await V.verifyDataDoc(JSON.parse(oddText.replace('"__proto__":{"b":2}', '"__proto__":{"b":3}')), kids)).accepted, false, "nested __proto__ value changed");
  // the other signed kinds build their body the same way
  const rb = { kind: "crawlcheck-remediation-receipt", subject: { domain: "site.example" }, before: { scanned_at: "2026-11-01T00:00:00Z" }, after: { scanned_at: "2026-11-02T00:00:00Z" }, verification: { verdict: "fixed" }, issuer: { key: { jwk: docKey.jwk } } };
  const rsha = await shaHex(S.canon(rb)), rmsg = "crawlcheck-receipt-v1\n" + rsha;
  const rc = Object.assign({}, rb, { receipt_id: "rc1:" + rsha, signature: { kid: docKey.kid, receipt_sha256: rsha, message: rmsg, sig: b64u(await subtle.sign({ name: "Ed25519" }, docKey.priv, enc.encode(rmsg))) } });
  const hashOk = (v) => (v.checks.find((c) => c.id === "receipt_hash") || {}).ok;
  assert.equal(hashOk(await V.verifyReceipt(rc, kids)), true);
  assert.equal(hashOk(await V.verifyReceipt(JSON.parse('{"__proto__":{"admin":true},' + JSON.stringify(rc).slice(1)), kids)), false);
});

test("tool lists: a tool or a member named like an Object.prototype member is compared like any other", async () => {
  const tool = (name, extra = "") => JSON.parse('{"name":' + JSON.stringify(name) + ',"description":"d","inputSchema":{"type":"object"}' + extra + "}");
  const base = [tool("search")], now = Date.parse("2026-11-20T00:00:00Z");
  const lock = Object.assign(await S.lockFromTools("https://mcp.example.com/mcp", base), { approved_at: "2026-11-19T00:00:00Z" });
  for (const digest of [undefined, "lk-v1"]) for (const name of ["constructor", "toString", "__proto__", "hasOwnProperty"]) {
    const r = await S.continuityCheck(lock, base.concat([tool(name)]), { now, digest });
    assert.ok(r.events.some((e) => e.class === "tool_added" && e.tool === name), "a tool named " + name + " was added and must be reported (" + (digest || "default") + "): " + JSON.stringify(r.events.map((e) => e.class + ":" + e.tool)));
  }
  // a member named __proto__ inside a tool definition is part of what is digested
  const a = await S.jcsV1([tool("search")]), b = await S.jcsV1([tool("search", ',"__proto__":{"hidden":true}')]), c = await S.jcsV1([tool("search", ',"annotations":{"__proto__":{"hidden":true}}')]), d = await S.jcsV1([tool("search", ',"annotations":{}')]);
  assert.notEqual(b.extras_sha256, a.extras_sha256, "a top-level __proto__ member must move the extras digest");
  assert.notEqual(c.extras_sha256, d.extras_sha256, "a nested __proto__ member must move the extras digest");
  const parts = await S.lockParts([tool("__proto__"), tool("search")]);
  assert.deepEqual(Object.keys(parts).sort(), ["__proto__", "search"]);
});

test("pinned keys: issuer_pinned needs a verifying signature, and key ids alone still carry the purposes this release knows", async () => {
  // a document that only NAMES a shipped key id
  const named = await sign(answer({ answered_at: "2026-11-20T00:00:00Z" }), evil); named.signature.kid = S.CRAWLCHECK_KEY_IDS[1];
  assert.equal((await S.verifyDocument(named)).issuer_pinned, false, "a claimed key id is not a pinned issuer");
  assert.equal((await V.verifyDataDoc(named)).issuer_pinned, false);
  // a genuine document under a shipped key
  const lock = fixture("lock-signed.json");
  let v = await S.verifyDocument(lock); assert.equal(v.issuer_pinned, true); assert.equal(v.accepted, false, "offline is never accepted");
  v = await S.verifyDocument(lock, { publishedKids: S.CRAWLCHECK_KEY_IDS }); assert.equal(v.accepted, true); assert.equal(v.checks.some((c) => c.id === "key_purpose"), false, "nothing is added when the purpose fits");
  // the policy for the shipped ids is the one the directory gave
  const dir = await S.keyPolicyFrom(fixture("key-directory-20261107.json"), null), pin = S.pinnedKeyPolicy();
  assert.deepEqual(pin.keys, dir.keys); assert.deepEqual(pin.kids.slice().sort(), [...S.CRAWLCHECK_KEY_IDS].sort());
  assert.deepEqual(S.pinnedKeyPolicy([S.CRAWLCHECK_KEY_IDS[0], "unknown"]).kids, [S.CRAWLCHECK_KEY_IDS[0]]);
  // key ids only: a decision under the shipped log-head key id fails key_purpose (the signature is not what is tested here)
  const logKid = pin.kids.find((k) => pin.keys[k].purpose === "log heads");
  const wrong = await sign(decision({ decided_at: "2026-11-20T00:00:00Z" }), evil); wrong.signature.kid = logKid;
  for (const r of [await S.verifyDocument(wrong, { publishedKids: S.CRAWLCHECK_KEY_IDS }), await V.verifyDataDoc(wrong, { publishedKids: [...S.CRAWLCHECK_KEY_IDS] })]) {
    const kpur = r.checks.find((c) => c.id === "key_purpose");
    assert.ok(kpur && kpur.ok === false, "key ids only must still apply the purposes of the ids this release knows"); assert.equal(r.key_policy_code, "key_wrong_purpose"); assert.equal(r.accepted, false);
  }
});

test("outside witness: the token must come from the witness workflow of the witness repository", async () => {
  // The witness states its identity in the token the live log serves; the fixture's token names an example repository.
  const live = await (await fetch("https://crawlcheck.io/api/v1/log/witness/latest", { headers: { "user-agent": "crawlcheck-selftest sdk-js-tests" } })).json();
  const claims = JSON.parse(Buffer.from(live.token.split(".")[1], "base64url")), F = fixture("split-view.json");
  assert.equal((await S.verifyWitnessToken(F.witness.token, F.A[2].sha256, F.jwks)).ok, false, "an example repository is not the witness");
  const rsa = await subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const pub = await subtle.exportKey("jwk", rsa.publicKey), jwks = { keys: [{ kty: "RSA", kid: "t1", n: pub.n, e: pub.e }] };
  const token = async (c) => { const h = b64u(enc.encode(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "t1" }))), p = b64u(enc.encode(JSON.stringify(c))); return h + "." + p + "." + b64u(await subtle.sign("RSASSA-PKCS1-v1_5", rsa.privateKey, enc.encode(h + "." + p))); };
  const sth = String(claims.aud).replace("crawlcheck-sth:", ""), ok = async (c) => (await S.verifyWitnessToken(await token(c), sth, jwks)).ok;
  assert.equal(await ok(claims), true, "the live token's identity is the witness");
  const ref = String(claims.job_workflow_ref), at = ref.indexOf("@refs/heads/");
  assert.equal(await ok(Object.assign({}, claims, { repository: "someone/else", job_workflow_ref: "someone/else" + ref.slice(String(claims.repository).length) })), false, "another repository");
  assert.equal(await ok(Object.assign({}, claims, { repository: claims.repository + "-fork" })), false, "a repository whose name starts the same");
  assert.equal(await ok(Object.assign({}, claims, { job_workflow_ref: ref.slice(0, at).replace(/[^/]+$/, "other.yml") + ref.slice(at) })), false, "another workflow of the same repository");
  assert.equal(await ok(Object.assign({}, claims, { job_workflow_ref: ref.slice(0, at) + "@refs/tags/v1" })), false, "not a branch run");
  assert.equal(await ok(Object.assign({}, claims, { job_workflow_ref: ref.slice(0, at) + ".disabled" + ref.slice(at) })), false, "a longer workflow path");
  // the package does not state the witness's repository in clear
  for (const f of ["log.js", "log.d.ts", "index.js", "index.d.ts"]) assert.equal(readFileSync(new URL("../dist/" + f, here), "utf8").includes(String(claims.repository)), false, f + " names the witness repository");
});
