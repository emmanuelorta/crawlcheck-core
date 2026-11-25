// Split-view detection for the CrawlCheck Resolve transparency log.
// A log that shows one client a different history than another (a "split view") has to sign two different heads for
// the same batch, or a head that does not chain to the one before. Both are caught here, three ways:
//   1. every head a client sees (in Resolve answers, from the log, from peers) is kept in a store and checked against
//      its neighbours: same batch with two digests, a broken prev link, or broken size arithmetic is a fork;
//   2. gossip: clients swap the signed heads they hold (logHeads / logGossip), so a head shown only to one of them
//      collides with the other's store;
//   3. the outside witness: a GitHub Actions run re-checks the chain and co-signs the newest head with a GitHub-signed
//      OIDC token whose audience is that head's digest. GitHub's key, not CrawlCheck's. A client that walks the chain
//      from the witnessed head back to its own heads detects any head the witness never saw.
// A fork comes with both signed heads: two documents carrying CrawlCheck's own signature that cannot both be true.
// That holds only for heads checked against CrawlCheck's keys: pass publishedKids or keyPolicy to every call (the
// CrawlCheck client does). A head that is not signed by a published key is ignored: never kept, never part of a fork.
// Zero dependencies; WebCrypto only.
import { verifyDataDoc, applyKeyPolicy } from "./verify.js";

export const LOG_ID = "crawlcheck-resolve-log-v1";
export const GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com";
// The witness is recognised by the SHA-256 of two claims GitHub signs into its token: the repository, and the workflow
// file (job_workflow_ref up to "@refs/heads/"). The token states both in clear; a verifier only has to recognise them.
const WITNESS_REPOSITORY_SHA256 = "588fecf96f4ed7df3792e369a5cfd3310eda480924112a9f0b5d9ddb4fe5be75";
const WITNESS_WORKFLOW_SHA256 = "60870f2d47396bd2e01b7587b03a35a0a0c1fe8e634500fba61a1ddd9d833378";
const sha256Hex = async (s) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(s)))), (b) => b.toString(16).padStart(2, "0")).join("");
const MAX_HEADS = 2000;

/** A new, empty store. It is plain JSON: keep it across runs (a file, any key-value store) so later heads are checked against earlier ones. */
export function newLogStore() { return { v: 1, log_id: LOG_ID, heads: {}, forks: [], witnessed: null }; }

function brief(s) { return { batch: s.batch, sha256: s.sha256, first_index: s.first_index, batch_size: s.batch_size, tree_size: s.tree_size, prev_sth_sha256: s.prev_sth_sha256 ?? null, created_at: s.created_at ?? null }; }
function forkOf(store, kind, batch, a, b, why, checked) {
  const f = { kind, batch, why, a: a, b: b, detected_at: new Date().toISOString(), issuer_checked: checked === true,
    proof: checked === true ? "both documents carry CrawlCheck's own signature and cannot both belong to one append-only log; publish them or send them to " + "https://crawlcheck.io/api/v1/log/gossip"
      : "NOT checked against CrawlCheck's published keys: these two heads contradict each other, but either may be signed by anyone. Observe them again with publishedKids or keyPolicy before concluding anything" };
  const key = kind + ":" + (a && a.sha256) + ":" + (b && b.sha256);
  if (!store.forks.some((x) => x.kind + ":" + (x.a && x.a.sha256) + ":" + (x.b && x.b.sha256) === key)) store.forks.push(f);
  return { state: "fork", fork: f };
}

/**
 * Check one signed tree head (kind crawlcheck-log-sth) against everything the store already holds, then keep it.
 * Returns { state: "new" | "known" | "fork" | "invalid", why?, fork? }. invalid means the document is not a head
 * CrawlCheck signed (it proves nothing either way, and it is not kept); fork means two signed heads that contradict
 * each other.
 * opts.publishedKids: key ids from the published directory; a head signed by another key is invalid.
 * opts.keyPolicy: keyPolicyFrom(directory, rotation) / publishedKeyPolicy(); the head must also be signed by a key the
 *   signing policy allows for log heads at its time. Pass one of the two: without either, the head is checked against
 *   its own key only, anyone can make one, and it is kept marked issuer_checked: false. Such a head never forms a fork
 *   with a checked head (the checked one replaces it), and a fork between two of them says so in its proof text.
 */
export async function logObserve(store, sth, opts = {}) {
  if (!store || typeof store !== "object" || !store.heads) throw new Error("pass a store from newLogStore()");
  if (!sth || sth.kind !== "crawlcheck-log-sth" || !Number.isInteger(sth.batch) || sth.batch < 0) return { state: "invalid", why: "not a signed tree head" };
  const kids = Array.isArray(opts.publishedKids) ? opts.publishedKids : null, checked = !!(opts.keyPolicy || kids);
  let v = null;
  try { v = opts.keyPolicy ? applyKeyPolicy(await verifyDataDoc(sth), sth, opts.keyPolicy) : await verifyDataDoc(sth, kids ? { publishedKids: kids } : undefined); } catch (e) { v = null; }
  if (!v || !v.verified) return { state: "invalid", why: "the head does not verify" + (v ? ": " + v.summary : "") };
  if (checked && !v.accepted) return { state: "invalid", why: "not signed by a key CrawlCheck publishes for log heads" };
  if (checked && v.key_policy_code === "purpose_unknown") return { state: "invalid", why: "signed by a listed key whose purpose this release does not know: pass keyPolicy, which says which key signs log heads" };
  if (sth.log_id !== (store.log_id || LOG_ID)) return { state: "invalid", why: "a head of another log (" + sth.log_id + ")" };
  // A head CrawlCheck signed whose own numbers do not add up is itself misbehaviour.
  const arith = Number.isInteger(sth.batch_size) && sth.batch_size > 0 && sth.tree_size === sth.first_index + sth.batch_size && (sth.batch > 0 || (sth.first_index === 0 && sth.prev_sth_sha256 == null)) && (sth.batch === 0 || /^[0-9a-f]{64}$/.test(String(sth.prev_sth_sha256)));
  if (!arith) return forkOf(store, "inconsistent_head", sth.batch, sth, sth, "batch " + sth.batch + ": a signed head whose sizes or chain link are malformed", checked);
  const k = sth.batch;
  // A head kept without a key check has no standing against one that was checked: the checked head replaces it, and
  // an unchecked head that contradicts a checked one is ignored.
  const was = (h) => !!h && h.issuer_checked === true;
  const clash = (h, bad) => { if (!h || !bad) return null; if (checked && !was(h)) { delete store.heads[h.batch]; return null; } return h; };
  const same = store.heads[k];
  if (same && same.sha256 === sth.sha256) { if (checked) same.issuer_checked = true; return { state: "known" }; }
  const have = clash(same, true);
  const p0 = store.heads[k - 1], n0 = store.heads[k + 1];
  const prev = clash(p0, !!p0 && (sth.prev_sth_sha256 !== p0.sha256 || sth.first_index !== p0.tree_size));
  const next = clash(n0, !!n0 && (n0.prev_sth_sha256 !== sth.sha256 || n0.first_index !== sth.tree_size));
  if (!checked && [have, prev, next].some(was)) return { state: "invalid", why: "contradicts a head this store checked against CrawlCheck's keys, and was not itself checked against them: ignored" };
  if (have) return forkOf(store, "two_heads_for_one_batch", k, have.sth, sth, "batch " + k + " has two signed heads: " + have.sha256.slice(0, 16) + "… and " + sth.sha256.slice(0, 16) + "…", checked);
  if (prev && sth.prev_sth_sha256 !== prev.sha256) return forkOf(store, "chain_break", k, prev.sth, sth, "batch " + k + " does not chain to the batch " + (k - 1) + " head this client holds", checked);
  if (prev) return forkOf(store, "size_mismatch", k, prev.sth, sth, "batch " + k + " starts at " + sth.first_index + ", batch " + (k - 1) + " ended at " + prev.tree_size, checked);
  if (next && next.prev_sth_sha256 !== sth.sha256) return forkOf(store, "chain_break", k + 1, sth, next.sth, "the batch " + (k + 1) + " head this client holds does not chain to this batch " + k + " head", checked);
  if (next) return forkOf(store, "size_mismatch", k + 1, sth, next.sth, "batch " + (k + 1) + " starts at " + next.first_index + ", this head ends at " + sth.tree_size, checked);
  store.heads[k] = Object.assign(brief(sth), { sth }, checked ? { issuer_checked: true } : {});
  const ks = Object.keys(store.heads).map(Number).sort((a, b) => a - b);
  while (ks.length > (opts.maxHeads || MAX_HEADS)) delete store.heads[ks.shift()];
  return { state: "new" };
}

/**
 * Re-check what a store holds against CrawlCheck's keys (opts.publishedKids or opts.keyPolicy, one is required): a
 * fork that carries its two heads is kept only when both are signed by a published key, and a head only when it is. Use it on a
 * store saved by an earlier release, or after heads were observed without a key list.
 * Returns { forks_dropped, heads_dropped }.
 */
export async function logPrune(store, opts = {}) {
  if (!opts.keyPolicy && !Array.isArray(opts.publishedKids)) throw new Error("logPrune needs publishedKids or keyPolicy");
  const ok = async (sth) => { const t = newLogStore(); t.log_id = store.log_id || LOG_ID; const r = await logObserve(t, sth, opts).catch(() => null); return !!r && r.state !== "invalid"; };
  const keep = []; let forks_dropped = 0, heads_dropped = 0;
  for (const f of store.forks || []) {
    if (f && f.issuer_checked === true) { keep.push(f); continue; }
    if (!f || !f.a || typeof f.a !== "object" || !f.b || typeof f.b !== "object") { keep.push(f); continue; }   // no head documents to re-check: left as it is
    if (f && await ok(f.a) && (f.b === f.a || await ok(f.b))) { f.issuer_checked = true; f.proof = "both documents carry CrawlCheck's own signature and cannot both belong to one append-only log; publish them or send them to " + "https://crawlcheck.io/api/v1/log/gossip"; keep.push(f); }
    else forks_dropped++;
  }
  store.forks = keep;
  for (const k of Object.keys(store.heads)) { const h = store.heads[k]; if (h && h.issuer_checked === true) continue; if (h && await ok(h.sth)) h.issuer_checked = true; else { delete store.heads[k]; heads_dropped++; } }
  return { forks_dropped, heads_dropped };
}

/** Observe the head inside a Resolve answer (transparency.sth), if it has one. */
export async function logObserveAnswer(store, answer, opts = {}) {
  const t = answer && answer.transparency;
  return t && t.state === "included" && t.sth ? logObserve(store, t.sth, opts) : { state: "none" };
}

/** The signed heads this store holds, newest first: what a client sends its peers. */
export function logHeads(store, limit = 50) {
  return Object.keys(store.heads).map(Number).sort((a, b) => b - a).slice(0, limit).map((k) => store.heads[k].sth);
}

/** Gossip: check heads another client holds against this store. Returns { forks, results }. */
export async function logGossip(store, sths, opts = {}) {
  const results = [], before = store.forks.length;
  for (const s of Array.isArray(sths) ? sths : []) results.push(Object.assign({ batch: s && s.batch, sha256: s && s.sha256 }, await logObserve(store, s, opts)));
  return { forks: store.forks.slice(before), results };
}

// ── the outside witness: a GitHub Actions OIDC token whose audience is the head's digest ──
const b64uBytes = (s) => { const t = String(s).replace(/-/g, "+").replace(/_/g, "/"); const b = atob(t + "=".repeat((4 - t.length % 4) % 4)); const o = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) o[i] = b.charCodeAt(i); return o; };
/**
 * Verify a witness co-signature: the JWT's RS256 signature against GitHub's published keys (jwks: the JSON from
 * https://token.actions.githubusercontent.com/.well-known/jwks), its issuer, repository, workflow and audience
 * crawlcheck-sth:<sthSha256>. exp is not checked: the token is a record of what the witness saw when it ran.
 * Returns { ok: true | false | null, why, claims? }; null when GitHub no longer publishes the key that signed it.
 */
export async function verifyWitnessToken(token, sthSha256, jwks) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return { ok: false, why: "not a JWT" };
  let h, c; try { h = JSON.parse(new TextDecoder().decode(b64uBytes(parts[0]))); c = JSON.parse(new TextDecoder().decode(b64uBytes(parts[1]))); } catch (e) { return { ok: false, why: "unreadable token" }; }
  if (h.alg !== "RS256") return { ok: false, why: "unexpected algorithm " + h.alg };
  const jwk = (jwks && jwks.keys || []).find((k) => k.kid === h.kid);
  if (!jwk) return { ok: null, why: "GitHub no longer publishes key " + h.kid + "; the co-signature cannot be checked now", claims: c };
  let sigOk = false;
  try {
    const key = await crypto.subtle.importKey("jwk", { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    sigOk = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64uBytes(parts[2]), new TextEncoder().encode(parts[0] + "." + parts[1]));
  } catch (e) { return { ok: null, why: "this runtime cannot verify RS256: " + (e && e.message || e), claims: c }; }
  if (!sigOk) return { ok: false, why: "GitHub's signature does NOT verify", claims: c };
  if (c.iss !== GITHUB_OIDC_ISSUER) return { ok: false, why: "issuer is " + c.iss, claims: c };
  const ref = String(c.job_workflow_ref || ""), cut = ref.indexOf("@refs/heads/");
  if (cut < 1 || await sha256Hex(c.repository) !== WITNESS_REPOSITORY_SHA256 || await sha256Hex(ref.slice(0, cut)) !== WITNESS_WORKFLOW_SHA256) return { ok: false, why: "issued to " + c.job_workflow_ref + ", not the witness workflow", claims: c };
  if (c.runner_environment && c.runner_environment !== "github-hosted") return { ok: false, why: "not a GitHub-hosted runner", claims: c };
  const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
  if (!aud.includes("crawlcheck-sth:" + sthSha256)) return { ok: false, why: "the token's audience does not name this head", claims: c };
  return { ok: true, why: "GitHub signed a token for run " + c.run_id + " of the witness workflow, audience this head's digest", claims: c };
}

/**
 * Online check of a store against the log and its outside witness. get(path) must return parsed JSON from
 * https://crawlcheck.io (the SDK clients pass their own). Steps: observe the current head; fetch the last witnessed
 * head and verify GitHub's co-signature; walk the chain from the witnessed head down to the oldest head this store
 * holds (at most opts.maxWalk batches), observing every link, so any head this client was shown that the witness's
 * chain does not contain surfaces as a fork. Heads newer than the witnessed one are listed as unwitnessed.
 */
// Signed heads for batches hi down to lo, newest first. Since 1.9.0 one request per 200 batches (/api/v1/log/sths);
// a server without that route is walked one head per request as before.
export async function walkHeads(get, hi, lo) {
  const out = []; let k = hi;
  while (k >= lo) {
    const n = Math.min(200, k - lo + 1);
    const d = await get("/api/v1/log/sths?to=" + k + "&n=" + n).catch(() => null);
    if (!d || !Array.isArray(d.sths)) break;
    const got = {}; for (const s of d.sths) if (s && Number.isInteger(s.batch)) got[s.batch] = s;
    for (let b = k; b > k - n; b--) if (got[b]) out.push(got[b]);
    k -= n;
  }
  for (; k >= lo; k--) { const d = await get("/api/v1/log/sth/" + k).catch(() => null); if (d && d.sth) out.push(d.sth); }
  return out;
}
export async function logCheck(store, get, opts = {}) {
  const before = store.forks.length, o = { publishedKids: opts.publishedKids, keyPolicy: opts.keyPolicy };
  const log = await get("/api/v1/log");
  if (log && log.head) await logObserve(store, log.head, o);
  let witnessed = null;
  const w = await get("/api/v1/log/witness/latest").catch(() => null);
  if (w && Number.isInteger(w.batch)) {
    const doc = await get("/api/v1/log/sth/" + w.batch);
    const sth = doc && doc.sth, rec = (doc && doc.witnesses || [])[0] || w;
    const jwks = opts.jwks || (opts.fetchJwks ? await opts.fetchJwks() : null);
    const tv = jwks ? await verifyWitnessToken(rec.token, sth && sth.sha256, jwks) : { ok: null, why: "no GitHub key set given" };
    const r = sth ? await logObserve(store, sth, o) : { state: "invalid" };
    witnessed = { batch: w.batch, sha256: sth && sth.sha256, at: rec.at || null, run_id: tv.claims ? tv.claims.run_id : (rec.run && rec.run.run_id) || null, token: tv.ok, why: tv.why, observed: r.state };
    if (tv.ok === false) witnessed.warning = "the witness record does not carry a valid GitHub co-signature for this head";
    if (tv.ok === true && r.state !== "invalid") store.witnessed = { batch: w.batch, sha256: sth.sha256, at: witnessed.at, run_id: witnessed.run_id };
    const held = Object.keys(store.heads).map(Number).filter((k) => k < w.batch);
    const lo = held.length ? Math.max(Math.min(...held), w.batch - (opts.maxWalk || 200)) : w.batch;
    for (const s of await walkHeads(get, w.batch - 1, lo)) await logObserve(store, s, o);
  }
  const wb = store.witnessed ? store.witnessed.batch : -1, now = Date.now(), maxAge = (opts.maxUnwitnessedMinutes || 120) * 60000;
  const unwitnessed = Object.keys(store.heads).map(Number).filter((k) => k > wb).sort((a, b) => a - b).map((k) => ({ batch: k, sha256: store.heads[k].sha256, created_at: store.heads[k].created_at }));
  const stale = unwitnessed.filter((u) => u.created_at && now - Date.parse(u.created_at) > maxAge);
  const forks = store.forks.slice(before);
  if (opts.post) {   // tell CrawlCheck which heads this client was shown; a fork reported here is recorded publicly at /api/v1/log/gossip
    const sths = logHeads(store, 20); for (const f of forks) { if (f.a) sths.push(f.a); if (f.b && f.b !== f.a) sths.push(f.b); }
    try { await opts.post("/api/v1/log/gossip", { sths: sths.slice(0, 50) }); } catch (e) { }
  }
  return { consistent: store.forks.length === 0, forks, all_forks: store.forks.length, witnessed, unwitnessed, stale_unwitnessed: stale,
    summary: store.forks.length ? "SPLIT VIEW: " + store.forks.length + " pair(s) of contradicting signed heads" : stale.length ? "no fork seen, but " + stale.length + " head(s) older than " + (opts.maxUnwitnessedMinutes || 120) + " min are not covered by a witness" : "consistent: every head this client holds is on one chain" + (witnessed && witnessed.token === true ? " up to the head GitHub's witness co-signed (batch " + witnessed.batch + ")" : "") };
}
