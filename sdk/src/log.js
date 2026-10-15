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
// Zero dependencies; WebCrypto only.
import { verifyDataDoc } from "./verify.js";

export const LOG_ID = "crawlcheck-resolve-log-v1";
export const GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com";
export const WITNESS_REPOSITORY = "emmanuelorta/crawlcheck";
export const WITNESS_WORKFLOW_PREFIX = "emmanuelorta/crawlcheck/.github/workflows/log-witness.yml@refs/heads/";
const MAX_HEADS = 2000;

/** A new, empty store. It is plain JSON: keep it across runs (a file, a KV value) so later heads are checked against earlier ones. */
export function newLogStore() { return { v: 1, log_id: LOG_ID, heads: {}, forks: [], witnessed: null }; }

function brief(s) { return { batch: s.batch, sha256: s.sha256, first_index: s.first_index, batch_size: s.batch_size, tree_size: s.tree_size, prev_sth_sha256: s.prev_sth_sha256 ?? null, created_at: s.created_at ?? null }; }
function forkOf(store, kind, batch, a, b, why) {
  const f = { kind, batch, why, a: a, b: b, detected_at: new Date().toISOString(),
    proof: "both documents carry CrawlCheck's own signature and cannot both belong to one append-only log; publish them or send them to " + "https://crawlcheck.io/api/v1/log/gossip" };
  const key = kind + ":" + (a && a.sha256) + ":" + (b && b.sha256);
  if (!store.forks.some((x) => x.kind + ":" + (x.a && x.a.sha256) + ":" + (x.b && x.b.sha256) === key)) store.forks.push(f);
  return { state: "fork", fork: f };
}

/**
 * Check one signed tree head (kind crawlcheck-log-sth) against everything the store already holds, then keep it.
 * Returns { state: "new" | "known" | "fork" | "invalid", why?, fork? }. invalid means the document is not a head
 * CrawlCheck signed (it proves nothing either way); fork means two signed heads that contradict each other.
 * opts.publishedKids: key ids from the published directory; a head signed by another key is invalid.
 */
export async function logObserve(store, sth, opts = {}) {
  if (!store || typeof store !== "object" || !store.heads) throw new Error("pass a store from newLogStore()");
  if (!sth || sth.kind !== "crawlcheck-log-sth" || !Number.isInteger(sth.batch) || sth.batch < 0) return { state: "invalid", why: "not a signed tree head" };
  let v = null; try { v = await verifyDataDoc(sth, opts.publishedKids ? { publishedKids: opts.publishedKids } : undefined); } catch (e) { v = null; }
  if (!v || !v.verified) return { state: "invalid", why: "the head does not verify" + (v ? ": " + v.summary : "") };
  if (opts.publishedKids && !opts.publishedKids.includes(sth.signature && sth.signature.kid)) return { state: "invalid", why: "signed by a key CrawlCheck does not publish" };
  if (sth.log_id !== (store.log_id || LOG_ID)) return { state: "invalid", why: "a head of another log (" + sth.log_id + ")" };
  // A head CrawlCheck signed whose own numbers do not add up is itself misbehaviour.
  const arith = Number.isInteger(sth.batch_size) && sth.batch_size > 0 && sth.tree_size === sth.first_index + sth.batch_size && (sth.batch > 0 || (sth.first_index === 0 && sth.prev_sth_sha256 == null)) && (sth.batch === 0 || /^[0-9a-f]{64}$/.test(String(sth.prev_sth_sha256)));
  if (!arith) return forkOf(store, "inconsistent_head", sth.batch, sth, sth, "batch " + sth.batch + ": a signed head whose sizes or chain link are malformed");
  const k = sth.batch, have = store.heads[k];
  if (have) {
    if (have.sha256 === sth.sha256) return { state: "known" };
    return forkOf(store, "two_heads_for_one_batch", k, have.sth, sth, "batch " + k + " has two signed heads: " + have.sha256.slice(0, 16) + "… and " + sth.sha256.slice(0, 16) + "…");
  }
  const prev = store.heads[k - 1], next = store.heads[k + 1];
  if (prev && sth.prev_sth_sha256 !== prev.sha256) return forkOf(store, "chain_break", k, prev.sth, sth, "batch " + k + " does not chain to the batch " + (k - 1) + " head this client holds");
  if (prev && sth.first_index !== prev.tree_size) return forkOf(store, "size_mismatch", k, prev.sth, sth, "batch " + k + " starts at " + sth.first_index + ", batch " + (k - 1) + " ended at " + prev.tree_size);
  if (next && next.prev_sth_sha256 !== sth.sha256) return forkOf(store, "chain_break", k + 1, sth, next.sth, "the batch " + (k + 1) + " head this client holds does not chain to this batch " + k + " head");
  if (next && next.first_index !== sth.tree_size) return forkOf(store, "size_mismatch", k + 1, sth, next.sth, "batch " + (k + 1) + " starts at " + next.first_index + ", this head ends at " + sth.tree_size);
  store.heads[k] = Object.assign(brief(sth), { sth });
  const ks = Object.keys(store.heads).map(Number).sort((a, b) => a - b);
  while (ks.length > (opts.maxHeads || MAX_HEADS)) delete store.heads[ks.shift()];
  return { state: "new" };
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
  if (c.repository !== WITNESS_REPOSITORY || String(c.job_workflow_ref || "").indexOf(WITNESS_WORKFLOW_PREFIX) !== 0) return { ok: false, why: "issued to " + c.job_workflow_ref + ", not the log-witness workflow", claims: c };
  if (c.runner_environment && c.runner_environment !== "github-hosted") return { ok: false, why: "not a GitHub-hosted runner", claims: c };
  const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
  if (!aud.includes("crawlcheck-sth:" + sthSha256)) return { ok: false, why: "the token's audience does not name this head", claims: c };
  return { ok: true, why: "GitHub signed a token for run " + c.run_id + " of the log-witness workflow, audience this head's digest", claims: c };
}

/**
 * Online check of a store against the log and its outside witness. get(path) must return parsed JSON from
 * https://crawlcheck.io (the SDK clients pass their own). Steps: observe the current head; fetch the last witnessed
 * head and verify GitHub's co-signature; walk the chain from the witnessed head down to the oldest head this store
 * holds (at most opts.maxWalk batches), observing every link, so any head this client was shown that the witness's
 * chain does not contain surfaces as a fork. Heads newer than the witnessed one are listed as unwitnessed.
 */
export async function logCheck(store, get, opts = {}) {
  const before = store.forks.length, o = { publishedKids: opts.publishedKids };
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
    for (let k = w.batch - 1; k >= lo; k--) { const d = await get("/api/v1/log/sth/" + k).catch(() => null); if (d && d.sth) await logObserve(store, d.sth, o); }
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
