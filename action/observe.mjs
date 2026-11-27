// CrawlCheck observer for the GitHub Action (observe: "true"). Reads the configured domain from this runner, under the
// same request profiles CrawlCheck's own scanner uses (served and hashed by CrawlCheck), and posts one signed
// observation, so CrawlCheck's readings of the site include one taken from this runner's network.
//
// No secret to store: each run makes a fresh Ed25519 key and asks GitHub for an OIDC token whose audience is the
// SHA-256 of that key. GitHub signs the token naming this repository, workflow and run; CrawlCheck checks it against
// GitHub's published keys. The observer id is gha:<owner>/<repo>. The private key never leaves the run.
// Needs Node 20+ and `permissions: id-token: write` on the job.
import crypto from "node:crypto";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { safeFetch } from "../src/surfaces.js";

export const SIG_PREFIX = "crawlcheck-observation-v1\n";
export const SOFTWARE = { name: "crawlcheck-action-observer", version: "1.0.0" };
const KEEP_HEADERS = ["content-type", "content-length", "age", "cache-control", "last-modified", "etag", "x-robots-tag", "server", "cf-mitigated", "cf-cache-status", "x-sucuri-id", "x-sucuri-block", "x-iinfo",
  "x-datadome", "x-amzn-waf-action", "x-vercel-mitigated", "x-cache", "via", "location"];
const BODY_MAX = 2 * 1024 * 1024;
const READ_MAX = 16 * 1024 * 1024;   // cap1: the most read from one response; BODY_MAX still limits what is attached

export function canon(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v === undefined ? null : v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
}
export const sha256hex = (b) => crypto.createHash("sha256").update(b).digest("hex");
export function newKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" });
  return { privateKey, pub: { kty: jwk.kty, crv: jwk.crv, x: jwk.x } };
}
export function audienceFor(pub) { return "crawlcheck-observer:" + crypto.createHash("sha256").update(Buffer.from(pub.x, "base64url")).digest("base64url"); }
export function signEnvelope(env, privateKey) { return crypto.sign(null, Buffer.from(SIG_PREFIX + canon(env), "utf8"), privateKey).toString("base64url"); }

export async function fetchOne(url, ident, timeoutMs, F) {
  const t0 = Date.now();
  const row = { identity: ident.id, request: { headers: ident.headers }, started_at: new Date().toISOString(), ms: 0, status: null, url_final: null, headers: {}, bytes: 0, sha256: null, error: null };
  let buf = null;
  try {
    // Each redirect hop must pass the public-address guard; never follow a task URL into a private network.
    const r = await safeFetch(url, { headers: ident.headers, signal: AbortSignal.timeout(timeoutMs || 12000) }, { fetch: F || fetch });
    // cap1 (2026-11-22, outside audit F6): read as a stream and stop at a ceiling instead of buffering any size; a cut body
    // carries no digest (a digest of a prefix would read as the page's) and says truncated.
    const cap = READ_MAX; const parts = []; let n = 0;
    if (r.body && r.body.getReader) { const rd = r.body.getReader(); for (;;) { const { done, value } = await rd.read(); if (done) break; if (n + value.byteLength > cap) { parts.push(value.subarray(0, cap - n)); n = cap; row.truncated = true; try { await rd.cancel(); } catch (e) { } break; } parts.push(value); n += value.byteLength; } buf = Buffer.concat(parts.map((x) => Buffer.from(x)), n); }
    else { buf = Buffer.from(await r.arrayBuffer()); if (buf.byteLength > cap) { buf = buf.subarray(0, cap); row.truncated = true; } }
    row.status = r.status; row.url_final = r.finalUrl || r.url || url;
    for (const h of KEEP_HEADERS) { const v = r.headers.get(h); if (v != null) row.headers[h] = String(v).slice(0, 300); }
    row.bytes = buf.byteLength; row.sha256 = row.truncated ? null : sha256hex(buf);
  } catch (e) { row.error = String((e && e.message) || e).slice(0, 160); }
  row.ms = Date.now() - t0;
  return { row, buf };
}

// opts: { base, domain, repository, oidcToken(aud) -> jwt, env, fetch } - injectable so the flow can be tested offline
export async function observe(opts) {
  const F = opts.fetch || fetch, E = opts.env || process.env;
  const BASE = String(opts.base || "https://crawlcheck.io").replace(/\/$/, "");
  const domain = String(opts.domain || "").replace(/^https?:\/\//, "").replace(/\/.*$/, "").toLowerCase();
  // queue mode (2026-10-26): an empty domain asks CrawlCheck for tasks from its public queue (the scheduled observer in this repo).
  const repo = opts.repository || E.GITHUB_REPOSITORY;
  if (!repo) throw new Error("GITHUB_REPOSITORY is not set: run this inside GitHub Actions");
  const observerId = "gha:" + repo;
  const script = fs.readFileSync(fileURLToPath(import.meta.url));
  const software = Object.assign({}, SOFTWARE, { script_sha256: sha256hex(script) });
  const { privateKey, pub } = newKey();
  const oidc = await opts.oidcToken(audienceFor(pub));
  const runnerEnv = E.RUNNER_ENVIRONMENT || null;
  const vantage = { provider: runnerEnv === "self-hosted" ? "self-hosted GitHub Actions runner" : "GitHub-hosted runner (Microsoft Azure)", runner_environment: runnerEnv, runner_os: E.RUNNER_OS || null, runner_arch: E.RUNNER_ARCH || null };
  const t0 = Date.now();
  const tk = await F(BASE + "/api/observe/tasks" + (domain ? "?domains=" + encodeURIComponent(domain) : ""), { headers: { authorization: "Bearer " + oidc, "x-cc-observer-id": observerId, "x-cc-observer-key": JSON.stringify(pub), "user-agent": "crawlcheck-action-observer/1" } });
  const rtt = Date.now() - t0;
  const plan = await tk.json().catch(() => ({}));
  if (!tk.ok) throw new Error("tasks refused: HTTP " + tk.status + " " + JSON.stringify(plan).slice(0, 300));
  const serverDate = tk.headers.get("date");
  const skew = serverDate ? Math.round(Date.parse(serverDate) - (t0 + rtt / 2)) : null;
  const run = { repository: repo, run_id: E.GITHUB_RUN_ID || null, run_attempt: E.GITHUB_RUN_ATTEMPT || null, sha: E.GITHUB_SHA || null };
  const results = [];
  for (const task of plan.tasks || []) {
    const got = await Promise.all(task.identities.map((i) => fetchOne(task.url, i, 12000, opts.siteFetch || F)));
    const bodies = {};
    for (const g of got) if (g.buf && g.row.sha256 && g.buf.byteLength <= BODY_MAX && !bodies[g.row.sha256]) bodies[g.row.sha256] = g.buf.toString("base64");
    const env = { v: 1, kind: "crawlcheck-observation", observer_id: observerId, software, run, vantage,
      clock: { observed_at: new Date().toISOString(), server_date: serverDate, skew_ms: skew, method: "CrawlCheck Date header at task fetch, midpoint of round trip" },
      profile_sha256: task.profile_sha256 || plan.profile_sha256, task: { task_id: task.task_id, domain: task.domain, url: task.url }, fetches: got.map((g) => g.row), key: pub };
    const sig = signEnvelope(env, privateKey);
    const pr = await F(BASE + "/api/observe/signed", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ oidc, envelope: env, sig, bodies }) });
    const pj = await pr.json().catch(() => ({}));
    results.push({ domain: task.domain, status: pr.status, ok: !!pj.ok, sha256: pj.sha256 || null, error: pj.error || null, identities: got.map((g) => g.row.identity + ":" + (g.row.status || "x")).join(" ") });
  }
  return { observer_id: observerId, reputation: plan.observer && plan.observer.reputation || null, tasks: (plan.tasks || []).length, results };
}

// The request token is a GitHub credential. It is sent to GitHub's own token service over https and to no other host.
export function githubTokenUrl(raw) {
  let u; try { u = new URL(String(raw)); } catch { return null; }
  const h = u.hostname.toLowerCase();
  if (u.protocol !== "https:" || u.username || u.password) return null;
  return h === "actions.githubusercontent.com" || h.endsWith(".actions.githubusercontent.com") ? u : null;
}

async function main() {
  if (!process.env.ACTIONS_ID_TOKEN_REQUEST_URL) {
    console.log("::warning::observe: the job needs `permissions: id-token: write` to prove which repository is observing; skipped.");
    return;
  }
  const tokenUrl = githubTokenUrl(process.env.ACTIONS_ID_TOKEN_REQUEST_URL);
  if (!tokenUrl) {
    console.log("::warning::observe: ACTIONS_ID_TOKEN_REQUEST_URL is not a GitHub Actions token service address; the request token was not sent; skipped.");
    return;
  }
  const r = await observe({ base: process.env.CC_API, domain: process.env.CC_DOMAIN, oidcToken: async (aud) => {
    const u = new URL(tokenUrl); u.searchParams.set("audience", aud);
    const tr = await fetch(u, { redirect: "error", headers: { authorization: "bearer " + process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN } });
    const v = (await tr.json()).value; if (!v) throw new Error("GitHub issued no OIDC token (HTTP " + tr.status + ")"); return v; } });
  console.log("observer " + r.observer_id + ": " + r.tasks + " task(s)" + (r.reputation ? " | vote: " + r.reputation.basis : ""));
  for (const x of r.results) console.log("  " + x.domain + " HTTP " + x.status + " " + (x.ok ? "stored " + String(x.sha256).slice(0, 12) : "REJECTED " + x.error) + " | " + x.identities);
  if (r.results.some((x) => !x.ok)) console.log("::warning::a reading was not accepted; the fix step is unaffected.");
}
if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) main().catch((e) => { console.log("::warning::observe failed (the fix step is unaffected): " + e.message); });
