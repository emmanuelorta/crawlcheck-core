// CrawlCheck staple for static sites (Action input staple-dir). Writes the site's signed CrawlCheck verdict into the
// build output before it is deployed: <staple-dir>/.well-known/crawlcheck-staple.json, and, when staple-headers-file
// is set (Netlify and Cloudflare Pages read a _headers file), a CrawlCheck-Staple header on every path.
// The record is verified here before anything is written: signed by a key CrawlCheck publishes, naming this domain,
// fresh. A staple lasts 7 days, so run this in the job that deploys the site, at least weekly.
// Spec: https://crawlcheck.io/spec/staple. Node 20+.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DNS_PREFIX = "crawlcheck-dns-v1\n";
const BEGIN = "# crawlcheck-staple begin (written by the CrawlCheck Action; replaced on every run)", END = "# crawlcheck-staple end";

export function parseRecord(rec) {
  const o = {}; for (const part of String(rec).split(";")) { const i = part.indexOf("="); if (i > 0) o[part.slice(0, i)] = part.slice(i + 1); }
  return o;
}
// The checks an agent runs (spec "Agent side"), so a staple that would be refused is never deployed.
export function checkRecord(rec, domain, kids, now) {
  const r = parseRecord(rec), why = [];
  if (r.v !== "ccr1") why.push("not a ccr1 record");
  if (r.d !== domain) why.push("names " + r.d + ", not " + domain);
  if (!(Date.parse(r.f) > (now || Date.now()))) why.push("expired (f=" + r.f + ")");
  const thumb = crypto.createHash("sha256").update(JSON.stringify({ crv: "Ed25519", kty: "OKP", x: r.x })).digest("base64url");
  if (thumb !== r.k) why.push("k is not the thumbprint of x");
  if (kids && !kids.includes(r.k)) why.push("key " + String(r.k).slice(0, 12) + "... is not in CrawlCheck's published directory");
  const cut = rec.indexOf(";s=");
  try {
    const pk = crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: r.x }, format: "jwk" });
    if (cut < 0 || !crypto.verify(null, Buffer.from(DNS_PREFIX + rec.slice(0, cut), "utf8"), pk, Buffer.from(r.s, "base64url"))) why.push("signature does not verify");
  } catch (e) { why.push("signature unreadable"); }
  return { ok: why.length === 0, why, fields: r };
}
export function headersBlock(existing, rec) {
  const block = BEGIN + "\n/*\n  CrawlCheck-Staple: " + rec + "\n" + END + "\n";
  const s = String(existing || ""), a = s.indexOf(BEGIN), b = s.indexOf(END);
  if (a > -1 && b > a) return s.slice(0, a) + block + s.slice(b + END.length).replace(/^\n/, "");
  return (s && !s.endsWith("\n") ? s + "\n" : s) + block;
}
export async function staple(opts) {
  const F = opts.fetch || fetch, BASE = String(opts.base || "https://crawlcheck.io").replace(/\/$/, "");
  const domain = String(opts.domain || "").replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, "").toLowerCase();
  const r = await F(BASE + "/api/v1/staple?domain=" + encodeURIComponent(domain), { headers: { "user-agent": "crawlcheck-action-staple/1", accept: "application/json" } });
  if (!r.ok) throw new Error("CrawlCheck answered HTTP " + r.status + " for the staple");
  const doc = await r.json();
  const kids = (await (await F(BASE + "/.well-known/http-message-signatures-directory")).json()).keys.map((k) => k.kid);
  const c = checkRecord(doc.record, domain, kids);
  if (!c.ok) throw new Error("the staple did not verify, nothing written: " + c.why.join("; "));
  const out = path.join(opts.dir, ".well-known", "crawlcheck-staple.json");
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, JSON.stringify(doc));
  let hf = null;
  if (opts.headersFile) { hf = opts.headersFile; const prev = fs.existsSync(hf) ? fs.readFileSync(hf, "utf8") : ""; fs.mkdirSync(path.dirname(path.resolve(hf)), { recursive: true }); fs.writeFileSync(hf, headersBlock(prev, doc.record)); }
  return { file: out, headers_file: hf, fresh_until: doc.fresh_until, verdict: { read: c.fields.read, cite: c.fields.cite, connect: c.fields.connect, transact: c.fields.transact } };
}
async function main() {
  const r = await staple({ base: process.env.CC_API, domain: process.env.CC_DOMAIN, dir: process.env.CC_STAPLE_DIR, headersFile: process.env.CC_STAPLE_HEADERS || "" });
  console.log("staple written: " + r.file + (r.headers_file ? " and " + r.headers_file : "") + " | fresh until " + r.fresh_until + " | read " + r.verdict.read + ", cite " + r.verdict.cite + ", connect " + r.verdict.connect + ", transact " + r.verdict.transact);
}
if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) main().catch((e) => { console.log("::warning::staple not written (the deploy continues without it): " + e.message); });
