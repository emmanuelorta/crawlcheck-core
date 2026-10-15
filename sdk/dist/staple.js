// Stapled Resolve and Resolve over DNS: the compact ccr1 record a site sends in the CrawlCheck-Staple header (or that
// <domain>._v.crawlcheck.io TXT carries). Verified offline: key id = RFC 7638 thumbprint of the public key, the key is
// one CrawlCheck publishes, the Ed25519 signature covers the record, the record names the host (or a parent domain),
// and fresh_until is in the future. An expired or foreign staple is never used.
const STAPLE_PREFIX = "crawlcheck-dns-v1\n";
const te = new TextEncoder();
function b64uToBytes(s) { s = String(s || "").replace(/-/g, "+").replace(/_/g, "/"); s += "===".slice((s.length + 3) % 4); const b = atob(s), u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++)
    u[i] = b.charCodeAt(i); return u; }
function bytesToB64u(u) { let s = ""; for (let i = 0; i < u.length; i++)
    s += String.fromCharCode(u[i]); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
/** Parse a ccr1 record ("v=ccr1;d=...;s=..."); quoted TXT strings from dig are joined. */
export function parseStaple(record) {
    const t = String(record || "").trim().replace(/"\s*"/g, "").replace(/^"|"$/g, "");
    const i = t.lastIndexOf(";s=");
    const body = i > 0 ? t.slice(0, i) : "", sig = i > 0 ? t.slice(i + 3) : "";
    const f = {};
    body.split(";").forEach((p) => { const j = p.indexOf("="); if (j > 0)
        f[p.slice(0, j)] = p.slice(j + 1); });
    return { fields: f, body, sig };
}
/** The staple a response carries, if any (a fetch Response, a Headers object or a plain header map). */
export function stapleFromResponse(res) {
    const h = res && (res.headers || res);
    if (!h)
        return null;
    if (typeof h.get === "function")
        return h.get("crawlcheck-staple");
    for (const k of Object.keys(h))
        if (k.toLowerCase() === "crawlcheck-staple")
            return h[k];
    return null;
}
/**
 * Check a staple offline. opts.host: the host the agent is talking to (required for a usable result);
 * opts.publishedKids: the key ids CrawlCheck publishes (from /.well-known/http-message-signatures-directory);
 * opts.now: epoch ms (default Date.now()).
 * Returns { valid, reason, expired, record, decisions } and never throws.
 */
export async function stapleCheck(record, opts = {}) {
    const out = { valid: false, reason: null, expired: false, record: null, decisions: null };
    try {
        const { fields: f, body, sig } = parseStaple(record);
        out.record = f;
        if (f.v !== "ccr1" || !f.d || !f.k || !f.x || !sig) {
            out.reason = "not a ccr1 record";
            return out;
        }
        out.decisions = { read: f.read || null, cite: f.cite || null, connect: f.connect || null, transact: f.transact || null };
        const now = opts.now || Date.now(), fu = Date.parse(f.f || "");
        if (!isFinite(fu) || fu <= now) {
            out.expired = true;
            out.reason = "expired at " + (f.f || "?") + ": ask CrawlCheck instead";
            return out;
        }
        const host = String(opts.host || "").toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
        const d = String(f.d).toLowerCase();
        if (!host) {
            out.reason = "no host given: a staple is only valid for the host it was served by";
            return out;
        }
        if (host !== d && !host.endsWith("." + d)) {
            out.reason = "the staple names " + d + ", not " + host;
            return out;
        }
        const thumb = bytesToB64u(new Uint8Array(await crypto.subtle.digest("SHA-256", te.encode(JSON.stringify({ crv: "Ed25519", kty: "OKP", x: f.x })))));
        if (thumb !== f.k) {
            out.reason = "key id does not match the public key";
            return out;
        }
        if (!Array.isArray(opts.publishedKids) || opts.publishedKids.indexOf(f.k) < 0) {
            out.reason = Array.isArray(opts.publishedKids) ? "key " + f.k + " is not one CrawlCheck publishes" : "no published key list given (opts.publishedKids)";
            return out;
        }
        const pk = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: f.x }, { name: "Ed25519" }, false, ["verify"]);
        const ok = await crypto.subtle.verify({ name: "Ed25519" }, pk, b64uToBytes(sig), te.encode(STAPLE_PREFIX + body));
        if (!ok) {
            out.reason = "signature does not verify";
            return out;
        }
        out.valid = true;
        out.reason = "valid until " + f.f;
        return out;
    }
    catch (e) {
        out.reason = "could not check: " + (e && e.message || e);
        return out;
    }
}
