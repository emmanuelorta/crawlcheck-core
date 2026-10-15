import * as V from "./verify.js";
import * as L from "./log.js";
import * as S from "./staple.js";
import * as M from "./mcp.js";
import * as R from "./revocations.js";
function withTrust(v, kid, published, related = []) {
    let checks = v.checks;
    let issuer = null;
    if (published) {
        // kp3: keys are separated by purpose, so a decision's resolve answer or an answer's log head can carry another key; every one must be published
        const miss = related.filter((k) => k !== kid && !published.includes(k));
        issuer = !!kid && published.includes(kid) && miss.length === 0;
        const kc = { id: "key_published", ok: issuer, why: issuer ? "key id " + kid + " is in the published key directory" + (related.length ? ", and so is every key it leans on" : "") : miss.length && kid && published.includes(kid) ? "the document leans on key " + miss.join(", ") + ", which is NOT published - reject this document" : "key id " + (kid || "?") + " is NOT in the published key directory - reject this document" };
        checks = checks.some((c) => c.id === "key_published") ? checks.map((c) => c.id === "key_published" ? kc : c) : checks.concat([kc]);
    }
    const ran = checks.filter((c) => c.ok !== null), failed = checks.filter((c) => c.ok === false);
    const verified = ran.length > 0 && failed.length === 0;
    const integrity_valid = checks.filter((c) => c.id !== "key_published").every((c) => c.ok !== false);
    return Object.assign({}, v, { checks, verified, summary: failed.length ? failed.length + " check(s) FAILED" : ran.length + " of " + checks.length + " checks ran and passed",
        integrity_valid, issuer_trusted: issuer, accepted: verified && issuer === true });
}
/** Verify an evidence bundle with no call to CrawlCheck (the same code as /crawlcheck-verify.mjs). */
export const verifyBundle = V.verifyBundle;
/** Verify a remediation receipt with no call to CrawlCheck. */
export const verifyReceipt = V.verifyReceipt;
/** Verify a signed resolve answer, preflight decision receipt, data inventory, export part or deletion record offline. */
export const verifyDocument = async (doc) => withTrust(await V.verifyDataDoc(doc), doc?.signature?.kid, null);
/** Verify a signed evidence export (and every bundle and receipt inside it) offline. */
export const verifyExport = V.verifyExport;
/** Verify a signed dispute resolution offline (re-runs the published decision table over the recorded readings). */
export const verifyResolution = V.verifyResolution;
export const canon = V.canon;
export const merkleRootHex = V.merkleRootHex;
export const otsInspect = V.otsInspect;
/** The header an agent sends with its request so the site can see it checked CrawlCheck first. */
export const RECEIPT_HEADER = "CrawlCheck-Receipt";
/** The domain the way CrawlCheck hashes and stores it: lowercased, no scheme, no leading www., no path or port. "" when not a domain. */
export function normalizeDomain(v) {
    const d = String(v ?? "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/[\/?#].*$/, "").replace(/:\d+$/, "");
    return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d) ? d : "";
}
/** { "CrawlCheck-Receipt": "v=1; sha256=..." } for a decision receipt. Send it only to the domain the receipt names, before expires_at. */
export function receiptHeader(receipt) { return { [RECEIPT_HEADER]: "v=1; sha256=" + receipt.sha256 }; }
function randomNonce() { const b = new Uint8Array(16); globalThis.crypto.getRandomValues(b); return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join(""); }
async function sha256Hex(s) {
    const b = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
    return Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, "0")).join("");
}
export async function lockToolHash(t) {
    return sha256Hex(V.canon({ name: t?.name ?? null, description: t?.description ?? null, inputSchema: t?.inputSchema ?? t?.input_schema ?? null, annotations: t?.annotations ?? null }));
}
/** Hash a tools/list result the way a lockfile does: per tool, and the sorted per-tool hashes joined by \n. No network, no key. */
export async function lockFromTools(tools) {
    const rows = [];
    for (const t of (tools ?? []).slice(0, 300))
        rows.push({ name: String(t?.name ?? "").slice(0, 120), sha256: await lockToolHash(t) });
    rows.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : a.sha256 < b.sha256 ? -1 : 1));
    return { tools: rows, tools_sha256: await sha256Hex(rows.map((r) => r.sha256).sort().join("\n")), count: rows.length };
}
/** Compare a lockfile with the tools a server lists now. Anything added, removed or changed means "block" until a person re-approves. Offline. */
export async function checkLock(lock, tools) {
    const now = await lockFromTools(tools);
    const was = {};
    (lock?.tools ?? []).forEach((r) => { was[r.name] = r.sha256; });
    const cur = {};
    now.tools.forEach((r) => { cur[r.name] = r.sha256; });
    const added = Object.keys(cur).filter((n) => !(n in was)), removed = Object.keys(was).filter((n) => !(n in cur)), modified = Object.keys(cur).filter((n) => n in was && was[n] !== cur[n]);
    const same = lock?.tools_sha256 === now.tools_sha256 && !added.length && !removed.length && !modified.length;
    return { verdict: same ? "unchanged" : "changed", decision: same ? "connect" : "block", approved_tools_sha256: lock?.tools_sha256 ?? "", current_tools_sha256: now.tools_sha256, added, removed, modified };
}
/** The operation for calling an MCP tool: its name, the sha256 of its definition (as in the lockfile) and the scopes you will use. */
export async function toolOperation(tool, scopes) { const o = { tool: String(tool?.name ?? ""), tool_schema_sha256: await lockToolHash(tool) }; if (scopes && scopes.length)
    o.scopes = scopes.slice(); return o; }
/** The longest a receipt may stay valid, per action (seconds). A receipt that claims longer is refused. Published at https://crawlcheck.io/spec/guard */
export const ACTION_MAX_LIFETIME_S = { read: 86400, cite: 86400, connect: 3600, transact: 300, administer: 300 };
/** The most clock skew a receipt may claim (seconds). */
export const MAX_CLOCK_SKEW_S = 300;
const DECISIONS = ["allow", "warn", "require_confirmation", "block", "unsupported"];
/**
 * Is this receipt about the operation you are about to perform? Checks the scope only (kind, domain, action, nonce,
 * time window, per-action lifetime, known decision, resolve binding); the signature and issuer are checked by
 * verifyDocument. guard() runs both. https://crawlcheck.io/spec/guard
 */
export function checkDecision(receipt, want) {
    const why = [], r = receipt;
    if (!r || typeof r !== "object" || Array.isArray(r))
        return { ok: false, why: ["no receipt: CrawlCheck sent " + (r === null || r === undefined ? "nothing" : typeof r)] };
    if (r.kind !== "crawlcheck-decision" || r.v !== 1)
        why.push("not a v1 decision receipt (kind " + r.kind + ", v " + r.v + ")");
    const wd = normalizeDomain(want.domain);
    if (!wd || normalizeDomain(r.domain) !== wd)
        why.push("the receipt is for " + r.domain + ", not " + want.domain);
    if (String(r.action) !== String(want.action))
        why.push("the receipt is for action " + r.action + ", not " + want.action);
    if (want.operation && canon(r.operation ?? null) !== canon(want.operation))
        why.push(r.operation ? "the receipt is for another operation (" + canon(r.operation).slice(0, 120) + ")" : "the receipt is not scoped to an operation, and this request named one");
    if (want.nonce && r.nonce !== want.nonce)
        why.push(r.nonce ? "the receipt carries another request's nonce (replayed)" : "the receipt does not carry the nonce this request sent");
    const now = want.now ?? Date.now(), skew = Math.min(Math.max(Number(r.clock_skew_s) || 0, 0), MAX_CLOCK_SKEW_S) * 1000;
    const at = Date.parse(r.decided_at), exp = Date.parse(r.expires_at);
    if (!isFinite(at) || !isFinite(exp))
        why.push("decided_at or expires_at missing");
    else {
        if (now > exp + skew)
            why.push("expired at " + r.expires_at);
        if (at > now + skew)
            why.push("decided in the future (" + r.decided_at + "): check the clock");
        const max = ACTION_MAX_LIFETIME_S[String(want.action)];
        if (max === undefined)
            why.push("unknown action " + want.action);
        else if (exp - at > max * 1000 + 1000)
            why.push("valid for " + Math.round((exp - at) / 1000) + " s; a " + want.action + " receipt may last at most " + max + " s");
    }
    if (DECISIONS.indexOf(r.decision) < 0)
        why.push("unknown decision " + r.decision);
    if (!r.resolve || !/^[0-9a-f]{64}$/.test(String(r.resolve.sha256 || "")))
        why.push("the receipt names no resolve answer");
    return { ok: why.length === 0, why };
}
export const LOG_ID = L.LOG_ID;
/** A new, empty transparency-log store (plain JSON: persist it between runs). */
export const newLogStore = L.newLogStore;
/** Check one signed tree head against the store and keep it. A fork carries both contradicting signed heads. */
export const logObserve = L.logObserve;
/** Check the head inside a Resolve answer (transparency.sth), if it carries one. */
export const logObserveAnswer = L.logObserveAnswer;
/** The signed heads a store holds, newest first: what a client sends its peers. */
export const logHeads = L.logHeads;
/** Gossip: check another client's heads against this store. */
export const logGossip = L.logGossip;
/** Verify the outside witness's co-signature: a GitHub OIDC JWT (RS256) whose audience is crawlcheck-sth:<head sha256>. */
export const verifyWitnessToken = L.verifyWitnessToken;
export const GITHUB_OIDC_JWKS = "https://token.actions.githubusercontent.com/.well-known/jwks";
/** Parse a ccr1 record (CrawlCheck-Staple header value or <domain>._v.crawlcheck.io TXT). */
export const parseStaple = S.parseStaple;
/** The CrawlCheck-Staple header of a response (fetch Response, Headers or a plain header map), or null. */
export const stapleFromResponse = S.stapleFromResponse;
/** Verify a staple offline: published key, signature, the record names opts.host (or a parent), fresh_until in the future. Expired or foreign staples are never valid. */
export const stapleCheck = S.stapleCheck;
/** A new, empty revocation store. */
export const newRevocationStore = R.newRevocationStore;
/** Apply a VERIFIED crawlcheck-revocations document (full list or ?since= delta) to a store. */
export const applyRevocations = R.applyRevocations;
/** The entry that revokes this domain (or a parent domain) for this action, or null. Offline. */
export const revokedFor = R.revokedFor;
/** Thrown by the hooks when a connect or tools/call is refused; the request was never sent. */
export const McpPreflightRefused = M.McpPreflightRefused;
/** The two hooks (beforeConnect, beforeToolCall) plus afterConnect for lockfiles, for any MCP client stack. */
export const mcpPreflight = M.mcpPreflight;
/** Wrap an MCP client (the official @modelcontextprotocol/sdk Client, or anything with connect(transport) and callTool(params)) so both run the preflight first. Returns the same client with client.preflight set. */
export const withPreflight = M.withPreflight;
/** The server URL a transport will talk to, if it exposes one (Streamable HTTP and SSE transports do). */
export const transportUrl = M.transportUrl;
export class CrawlCheckError extends Error {
    status;
    body;
    path;
    constructor(status, path, body) {
        const m = body && typeof body === "object" ? (body.error?.message ?? body.error ?? body.message) : null;
        super("CrawlCheck " + path + " answered " + status + (m ? ": " + (typeof m === "string" ? m : JSON.stringify(m)) : ""));
        this.name = "CrawlCheckError";
        this.status = status;
        this.body = body;
        this.path = path;
    }
    /** true when the answer was "this needs a licence for the domain (or the owner's session)". */
    get locked() { return this.status === 403; }
}
export class CrawlCheck {
    base;
    key;
    f;
    extra;
    /** The transparency-log store this client checks every signed tree head against. Persist it (JSON) between runs. */
    log;
    /** The signed revocation list this client holds. Persist it (JSON) between runs; syncRevocations() keeps it current. */
    revocations;
    /** Private mode (ClientOptions.privateLookups). */
    privateLookups;
    constructor(opts = {}) {
        this.base = (opts.base ?? "https://crawlcheck.io").replace(/\/+$/, "");
        this.key = opts.key;
        this.extra = opts.headers ?? {};
        this.log = opts.logStore ?? newLogStore();
        this.revocations = opts.revocationStore ?? newRevocationStore();
        this.privateLookups = !!opts.privateLookups;
        const f = opts.fetch ?? globalThis.fetch;
        if (typeof f !== "function")
            throw new Error("no fetch available: pass { fetch } (Node 18+ and every browser have one)");
        this.f = f.bind(globalThis);
    }
    /** Any documented GET, typed from the OpenAPI document: client.get("/api/explain", { domain: "example.com" }). */
    async get(path, query) {
        return this.req("GET", path, query);
    }
    /** Any documented POST, typed from the OpenAPI document. */
    async post(path, body, query) {
        return this.req("POST", path, query, body);
    }
    // ── read before acting ──
    /** The signed ResolveV1 answer: crawl policy, delivery, machine files, capabilities, entity, findings, freshness and a decision per action. */
    async resolve(domain) {
        if (this.privateLookups) { // pfx2: only the hash prefix leaves this process
            const p = await this.resolvePrivate(domain);
            if (!p.ready)
                throw new CrawlCheckError(503, "/api/v1/resolve-prefix", { error: p.why || "the prefix index is not built yet" });
            if (!p.found)
                throw new CrawlCheckError(404, "/api/v1/resolve-prefix", { error: "CrawlCheck holds no public measurement of " + domain + "; in private mode the domain is never sent, so no just-in-time answer is made" });
            if (!p.accepted)
                throw new CrawlCheckError(502, "/api/v1/resolve-prefix", { error: "the answer in the bucket did not verify: " + (p.verification ? p.verification.summary : "no verification") });
            await logObserveAnswer(this.log, p.answer).catch(() => null);
            return p.answer;
        }
        const a = await this.get("/api/v1/resolve", { domain });
        await logObserveAnswer(this.log, a).catch(() => null); // a head that contradicts one this client already holds is recorded in this.log.forks
        return a;
    }
    kidCache = null;
    /** The key ids CrawlCheck publishes (/.well-known/http-message-signatures-directory), cached for an hour. */
    async publishedKids() {
        if (this.kidCache && Date.now() - this.kidCache.at < 3600e3)
            return this.kidCache.kids;
        const r = await this.f(this.base + "/.well-known/http-message-signatures-directory", { headers: { accept: "application/json" } });
        const j = await r.json();
        const kids = ((j && j.keys) || []).map((k) => k.kid).filter(Boolean);
        this.kidCache = { at: Date.now(), kids };
        return kids;
    }
    /**
     * The verdict for a domain, preferring a valid staple the site sent (opts.staple, or opts.response's CrawlCheck-Staple
     * header): no request to CrawlCheck is made when the staple verifies. An expired, foreign or invalid staple is ignored
     * and the signed answer is fetched instead; source says which was used and staple says why.
     */
    async resolveFor(domain, opts = {}) {
        const rec = opts.staple || (opts.response ? stapleFromResponse(opts.response) : null);
        let chk = null;
        if (rec) {
            let kids = [];
            try {
                kids = await this.publishedKids();
            }
            catch {
                kids = [];
            }
            chk = await stapleCheck(rec, { host: normalizeDomain(domain), publishedKids: kids });
            if (chk.valid && chk.decisions)
                return { source: "staple", decisions: chk.decisions, staple: chk };
        }
        const a = await this.resolve(domain);
        const act = (k) => (a && a.actions && a.actions[k] && a.actions[k].decision) || null;
        return { source: "network", decisions: { read: act("read"), cite: act("cite"), connect: act("connect"), transact: act("transact") }, staple: chk, answer: a };
    }
    /** Up to 100 domains in one call; each answer is a full signed ResolveV1 document. */
    async resolveBatch(domains) {
        const r = await this.post("/api/v1/resolve", { domains });
        for (const a of (r && r.answers) || [])
            await logObserveAnswer(this.log, a).catch(() => null);
        return r;
    }
    /** Split-view check: the current head, GitHub's witness co-signature on the last witnessed head, and the chain from it down to every head this client holds. Reports the heads it holds to /api/v1/log/gossip unless report is false. */
    async logCheck(opts = {}) {
        const kids = await this.publishedKeyIds();
        return L.logCheck(this.log, (p) => this.req("GET", p), { publishedKids: kids, maxWalk: opts.maxWalk, maxUnwitnessedMinutes: opts.maxUnwitnessedMinutes,
            fetchJwks: async () => { const r = await this.f(GITHUB_OIDC_JWKS); return r.ok ? r.json() : null; },
            post: opts.report === false ? undefined : (p, b) => this.req("POST", p, undefined, b) });
    }
    /** Check heads another client sent (logHeads on their side) against this client's store. */
    logGossip(sths) { return logGossip(this.log, sths); }
    /**
     * Fetch the signed revocation list (a ?since= delta when the store already holds one), verify it (integrity and a
     * published signing key) and apply it. A delta that no longer reaches back is replaced by the full list. Nothing is
     * applied from a document that does not verify. Call it on a timer (poll_seconds, 60) and before going offline.
     */
    async syncRevocations(opts = {}) {
        const st = this.revocations;
        const get = async (since) => (await this.req("GET", "/api/v1/revocations", since ? { since } : undefined));
        let doc = await get(opts.full || !st.generated_at ? null : st.generated_at);
        const verify = async (d) => this.verifyDocument(d, true);
        let v = await verify(doc);
        if (!v.accepted)
            return { applied: false, full: false, added: 0, removed: 0, reason: "the revocation list did not verify: " + v.summary, total: Object.keys(st.revoked).length, generated_at: st.generated_at, verification: v };
        let r = applyRevocations(st, doc);
        if (!r.applied && doc && doc.since) {
            doc = await get(null);
            v = await verify(doc);
            if (!v.accepted)
                return { applied: false, full: true, added: 0, removed: 0, reason: "the full revocation list did not verify: " + v.summary, total: Object.keys(st.revoked).length, generated_at: st.generated_at, verification: v };
            r = applyRevocations(st, doc);
        }
        return Object.assign({}, r, { total: Object.keys(st.revoked).length, generated_at: st.generated_at, verification: v });
    }
    /** The policy engine: a signed decision receipt (allow | warn | require_confirmation | block | unsupported). A policy can only make the decision stricter. */
    async preflight(domain, action = "read", opts = {}) {
        const b = { domain, action };
        if (opts.agent)
            b.agent = opts.agent;
        if (opts.template)
            b.template = opts.template;
        if (opts.policy)
            b.policy = opts.policy;
        if (opts.nonce)
            b.nonce = opts.nonce;
        if (opts.operation)
            b.operation = opts.operation;
        return this.post("/api/v1/preflight", b);
    }
    /** Verify a signed document here. With onlineKeys (default), its signing key must also be in the published directory. */
    async verifyDocument(doc, onlineKeys = true) {
        return withTrust(await V.verifyDataDoc(doc), doc?.signature?.kid, onlineKeys ? await this.publishedKeyIds() : null, V.relatedKids(doc));
    }
    /**
     * Preflight, verify the receipt, check it is for THIS operation, and decide. Proceeds on allow; warn only with allowWarn;
     * require_confirmation only if confirm() says yes; block, unsupported and every failure never (fail closed: an error,
     * an unreachable CrawlCheck, a malformed, foreign, expired, replayed or out-of-scope receipt all return proceed false
     * with why[]). Passes the acceptance suite at https://crawlcheck.io/spec/guard
     */
    async guard(domain, action = "read", opts = {}) {
        const nonce = opts.nonce || randomNonce();
        const no = (why, receipt = null, verification = null) => ({ proceed: false, receipt, verification, header: null, why });
        const rv = revokedFor(this.revocations, normalizeDomain(domain) || domain, action); // rvd1: refused offline, before any request
        if (rv)
            return Object.assign(no([rv.domain + " is on CrawlCheck's signed revocation list for " + action + " (" + (rv.causes.join(", ") || rv.state || "revoked") + (rv.since ? ", since " + rv.since : "") + "; list of " + this.revocations.generated_at + ")"]), { revoked: rv });
        let receipt;
        try {
            receipt = await this.preflight(domain, action, Object.assign({}, opts, { nonce }));
        }
        catch (e) {
            return no(["CrawlCheck did not give a decision: " + (e?.message || e)]);
        }
        if (this.log.forks.length)
            return Object.assign(no(["the transparency log has shown this client two histories (split view)"], receipt), { split_view: this.log.forks.slice() });
        const scope = checkDecision(receipt, { domain, action, nonce, now: opts.now, operation: opts.operation });
        if (!receipt || typeof receipt !== "object")
            return no(scope.why);
        const online = opts.onlineKeys ?? true;
        if (!online && !(Array.isArray(opts.publishedKids) && opts.publishedKids.length))
            return no(["onlineKeys is false and no publishedKids were pinned: the signer cannot be checked"], receipt);
        let verification;
        try {
            verification = withTrust(await V.verifyDataDoc(receipt), receipt?.signature?.kid, online ? await this.publishedKeyIds() : opts.publishedKids, V.relatedKids(receipt));
        }
        catch (e) {
            return no(["the receipt could not be verified: " + (e?.message || e)].concat(scope.why), receipt);
        }
        const why = scope.why.slice();
        if (!verification.integrity_valid)
            why.push("integrity failed: " + verification.checks.filter((c) => c.ok === false).map((c) => c.id).join(", "));
        if (verification.issuer_trusted !== true)
            why.push("signed by a key that is not in CrawlCheck's published key directory");
        if (why.length)
            return no(why, receipt, verification);
        const d = receipt.decision;
        let proceed = d === "allow" || (d === "warn" && !!opts.allowWarn);
        if (d === "require_confirmation") {
            if (opts.confirm) {
                try {
                    proceed = (await opts.confirm(receipt)) === true;
                }
                catch {
                    proceed = false;
                }
            }
        }
        if (!proceed)
            why.push(d === "warn" ? "decision is warn and allowWarn is not set" : d === "require_confirmation" ? (opts.confirm ? "a human did not confirm" : "decision is require_confirmation and no confirm() was given") : "decision is " + d);
        return { proceed, receipt, verification, header: proceed ? receiptHeader(receipt) : null, why };
    }
    /**
     * fetch() with the check where the action runs: guard() before the first request, and again before every redirect hop
     * to a new domain. The site is contacted only after its domain proceeds; a refused hop is never requested. Redirects
     * are followed by hand (GET/HEAD only), to http(s) only, at most maxHops (10). The receipt header is sent only to the
     * domain it names. In a browser a cross-origin redirect hides its target, so it is refused rather than followed blind.
     */
    async guardedFetch(url, opts = {}) {
        const action = opts.action ?? "read", max = opts.maxHops ?? 10, f = opts.fetch ? opts.fetch.bind(globalThis) : this.f;
        const init = Object.assign({}, opts.init || {}), method = String(init.method || "GET").toUpperCase();
        const hops = [], seen = new Map();
        let cur = url;
        for (let n = 0; n <= max; n++) {
            let u;
            try {
                u = new URL(cur);
            }
            catch {
                return { proceed: false, response: null, url: cur, hops, why: ["not a URL: " + cur] };
            }
            if (u.protocol !== "https:" && u.protocol !== "http:")
                return { proceed: false, response: null, url: cur, hops, why: ["refused a " + u.protocol + " URL"] };
            const dom = normalizeDomain(u.hostname);
            if (!dom)
                return { proceed: false, response: null, url: cur, hops, why: ["not a public domain name: " + u.hostname] };
            const op = { method: method, url: cur }; // op1: each hop's receipt names that exact request
            let g = seen.get(method + " " + cur);
            if (!g) {
                g = await this.guard(dom, action, Object.assign({}, opts, { operation: op }));
                seen.set(method + " " + cur, g);
            }
            const hop = { url: cur, domain: dom, proceed: g.proceed, decision: g.receipt ? String(g.receipt.decision) : null, why: g.why };
            hops.push(hop);
            if (!g.proceed)
                return { proceed: false, response: null, url: cur, hops, why: [dom + ": " + (g.why.join("; ") || "refused")] };
            const h = new Headers(init.headers || {});
            if (g.header)
                for (const [k, v] of Object.entries(g.header))
                    h.set(k, v);
            const res = await f(cur, Object.assign({}, init, { headers: h, redirect: "manual" }));
            hop.status = res.status;
            if (res.type === "opaqueredirect")
                return { proceed: false, response: null, url: cur, hops, why: ["the runtime hid the redirect target, so it cannot be checked"] };
            const loc = res.headers.get("location");
            if (![301, 302, 303, 307, 308].includes(res.status) || !loc)
                return { proceed: true, response: res, url: cur, hops, why: [] };
            if (method !== "GET" && method !== "HEAD")
                return { proceed: true, response: res, url: cur, hops, why: ["redirect not followed for " + method] };
            try {
                cur = new URL(loc, cur).toString();
            }
            catch {
                return { proceed: false, response: null, url: cur, hops, why: ["unreadable redirect target " + loc] };
            }
        }
        return { proceed: false, response: null, url: cur, hops, why: ["more than " + max + " redirects"] };
    }
    /** Look a domain up without sending it: only the first prefixLen hex characters of sha256(domain) leave this process (one more character per 413, up to 8). found false with ready true means no public measurement. */
    /** Make a signed lockfile for an MCP server (CrawlCheck reads tools/list; no tool is called). Save it; check with checkLock before every connect. */
    async mcpLock(url) { return this.req("GET", "/api/v1/mcp/lock", { url }); }
    /** Read the server's tools now (through CrawlCheck) and compare with a lockfile; the answer is signed. For a fully offline check, list the tools yourself and call checkLock. */
    async mcpLockCheck(lock, url) { return this.req("POST", "/api/v1/mcp/lock/check", undefined, { lock, url: url ?? lock?.server?.url ?? undefined }); }
    /** Tool-poisoning scan of a server URL or a tool list. */
    async mcpScan(target) { return (typeof target === "string" ? this.req("GET", "/api/v1/mcp/scan", { url: target }) : this.req("POST", "/api/v1/mcp/scan", undefined, { tools: target })); }
    async resolvePrivate(domain, prefixLen = 2) {
        const d = normalizeDomain(domain);
        if (!d)
            throw new Error("not a domain name: " + domain);
        if (prefixLen < 2 || prefixLen > 8)
            throw new Error("prefixLen must be 2 to 8");
        const h = await sha256Hex(d);
        let r;
        // pfx3: a 413 means more than 100 measured domains share the prefix (the corpus grows); send one more hex character and
        // try again, up to 8. Each extra character halves the bucket twice and still never names the domain.
        for (let n = prefixLen;; n++) {
            try {
                r = await this.req("GET", "/api/v1/resolve-prefix/" + h.slice(0, n));
                break;
            }
            catch (e) {
                if (e instanceof CrawlCheckError && e.status === 503)
                    return { found: false, ready: false, in_bucket: null, answer: null, verification: null, accepted: false, why: "the prefix index is not built yet" };
                if (e instanceof CrawlCheckError && e.status === 413 && n < 8)
                    continue;
                throw e;
            }
        }
        const hit = (r.answers || []).find((a) => a.domain_sha256 === h);
        if (!hit)
            return { found: false, ready: true, in_bucket: r.in_bucket ?? null, answer: null, verification: null, accepted: false };
        const verification = await this.verifyDocument(hit.answer);
        return { found: true, ready: true, in_bucket: r.in_bucket ?? null, answer: hit.answer, verification, accepted: !!verification.accepted && normalizeDomain(hit.answer.domain) === d };
    }
    /** For sites: check a CrawlCheck-Receipt header received with a request to host. accept only when the receipt is held, names host, has not expired, decided allow or warn, and verifies with a published key. */
    async checkReceiptHeader(headerValue, host) {
        const m = String(headerValue || "").match(/sha256=([0-9a-fA-F]{64})/) || String(headerValue || "").trim().match(/^([0-9a-fA-F]{64})$/);
        if (!m)
            return { accept: false, why: "no receipt digest in the header", check: null, verification: null };
        const sha = m[1].toLowerCase(), h = normalizeDomain(host);
        let r;
        try {
            r = await this.req("GET", "/api/v1/decisions/" + sha, { host: h });
        }
        catch (e) {
            if (e instanceof CrawlCheckError && e.status === 404)
                return { accept: false, why: "CrawlCheck holds no receipt with that digest", check: e.body, verification: null };
            throw e;
        }
        const rc = r.receipt || {}, verification = await this.verifyDocument(rc);
        return { accept: !!r.accept && !!verification.accepted && rc.sha256 === sha && normalizeDomain(rc.domain) === h, why: r.reason, check: r, verification };
    }
    /** Signed change feed (what changed since a time, optionally for one domain). */
    changes(q = {}) { return this.get("/api/v1/changes", q); }
    /** Report what happened after acting. Outcomes are kept apart from the signed record and never rewrite it. */
    outcome(body) { return this.post("/api/v1/outcome", body); }
    /** The registry record (RDAP) and lifecycle of a domain. */
    domain(domain) { return this.get("/api/v1/domain", { domain }); }
    // ── the records ──
    /** The whole observation in one shape: findings (gated like the site), trust, freshness, score ledger, evidence links. */
    machineRecord(q) { return this.get("/api/v1/machine-record", q); }
    /** Scan a domain now (free lane without a key; the licensed lane with one). */
    scan(domain) { return this.post("/api/v1/scan", { domain }); }
    /** A stored report by id, in the public v1 shape. */
    async report(id) { return this.req("GET", "/r/" + encodeURIComponent(id) + ".json"); }
    // ── why ──
    explain(q) { return this.get("/api/explain", q); }
    impact(q) { return this.get("/api/impact", q); }
    whatIf(q) { return this.get("/api/whatif", q); }
    locate(q) { return this.get("/api/locate", q); }
    // ── proof ──
    /** Every server-side verifier on one record. */
    verify(id) { return this.get("/api/verify", { id }); }
    /** The evidence bundle (anonymous: subject and leaves withheld; with a licence for the domain: complete). */
    bundle(id) { return this.get("/api/bundle", { id, download: "0" }); }
    /** Download the bundle and verify it here, with the offline verifier: no trust in the API's own answer. */
    async verifyOffline(id) { const b = await this.bundle(id); return withTrust(await verifyBundle(b), b?.manifest?.signature?.kid, await this.publishedKeyIds()); }
    /** A signed remediation receipt by its id (rc1:…). */
    async receipt(id) { const r = await this.get("/api/receipt", { id }); return r.receipt; }
    /** Fetch a receipt and verify its hash and signature here. key_published stays null offline: compare the key id with publishedKeyIds(). */
    async verifyReceiptOffline(id) { const rc = await this.receipt(id); return withTrust(await verifyReceipt(rc), rc?.signature?.kid, await this.publishedKeyIds()); }
    /** The observer's published Ed25519 key ids (RFC 7638 thumbprints), to close the one check a verifier cannot do offline. */
    async publishedKeyIds() {
        const d = await this.req("GET", "/.well-known/http-message-signatures-directory");
        const out = [];
        for (const k of (d?.keys ?? [])) {
            if (!k?.x)
                continue;
            const h = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify({ crv: k.crv, kty: k.kty, x: k.x }))));
            let s = "";
            for (const b of h)
                s += String.fromCharCode(b);
            out.push(btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
        }
        return out;
    }
    receipts(domain) { return this.get("/api/receipts", { domain }); }
    // ── the suite ──
    /** Run the published conformance fixtures through THIS package's verifier. Every result must be ok. */
    async conformance() {
        const ix = await this.req("GET", "/conformance/index.json");
        const results = [];
        for (const f of ix.fixtures) {
            const doc = await this.req("GET", new URL(f.file).pathname + new URL(f.file).search);
            const res = f.kind === "receipt" ? await verifyReceipt(doc) : await verifyBundle(doc);
            const got = {};
            for (const c of res.checks)
                got[c.id] = c.ok;
            const diffs = Object.keys(f.expected.checks).filter((k) => got[k] !== f.expected.checks[k]).map((k) => k + " expected " + f.expected.checks[k] + " got " + got[k]);
            if (res.verified !== f.expected.verified)
                diffs.push("verified expected " + f.expected.verified + " got " + res.verified);
            results.push({ name: f.name, group: f.group, ok: diffs.length === 0, diffs, must_reject: f.must_reject ?? null });
        }
        return { ok: results.every((r) => r.ok), results, built_at: ix.built_at, verifier_sha256: ix.verifier.sha256 };
    }
    async req(method, path, query, body) {
        const u = new URL(path, this.base + "/");
        if (query)
            for (const [k, v] of Object.entries(query))
                if (v !== undefined && v !== null)
                    u.searchParams.set(k, Array.isArray(v) ? v.join(",") : String(v));
        const h = Object.assign({ accept: "application/json" }, this.extra);
        if (this.key)
            h["x-crawlcheck-key"] = this.key;
        if (body !== undefined)
            h["content-type"] = "application/json";
        const r = await this.f(u.toString(), { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
        const t = await r.text();
        let j;
        try {
            j = t ? JSON.parse(t) : null;
        }
        catch {
            j = t;
        }
        if (!r.ok)
            throw new CrawlCheckError(r.status, u.pathname, j);
        return j;
    }
}
export default CrawlCheck;
