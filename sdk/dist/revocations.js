// Offline revocations (rvd1): hold CrawlCheck's signed revocation list and refuse a listed domain for a listed action
// with no network call. A store is plain JSON; persist it between runs. Only a document whose signature was checked
// should be applied (the client's syncRevocations does that). https://crawlcheck.io/docs/api#revocations
/** An empty store. */
export function newRevocationStore() { return { v: 1, generated_at: null, seq: null, synced_at: null, revoked: {} }; }
function norm(d) { return String(d || "").toLowerCase().trim().replace(/\.$/, "").replace(/^www\./, ""); }
/**
 * Apply a verified crawlcheck-revocations document. A full list (since null) replaces the store; a delta replaces each
 * revoked entry it carries and removes each cleared or lifted one. A delta that is not complete (delta_complete false),
 * or one older than the store, is refused: fetch the full list instead. Returns { applied, full, added, removed, reason }.
 */
export function applyRevocations(store, doc, now) {
    const out = { applied: false, full: false, added: 0, removed: 0, reason: null };
    if (!store || store.v !== 1) {
        out.reason = "not a revocation store (newRevocationStore())";
        return out;
    }
    if (!doc || doc.kind !== "crawlcheck-revocations" || !Array.isArray(doc.revoked)) {
        out.reason = "not a crawlcheck-revocations document";
        return out;
    }
    if (store.generated_at && doc.generated_at && Date.parse(doc.generated_at) < Date.parse(store.generated_at)) {
        out.reason = "older than the list already held";
        return out;
    }
    const full = !doc.since;
    if (!full && doc.delta_complete === false) {
        out.reason = "the delta does not reach back to " + doc.since + ": fetch the full list";
        return out;
    }
    if (!full && store.generated_at && Date.parse(doc.since) > Date.parse(store.generated_at)) {
        out.reason = "the delta starts after the list held (" + store.generated_at + "): fetch the full list";
        return out;
    }
    const next = full ? {} : Object.assign({}, store.revoked);
    for (const l of doc.cleared || []) {
        const d = norm(l && l.domain);
        if (d && next[d]) {
            delete next[d];
            out.removed++;
        }
    }
    for (const e of doc.revoked) {
        const d = norm(e && e.domain);
        if (!d || !Array.isArray(e.actions))
            continue;
        if (!next[d])
            out.added++;
        next[d] = { actions: e.actions.slice(), causes: Array.isArray(e.causes) ? e.causes.slice() : [], state: e.state || null, since: e.since || null, updated_at: e.updated_at || null };
    }
    if (full)
        out.removed = Math.max(0, Object.keys(store.revoked).filter((d) => !next[d]).length);
    store.revoked = next;
    store.generated_at = doc.generated_at || null;
    store.seq = doc.seq != null ? String(doc.seq) : null;
    store.synced_at = new Date(now || Date.now()).toISOString();
    out.applied = true;
    out.full = full;
    return out;
}
/**
 * Is this domain (or a parent domain) revoked for this action in the store? Returns the entry with the domain that
 * matched, or null. Reading and citing are never revoked by this list.
 */
export function revokedFor(store, domain, action) {
    if (!store || !store.revoked)
        return null;
    const labels = norm(domain).split(".");
    for (let i = 0; i < labels.length - 1; i++) {
        const d = labels.slice(i).join("."), e = store.revoked[d];
        if (e && (!action || e.actions.indexOf(action) >= 0))
            return Object.assign({ domain: d }, e);
    }
    return null;
}
