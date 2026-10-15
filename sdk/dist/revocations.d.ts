/** An empty store. */
export function newRevocationStore(): {
    v: number;
    generated_at: null;
    seq: null;
    synced_at: null;
    revoked: {};
};
/**
 * Apply a verified crawlcheck-revocations document. A full list (since null) replaces the store; a delta replaces each
 * revoked entry it carries and removes each cleared or lifted one. A delta that is not complete (delta_complete false),
 * or one older than the store, is refused: fetch the full list instead. Returns { applied, full, added, removed, reason }.
 */
export function applyRevocations(store: any, doc: any, now: any): {
    applied: boolean;
    full: boolean;
    added: number;
    removed: number;
    reason: null;
};
/**
 * Is this domain (or a parent domain) revoked for this action in the store? Returns the entry with the domain that
 * matched, or null. Reading and citing are never revoked by this list.
 */
export function revokedFor(store: any, domain: any, action: any): any;
