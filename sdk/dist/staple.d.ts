/** Parse a ccr1 record ("v=ccr1;d=...;s=..."); quoted TXT strings from dig are joined. */
export function parseStaple(record: any): {
    fields: {};
    body: string;
    sig: string;
};
/** The staple a response carries, if any (a fetch Response, a Headers object or a plain header map). */
export function stapleFromResponse(res: any): any;
/**
 * Check a staple offline. opts.host: the host the agent is talking to (required for a usable result);
 * opts.publishedKids: the key ids CrawlCheck publishes (from /.well-known/http-message-signatures-directory);
 * opts.now: epoch ms (default Date.now()).
 * Returns { valid, reason, expired, record, decisions } and never throws.
 */
export function stapleCheck(record: any, opts?: {}): Promise<{
    valid: boolean;
    reason: null;
    expired: boolean;
    record: null;
    decisions: null;
}>;
