/** A new, empty store. It is plain JSON: keep it across runs (a file, a KV value) so later heads are checked against earlier ones. */
export function newLogStore(): {
    v: number;
    log_id: string;
    heads: {};
    forks: never[];
    witnessed: null;
};
/**
 * Check one signed tree head (kind crawlcheck-log-sth) against everything the store already holds, then keep it.
 * Returns { state: "new" | "known" | "fork" | "invalid", why?, fork? }. invalid means the document is not a head
 * CrawlCheck signed (it proves nothing either way); fork means two signed heads that contradict each other.
 * opts.publishedKids: key ids from the published directory; a head signed by another key is invalid.
 */
export function logObserve(store: any, sth: any, opts?: {}): Promise<{
    state: string;
    fork: {
        kind: any;
        batch: any;
        why: any;
        a: any;
        b: any;
        detected_at: string;
        proof: string;
    };
} | {
    state: string;
    why: string;
} | {
    state: string;
    why?: undefined;
}>;
/** Observe the head inside a Resolve answer (transparency.sth), if it has one. */
export function logObserveAnswer(store: any, answer: any, opts?: {}): Promise<{
    state: string;
    fork: {
        kind: any;
        batch: any;
        why: any;
        a: any;
        b: any;
        detected_at: string;
        proof: string;
    };
} | {
    state: string;
    why: string;
} | {
    state: string;
    why?: undefined;
} | {
    state: string;
}>;
/** The signed heads this store holds, newest first: what a client sends its peers. */
export function logHeads(store: any, limit?: number): any[];
/** Gossip: check heads another client holds against this store. Returns { forks, results }. */
export function logGossip(store: any, sths: any, opts?: {}): Promise<{
    forks: any;
    results: (({
        batch: any;
        sha256: any;
    } & {
        state: string;
        fork: {
            kind: any;
            batch: any;
            why: any;
            a: any;
            b: any;
            detected_at: string;
            proof: string;
        };
    }) | ({
        batch: any;
        sha256: any;
    } & {
        state: string;
        why: string;
    }) | ({
        batch: any;
        sha256: any;
    } & {
        state: string;
        why?: undefined;
    }))[];
}>;
/**
 * Verify a witness co-signature: the JWT's RS256 signature against GitHub's published keys (jwks: the JSON from
 * https://token.actions.githubusercontent.com/.well-known/jwks), its issuer, repository, workflow and audience
 * crawlcheck-sth:<sthSha256>. exp is not checked: the token is a record of what the witness saw when it ran.
 * Returns { ok: true | false | null, why, claims? }; null when GitHub no longer publishes the key that signed it.
 */
export function verifyWitnessToken(token: any, sthSha256: any, jwks: any): Promise<{
    ok: boolean;
    why: string;
    claims?: undefined;
} | {
    ok: null;
    why: string;
    claims: any;
} | {
    ok: boolean;
    why: string;
    claims: any;
}>;
/**
 * Online check of a store against the log and its outside witness. get(path) must return parsed JSON from
 * https://crawlcheck.io (the SDK clients pass their own). Steps: observe the current head; fetch the last witnessed
 * head and verify GitHub's co-signature; walk the chain from the witnessed head down to the oldest head this store
 * holds (at most opts.maxWalk batches), observing every link, so any head this client was shown that the witness's
 * chain does not contain surfaces as a fork. Heads newer than the witnessed one are listed as unwitnessed.
 */
export function logCheck(store: any, get: any, opts?: {}): Promise<{
    consistent: boolean;
    forks: any;
    all_forks: any;
    witnessed: {
        batch: any;
        sha256: any;
        at: any;
        run_id: any;
        token: boolean | null;
        why: string;
        observed: string;
    } | null;
    unwitnessed: {
        batch: number;
        sha256: any;
        created_at: any;
    }[];
    stale_unwitnessed: {
        batch: number;
        sha256: any;
        created_at: any;
    }[];
    summary: string;
}>;
export const LOG_ID: "crawlcheck-resolve-log-v1";
export const GITHUB_OIDC_ISSUER: "https://token.actions.githubusercontent.com";
export const WITNESS_REPOSITORY: "emmanuelorta/crawlcheck";
export const WITNESS_WORKFLOW_PREFIX: "emmanuelorta/crawlcheck/.github/workflows/log-witness.yml@refs/heads/";
