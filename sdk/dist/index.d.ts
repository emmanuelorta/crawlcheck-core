import type { paths, components } from "./gen/openapi.js";
import * as S from "./staple.js";
export type { paths, components };
/** One verifier check. ok: true passed, false FAILED, null could not run (why says why) - never a pass. */
export interface VerifyCheck {
    id: string;
    ok: boolean | null;
    why: string;
    [k: string]: unknown;
}
/**
 * Three separate answers. integrity_valid: hashes and the signature agree with the document. issuer_trusted: the
 * signing key is one CrawlCheck publishes (null offline: not decided). accepted: both - the only field to act on.
 * A document someone else signed with their own key is verified: true offline and accepted: false.
 */
export interface Trust {
    integrity_valid: boolean;
    issuer_trusted: boolean | null;
    accepted: boolean; /** conf2: the signing policy accepts this key for this object at its signing time (purpose, retired, compromised). null: not decided. */
    key_policy_valid?: boolean | null; /** conf2: stable reason: ok, ok_bound, key_wrong_purpose, key_not_yet_active, key_retired, key_compromised, key_unknown, no_signing_time, or related_<code> for a key the document leans on. */
    key_policy_code?: string | null;
}
/** conf2: the key directory and rotation record as the signing policy reads them (keyPolicyFrom / publishedKeyPolicy). */
export interface KeyPolicyInput {
    v: 2;
    kids: string[];
    keys: Record<string, {
        purpose: string;
        start: number | null;
    }>;
    retired: Record<string, {
        purpose: string;
        stopped: number | null;
    }>;
    compromised: Record<string, number>;
    rotation: boolean;
    read_at?: string;
    source?: string;
}
export interface KeyPolicyResult {
    ok: boolean | null;
    code: string;
    known: boolean;
    purpose: string | null;
    expected: string | null;
    why: string;
}
/** The signing policy as data (https://crawlcheck.io/keys#policy): object purposes, purpose chains, start times. */
export declare const KEY_POLICY: {
    v: 2;
    object_purpose: Record<string, string>;
    chains: Record<string, string[]>;
    starts: Record<string, string | null>;
    bound: Record<string, string>;
    purpose_aliases: Record<string, string>;
};
/** Build the policy input from a key directory you hold and, optionally, the rotation record saved with it. */
export declare const keyPolicyFrom: (directory: unknown, rotation?: unknown) => Promise<KeyPolicyInput>;
/** Does the signing policy accept this document's signing key for this object at its signing time? */
export declare const keyPolicyCheck: (doc: unknown, kp: KeyPolicyInput) => KeyPolicyResult;
/** Apply the signing policy to a verification: key_published (retired keys included), key_purpose, and the trust fields. */
export declare const applyKeyPolicy: <T>(res: T, doc: unknown, kp: KeyPolicyInput) => T & Trust;
export interface BundleVerification extends Partial<Trust> {
    verified: boolean;
    summary: string;
    report: {
        id?: string;
        domain?: string;
        scanned_at?: string;
    };
    checks: VerifyCheck[];
    experiences: number | null;
    note: string;
}
export interface ReceiptVerification extends Partial<Trust> {
    verified: boolean;
    summary: string;
    receipt: {
        id: string;
        domain: string;
        verdict: string;
        before: string;
        after: string;
    };
    checks: VerifyCheck[];
    note: string;
}
/** Verify an evidence bundle with no call to CrawlCheck (the same code as /crawlcheck-verify.mjs). */
export declare const verifyBundle: (b: unknown) => Promise<BundleVerification>;
/** Verify a remediation receipt with no call to CrawlCheck. */
export declare const verifyReceipt: (rc: unknown) => Promise<ReceiptVerification>;
export interface DocumentVerification extends Partial<Trust> {
    verified: boolean;
    summary: string;
    document: {
        kind: string;
        domain?: string;
        sha256: string;
    };
    checks: VerifyCheck[];
}
/** Verify a signed resolve answer, preflight decision receipt, data inventory, export part or deletion record offline. */
export declare const verifyDocument: (doc: unknown) => Promise<DocumentVerification & Trust>;
/** Verify a signed evidence export (and every bundle and receipt inside it) offline. */
export declare const verifyExport: (x: unknown) => Promise<{
    verified: boolean;
    summary: string;
    checks: VerifyCheck[];
    [k: string]: unknown;
}>;
/** Verify a signed dispute resolution offline (re-runs the published decision table over the recorded readings). */
export declare const verifyResolution: (x: unknown) => Promise<{
    verified: boolean;
    summary: string;
    checks: VerifyCheck[];
    [k: string]: unknown;
}>;
export declare const canon: (v: unknown) => string;
export declare const merkleRootHex: (hexLeaves: string[]) => Promise<string>;
export declare const otsInspect: (u8: Uint8Array) => Promise<{
    digest: string;
    attestations: Array<{
        kind: string;
        [k: string]: unknown;
    }>;
}>;
type S = components["schemas"];
export type MachineRecordV1 = S["MachineRecordV1"];
export type PublicReportV1 = S["PublicReportV1"];
export type EvidenceBundleV1 = S["EvidenceBundleV1"];
export type RemediationReceiptV1 = S["RemediationReceiptV1"];
export type ErrorV1 = S["ErrorV1"];
export type JsonObject = {
    [k: string]: unknown;
};
type Op<P extends keyof paths, M extends "get" | "post"> = paths[P] extends {
    [K in M]: infer O;
} ? O : never;
export type QueryOf<P extends keyof paths, M extends "get" | "post" = "get"> = Op<P, M> extends {
    parameters: {
        query?: infer Q;
    };
} ? NonNullable<Q> : Record<string, never>;
export type ResponseOf<P extends keyof paths, M extends "get" | "post" = "get"> = Op<P, M> extends {
    responses: {
        200: {
            content: {
                "application/json": infer J;
            };
        };
    };
} ? (unknown extends J ? JsonObject : J) : JsonObject;
export type BodyOf<P extends keyof paths> = Op<P, "post"> extends {
    requestBody?: {
        content: {
            "application/json": infer B;
        };
    };
} ? B : JsonObject;
export type Action = "read" | "cite" | "connect" | "transact" | "administer";
/** The header an agent sends with its request so the site can see it checked CrawlCheck first. */
export declare const RECEIPT_HEADER = "CrawlCheck-Receipt";
/** The domain the way CrawlCheck hashes and stores it: lowercased, no scheme, no leading www., no path or port. "" when not a domain. */
export declare function normalizeDomain(v: string): string;
/** { "CrawlCheck-Receipt": "v=1; sha256=..." } for a decision receipt. Send it only to the domain the receipt names, before expires_at. */
export declare function receiptHeader(receipt: {
    sha256: string;
}): Record<string, string>;
/** MCP tool lockfile (https://crawlcheck.io/spec/mcp-lockfile). A tool's hash is sha256 of the canonical JSON of {name, description, inputSchema, annotations}. */
export interface McpTool {
    name?: string;
    description?: string;
    inputSchema?: unknown;
    input_schema?: unknown;
    annotations?: unknown;
    [k: string]: unknown;
}
export interface McpLock {
    tools_sha256: string;
    tools: {
        name: string;
        sha256: string;
    }[];
    descriptions?: Record<string, string>;
    server?: {
        url?: string | null;
    } | null;
    approved_at?: string;
    [k: string]: unknown;
}
export interface McpLockCheck {
    verdict: "unchanged" | "changed";
    decision: "connect" | "block";
    approved_tools_sha256: string;
    current_tools_sha256: string;
    added: string[];
    removed: string[];
    modified: string[];
}
export declare function lockToolHash(t: McpTool): Promise<string>;
/** Hash a tools/list result the way a lockfile does: per tool, and the sorted per-tool hashes joined by \n. No network, no key. */
export declare function lockFromTools(tools: McpTool[]): Promise<{
    tools: {
        name: string;
        sha256: string;
    }[];
    tools_sha256: string;
    count: number;
}>;
/** Compare a lockfile with the tools a server lists now. Anything added, removed or changed means "block" until a person re-approves. Offline. */
export declare function checkLock(lock: McpLock, tools: McpTool[]): Promise<McpLockCheck>;
export interface PrivateLookup {
    found: boolean;
    ready: boolean;
    in_bucket: number | null;
    answer: JsonObject | null;
    verification: (DocumentVerification & Trust) | null;
    accepted: boolean;
    why?: string;
}
export interface ReceiptCheck {
    accept: boolean;
    why: string;
    check: JsonObject | null;
    verification: (DocumentVerification & Trust) | null;
}
export type Decision = "allow" | "warn" | "require_confirmation" | "block" | "unsupported";
export interface PreflightPolicy {
    max_age_hours?: number;
    on_warn?: "warn" | "require_confirmation" | "block";
    require_entity?: boolean;
    human_approval?: Action[];
    allow?: Action[];
    deny?: Action[];
    [k: string]: unknown;
}
export interface PreflightOptions {
    agent?: string;
    template?: string;
    policy?: PreflightPolicy; /** 8-128 characters of A-Z a-z 0-9 . _ : - signed into the receipt (replay binding). guard() sends a fresh one when you give none. */
    nonce?: string; /** The exact operation this decision is for (method + url, or an MCP tool); signed into the receipt. */
    operation?: Operation; /** An MCP server on this domain and the tool-list hash you approved (mcp-lockfile tools_sha256). The decision then reads the live tools, blocks when they differ, and its signed `assessed` block names exactly what it covered. https://crawlcheck.io/spec/mcp-lockfile */
    mcp?: {
        url: string;
        tools_sha256?: string;
    };
}
/** What a receipt can be scoped to. Send only the keys that apply; CrawlCheck signs them back exactly as sent. https://crawlcheck.io/spec/guard#operation */
export interface Operation {
    method?: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
    url?: string;
    tool?: string;
    tool_schema_sha256?: string;
    scopes?: string[];
}
/** The operation for calling an MCP tool: its name, the sha256 of its definition (as in the lockfile) and the scopes you will use. */
export declare function toolOperation(tool: McpTool, scopes?: string[]): Promise<Operation>;
/** A signed crawlcheck-decision receipt. Verify it with verifyDocument (or let guard() do it). */
export interface DecisionReceipt {
    kind: "crawlcheck-decision";
    domain: string;
    action: Action;
    decision: Decision;
    sha256: string;
    signature: {
        kid: string;
        [k: string]: unknown;
    };
    resolve?: {
        sha256: string;
        kid: string;
    };
    alternatives?: JsonObject[];
    [k: string]: unknown;
}
export interface GuardOptions extends PreflightOptions {
    /** Proceed on "warn" too. Default false: warn does not proceed. */
    allowWarn?: boolean;
    /** Called on "require_confirmation"; proceed only if it resolves true. Without it, require_confirmation does not proceed. */
    confirm?: (receipt: DecisionReceipt) => boolean | Promise<boolean>;
    /** Read the published key directory (default true). With false, pass publishedKids: a guard never accepts a receipt without checking who signed it. */
    onlineKeys?: boolean;
    /** Pinned CrawlCheck key ids, for offline use with onlineKeys: false. */
    publishedKids?: string[];
    /** conf2: a pinned key policy (keyPolicyFrom(savedDirectory, savedRotation)), for offline use with onlineKeys: false. Checks key purpose too. */
    keyPolicy?: KeyPolicyInput;
    /** Testing clock (ms since epoch). Default Date.now(). */
    now?: number;
}
/** The longest a receipt may stay valid, per action (seconds). A receipt that claims longer is refused. Published at https://crawlcheck.io/spec/guard */
export declare const ACTION_MAX_LIFETIME_S: Record<string, number>;
/** The most clock skew a receipt may claim (seconds). */
export declare const MAX_CLOCK_SKEW_S = 300;
export interface DecisionWant {
    domain: string;
    action: Action | string;
    nonce?: string | null;
    now?: number;
    operation?: Operation | null;
}
/**
 * Is this receipt about the operation you are about to perform? Checks the scope only (kind, domain, action, nonce,
 * time window, per-action lifetime, known decision, resolve binding); the signature and issuer are checked by
 * verifyDocument. guard() runs both. https://crawlcheck.io/spec/guard
 */
export declare function checkDecision(receipt: unknown, want: DecisionWant): {
    ok: boolean;
    why: string[];
};
export interface GuardResult {
    proceed: boolean;
    receipt: DecisionReceipt | null;
    verification: (DocumentVerification & Trust) | null;
    header: Record<string, string> | null;
    why: string[];
    split_view?: LogFork[]; /** Set when the domain was refused from the held revocation list, with no network call. */
    revoked?: RevokedEntry;
}
export interface GuardedFetchOptions extends GuardOptions {
    action?: Action;
    init?: RequestInit;
    maxHops?: number;
    fetch?: typeof fetch;
}
export interface GuardedHop {
    url: string;
    domain: string;
    proceed: boolean;
    decision: string | null;
    why: string[];
    status?: number;
}
export interface GuardedFetchResult {
    proceed: boolean;
    response: Response | null;
    url: string;
    hops: GuardedHop[];
    why: string[];
}
export interface LogHead {
    kind: "crawlcheck-log-sth";
    log_id: string;
    batch: number;
    first_index: number;
    batch_size: number;
    tree_size: number;
    batch_root: string;
    prev_sth_sha256: string | null;
    created_at: string;
    sha256: string;
    signature: JsonObject;
    [k: string]: unknown;
}
export interface LogFork {
    kind: "two_heads_for_one_batch" | "chain_break" | "size_mismatch" | "inconsistent_head";
    batch: number;
    why: string;
    a: LogHead;
    b: LogHead;
    detected_at: string;
    proof: string;
}
export interface LogStore {
    v: 1;
    log_id: string;
    heads: Record<string, {
        batch: number;
        sha256: string;
        first_index: number;
        batch_size: number;
        tree_size: number;
        prev_sth_sha256: string | null;
        created_at: string | null;
        sth: LogHead;
    }>;
    forks: LogFork[];
    witnessed: {
        batch: number;
        sha256: string;
        at: string | null;
        run_id: string | null;
    } | null;
}
export interface LogObservation {
    state: "new" | "known" | "fork" | "invalid" | "none";
    why?: string;
    fork?: LogFork;
}
export interface LogCheckResult {
    consistent: boolean;
    forks: LogFork[];
    all_forks: number;
    witnessed: {
        batch: number;
        sha256: string;
        at: string | null;
        run_id: string | null;
        token: boolean | null;
        why: string;
        observed: string;
        warning?: string;
    } | null;
    unwitnessed: {
        batch: number;
        sha256: string;
        created_at: string | null;
    }[];
    stale_unwitnessed: {
        batch: number;
        sha256: string;
        created_at: string | null;
    }[];
    summary: string;
}
export declare const LOG_ID: string;
/** A new, empty transparency-log store (plain JSON: persist it between runs). */
export declare const newLogStore: () => LogStore;
/** Check one signed tree head against the store and keep it. A fork carries both contradicting signed heads. */
export declare const logObserve: (store: LogStore, sth: unknown, opts?: {
    publishedKids?: string[];
    maxHeads?: number;
}) => Promise<LogObservation>;
/** Check the head inside a Resolve answer (transparency.sth), if it carries one. */
export declare const logObserveAnswer: (store: LogStore, answer: unknown, opts?: {
    publishedKids?: string[];
}) => Promise<LogObservation>;
/** The signed heads a store holds, newest first: what a client sends its peers. */
export declare const logHeads: (store: LogStore, limit?: number) => LogHead[];
/** Gossip: check another client's heads against this store. */
export declare const logGossip: (store: LogStore, sths: unknown[], opts?: {
    publishedKids?: string[];
}) => Promise<{
    forks: LogFork[];
    results: (LogObservation & {
        batch: number;
        sha256: string;
    })[];
}>;
/** Verify the outside witness's co-signature: a GitHub OIDC JWT (RS256) whose audience is crawlcheck-sth:<head sha256>. */
export declare const verifyWitnessToken: (token: string, sthSha256: string, jwks: unknown) => Promise<{
    ok: boolean | null;
    why: string;
    claims?: JsonObject;
}>;
export declare const GITHUB_OIDC_JWKS = "https://token.actions.githubusercontent.com/.well-known/jwks";
export type StapleDecisions = {
    read: string | null;
    cite: string | null;
    connect: string | null;
    transact: string | null;
};
export interface StapleCheck {
    valid: boolean;
    reason: string | null;
    expired: boolean;
    record: Record<string, string> | null;
    decisions: StapleDecisions | null;
}
/** Parse a ccr1 record (CrawlCheck-Staple header value or <domain>._v.crawlcheck.io TXT). */
export declare const parseStaple: (record: string) => {
    fields: Record<string, string>;
    body: string;
    sig: string;
};
/** The CrawlCheck-Staple header of a response (fetch Response, Headers or a plain header map), or null. */
export declare const stapleFromResponse: (res: unknown) => string | null;
/** Verify a staple offline: published key, signature, the record names opts.host (or a parent), fresh_until in the future. Expired or foreign staples are never valid. */
export declare const stapleCheck: (record: string, opts: {
    host: string;
    publishedKids: string[];
    now?: number;
}) => Promise<StapleCheck>;
export interface RevokedEntry {
    domain?: string;
    actions: string[];
    causes: string[];
    state: string | null;
    since: string | null;
    updated_at: string | null;
}
/** The signed revocation list held locally (plain JSON: persist it between runs). */
export interface RevocationStore {
    v: 1;
    generated_at: string | null;
    seq: string | null;
    synced_at: string | null;
    revoked: Record<string, RevokedEntry>;
}
export interface RevocationSync {
    applied: boolean;
    full: boolean;
    added: number;
    removed: number;
    reason: string | null;
    total: number;
    generated_at: string | null;
    verification?: DocumentVerification & Trust;
}
/** A new, empty revocation store. */
export declare const newRevocationStore: () => RevocationStore;
/** Apply a VERIFIED crawlcheck-revocations document (full list or ?since= delta) to a store. */
export declare const applyRevocations: (store: RevocationStore, doc: unknown, now?: number) => {
    applied: boolean;
    full: boolean;
    added: number;
    removed: number;
    reason: string | null;
};
/** The entry that revokes this domain (or a parent domain) for this action, or null. Offline. */
export declare const revokedFor: (store: RevocationStore, domain: string, action?: string) => (RevokedEntry & {
    domain: string;
}) | null;
export interface McpPreflightOptions extends PreflightOptions {
    /** Proceed on warn too (default false). */
    allowWarn?: boolean;
    /** Called on require_confirmation (and, with confirmDestructive, before a destructive tool call); the connect or call proceeds only if it resolves true. */
    confirm?: (receipt: DecisionReceipt & {
        tool?: string;
        annotations?: unknown;
    }) => boolean | Promise<boolean>;
    /** An approved lockfile (mcpLock / lockFromTools): the tools the server lists after connecting must match it, and only tools in it may be called. */
    lock?: McpLock;
    /** Ask confirm() before a tool annotated destructive (destructiveHint true, or readOnlyHint false with openWorldHint true). */
    confirmDestructive?: boolean;
    /** Re-decide the host when the cached connect receipt is older than this (default: until its expires_at). */
    maxAgeMs?: number;
    /** A local (stdio) server has no host to resolve: "allow" (default) or "refuse". */
    local?: "allow" | "refuse";
    /** The server URL when the transport does not expose it. */
    serverUrl?: string;
    onlineKeys?: boolean;
}
export interface McpPreflightState {
    url: string | null;
    host: string | null;
    receipt: DecisionReceipt | null;
    verification: (DocumentVerification & Trust) | null;
    decidedAt: number;
    lockCheck: McpLockCheck | null;
    approved: Set<string> | null;
}
export interface McpPreflightHooks {
    state: McpPreflightState;
    beforeConnect(url: string | null | undefined): Promise<{
        local: boolean;
        host?: string;
        receipt: DecisionReceipt | null;
        verification?: DocumentVerification & Trust;
    }>;
    afterConnect(tools: McpTool[]): Promise<McpLockCheck | null>;
    beforeToolCall(name: string, annotations?: unknown): Promise<{
        receipt: DecisionReceipt | null;
    }>;
}
/** Thrown by the hooks when a connect or tools/call is refused; the request was never sent. */
export declare const McpPreflightRefused: new (stage: "connect" | "tools/call", why: string, detail?: {
    receipt?: DecisionReceipt | null;
    lock?: McpLockCheck | null;
    verification?: unknown;
}) => Error & {
    stage: "connect" | "tools/call";
    why: string;
    receipt: DecisionReceipt | null;
    lock: McpLockCheck | null;
    verification: unknown;
};
/** The two hooks (beforeConnect, beforeToolCall) plus afterConnect for lockfiles, for any MCP client stack. */
export declare const mcpPreflight: (cc: CrawlCheck, opts?: McpPreflightOptions) => McpPreflightHooks;
/** Wrap an MCP client (the official @modelcontextprotocol/sdk Client, or anything with connect(transport) and callTool(params)) so both run the preflight first. Returns the same client with client.preflight set. */
export declare const withPreflight: <C extends {
    connect: (...a: any[]) => Promise<any>;
    callTool: (...a: any[]) => Promise<any>;
}>(client: C, cc: CrawlCheck, opts?: McpPreflightOptions) => C & {
    preflight: McpPreflightHooks;
};
/** The server URL a transport will talk to, if it exposes one (Streamable HTTP and SSE transports do). */
export declare const transportUrl: (transport: unknown) => string | null;
export interface ClientOptions {
    /** Licence key (cc_ + 32 hex). Without one, licence-gated fields come back withheld, exactly as on the website. */
    key?: string;
    /** API origin. Default https://crawlcheck.io */
    base?: string;
    /** A fetch implementation (default: globalThis.fetch). */
    fetch?: typeof fetch;
    /** Extra headers for every request. */
    headers?: Record<string, string>;
    /** Transparency-log store (newLogStore()). Every Resolve answer's signed tree head is checked against it; keep it across runs to catch a split view. Default: a fresh in-memory store. */
    logStore?: LogStore;
    /** Revocation store (newRevocationStore()). syncRevocations() fills it; guard() refuses a listed domain for a listed action without a network call. Default: a fresh, empty store. */
    revocationStore?: RevocationStore;
    /** Private mode: resolve() and resolveFor() send only a 2-hex prefix of sha256(domain) (resolvePrivate), never the domain. A domain with no public measurement then raises a 404 CrawlCheckError instead of a just-in-time answer, which would name it. preflight() and guard() still name the domain: a receipt is bound to it. */
    privateLookups?: boolean;
}
export declare class CrawlCheckError extends Error {
    readonly status: number;
    readonly body: unknown;
    readonly path: string;
    constructor(status: number, path: string, body: unknown);
    /** true when the answer was "this needs a licence for the domain (or the owner's session)". */
    get locked(): boolean;
}
export interface ConformanceResult {
    name: string;
    group: string;
    ok: boolean;
    diffs: string[];
    must_reject: string | null;
}
export declare class CrawlCheck {
    readonly base: string;
    private readonly key?;
    private readonly f;
    private readonly extra;
    /** The transparency-log store this client checks every signed tree head against. Persist it (JSON) between runs. */
    readonly log: LogStore;
    /** The signed revocation list this client holds. Persist it (JSON) between runs; syncRevocations() keeps it current. */
    readonly revocations: RevocationStore;
    /** Private mode (ClientOptions.privateLookups). */
    readonly privateLookups: boolean;
    constructor(opts?: ClientOptions);
    /** Any documented GET, typed from the OpenAPI document: client.get("/api/explain", { domain: "example.com" }). */
    get<P extends keyof paths>(path: P, query?: QueryOf<P, "get">): Promise<ResponseOf<P, "get">>;
    /** Any documented POST, typed from the OpenAPI document. */
    post<P extends keyof paths>(path: P, body: BodyOf<P> | JsonObject, query?: QueryOf<P, "post">): Promise<ResponseOf<P, "post">>;
    /** The signed ResolveV1 answer: crawl policy, delivery, machine files, capabilities, entity, findings, freshness and a decision per action. */
    resolve(domain: string): Promise<ResponseOf<"/api/v1/resolve", "get">>;
    private kidCache;
    /** The key ids CrawlCheck publishes (/.well-known/http-message-signatures-directory), cached for an hour. */
    publishedKids(): Promise<string[]>;
    /**
     * The verdict for a domain, preferring a valid staple the site sent (opts.staple, or opts.response's CrawlCheck-Staple
     * header): no request to CrawlCheck is made when the staple verifies. An expired, foreign or invalid staple is ignored
     * and the signed answer is fetched instead; source says which was used and staple says why.
     */
    resolveFor(domain: string, opts?: {
        staple?: string | null;
        response?: unknown;
    }): Promise<{
        source: "staple" | "network";
        decisions: StapleDecisions;
        staple: StapleCheck | null;
        answer?: unknown;
    }>;
    /** Up to 100 domains in one call; each answer is a full signed ResolveV1 document. */
    resolveBatch(domains: string[]): Promise<any>;
    /** Split-view check: the current head, GitHub's witness co-signature on the last witnessed head, and the chain from it down to every head this client holds. Reports the heads it holds to /api/v1/log/gossip unless report is false. */
    logCheck(opts?: {
        report?: boolean;
        maxWalk?: number;
        maxUnwitnessedMinutes?: number;
    }): Promise<LogCheckResult>;
    /** Check heads another client sent (logHeads on their side) against this client's store. */
    logGossip(sths: unknown[]): Promise<{
        forks: LogFork[];
        results: (LogObservation & {
            batch: number;
            sha256: string;
        })[];
    }>;
    /**
     * Fetch the signed revocation list (a ?since= delta when the store already holds one), verify it (integrity and a
     * published signing key) and apply it. A delta that no longer reaches back is replaced by the full list. Nothing is
     * applied from a document that does not verify. Call it on a timer (poll_seconds, 60) and before going offline.
     */
    syncRevocations(opts?: {
        full?: boolean;
    }): Promise<RevocationSync>;
    /** The policy engine: a signed decision receipt (allow | warn | require_confirmation | block | unsupported). A policy can only make the decision stricter. */
    preflight(domain: string, action?: Action, opts?: PreflightOptions): Promise<DecisionReceipt>;
    private kpCache;
    /** conf2: the key directory and rotation record, read now (cached 10 minutes), as the signing policy reads them. */
    publishedKeyPolicy(): Promise<KeyPolicyInput>;
    /** Verify a signed document here. With onlineKeys (default), its signing key must also be in the published directory and the signing policy must accept it. */
    verifyDocument(doc: unknown, onlineKeys?: boolean): Promise<DocumentVerification & Trust>;
    /**
     * Preflight, verify the receipt, check it is for THIS operation, and decide. Proceeds on allow; warn only with allowWarn;
     * require_confirmation only if confirm() says yes; block, unsupported and every failure never (fail closed: an error,
     * an unreachable CrawlCheck, a malformed, foreign, expired, replayed or out-of-scope receipt all return proceed false
     * with why[]). Passes the acceptance suite at https://crawlcheck.io/spec/guard
     */
    guard(domain: string, action?: Action, opts?: GuardOptions): Promise<GuardResult>;
    /**
     * fetch() with the check where the action runs: guard() before the first request, and again before every redirect hop
     * to a new domain. The site is contacted only after its domain proceeds; a refused hop is never requested. Redirects
     * are followed by hand (GET/HEAD only), to http(s) only, at most maxHops (10). The receipt header is sent only to the
     * domain it names. In a browser a cross-origin redirect hides its target, so it is refused rather than followed blind.
     */
    guardedFetch(url: string, opts?: GuardedFetchOptions): Promise<GuardedFetchResult>;
    /** Look a domain up without sending it: only the first prefixLen hex characters of sha256(domain) leave this process (one more character per 413, up to 8). found false with ready true means no public measurement. */
    /** Make a signed lockfile for an MCP server (CrawlCheck reads tools/list; no tool is called). Save it; check with checkLock before every connect. */
    /** One signed verdict on a business fact (phone, address, hours, service_area) against what the business publishes: GET /api/v1/field-check. */
    fieldCheck(domain: string, field: FactField, value: string): Promise<JsonObject>;
    mcpLock(url: string): Promise<McpLock & JsonObject>;
    /** Read the server's tools now (through CrawlCheck) and compare with a lockfile; the answer is signed. For a fully offline check, list the tools yourself and call checkLock. */
    mcpLockCheck(lock: McpLock, url?: string): Promise<McpLockCheck & JsonObject>;
    /** Tool-poisoning scan of a server URL or a tool list. */
    mcpScan(target: string | McpTool[]): Promise<JsonObject>;
    resolvePrivate(domain: string, prefixLen?: number): Promise<PrivateLookup>;
    /** For sites: check a CrawlCheck-Receipt header received with a request to host. accept only when the receipt is held, names host, has not expired, decided allow or warn, and verifies with a published key. */
    checkReceiptHeader(headerValue: string, host: string): Promise<ReceiptCheck>;
    /** Signed change feed (what changed since a time, optionally for one domain). */
    changes(q?: QueryOf<"/api/v1/changes">): Promise<JsonObject>;
    /** Report what happened after acting. Outcomes are kept apart from the signed record and never rewrite it. */
    outcome(body: JsonObject & {
        domain: string;
        action: Action;
    }): Promise<JsonObject>;
    /** The registry record (RDAP) and lifecycle of a domain. */
    domain(domain: string): Promise<JsonObject>;
    /** The whole observation in one shape: findings (gated like the site), trust, freshness, score ledger, evidence links. */
    machineRecord(q: QueryOf<"/api/v1/machine-record">): Promise<MachineRecordV1>;
    /** Scan a domain now (free lane without a key; the licensed lane with one). */
    scan(domain: string): Promise<PublicReportV1>;
    /** A stored report by id, in the public v1 shape. */
    report(id: string): Promise<PublicReportV1>;
    explain(q: QueryOf<"/api/explain">): Promise<JsonObject>;
    impact(q: QueryOf<"/api/impact">): Promise<JsonObject>;
    whatIf(q: QueryOf<"/api/whatif">): Promise<JsonObject>;
    locate(q: QueryOf<"/api/locate">): Promise<JsonObject>;
    /** Every server-side verifier on one record. */
    verify(id: string): Promise<JsonObject>;
    /** The evidence bundle (anonymous: subject and leaves withheld; with a licence for the domain: complete). */
    bundle(id: string): Promise<EvidenceBundleV1>;
    /** Download the bundle and verify it here, with the offline verifier: no trust in the API's own answer. */
    verifyOffline(id: string): Promise<BundleVerification & Trust>;
    /** A signed remediation receipt by its id (rc1:…). */
    receipt(id: string): Promise<RemediationReceiptV1>;
    /** Fetch a receipt and verify its hash and signature here. key_published stays null offline: compare the key id with publishedKeyIds(). */
    verifyReceiptOffline(id: string): Promise<ReceiptVerification & Trust>;
    /** The observer's published Ed25519 key ids (RFC 7638 thumbprints), to close the one check a verifier cannot do offline. */
    publishedKeyIds(): Promise<string[]>;
    receipts(domain: string): Promise<JsonObject>;
    /** Run the published conformance fixtures through THIS package's verifier. Every result must be ok. */
    conformance(): Promise<{
        ok: boolean;
        results: ConformanceResult[];
        built_at: string;
        verifier_sha256: string;
    }>;
    private req;
}
/**
 * Agent tools (1.6.0; crawlcheck_verify_fact and decision facts 1.7.0): CrawlCheck as tools any agent framework can register, so the check happens inside the agent's
 * own tool loop. crawlcheck_check_site returns the signed, verified decision for an action on a site (with the business facts the site publishes); crawlcheck_verify_fact checks one phone, address or hours value; crawlcheck_fetch
 * fetches a page only after its domain (and every redirect hop) proceeds. Both fail closed, exactly like guard().
 * toolsFor() shapes them for OpenAI function calling, Anthropic tool use, the Vercel AI SDK or an MCP server.
 */
export type FactField = "phone" | "address" | "hours" | "service_area";
export interface AgentTool {
    name: string;
    description: string;
    parameters: JsonObject;
    execute: (args: any) => Promise<JsonObject>;
}
export interface AgentToolOptions extends GuardOptions {
    maxChars?: number;
}
export declare function agentTools(cc: CrawlCheck, opts?: AgentToolOptions): AgentTool[];
export type ToolFormat = "openai" | "anthropic" | "vercel" | "mcp";
/** Shape agentTools() for a framework. call(name, args) runs a tool by name for formats that hand you the call (OpenAI, Anthropic, MCP). For the Vercel AI SDK wrap each parameters object: tool({ description, parameters: jsonSchema(t.parameters), execute: t.execute }). */
export declare function toolsFor(format: ToolFormat, tools: AgentTool[]): {
    tools: unknown;
    call: (name: string, args: unknown) => Promise<JsonObject>;
};
export default CrawlCheck;
