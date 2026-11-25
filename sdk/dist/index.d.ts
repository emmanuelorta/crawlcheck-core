import type { paths, components } from "./gen/openapi.js";
import * as S from "./staple.js";
export type { paths, components };
export interface Acceptance {
    integrity_valid: boolean;
    issuer_trusted: boolean | null;
    key_policy_valid: boolean | null;
    freshness_valid: boolean;
    subject_matches: boolean;
    operation_matches: boolean | null;
    replay_safe: boolean | null;
    baseline_matches: boolean | null;
    assessment_complete: boolean;
    decision: string | null;
    policy_source: string | null;
    evidence_level: "A" | "B" | "C" | null;
    policy_result: "proceed" | "pause" | "deny";
    accepted: boolean;
    why: string[];
}
export type ContinuityEffect = "proceed" | "proceed_recorded" | "refresh" | "pause_tool" | "pause" | "deny";
export interface ContinuityPolicy {
    v?: 1;
    id?: string;
    max_baseline_age_days?: number;
    effects?: Partial<Record<string, ContinuityEffect>>;
    allow_integrity_override?: boolean;
}
export interface ContinuityException {
    tool?: string;
    class: string;
    until?: string;
    by?: string;
    reason?: string;
}
export interface ContinuityEvent {
    class: string;
    tool: string | null;
    why: string;
    policy_effect: ContinuityEffect;
    effect: ContinuityEffect;
    exception?: {
        by: string | null;
        reason: string | null;
        until: string | null;
    };
    detail?: string;
}
export interface ContinuityRecord {
    kind: "crawlcheck-continuity-record";
    v: 1;
    checked_at: string;
    mode: "observe" | "review" | "enforce";
    server: string | null;
    policy: {
        id: string;
        sha256: string;
        integrity_override: boolean;
    };
    claims: string;
    baseline: {
        alg?: "jcs-v1";
        extras_sha256?: string | null;
        tools_sha256: string | null;
        approved_at: string | null;
        age_days: number | null;
        server: string | null;
        per_part: boolean; /** 1.13.0: verified | operator_signed | unsigned | invalid (null when the caller did not check). */
        trust: BaselineTrust["trust"] | null;
    } | null;
    observed: {
        alg?: "jcs-v1";
        extras_sha256?: string | null;
        tools_sha256: string | null;
        count: number;
        complete: boolean; /** 1.14.0: the number of tools offered, when more than a v1 lockfile hashes (the read is then incomplete). */
        offered?: number;
    } | null;
    events: ContinuityEvent[];
    would: ContinuityEffect;
    enforced: boolean;
    outcome: "proceed" | "refresh" | "pause" | "deny";
    paused_tools: string[];
    why: string[];
    record_sha256: string;
}
export interface ContinuityOptions {
    mode?: "observe" | "review" | "enforce";
    policy?: ContinuityPolicy;
    exceptions?: ContinuityException[];
    complete?: boolean;
    server?: string;
    serverIdentity?: string;
    expectPolicySha256?: string;
    now?: number;
    detail?: string; /** 1.13.0: the result of verifyLockBaseline, named in record.baseline.trust. */
    baselineTrust?: BaselineTrust["trust"]; /** 1.14.0: "lk-v1" compares on the v1 hashes even when the lockfile carries jcs_v1 (default: jcs-v1 when present). */
    digest?: "lk-v1" | "jcs-v1";
}
export declare const CONTINUITY_DEFAULT_POLICY: {
    v: 1;
    id: string;
    max_baseline_age_days: number;
    effects: Record<string, ContinuityEffect>;
};
export declare const CONTINUITY_CHANGE_CLASSES: string[];
export declare const CONTINUITY_FAILURE_CLASSES: string[];
/** Compare offered tools with the approved baseline and apply the operator's policy; returns the record to keep. */
export declare const continuityCheck: (lock: McpLock, tools: unknown, opts?: ContinuityOptions) => Promise<ContinuityRecord>;
/** The record for a check that could not compare (server, evidence or service failed). */
export declare const continuityFailure: (cls: string, opts?: ContinuityOptions) => Promise<ContinuityRecord>;
/** The policy in force (default + yours) and its sha256. */
export declare const continuityPolicy: (p?: ContinuityPolicy) => Promise<Required<ContinuityPolicy> & {
    sha256: string;
}>;
/** Per-part hashes (description, schema, annotations) so a change can be named. Store lockParts(tools) as lock.parts. */
export declare const lockToolParts: (t: McpTool) => Promise<{
    description_sha256: string;
    schema_sha256: string;
    annotations_sha256: string;
}>;
export interface JcsV1 {
    alg: "jcs-v1";
    spec: string;
    count?: number;
    tools_sha256: string | null;
    extras_sha256?: string;
    tools?: {
        name: string;
        contract: string;
        extras: string;
    }[];
    reason?: string;
}
/** jcs-v1 contract and extras digests of a tools/list result (every page; no cap). Equals lock.jcs_v1 from /api/v1/mcp/lock. */
export declare const jcsV1: (tools: McpTool[], opts?: {
    partial?: boolean;
}) => Promise<JcsV1>;
/** RFC 8785 canonical JSON. */
export declare const jcsCanon: (v: unknown) => string;
export declare const jcsContract: (t: McpTool) => {
    name: string;
    description: string;
    inputSchema: unknown;
    outputSchema?: unknown;
};
export declare const jcsExtras: (t: McpTool) => Record<string, unknown>;
export type ToolSetDigestCode = "TSD-PAGE" | "TSD-TOOL" | "TSD-NUMBER" | "TSD-TEXT" | "TSD-NAME" | "TSD-DEPTH";
export type ToolSetDigestSide = {
    digest: string;
    canonical: string;
} | {
    digest: null;
} | {
    error: ToolSetDigestCode;
    tool?: string;
};
export interface ToolSetDigest {
    spec: "mcp-tool-set-digest/1";
    contract: ToolSetDigestSide;
    extras: ToolSetDigestSide;
    tools?: {
        name: string;
        contract: string;
        extras: string | null;
        extras_error?: ToolSetDigestCode;
    }[];
}
export declare const TSD_SPEC: "mcp-tool-set-digest/1";
/** The contract and extras digests of a complete tools/list result as mcp-tool-set-digest/1 defines them. Each side is a digest or an error code; a member outside the contract never takes the contract digest away. Equals lock.jcs_v1 in the ordinary case. */
export declare const toolSetDigest: (tools: unknown[], opts?: {
    partial?: boolean;
    perTool?: boolean;
}) => Promise<ToolSetDigest>;
/** RFC 8785 text of a parsed JSON value; throws ToolSetDigestError (TSD-TEXT, TSD-NUMBER, TSD-DEPTH) where it has none. level: nesting level of v (1 = the tools array). */
export declare const tsdCanonical: (v: unknown, level?: number) => string;
export declare const ToolSetDigestError: new (code: ToolSetDigestCode, detail: string, tool?: string) => Error & {
    code: ToolSetDigestCode;
    tool?: string;
};
/** The most tools a v1 lockfile hashes; a longer list is compared on that many and marked incomplete. */
export declare const LOCK_V1_MAX_TOOLS: number;
export declare const lockParts: (tools: McpTool[]) => Promise<Record<string, {
    description_sha256: string;
    schema_sha256: string;
    annotations_sha256: string;
}>>;
/** The separate acceptance questions for one decision receipt. Act on policy_result, never on integrity_valid alone. */
/** Which continuity failure class a refused guard() result is. */
export declare const continuityClassOf: (g: GuardResult | null) => string;
/** Why a guard() or guardedFetch() result did not proceed (or, in observe mode, would not have). fetch_refused is set by guardedFetch only. https://crawlcheck.io/spec/guard */
export type GuardFailureClass = "service_unavailable" | "check_timeout" | "response_malformed" | "signature_invalid" | "key_unknown" | "key_retired" | "server_identity_mismatch" | "evidence_expired" | "operation_mismatch" | "replay_mismatch" | "decision_refused" | "revoked" | "split_view" | "fetch_refused";
export declare const GUARD_FAILURE_CLASSES: GuardFailureClass[];
/** Which failure class a refused guard() result is. Finer than continuityClassOf (which is unchanged): operation_mismatch, replay_mismatch, revoked, split_view and response_malformed are named separately. guard() puts it on the result as failure_class. */
export declare const guardFailureClassOf: (g: GuardResult | null) => GuardFailureClass;
/** enforce (default): a refused result has proceed false. observe: the same checks run and are reported, and nothing is enforced (proceed is true; would_proceed says what enforce would have returned). */
export type GuardMode = "enforce" | "observe";
export declare const acceptanceOf: (receipt: unknown, verification: unknown, scope: {
    fields?: unknown;
} | null, opts?: {
    allowWarn?: boolean;
    confirmed?: boolean | null;
    lock?: unknown;
}) => Acceptance;
/** An Ed25519 public key ({kty: "OKP", crv: "Ed25519", x}) or its x. */
export type OperatorKey = {
    kty?: "OKP";
    crv?: "Ed25519";
    x: string;
} | string;
export interface BaselineOptions {
    /** The operator's Ed25519 public keys; a lockfile signed with signLock by one of them is operator_signed. */
    operatorKeys?: OperatorKey[];
    /** keyPolicyFrom(directory) / publishedKeyPolicy(): CrawlCheck's keys with purposes and rotation, instead of the pinned ids. */
    keyPolicy?: unknown;
    /** CrawlCheck key ids to accept instead of the pinned CRAWLCHECK_LOCK_KIDS (publishedKeyIds()). */
    publishedKids?: string[];
    trustedKids?: string[];
    /** Refuse an unsigned lockfile (default: true when operatorKeys are given). */
    requireSignedBaseline?: boolean;
}
export interface BaselineTrust {
    trust: "verified" | "operator_signed" | "unsigned" | "invalid";
    signer: "crawlcheck" | "operator" | null;
    kid: string | null;
    why: string;
    parts_used: boolean;
}
export declare const CRAWLCHECK_LOCK_KIDS: readonly string[];
/** Is this the lockfile CrawlCheck or the operator signed? Offline. lock is the baseline to compare against (unsigned parts removed). */
export declare const verifyLockBaseline: (lock: unknown, opts?: BaselineOptions) => Promise<BaselineTrust & {
    lock: McpLock;
}>;
/** Sign a lockfile you approved (or edited) with your own Ed25519 key, over its canonical JSON. Returns a copy with operator_signature. */
export declare const signLock: <T extends McpLock>(lock: T, privateKey: {
    kty?: "OKP";
    crv?: "Ed25519";
    x: string;
    d: string;
}) => Promise<T & {
    operator_signature: {
        v: 1;
        alg: "Ed25519";
        kid: string;
        message: string;
        sig: string;
    };
}>;
/** A new operator key: keep privateKey away from the agent; pass publicKey in operatorKeys. */
export declare const newOperatorKey: () => Promise<{
    privateKey: {
        kty: "OKP";
        crv: "Ed25519";
        x: string;
        d: string;
    };
    publicKey: {
        kty: "OKP";
        crv: "Ed25519";
        x: string;
    };
    kid: string;
}>;
export interface ContinuityGateOptions extends ContinuityOptions, BaselineOptions {
    /** A person's re-approval: { continuity } for the server, { tool, continuity } for one tool. Remembered per definition. */
    confirm?: (request: {
        tool?: string;
        continuity: ContinuityRecord;
    }) => boolean | Promise<boolean>;
    onRecord?: (record: ContinuityRecord) => unknown;
    /** false: no console.warn on a change. */ log?: boolean;
    logger?: {
        warn: (msg: string) => unknown;
    };
    /** Records kept in gate.records (default 50). */ keep?: number;
}
export interface ContinuityGate {
    mode: "observe" | "review" | "enforce";
    records: ContinuityRecord[];
    record: ContinuityRecord | null;
    paused: Set<string>; /** 1.13.0: the startup check of the lockfile's signature. */
    ready: Promise<BaselineTrust>;
    baseline: BaselineTrust | null;
    readonly refused: Error | null;
    check(tools: McpTool[], meta?: {
        complete?: boolean;
    }): Promise<ContinuityRecord>;
    fail(cls: string, detail?: string): Promise<ContinuityRecord>;
    allowed<T>(tools: T[], nameOf?: (t: T) => string): T[];
    callOk(name: string): true;
}
/** Thrown in review/enforce when a record's outcome is pause, refresh or deny and nobody re-approved (or a paused tool is called). */
export declare const ContinuityRefused: new (why: string, record?: ContinuityRecord | null, tool?: string | null) => Error & {
    why: string;
    record: ContinuityRecord | null;
    tool: string | null;
};
/** The shared gate behind the framework adapters. Default mode observe. */
export declare const continuityGate: (lock: McpLock, opts?: ContinuityGateOptions) => ContinuityGate;
/** 1.13.0: continuityGate that fails at startup: throws ContinuityRefused when the baseline is untrusted (outside observe). */
export declare const openContinuityGate: (lock: McpLock, opts?: ContinuityGateOptions) => Promise<ContinuityGate>;
/** @openai/agents: wrap an MCP server so every listTools() is checked against lock. Records at server.continuity. */
export declare const withContinuity: <S extends {
    listTools: (...a: any[]) => Promise<any[]>;
    callTool: (...a: any[]) => Promise<any>;
}>(server: S, lock: McpLock, opts?: ContinuityGateOptions & {
    serverUrl?: string;
    gate?: ContinuityGate;
}) => S & {
    continuity: ContinuityGate;
};
/** @langchain/mcp-adapters: loadMcpTools with the check. client: a MultiServerMCPClient or a connected MCP SDK Client. */
export declare const loadMcpToolsWithContinuity: (serverName: string, client: unknown, lock: McpLock, opts?: ContinuityGateOptions & {
    serverUrl?: string;
    gate?: ContinuityGate;
    adapters?: unknown;
    loadOptions?: unknown;
}) => Promise<any[] & {
    continuity: ContinuityGate;
}>;
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
    accepted: boolean; /** Offline only (no published key ids given): whether the signature verifies under a key id this release ships (CRAWLCHECK_KEY_IDS). false: not a CrawlCheck key as far as this release knows, or the document only names one. null: not applicable. An SDK released before a key rotation does not list the new key. */
    issuer_pinned?: boolean | null; /** the signing policy accepts this key for this object at its signing time (purpose, retired, compromised). null: not decided. */
    key_policy_valid?: boolean | null; /** stable reason: ok, ok_bound, key_wrong_purpose, key_not_yet_active, key_retired, key_compromised, key_unknown, no_signing_time, purpose_unknown (key ids only, and the id is not one this release ships: partial, purpose not checked), or related_<code> for a key the document leans on. */
    key_policy_code?: string | null;
}
/** the key directory and rotation record as the signing policy reads them (keyPolicyFrom / publishedKeyPolicy). */
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
/** The signing policy for the key ids this release ships (purposes and start times; no rotation record), limited to the ids given. For offline use; online, publishedKeyPolicy() is current. */
export declare const pinnedKeyPolicy: (kids?: string[] | readonly string[]) => KeyPolicyInput;
/** CrawlCheck's signing key ids (RFC 7638 thumbprints) as published when this release was cut. Offline, a document under any other key id has issuer_pinned: false. */
export declare const CRAWLCHECK_KEY_IDS: readonly string[];
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
export declare const verifyBundle: (b: unknown, opts?: {
    publishedKids?: string[];
}) => Promise<BundleVerification>;
/** Verify a remediation receipt with no call to CrawlCheck. */
export declare const verifyReceipt: (rc: unknown, opts?: {
    publishedKids?: string[];
}) => Promise<ReceiptVerification>;
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
/**
 * Verify a signed resolve answer, preflight decision receipt, data inventory, export part or deletion record offline.
 * Offline it is never accepted (issuer_trusted: null); issuer_pinned says whether the key id is one this release ships.
 * Pass opts.publishedKids (publishedKeyIds(), or CRAWLCHECK_KEY_IDS to trust the ids this release ships) to decide the issuer.
 */
export declare const verifyDocument: (doc: unknown, opts?: {
    publishedKids?: string[] | readonly string[];
}) => Promise<DocumentVerification & Trust>;
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
    }[]; /** 1.11.0: per-part hashes (lockParts) so continuityCheck can name what changed. */
    parts?: Record<string, {
        description_sha256: string;
        schema_sha256: string;
        annotations_sha256: string;
    }>;
    descriptions?: Record<string, string>;
    server?: {
        url?: string | null;
    } | null;
    approved_at?: string;
    [k: string]: unknown;
}
export interface McpLockCheck {
    verdict: "unchanged" | "changed" | "incomplete";
    decision: "connect" | "block";
    approved_tools_sha256: string;
    current_tools_sha256: string;
    added: string[];
    removed: string[];
    modified: string[]; /** 1.14.0: the jcs-v1 comparison, when the lockfile carries jcs_v1. */
    jcs_v1?: {
        alg: "jcs-v1";
        current_tools_sha256: string | null;
        current_extras_sha256: string | null;
        approved_tools_sha256?: string;
        contract_unchanged?: boolean;
        extras_unchanged?: boolean;
    } | null; /** 1.14.0: more tools than a v1 lockfile hashes were offered. */
    offered?: number;
}
export declare function lockToolHash(t: McpTool): Promise<string>;
/** Hash a tools/list result the way a lockfile does: per tool, and the sorted per-tool hashes joined by \n. No network, no key. */
/** 1.14.0: also jcs_v1 (the jcs-v1 digests over every tool), and complete: false with offered when the list is longer than a v1 lockfile hashes (LOCK_V1_MAX_TOOLS). */
export declare function lockFromTools(tools: McpTool[]): Promise<{
    tools: {
        name: string;
        sha256: string;
    }[];
    tools_sha256: string;
    count: number;
    complete: boolean;
    offered?: number;
    jcs_v1: JcsV1;
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
    /** a pinned key policy (keyPolicyFrom(savedDirectory, savedRotation)), for offline use with onlineKeys: false. Checks key purpose too. */
    keyPolicy?: KeyPolicyInput;
    /** Testing clock (ms since epoch). Default Date.now(). */
    now?: number;
    /** "enforce" (default) or "observe". In observe every check still runs and the result says what enforce would have done (would_proceed, failure_class, why), but proceed is always true: nothing is refused. For a pilot before turning enforcement on. */
    mode?: GuardMode;
    /** Called with every guard() result, in both modes, before it is returned (guardedFetch: once per checked hop). Keep the results to see what the guard decides. An error it throws is ignored. */
    onRecord?: (result: GuardResult) => void | Promise<void>;
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
export interface DecisionScopeFields {
    kind_ok: boolean;
    domain_matches: boolean;
    action_matches: boolean;
    operation_matches?: boolean;
    nonce_matches?: boolean;
    times_present: boolean;
    not_expired: boolean;
    not_future: boolean;
    lifetime_ok: boolean;
    decision_known: boolean;
    resolve_bound: boolean;
}
export declare function checkDecision(receipt: unknown, want: DecisionWant): {
    ok: boolean;
    why: string[];
    fields: DecisionScopeFields;
};
export interface GuardResult {
    proceed: boolean;
    receipt: DecisionReceipt | null;
    verification: (DocumentVerification & Trust) | null;
    header: Record<string, string> | null;
    why: string[]; /** 1.11.0: the separate acceptance questions (integrity, issuer, key policy, freshness, subject, operation, replay, baseline, completeness) and policy_result. Null when no receipt came back. */
    acceptance: Acceptance | null;
    split_view?: LogFork[]; /** Set when the domain was refused from the held revocation list, with no network call. */
    revoked?: RevokedEntry;
    /** Why the result did not proceed, as one class; null when it did. In observe mode: why enforce would not have proceeded. Always set by guard(). */
    failure_class?: GuardFailureClass | null;
    /** The mode this result was produced in. Always set by guard(). */
    mode?: GuardMode;
    /** false in observe mode: proceed was not decided by the checks. Always set by guard(). */
    enforced?: boolean;
    /** What enforce mode returns as proceed for the same checks. Equals proceed in enforce mode. Always set by guard(). */
    would_proceed?: boolean;
}
/** Headers guardedFetch still sends after a redirect leaves the origin the caller named. Everything else stays behind. */
export declare const GUARDED_SAFE_HEADERS: string[];
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
    status?: number; /** This hop's guard failure class; null when its check passed. */
    failure_class?: GuardFailureClass | null; /** What enforce mode decides for this hop. */
    would_proceed?: boolean;
}
export interface GuardedFetchResult {
    proceed: boolean;
    response: Response | null;
    url: string;
    hops: GuardedHop[];
    why: string[];
    /** Why the fetch did not proceed: the refused hop's guard failure class, or fetch_refused when the URL or a redirect could not be checked at all. null when every check passed. In observe mode: the first hop enforce would have refused. */
    failure_class?: GuardFailureClass | null;
    mode?: GuardMode;
    /** false in observe mode. */
    enforced?: boolean;
    /** false when enforce mode would have stopped the fetch (at the first hop whose would_proceed is false). */
    would_proceed?: boolean;
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
    proof: string; /** true when both heads were checked against CrawlCheck's keys; false: either may be signed by anyone. */
    issuer_checked?: boolean;
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
        sth: LogHead; /** true when the head was checked against CrawlCheck's keys before it was kept. */
        issuer_checked?: boolean;
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
/** The keys a log head is checked against: key ids, or (better) the signing policy with purposes and rotation. */
export interface LogKeyOptions {
    publishedKids?: string[];
    keyPolicy?: KeyPolicyInput;
}
/** Check one signed tree head against the store and keep it. Pass publishedKids or keyPolicy: a head that is not signed by a published key is invalid and is not kept. A fork carries both contradicting signed heads. */
export declare const logObserve: (store: LogStore, sth: unknown, opts?: LogKeyOptions & {
    maxHeads?: number;
}) => Promise<LogObservation>;
/** Check the head inside a Resolve answer (transparency.sth), if it carries one. */
export declare const logObserveAnswer: (store: LogStore, answer: unknown, opts?: LogKeyOptions) => Promise<LogObservation>;
/** The signed heads a store holds, newest first: what a client sends its peers. */
export declare const logHeads: (store: LogStore, limit?: number) => LogHead[];
/** Gossip: check another client's heads against this store. */
export declare const logGossip: (store: LogStore, sths: unknown[], opts?: LogKeyOptions) => Promise<{
    forks: LogFork[];
    results: (LogObservation & {
        batch: number;
        sha256: string;
    })[];
}>;
/** Re-check a saved store against CrawlCheck's keys: forks and heads that are not signed by a published key are dropped. */
export declare const logPrune: (store: LogStore, opts: LogKeyOptions) => Promise<{
    forks_dropped: number;
    heads_dropped: number;
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
export interface McpPreflightOptions extends PreflightOptions, BaselineOptions {
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
    /** 1.11.0: tool-interface continuity with lock. mode observe (record only), review (changes go to confirm), enforce (the policy applies). Every check is kept in state.records and passed to onRecord. https://crawlcheck.io/spec/continuity */
    continuity?: ContinuityOptions & BaselineOptions & {
        onRecord?: (record: ContinuityRecord) => unknown;
    };
    onlineKeys?: boolean;
}
export interface McpPreflightState {
    url: string | null;
    host: string | null;
    receipt: DecisionReceipt | null;
    verification: (DocumentVerification & Trust) | null;
    decidedAt: number;
    lockCheck: McpLockCheck | ContinuityRecord | null;
    approved: Set<string> | null;
    continuity: ContinuityRecord | null;
    records: ContinuityRecord[];
    pausedTools: Set<string> | null; /** 1.13.0 */
    baseline: BaselineTrust | null;
    ready: Promise<BaselineTrust | null>;
}
export interface McpPreflightHooks {
    state: McpPreflightState;
    beforeConnect(url: string | null | undefined): Promise<{
        local: boolean;
        host?: string;
        receipt: DecisionReceipt | null;
        verification?: DocumentVerification & Trust;
    }>;
    afterConnect(tools: McpTool[] | null, meta?: {
        nextCursor?: string | null;
    } | null): Promise<McpLockCheck | ContinuityRecord | null>;
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
    /** Log heads this client was shown and did not keep, newest last (at most 50): not signed by a key CrawlCheck publishes for log heads, or not a head at all. They are never stored and never count as a fork. */
    logIgnored: {
        batch: number | null;
        sha256: string | null;
        why: string;
        at: string;
    }[];
    private noteIgnored;
    /** What a log head must be signed with before this client keeps it: the published signing policy, or (when the directory cannot be read) the policy for the key ids this release ships. A head is never kept on its own word. */
    private logKeyOptions;
    private observeAnswer;
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
    /** the key directory and rotation record, read now (cached 10 minutes), as the signing policy reads them. */
    publishedKeyPolicy(): Promise<KeyPolicyInput>;
    /** Verify a signed document here. With onlineKeys (default), its signing key must also be in the published directory and the signing policy must accept it. */
    verifyDocument(doc: unknown, onlineKeys?: boolean): Promise<DocumentVerification & Trust>;
    /**
     * Preflight, verify the receipt, check it is for THIS operation, and decide. Proceeds on allow; warn only with allowWarn;
     * require_confirmation only if confirm() says yes; block, unsupported and every failure never (fail closed: an error,
     * an unreachable CrawlCheck, a malformed, foreign, expired, replayed or out-of-scope receipt all return proceed false
     * with why[]). Passes the acceptance suite at https://crawlcheck.io/spec/guard
     * Every result carries failure_class (null when it proceeds; otherwise one of GUARD_FAILURE_CLASSES). With
     * opts.mode "observe" the same checks run and are reported (would_proceed, failure_class, why) and nothing is refused.
     */
    guard(domain: string, action?: Action, opts?: GuardOptions): Promise<GuardResult>;
    private guardDecide;
    /**
     * fetch() with the check where the action runs: guard() before the first request, and again before every redirect hop
     * to a new domain. The site is contacted only after its domain proceeds; a refused hop is never requested. Redirects
     * are followed by hand (GET/HEAD only), to http(s) only, at most maxHops (10). The receipt header is sent only to the
     * domain it names. In a browser a cross-origin redirect hides its target, so it is refused rather than followed blind.
     * The result and every hop carry failure_class. With opts.mode "observe" a hop the guard would refuse is recorded
     * (would_proceed false, failure_class, why) and requested anyway, without a receipt header; a URL or redirect that
     * cannot be checked at all (fetch_refused) is refused in both modes.
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
    changes(q?: QueryOf<"/api/v1/changes">): Promise<({
        kind?: string | null;
        v?: number | null;
        since?: string | null;
        domain?: unknown;
        generated_at?: string | null;
        count?: number | null;
        next_since?: string | null;
        reading?: string | null;
        events?: (({
            domain?: string | null;
            at?: string | null;
            section?: string | null;
            from_state?: string | null;
            to_state?: string | null;
            detail?: string | null;
        } & {
            [key: string]: unknown;
        }) | null)[] | null;
    } & {
        [key: string]: unknown;
    }) | null>;
    /** Report what happened after acting. Outcomes are kept apart from the signed record and never rewrite it. */
    outcome(body: JsonObject & {
        domain: string;
        action: Action;
    }): Promise<JsonObject>;
    /** The registry record (RDAP) and lifecycle of a domain. */
    domain(domain: string): Promise<({
        kind?: string | null;
        v?: number | null;
        domain?: string | null;
        registry?: ({
            state?: string | null;
            source?: string | null;
            registrar?: string | null;
            registrar_iana_id?: string | null;
            created?: string | null;
            expires?: string | null;
            changed?: string | null;
            nameservers?: (string | null)[] | null;
            dnssec?: boolean | null;
            status?: (string | null)[] | null;
        } & {
            [key: string]: unknown;
        }) | null;
        timeline?: (({
            at?: string | null;
            type?: string | null;
            detail?: string | null;
            source?: string | null;
        } & {
            [key: string]: unknown;
        }) | null)[] | null;
    } & {
        [key: string]: unknown;
    }) | null>;
    /** The whole observation in one shape: findings (gated like the site), trust, freshness, score ledger, evidence links. */
    machineRecord(q: QueryOf<"/api/v1/machine-record">): Promise<MachineRecordV1>;
    /** Scan a domain now (free lane without a key; the licensed lane with one). */
    scan(domain: string): Promise<PublicReportV1>;
    /** A stored report by id, in the public v1 shape. */
    report(id: string): Promise<PublicReportV1>;
    explain(q: QueryOf<"/api/explain">): Promise<({
        ok?: boolean | null;
        kind?: string | null;
        version?: string | null;
        subject?: ({
            domain?: string | null;
            host?: string | null;
            report_id?: string | null;
            scanned_at?: string | null;
        } & {
            [key: string]: unknown;
        }) | null;
        finding?: ({
            fid?: string | null;
            decision_id?: string | null;
            code?: string | null;
            severity?: number | null;
            path?: string | null;
            title?: string | null;
            detail?: unknown;
            meaning?: unknown;
        } & {
            [key: string]: unknown;
        }) | null;
        rule?: ({
            code?: string | null;
            revision?: number | null;
            revision_note?: unknown;
            score_version?: number | null;
            decided_in?: ({
                trace_id?: string | null;
                span_id?: string | null;
            } & {
                [key: string]: unknown;
            }) | null;
        } & {
            [key: string]: unknown;
        }) | null;
        observed?: ({
            evidence?: ({
                shadowed_groups?: number | null;
                agents_affected?: number | null;
                search_engines_affected?: number | null;
                sample?: ({
                    [key: string]: unknown;
                } | null)[] | null;
            } & {
                [key: string]: unknown;
            }) | null;
            compared_fetches?: unknown;
            support_scope?: string | null;
        } & {
            [key: string]: unknown;
        }) | null;
        corroboration?: ({
            status?: string | null;
            reading?: string | null;
        } & {
            [key: string]: unknown;
        }) | null;
        trust?: ({
            freshness?: ({
                observed_at?: string | null;
                last_observed?: string | null;
                held_since?: string | null;
                state?: string | null;
            } & {
                [key: string]: unknown;
            }) | null;
            confidence?: ({
                level?: string | null;
                means?: string | null;
                basis?: (string | null)[] | null;
            } & {
                [key: string]: unknown;
            }) | null;
            contradictions?: unknown[] | null;
        } & {
            [key: string]: unknown;
        }) | null;
        score_effect?: ({
            decision_id?: string | null;
            code?: string | null;
            path?: string | null;
            severity?: number | null;
            level?: string | null;
            points?: number | null;
            cap?: string | null;
            binding?: boolean | null;
            letter_now?: string | null;
            letter_without_it?: string | null;
            same_level_others?: number | null;
            says?: string | null;
        } & {
            [key: string]: unknown;
        }) | null;
        held?: ({
            state?: string | null;
            first_seen?: string | null;
            scans_seen?: number | null;
            valid_time?: ({
                valid_from?: ({
                    after?: unknown;
                    by?: string | null;
                } & {
                    [key: string]: unknown;
                }) | null;
                valid_to?: unknown;
                recorded_at?: string | null;
                superseded_at?: unknown;
                superseded_by?: unknown;
                earlier_intervals?: number | null;
                before_bt1?: boolean | null;
            } & {
                [key: string]: unknown;
            }) | null;
            history?: string | null;
        } & {
            [key: string]: unknown;
        }) | null;
        proof?: ({
            in_signed_manifest?: boolean | null;
            manifest_sha256?: string | null;
            decision_root?: string | null;
            leaf?: string | null;
            path?: (({
                side?: string | null;
                hash?: string | null;
            } & {
                [key: string]: unknown;
            }) | null)[] | null;
            how?: unknown;
        } & {
            [key: string]: unknown;
        }) | null;
        check?: ({
            verify?: string | null;
            bundle?: string | null;
            offline_verifier?: string | null;
        } & {
            [key: string]: unknown;
        }) | null;
        access?: string | null;
    } & {
        [key: string]: unknown;
    }) | null>;
    impact(q: QueryOf<"/api/impact">): Promise<({
        ok?: boolean | null;
        kind?: string | null;
        subject?: ({
            domain?: string | null;
            report_id?: string | null;
            scanned_at?: string | null;
        } & {
            [key: string]: unknown;
        }) | null;
        fixes?: (string | null)[] | null;
        each?: (({
            fix?: string | null;
            label?: string | null;
            generator?: string | null;
            findings_cleared?: number | null;
            rows_cleared?: number | null;
            clears_only_with?: (string | null)[] | null;
            score_after?: number | null;
            letter_after?: string | null;
            points?: number | null;
            root_causes_closed?: unknown[] | null;
            certificate_newly_passing?: (string | null)[] | null;
        } & {
            [key: string]: unknown;
        }) | null)[] | null;
        asked?: (string | null)[] | null;
        result?: ({
            ok?: boolean | null;
            fix?: (({
                id?: string | null;
                label?: string | null;
                file?: string | null;
                generator?: string | null;
                failing_now?: boolean | null;
            } & {
                [key: string]: unknown;
            }) | null)[] | null;
            unknown?: unknown[] | null;
            nothing_to_fix?: unknown[] | null;
            clears?: ({
                findings?: (({
                    code?: string | null;
                    path?: string | null;
                    severity?: number | null;
                    caps_letter_at?: unknown;
                    decision_id?: string | null;
                } & {
                    [key: string]: unknown;
                }) | null)[] | null;
                rows?: (({
                    section?: string | null;
                    id?: string | null;
                    row?: string | null;
                } & {
                    [key: string]: unknown;
                }) | null)[] | null;
            } & {
                [key: string]: unknown;
            }) | null;
            clears_only_with?: (({
                also_needs?: (string | null)[] | null;
                findings?: (({
                    code?: string | null;
                    path?: string | null;
                    severity?: number | null;
                    caps_letter_at?: string | null;
                    decision_id?: string | null;
                } & {
                    [key: string]: unknown;
                }) | null)[] | null;
                rows?: unknown[] | null;
                why?: string | null;
            } & {
                [key: string]: unknown;
            }) | null)[] | null;
            policy_rows?: unknown[] | null;
            root_causes?: (({
                id?: string | null;
                relation?: string | null;
                members?: number | null;
                cleared?: number | null;
                closed?: boolean | null;
                still_open?: (string | null)[] | null;
            } & {
                [key: string]: unknown;
            }) | null)[] | null;
            certificate?: ({
                passing_now?: number | null;
                passing_after?: number | null;
                of?: number | null;
                newly_passing?: (string | null)[] | null;
            } & {
                [key: string]: unknown;
            }) | null;
            score?: ({
                now?: ({
                    score?: number | null;
                    letter?: string | null;
                    cap?: string | null;
                } & {
                    [key: string]: unknown;
                }) | null;
                after?: ({
                    score?: number | null;
                    letter?: string | null;
                    cap?: string | null;
                    capped?: boolean | null;
                    held_at_reach?: boolean | null;
                    rows_applied?: number | null;
                    findings_cleared?: number | null;
                } & {
                    [key: string]: unknown;
                }) | null;
                after_if_policy_also_allows?: unknown;
                method?: string | null;
            } & {
                [key: string]: unknown;
            }) | null;
            policy_note?: unknown;
        } & {
            [key: string]: unknown;
        }) | null;
        method?: string | null;
    } & {
        [key: string]: unknown;
    }) | null>;
    whatIf(q: QueryOf<"/api/whatif">): Promise<({
        ok?: boolean | null;
        kind?: string | null;
        subject?: ({
            domain?: string | null;
            report_id?: string | null;
            scanned_at?: string | null;
        } & {
            [key: string]: unknown;
        }) | null;
        now?: ({
            score?: number | null;
            letter?: string | null;
            cap?: unknown;
        } & {
            [key: string]: unknown;
        }) | null;
        asked?: ({
            fix?: unknown[] | null;
            clear?: (string | null)[] | null;
        } & {
            [key: string]: unknown;
        }) | null;
        result?: ({
            score?: number | null;
            letter?: string | null;
            cap?: unknown;
            capped?: boolean | null;
            held_at_reach?: boolean | null;
            rows_applied?: number | null;
            findings_cleared?: number | null;
        } & {
            [key: string]: unknown;
        }) | null;
        not_applied?: ({
            rows?: unknown[] | null;
            findings?: (string | null)[] | null;
        } & {
            [key: string]: unknown;
        }) | null;
        next_letter?: ({
            target?: unknown;
            why?: string | null;
        } & {
            [key: string]: unknown;
        }) | null;
        combined?: ({
            all_rows_fixed?: ({
                score?: number | null;
                letter?: string | null;
                cap?: unknown;
                capped?: boolean | null;
                held_at_reach?: boolean | null;
                rows_applied?: number | null;
                findings_cleared?: number | null;
            } & {
                [key: string]: unknown;
            }) | null;
            all_findings_cleared?: ({
                score?: number | null;
                letter?: string | null;
                cap?: unknown;
                capped?: boolean | null;
                held_at_reach?: boolean | null;
                rows_applied?: number | null;
                findings_cleared?: number | null;
            } & {
                [key: string]: unknown;
            }) | null;
            both?: ({
                score?: number | null;
                letter?: string | null;
                cap?: unknown;
                capped?: boolean | null;
                held_at_reach?: boolean | null;
                rows_applied?: number | null;
                findings_cleared?: number | null;
            } & {
                [key: string]: unknown;
            }) | null;
        } & {
            [key: string]: unknown;
        }) | null;
        rows?: (({
            section_id?: string | null;
            row?: string | null;
            points?: number | null;
            why?: unknown;
        } & {
            [key: string]: unknown;
        }) | null)[] | null;
        method?: string | null;
    } & {
        [key: string]: unknown;
    }) | null>;
    locate(q: QueryOf<"/api/locate">): Promise<({
        ok?: boolean | null;
        kind?: string | null;
        report_id?: string | null;
        domain?: string | null;
        page?: ({
            experience_id?: string | null;
            sha256?: string | null;
            bytes?: number | null;
            artifact?: string | null;
        } & {
            [key: string]: unknown;
        }) | null;
        statements?: number | null;
        located?: number | null;
        read_back?: number | null;
        rows?: (({
            field?: string | null;
            value?: string | null;
            source?: ({
                kind?: string | null;
                via?: string | null;
                name?: string | null;
                node?: string | null;
                id?: string | null;
            } & {
                [key: string]: unknown;
            }) | null;
            located?: boolean | null;
            bytes?: (number | null)[] | null;
            line?: number | null;
            col?: number | null;
            scope?: string | null;
            match?: string | null;
            cut?: string | null;
            reads_back?: boolean | null;
        } & {
            [key: string]: unknown;
        }) | null)[] | null;
        method?: string | null;
    } & {
        [key: string]: unknown;
    }) | null>;
    /** Every server-side verifier on one record. */
    verify(id: string): Promise<({
        served_from?: string | null;
        bundle?: string | null;
        ok?: boolean | null;
        id?: string | null;
        domain?: string | null;
        scanned_at?: string | null;
        report?: string | null;
        checks?: (({
            name?: string | null;
            ok?: boolean | null;
            why?: string | null;
            digest?: string | null;
            recorded?: string | null;
            date?: string | null;
            manifest?: string | null;
            kid?: string | null;
            key_directory?: string | null;
            bytes?: number | null;
        } & {
            [key: string]: unknown;
        }) | null)[] | null;
        summary?: ({
            passed?: number | null;
            failed?: number | null;
            unverifiable?: number | null;
            total?: number | null;
        } & {
            [key: string]: unknown;
        }) | null;
        note?: unknown;
    } & {
        [key: string]: unknown;
    }) | null>;
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
    receipts(domain: string): Promise<({
        ok?: boolean | null;
        domain?: string | null;
        receipts?: (({
            id?: string | null;
            at?: string | null;
            before?: string | null;
            after?: string | null;
            verdict?: string | null;
            url?: string | null;
        } & {
            [key: string]: unknown;
        }) | null)[] | null;
    } & {
        [key: string]: unknown;
    }) | null>;
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
/** Structural view of the Vercel AI SDK module ("ai") - passed in, so this package keeps no dependency. */
export interface VercelAiModule {
    tool: (def: any) => any;
    jsonSchema: (schema: any) => any;
}
/** Vercel AI SDK adapter (1.10.0): `import * as ai from "ai"; const tools = vercelTools(cc, ai);` then generateText({ tools, ... }).
 * Same three tools as agentTools(); they fail closed. The schema is given as both inputSchema (AI SDK 5+) and parameters (AI SDK 4). */
export declare function vercelTools(cc: CrawlCheck, ai: VercelAiModule, opts?: AgentToolOptions): Record<string, unknown>;
/** Structural view of "@langchain/core/tools" - passed in, so this package keeps no dependency. */
export interface LangChainToolsModule {
    tool: (fn: (input: any) => any, fields: {
        name: string;
        description: string;
        schema: any;
    }) => any;
}
/** LangChain.js adapter (1.10.0): `import * as lc from "@langchain/core/tools"; const tools = langchainTools(cc, lc);`
 * Same three tools as agentTools(); each returns its result as a JSON string; they fail closed. */
export declare function langchainTools(cc: CrawlCheck, lc: LangChainToolsModule, opts?: AgentToolOptions): unknown[];
export default CrawlCheck;
