export declare const CONTINUITY_EFFECTS: string[];
export declare const CONTINUITY_CHANGE_CLASSES: string[];
export declare const CONTINUITY_FAILURE_CLASSES: string[];
/** The default operator policy. Every value can be overridden; the record names the policy's sha256, so what decided is attributable. */
export declare const CONTINUITY_DEFAULT_POLICY: Readonly<{
    v: 1;
    id: "crawlcheck-continuity-default";
    max_baseline_age_days: 90;
    effects: Readonly<{
        unchanged: "proceed";
        tool_added: "pause_tool";
        tool_removed: "proceed";
        description_changed: "pause_tool";
        schema_changed: "pause_tool";
        annotations_changed: "pause_tool";
        tool_changed: "pause_tool";
        evidence_expired: "refresh";
        signature_invalid: "deny";
        key_unknown: "deny";
        key_retired: "deny";
        server_identity_mismatch: "deny";
        server_unavailable: "pause";
        tool_list_truncated: "pause";
        response_malformed: "pause";
        baseline_stale: "pause";
        policy_version_mismatch: "pause";
        check_timeout: "pause";
        service_unavailable: "pause";
        decision_refused: "deny";
        baseline_untrusted: "deny";
    }>;
}>;
/** Per-part hashes of one tool, so a change can be named (description, schema, annotations). */
export declare function lockToolParts(t: any): Promise<{
    description_sha256: string;
    schema_sha256: string;
    annotations_sha256: string;
}>;
/** parts for a lockfile: { [tool name]: lockToolParts(tool) }. Store it as lock.parts next to lock.tools. */
export declare function lockParts(tools: any): Promise<{}>;
/** The policy in force: the default with the operator's values over it, and its sha256 (what the record names). */
export declare function continuityPolicy(p: any): Promise<{
    v: number;
    id: string;
    max_baseline_age_days: any;
    effects: Readonly<{
        unchanged: "proceed";
        tool_added: "pause_tool";
        tool_removed: "proceed";
        description_changed: "pause_tool";
        schema_changed: "pause_tool";
        annotations_changed: "pause_tool";
        tool_changed: "pause_tool";
        evidence_expired: "refresh";
        signature_invalid: "deny";
        key_unknown: "deny";
        key_retired: "deny";
        server_identity_mismatch: "deny";
        server_unavailable: "pause";
        tool_list_truncated: "pause";
        response_malformed: "pause";
        baseline_stale: "pause";
        policy_version_mismatch: "pause";
        check_timeout: "pause";
        service_unavailable: "pause";
        decision_refused: "deny";
        baseline_untrusted: "deny";
    }>;
    allow_integrity_override: boolean;
} & {
    sha256: string;
}>;
/**
 * Compare the offered tools with the approved baseline (an mcp-lockfile, ideally with lock.parts) and apply the policy.
 * opts: mode ("observe" | "review" | "enforce", default "enforce"), policy, exceptions [{tool, class, until, by, reason}],
 * complete (false when tools/list returned a nextCursor you did not follow), server (the URL checked), serverIdentity
 * (the URL the baseline was approved for; differs -> server_identity_mismatch), expectPolicySha256, now (ms).
 */
export declare function continuityCheck(lock: any, tools: any, opts?: {}): Promise<any>;
/** A record for a check that could not compare anything (the server, the evidence or the service failed). cls: one of CONTINUITY_FAILURE_CLASSES. */
export declare function continuityFailure(cls: any, opts?: {}): Promise<any>;
/**
 * Acceptance, split: the separate questions a single "verified: true" used to answer at once, for one decision receipt.
 * receipt: the crawlcheck-decision. verification: verifyDocument()'s result (integrity_valid, issuer_trusted, key_policy_valid,
 * unavailable). scope: checkDecision()'s result (its fields). opts: allowWarn, confirmed (true when a person approved a
 * require_confirmation), lock (a continuity record or checkLock result for the same server).
 * policy_result: proceed | pause | deny. accepted is policy_result === "proceed". Never act on integrity_valid alone.
 */
export declare function acceptanceOf(receipt: any, verification: any, scope: any, opts?: {}): {
    integrity_valid: boolean;
    issuer_trusted: any;
    key_policy_valid: any;
    freshness_valid: boolean;
    subject_matches: boolean;
    operation_matches: any;
    replay_safe: any;
    baseline_matches: null;
    assessment_complete: boolean;
    decision: any;
    policy_source: any;
    evidence_level: any;
    policy_result: string;
    accepted: boolean;
    why: any[];
};
/** Which failure class a refused guard() result is (for continuityFailure). */
export declare function continuityClassOf(g: any): "check_timeout" | "decision_refused" | "evidence_expired" | "key_retired" | "key_unknown" | "response_malformed" | "server_identity_mismatch" | "service_unavailable" | "signature_invalid";
/** CrawlCheck's lockfile signing keys (RFC 7638 thumbprints), as published at /.well-known/http-message-signatures-directory on 2026-11-07. */
export declare const CRAWLCHECK_LOCK_KIDS: readonly string[];
/** The operator's signature over the canonical lockfile (every field but operator_signature). privateKey: an Ed25519 private JWK ({kty, crv, x, d}). */
export declare function signLock(lock: any, privateKey: any): Promise<{
    operator_signature: {
        v: number;
        alg: string;
        kid: string;
        message: string;
        sig: string;
    };
}>;
/** A new operator signing key: { privateKey (JWK, keep it out of the agent's reach), publicKey ({kty, crv, x}: pass it as operatorKeys) }. */
export declare function newOperatorKey(): Promise<{
    privateKey: {
        kty: string;
        crv: string;
        x: string | undefined;
        d: string | undefined;
    };
    publicKey: {
        kty: string;
        crv: string;
        x: string | undefined;
    };
    kid: string;
}>;
/**
 * Is this baseline the one CrawlCheck or the operator signed? opts: operatorKeys (public JWKs or their x), keyPolicy,
 * publishedKids, trustedKids. Returns { trust: verified | operator_signed | unsigned | invalid, signer, kid, why, parts_used,
 * lock } where lock is the baseline to compare against (without unsigned parts). Offline; no network.
 */
export declare function verifyLockBaseline(lock: any, opts?: {}): Promise<{
    trust: any;
    signer: any;
    kid: any;
    why: any;
    parts_used: boolean;
    lock: any;
}>;
/** Why a baseline is refused (null when it is accepted). */
export declare function baselineRefusal(b: any, requireSigned: any): any;
