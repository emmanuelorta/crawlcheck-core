export declare function canon(v: any): any;
export declare function merkleRootHex(hexLeaves: any): Promise<any>;
/** CrawlCheck's signing key ids (RFC 7638 thumbprints), as published at /.well-known/http-message-signatures-directory on 2026-11-25. */
export declare const CRAWLCHECK_KEY_IDS: readonly string[];
export declare function otsInspect(u8: any): Promise<{
    digest: string;
    attestations: any[];
}>;
export declare function dspVerdict(m: any): {
    verdict: string;
    effect: string;
    rule: string;
};
export declare function rfcRootV(leafHex: any, index: any, size: any, path: any): Promise<string | null>;
export declare function tvReachV(envelope: any): any;
export declare function verifyThresholdSigners(x: any): Promise<{
    observer_id: any;
    network: any;
    signature: boolean;
    binding: boolean;
    values_match: boolean;
    why: never[];
}[]>;
export declare function relatedKids(x: any): any[];
export declare const KEY_POLICY: {
    v: number;
    object_purpose: {
        "crawlcheck-decision": string;
        "crawlcheck-log-sth": string;
        "*": string;
    };
    chains: {
        documents: string[];
        decisions: string[];
        "log heads": string[];
    };
    starts: {
        requests: null;
        documents: string;
        decisions: string;
        "log heads": string;
    };
    bound: {
        "crawlcheck-resolve": string;
        "crawlcheck-decision": string;
    };
    purpose_aliases: {
        "requests and documents": string;
    };
};
export declare function keyPolicyFrom(directory: any, rotation: any): Promise<{
    v: number;
    kids: string[];
    keys: {};
    retired: {};
    compromised: {};
    rotation: boolean;
}>;
export declare function signedAtOf(x: any): number | null;
export declare function keyPolicyCheck(x: any, kp: any): {
    ok: boolean;
    code: string;
    known: boolean;
    purpose: any;
    expected: any;
    why: string;
} | {
    ok: false | null;
    code: string | undefined;
    known: boolean;
    purpose: any;
    expected: null;
    why: string | undefined;
};
export declare function applyKeyPolicy(res: any, x: any, kp: any): any;
/** The signing policy for the key ids this release ships, limited to the ids in kids (all of them when omitted). It has no rotation record, so retired and compromised keys are unknown to it: prefer publishedKeyPolicy() when online. */
export declare function pinnedKeyPolicy(kids: any): {
    v: number;
    kids: string[];
    keys: {};
    retired: {};
    compromised: {};
    rotation: boolean;
    source: string;
};
export declare function applyPinnedPurpose(res: any, x: any, publishedKids: any): any;
export declare function publishedKeyPolicy(base: any): Promise<{
    v: number;
    kids: string[];
    keys: {};
    retired: {};
    compromised: {};
    rotation: boolean;
} & {
    read_at: string;
    source: string;
}>;
export declare function trustOf(res: any, kid: any, publishedKids: any, related: any): any;
export declare function publishedKeyIds(base: any): Promise<string[]>;
export declare function verifyBundle(b: any, opts: any): Promise<any>;
export declare function verifyReceipt(rc: any, opts: any): Promise<any>;
export declare function verifyExport(x: any, opts: any): Promise<any>;
export declare function verifyResolution(x: any, opts: any): Promise<any>;
export declare function verifyDnsTxt(txt: any, opts: any): Promise<any>;
export declare function verifyDataDoc(x: any, opts: any): Promise<any>;
