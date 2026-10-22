export function canon(v: any): any;
export function merkleRootHex(hexLeaves: any): Promise<any>;
export function otsInspect(u8: any): Promise<{
    digest: string;
    attestations: any[];
}>;
export function dspVerdict(m: any): {
    verdict: string;
    effect: string;
    rule: string;
};
export function rfcRootV(leafHex: any, index: any, size: any, path: any): Promise<string | null>;
export function tvReachV(envelope: any): any;
export function verifyThresholdSigners(x: any): Promise<{
    observer_id: any;
    network: any;
    signature: boolean;
    binding: boolean;
    values_match: boolean;
    why: never[];
}[]>;
export function relatedKids(x: any): any[];
export function keyPolicyFrom(directory: any, rotation: any): Promise<{
    v: number;
    kids: string[];
    keys: {};
    retired: {};
    compromised: {};
    rotation: boolean;
}>;
export function signedAtOf(x: any): number | null;
export function keyPolicyCheck(x: any, kp: any): {
    ok: false | null;
    code: string | undefined;
    known: boolean;
    purpose: any;
    expected: null;
    why: string | undefined;
} | {
    ok: boolean;
    code: string;
    known: boolean;
    purpose: any;
    expected: any;
    why: string;
};
export function applyKeyPolicy(res: any, x: any, kp: any): any;
export function publishedKeyPolicy(base: any): Promise<{
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
export function trustOf(res: any, kid: any, publishedKids: any, related: any): any;
export function publishedKeyIds(base: any): Promise<string[]>;
export function verifyBundle(b: any, opts: any): Promise<any>;
export function verifyReceipt(rc: any, opts: any): Promise<any>;
export function verifyExport(x: any, opts: any): Promise<any>;
export function verifyResolution(x: any, opts: any): Promise<any>;
export function verifyDnsTxt(txt: any, opts: any): Promise<any>;
export function verifyDataDoc(x: any, opts: any): Promise<any>;
export namespace KEY_POLICY {
    let v: number;
    let object_purpose: {
        "crawlcheck-decision": string;
        "crawlcheck-log-sth": string;
        "*": string;
    };
    let chains: {
        documents: string[];
        decisions: string[];
        "log heads": string[];
    };
    let starts: {
        requests: null;
        documents: string;
        decisions: string;
        "log heads": string;
    };
    let bound: {
        "crawlcheck-resolve": string;
        "crawlcheck-decision": string;
    };
    let purpose_aliases: {
        "requests and documents": string;
    };
}
