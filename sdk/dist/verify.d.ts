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
export function trustOf(res: any, kid: any, publishedKids: any, related: any): any;
export function publishedKeyIds(base: any): Promise<string[]>;
export function verifyBundle(b: any, opts: any): Promise<any>;
export function verifyReceipt(rc: any, opts: any): Promise<any>;
export function verifyExport(x: any, opts: any): Promise<any>;
export function verifyResolution(x: any, opts: any): Promise<any>;
export function verifyDnsTxt(txt: any, opts: any): Promise<any>;
export function verifyDataDoc(x: any, opts: any): Promise<any>;
