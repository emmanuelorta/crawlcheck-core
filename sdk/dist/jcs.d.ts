export declare const JCS_V1_SPEC = "https://crawlcheck.io/spec/mcp-lockfile#jcs-v1";
/** RFC 8785 canonical JSON (keys in UTF-16 code-unit order, ECMAScript number form, no whitespace). Throws on a non-finite number. */
export declare function jcsCanon(v: any): any;
/** A tool's contract: what the model reads and the call takes or returns. */
export declare function jcsContract(t: any): {
    name: any;
    description: any;
    inputSchema: any;
};
/** A tool's extras: every member beyond name, description, inputSchema and outputSchema. */
export declare function jcsExtras(t: any): any;
/**
 * The jcs-v1 digests of a tools/list result (every page). opts.partial: true when a page was not read (the list is then
 * not digested). Returns { alg, spec, count, tools_sha256, extras_sha256, tools: [{name, contract, extras}] } or
 * { alg, spec, tools_sha256: null, reason }.
 */
export declare function jcsV1(tools: any, opts?: {}): Promise<{
    alg: string;
    spec: string;
    tools_sha256: null;
    reason: string;
    count?: undefined;
    extras_sha256?: undefined;
    tools?: undefined;
} | {
    reason?: undefined;
    alg: string;
    spec: string;
    count: number;
    tools_sha256: string;
    extras_sha256: string;
    tools: {
        name: any;
        contract: string;
        extras: string;
    }[];
}>;
