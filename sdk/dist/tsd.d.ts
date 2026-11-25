export declare const TSD_SPEC = "mcp-tool-set-digest/1";
export declare class ToolSetDigestError extends Error {
    code: any;
    tool: any;
    constructor(code: any, detail: any, tool: any);
}
/** RFC 8785 text of a parsed JSON value. Throws ToolSetDigestError (TSD-TEXT, TSD-NUMBER, TSD-DEPTH) where the value has none.
 * level is the nesting level of v itself (1 = the tools array). Iterative, so the depth bound and not the engine's stack
 * decides how deep a value may go; errors surface in document order. */
export declare function tsdCanonical(v: any, level?: number): string;
/** A tool's contract entry (section 4). */
export declare function tsdContractEntry(tool: any): {
    name: any;
    description: any;
    inputSchema: any;
};
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
export type ToolSetDigestResult = {
    spec: "mcp-tool-set-digest/1";
    contract: ToolSetDigestSide;
    extras: ToolSetDigestSide;
    tools?: {
        name: string;
        contract: string;
        extras: string | null;
        extras_error?: ToolSetDigestCode;
    }[];
};
/** @typedef {"TSD-PAGE" | "TSD-TOOL" | "TSD-NUMBER" | "TSD-TEXT" | "TSD-NAME" | "TSD-DEPTH"} ToolSetDigestCode */
/** @typedef {{ digest: string, canonical: string } | { digest: null } | { error: ToolSetDigestCode, tool?: string }} ToolSetDigestSide */
/** @typedef {{ spec: "mcp-tool-set-digest/1", contract: ToolSetDigestSide, extras: ToolSetDigestSide, tools?: { name: string, contract: string, extras: string | null, extras_error?: ToolSetDigestCode }[] }} ToolSetDigestResult */
/**
 * The two digests of a complete tools/list result (every page joined). Each side is { digest, canonical } or
 * { error: "TSD-…", tool? }; extras is { digest: null } when no tool carries a member outside the contract.
 * opts.partial: true when a page was not read: neither digest (TSD-PAGE). opts.perTool adds the optional per-tool digests.
 * @param {unknown} tools
 * @param {{ partial?: boolean, perTool?: boolean }} [opts]
 * @returns {Promise<ToolSetDigestResult>}
 */
export declare function toolSetDigest(tools: unknown, opts?: {
    partial?: boolean;
    perTool?: boolean;
}): Promise<ToolSetDigestResult>;
