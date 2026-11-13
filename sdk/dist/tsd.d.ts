export declare const TSD_SPEC = "mcp-tool-set-digest/1";
export declare class ToolSetDigestError extends Error {
    constructor(code: any, detail: any, tool?: any);
    code: any;
    tool?: any;
}
/** RFC 8785 text of a parsed JSON value. Throws ToolSetDigestError (TSD-TEXT, TSD-NUMBER) where the value has none. */
export declare function tsdCanonical(v: any): any;
/** A tool's contract entry (section 4). */
export declare function tsdContractEntry(tool: any): {
    name: any;
    description: any;
    inputSchema: any;
};
export declare function toolSetDigest(tools: any, opts?: {}): Promise<any>;
