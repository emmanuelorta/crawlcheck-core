export declare const LOG_ORIGIN = "crawlcheck.io/log";
export declare const LOG_VKEY = "crawlcheck.io/log+4b13e34e+AdysJh4Ix53TtkimkZ22ciVKyLSkE7Fe66ocUkTfWcpe";
/** Witness verifier keys (cosignature/v1, key type 0x04) this SDK version trusts by default. None yet. */
export declare const WITNESS_VKEYS: any[];
/** Parse a verifier key "<name>+<8 hex key id>+<base64(type byte || 32-byte key)>"; null unless the key id matches. */
export declare function parseVkey(vkey: any): Promise<{
    name: string;
    id: string;
    type: number;
    pub: Uint8Array<ArrayBuffer>;
    vkey: string;
} | null>;
/** Parse a checkpoint note into its body and signature lines. Returns { error } when it is not one. */
export declare function parseCheckpoint(note: any): {
    error: string;
    text?: undefined;
    origin?: undefined;
    size?: undefined;
    root?: undefined;
    sigs?: undefined;
} | {
    error?: undefined;
    text: string;
    origin: string;
    size: number;
    root: Uint8Array<ArrayBuffer>;
    sigs: {
        name: string;
        id: string;
        sig: Uint8Array<ArrayBuffer>;
    }[];
};
/**
 * Verify a checkpoint: the pinned log key signed it, and count cosignatures from the pinned witnesses.
 * opts: { logVkey = LOG_VKEY, witnesses = WITNESS_VKEYS, quorum = 0 }.
 * ok is true only when the log signature verifies AND at least `quorum` distinct pinned witnesses cosigned.
 */
export declare function verifyCheckpoint(note: any, opts?: {}): Promise<{
    ok: boolean;
    origin: null;
    size: null;
    root: null;
    log_signed: boolean;
    cosigned_by: never[];
    witnesses_pinned: number;
    quorum: number;
    quorum_met: boolean;
    witnessed: boolean;
} | {
    ok: boolean;
    origin: null;
    size: null;
    root: null;
    log_signed: boolean;
    cosigned_by: never[];
    witnesses_pinned: number;
    quorum: number;
    quorum_met: boolean;
    witnessed: boolean;
    why: string;
}>;
/** RFC 6962 audit path check: leaf (hex or base64 or bytes) at `index` of a tree of `treeSize` leaves hashes up `path` to `root`. */
export declare function verifyInclusion(leaf: any, index: any, treeSize: any, path: any, root: any): Promise<boolean>;
/** RFC 6962 consistency check: the tree of `second` leaves with root `root2` extends the tree of `first` leaves with root `root1`. */
export declare function verifyConsistency(first: any, second: any, root1: any, root2: any, proof: any): Promise<boolean>;
/**
 * Check one answer against the witnessed tree. `doc` is what GET https://crawlcheck.io/log/inclusion?leaf=<leaf hash> returns
 * ({ leaf_hash, index, tree_size, path, checkpoint }); `leafHash` is the leaf the caller computed or was given for the answer.
 * The root is taken from the VERIFIED checkpoint, never from the document's own "root" field.
 */
export declare function verifyAnswerInLog(doc: any, leafHash: any, opts?: {}): Promise<{
    ok: boolean;
    included: boolean;
    checkpoint: {
        ok: boolean;
        origin: null;
        size: null;
        root: null;
        log_signed: boolean;
        cosigned_by: never[];
        witnesses_pinned: number;
        quorum: number;
        quorum_met: boolean;
        witnessed: boolean;
    } | {
        ok: boolean;
        origin: null;
        size: null;
        root: null;
        log_signed: boolean;
        cosigned_by: never[];
        witnesses_pinned: number;
        quorum: number;
        quorum_met: boolean;
        witnessed: boolean;
        why: string;
    };
} | {
    ok: boolean;
    included: boolean;
    checkpoint: {
        ok: boolean;
        origin: null;
        size: null;
        root: null;
        log_signed: boolean;
        cosigned_by: never[];
        witnesses_pinned: number;
        quorum: number;
        quorum_met: boolean;
        witnessed: boolean;
    } | {
        ok: boolean;
        origin: null;
        size: null;
        root: null;
        log_signed: boolean;
        cosigned_by: never[];
        witnesses_pinned: number;
        quorum: number;
        quorum_met: boolean;
        witnessed: boolean;
        why: string;
    };
    why: any;
}>;
