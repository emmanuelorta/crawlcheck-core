// mcp-tool-set-digest/1 (https://github.com/alexar76/mcp-tool-set-digest, draft of 2026-11-12), 1.15.0.
//
// The shared definition of the two tool-list digests, written down by HISTOR's author from the construction CrawlCheck
// publishes as jcs-v1. In the ordinary case the values equal lock.jcs_v1 (same contract members, RFC 8785, SHA-256, SRI).
// They part only where jcs-v1 repairs or bounds the input and this definition gives no digest:
//   TSD-TOOL    an element is not a JSON object, or has no non-empty string name           -> neither digest
//   TSD-TEXT    a string or member name holds a surrogate without its pair                 -> the digest covering it
//   TSD-NUMBER  a number with no IEEE 754 double (1e400)                                   -> the digest covering it
//   TSD-NAME    two tools share a name and both carry extras                               -> the extras digest
//   TSD-PAGE    the list is not complete                                                   -> neither digest
//   TSD-DEPTH   an array or object nested deeper than TSD_MAX_DEPTH (512) levels,
//               counting the tools array as level 1                                        -> the digest covering it
// TSD-DEPTH is a reader limit, not a code of /1 yet: without it a deep list either exhausted the stack or gave a digest
// in one SDK and not the other (1.15.3). Nothing is repaired, skipped or cut here. The two digests are computed apart:
// a member outside the contract cannot take the contract digest away. jcs-v1 (./jcs.js) stays the bounded form the
// signed lockfile carries.
const enc = new TextEncoder();
const subtle = globalThis.crypto && globalThis.crypto.subtle;
const b64 = (u8) => { let s = ""; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s); };
const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
const sha = async (text) => new Uint8Array(await subtle.digest("SHA-256", enc.encode(text)));
export const TSD_SPEC = "mcp-tool-set-digest/1";
const TSD_MAX_DEPTH = 512;   // arrays and objects; the tools array is level 1, a tool object level 2 (same bound in tsd.py)
const LONE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

export class ToolSetDigestError extends Error { constructor(code, detail, tool) { super(code + ": " + detail); this.code = code; if (tool) this.tool = tool; } }
const str = (s) => { if (LONE.test(s)) throw new ToolSetDigestError("TSD-TEXT", "a string holds a surrogate without its pair"); return JSON.stringify(s); };
/** RFC 8785 text of a parsed JSON value. Throws ToolSetDigestError (TSD-TEXT, TSD-NUMBER, TSD-DEPTH) where the value has none.
 * level is the nesting level of v itself (1 = the tools array). Iterative, so the depth bound and not the engine's stack
 * decides how deep a value may go; errors surface in document order. */
export function tsdCanonical(v, level = 1) {
  const out = [], todo = [[0, v, level]];   // [0, value, level] writes a value, [1, text] writes text, [2, name] a member name
  while (todo.length) {
    const [kind, x, lv] = todo.pop();
    if (kind === 1) { out.push(x); continue; }
    if (kind === 2) { out.push(str(x) + ":"); continue; }
    if (x === null || typeof x === "boolean") out.push(String(x));
    else if (typeof x === "number") { if (!Number.isFinite(x)) throw new ToolSetDigestError("TSD-NUMBER", "a number with no IEEE 754 double"); out.push(JSON.stringify(x)); }
    else if (typeof x === "string") out.push(str(x));
    else if (typeof x === "object") {
      if (lv > TSD_MAX_DEPTH) throw new ToolSetDigestError("TSD-DEPTH", "nested deeper than " + TSD_MAX_DEPTH + " levels");
      if (Array.isArray(x)) {
        todo.push([1, "]"]);
        for (let i = x.length - 1; i >= 0; i--) { todo.push([0, x[i], lv + 1]); if (i) todo.push([1, ","]); }
        todo.push([1, "["]);
      } else {
        const keys = Object.keys(x).sort();
        todo.push([1, "}"]);
        for (let i = keys.length - 1; i >= 0; i--) { todo.push([0, x[keys[i]], lv + 1]); todo.push([2, keys[i]]); if (i) todo.push([1, ","]); }
        todo.push([1, "{"]);
      }
    } else throw new TypeError(typeof x + " is not a JSON value");
  }
  return out.join("");
}
const isObj = (x) => !!x && typeof x === "object" && !Array.isArray(x);
function toolObject(t) {
  if (!isObj(t)) throw new ToolSetDigestError("TSD-TOOL", "a tool entry is not a JSON object");
  if (typeof t.name !== "string" || !t.name) throw new ToolSetDigestError("TSD-TOOL", "a tool entry has no non-empty string name");
  return t;
}
/** A tool's contract entry (section 4). */
export function tsdContractEntry(tool) {
  const t = toolObject(tool);
  const o = { name: t.name, description: typeof t.description === "string" ? t.description : "", inputSchema: isObj(t.inputSchema) ? t.inputSchema : {} };
  if (isObj(t.outputSchema)) o.outputSchema = t.outputSchema;
  return o;
}
const CONTRACT = { name: 1, description: 1, inputSchema: 1, outputSchema: 1 };
const extrasOf = (t) => Object.fromEntries(Object.entries(t).filter(([k]) => !Object.prototype.hasOwnProperty.call(CONTRACT, k)));   // every own member, one named __proto__ included
const byteCmp = (a, b) => { const n = Math.min(a.length, b.length); for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i]; return a.length - b.length; };
const named = (e, t) => { if (e instanceof ToolSetDigestError && !e.tool && isObj(t) && typeof t.name === "string" && t.name && !LONE.test(t.name)) e.tool = t.name; return e; };

async function contractOf(tools) {
  const rows = tools.map((t) => { try { const e = tsdContractEntry(t), text = tsdCanonical(e, 2); return { name: e.name, text, bytes: enc.encode(text) }; } catch (e) { throw named(e, t); } });
  rows.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : byteCmp(a.bytes, b.bytes)));
  const text = "[" + rows.map((r) => r.text).join(",") + "]";
  return { digest: "sha256-" + b64(await sha(text)), canonical: text };
}
async function extrasDigestOf(tools) {
  const names = [], per = new Map();
  for (const item of tools) {
    const t = toolObject(item), x = extrasOf(t);
    if (!Object.keys(x).length) continue;
    if (per.has(t.name)) throw new ToolSetDigestError("TSD-NAME", "two tools share a name and both carry extras", LONE.test(t.name) ? undefined : t.name);
    per.set(t.name, x); names.push(t.name);
  }
  if (!names.length) return { digest: null };
  names.sort();   // UTF-16 code units, the order RFC 8785 gives member names
  const text = '{"tools":{' + names.map((n) => { try { return str(n) + ":" + tsdCanonical(per.get(n), 2); } catch (e) { throw named(e, { name: n }); } }).join(",") + "}}";
  return { digest: "sha256-" + b64(await sha(text)), canonical: text };
}
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
export async function toolSetDigest(tools, opts = {}) {
  const out = { spec: TSD_SPEC, contract: null, extras: null };
  if (opts.partial) { out.contract = { error: "TSD-PAGE" }; out.extras = { error: "TSD-PAGE" }; return out; }
  if (!Array.isArray(tools)) { out.contract = { error: "TSD-TOOL" }; out.extras = { error: "TSD-TOOL" }; return out; }
  // Section 10: a set-level fault (TSD-TOOL) is found before any value is written, so it wins over TSD-TEXT / TSD-NUMBER in an earlier entry.
  try { for (const item of tools) toolObject(item); }
  catch (e) { if (!(e instanceof ToolSetDigestError)) throw e; const r = e.tool ? { error: e.code, tool: e.tool } : { error: e.code }; out.contract = r; out.extras = Object.assign({}, r); return out; }
  for (const [kind, fn] of [["contract", contractOf], ["extras", extrasDigestOf]]) {
    try { out[kind] = await fn(tools); }
    catch (e) { if (!(e instanceof ToolSetDigestError)) throw e; out[kind] = e.tool ? { error: e.code, tool: e.tool } : { error: e.code }; }
  }
  if (opts.perTool && out.contract.digest) {
    out.tools = [];
    for (const t of tools) { const row = { name: t.name, contract: hex(await sha(tsdCanonical(tsdContractEntry(t), 2))) }; try { row.extras = hex(await sha(tsdCanonical(extrasOf(t), 2))); } catch (e) { if (!(e instanceof ToolSetDigestError)) throw e; row.extras = null; row.extras_error = e.code; } out.tools.push(row); }
  }
  return out;
}
