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
// Nothing is repaired, skipped, cut or bounded here. The two digests are computed apart: a member outside the contract
// cannot take the contract digest away. jcs-v1 (./jcs.js) stays the bounded form the signed lockfile carries.
const enc = new TextEncoder();
const subtle = globalThis.crypto && globalThis.crypto.subtle;
const b64 = (u8) => { let s = ""; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s); };
const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
const sha = async (text) => new Uint8Array(await subtle.digest("SHA-256", enc.encode(text)));
export const TSD_SPEC = "mcp-tool-set-digest/1";
const LONE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

export class ToolSetDigestError extends Error { constructor(code, detail, tool) { super(code + ": " + detail); this.code = code; if (tool) this.tool = tool; } }
const str = (s) => { if (LONE.test(s)) throw new ToolSetDigestError("TSD-TEXT", "a string holds a surrogate without its pair"); return JSON.stringify(s); };
/** RFC 8785 text of a parsed JSON value. Throws ToolSetDigestError (TSD-TEXT, TSD-NUMBER) where the value has none. */
export function tsdCanonical(v) {
  if (v === null || typeof v === "boolean") return String(v);
  if (typeof v === "number") { if (!Number.isFinite(v)) throw new ToolSetDigestError("TSD-NUMBER", "a number with no IEEE 754 double"); return JSON.stringify(v); }
  if (typeof v === "string") return str(v);
  if (Array.isArray(v)) return "[" + v.map(tsdCanonical).join(",") + "]";
  if (typeof v === "object") return "{" + Object.keys(v).sort().map((k) => str(k) + ":" + tsdCanonical(v[k])).join(",") + "}";
  throw new TypeError(typeof v + " is not a JSON value");
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
const extrasOf = (t) => { const o = {}; for (const k of Object.keys(t)) if (!Object.prototype.hasOwnProperty.call(CONTRACT, k)) o[k] = t[k]; return o; };
const byteCmp = (a, b) => { const n = Math.min(a.length, b.length); for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i]; return a.length - b.length; };
const named = (e, t) => { if (e instanceof ToolSetDigestError && !e.tool && isObj(t) && typeof t.name === "string" && t.name && !LONE.test(t.name)) e.tool = t.name; return e; };

async function contractOf(tools) {
  const rows = tools.map((t) => { try { const e = tsdContractEntry(t), text = tsdCanonical(e); return { name: e.name, text, bytes: enc.encode(text) }; } catch (e) { throw named(e, t); } });
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
  const text = '{"tools":{' + names.map((n) => { try { return str(n) + ":" + tsdCanonical(per.get(n)); } catch (e) { throw named(e, { name: n }); } }).join(",") + "}}";
  return { digest: "sha256-" + b64(await sha(text)), canonical: text };
}
/**
 * The two digests of a complete tools/list result (every page joined). Each side is { digest, canonical } or
 * { error: "TSD-…", tool? }; extras is { digest: null } when no tool carries a member outside the contract.
 * opts.partial: true when a page was not read: neither digest (TSD-PAGE). opts.perTool adds the optional per-tool digests.
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
    for (const t of tools) { const row = { name: t.name, contract: hex(await sha(tsdCanonical(tsdContractEntry(t)))) }; try { row.extras = hex(await sha(tsdCanonical(extrasOf(t)))); } catch (e) { if (!(e instanceof ToolSetDigestError)) throw e; row.extras = null; row.extras_error = e.code; } out.tools.push(row); }
  }
  return out;
}
