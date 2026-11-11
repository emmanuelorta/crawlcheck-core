// jcs-v1 tool-list digests (https://crawlcheck.io/spec/mcp-lockfile#jcs-v1), 1.14.0. The same construction the lockfile
// endpoint publishes as lock.jcs_v1, step for step, so a digest computed here equals the signed one byte for byte.
//
//   contract  {name, description, inputSchema, outputSchema}: description "" when absent or not a string, inputSchema {}
//             when absent or not an object, outputSchema only when the server sent an object. RFC 8785, SHA-256 (hex).
//   extras    every other member (title, annotations, icons, execution, _meta, vendor members), strings cleaned (NUL and
//             unpaired surrogates -> U+FFFD), nesting past 12 levels -> "…". RFC 8785, SHA-256 (hex).
//   tools_sha256   SRI sha256 over the RFC 8785 array of contracts sorted by name (UTF-16 code units; ties by bytes).
//   extras_sha256  SRI sha256 over {"tools": {name: extras}} for the tools that carry extras ("" when none do), with
//                  "oversized" (one tool's extras > 16,384 bytes) and "omitted" (past 262,144 bytes in all).
// A tool with no name, or a number with no IEEE 754 double, makes the list not digestible: tools_sha256 null and a reason.
// No list is cut: every tool given is digested and listed.
const enc = new TextEncoder();
const subtle = globalThis.crypto && globalThis.crypto.subtle;
const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
const b64 = (u8) => { let s = ""; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s); };
const sha = async (bytes) => new Uint8Array(await subtle.digest("SHA-256", bytes));
export const JCS_V1_SPEC = "https://crawlcheck.io/spec/mcp-lockfile#jcs-v1";

/** RFC 8785 canonical JSON (keys in UTF-16 code-unit order, ECMAScript number form, no whitespace). Throws on a non-finite number. */
export function jcsCanon(v) {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") { if (!isFinite(v)) throw new Error("a number with no IEEE 754 double"); return JSON.stringify(v); }
  if (Array.isArray(v)) return "[" + v.map(jcsCanon).join(",") + "]";
  if (typeof v === "object") return "{" + Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => JSON.stringify(k) + ":" + jcsCanon(v[k])).join(",") + "}";
  throw new Error("not a JSON value");
}
const isObj = (x) => !!x && typeof x === "object" && !Array.isArray(x);
/** A tool's contract: what the model reads and the call takes or returns. */
export function jcsContract(t) {
  const o = { name: t.name, description: typeof t.description === "string" ? t.description : "", inputSchema: isObj(t.inputSchema) ? t.inputSchema : {} };
  if (isObj(t.outputSchema)) o.outputSchema = t.outputSchema;
  return o;
}
const cleanS = (s) => String(s).replace(/\u0000/g, "�").replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, "�");
function clean(v, d) {
  if (d > 12) return "…";
  if (typeof v === "string") return cleanS(v);
  if (Array.isArray(v)) return v.map((x) => clean(x, d + 1));
  if (v && typeof v === "object") { const o = {}; Object.keys(v).forEach((k) => { o[cleanS(k)] = clean(v[k], d + 1); }); return o; }
  return v;
}
/** A tool's extras: every member beyond name, description, inputSchema and outputSchema. */
export function jcsExtras(t) {
  const o = {};
  Object.keys(t || {}).forEach((k) => { if (k !== "name" && k !== "description" && k !== "inputSchema" && k !== "outputSchema") o[k] = t[k]; });
  return clean(o, 0);
}
const cpCmp = (a, b) => { const x = Array.from(a), y = Array.from(b), n = Math.min(x.length, y.length); for (let i = 0; i < n; i++) { const c = x[i].codePointAt(0) - y[i].codePointAt(0); if (c) return c; } return x.length - y.length; };
const byteCmp = (a, b) => { const n = Math.min(a.length, b.length); for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i]; return a.length - b.length; };
async function extrasSet(tools) {
  const per = {};
  for (const t of tools || []) { if (!t || typeof t.name !== "string" || !t.name) continue; const x = jcsExtras(t); if (Object.keys(x).length) per[cleanS(t.name)] = x; }
  const names = Object.keys(per).sort(cpCmp); if (!names.length) return "";
  const body = { tools: {} }, over = {}, omit = []; let used = 0;
  for (const n of names) { const sz = enc.encode(jcsCanon(per[n])).length; if (sz > 16384) { over[n] = sz; continue; } if (used + sz > 262144) { omit.push(n); continue; } body.tools[n] = per[n]; used += sz; }
  if (Object.keys(over).length) body.oversized = over; if (omit.length) body.omitted = omit;
  return "sha256-" + b64(await sha(enc.encode(jcsCanon(body))));
}

/**
 * The jcs-v1 digests of a tools/list result (every page). opts.partial: true when a page was not read (the list is then
 * not digested). Returns { alg, spec, count, tools_sha256, extras_sha256, tools: [{name, contract, extras}] } or
 * { alg, spec, tools_sha256: null, reason }.
 */
export async function jcsV1(tools, opts = {}) {
  if (opts.partial) return { alg: "jcs-v1", spec: JCS_V1_SPEC, tools_sha256: null, reason: "the tool list has more pages than were read; a partial list is not digested" };
  try {
    const rows = [];
    for (const t of tools || []) {
      if (!t || typeof t.name !== "string" || !t.name) return { alg: "jcs-v1", spec: JCS_V1_SPEC, tools_sha256: null, reason: "a tool has no name" };
      const cj = jcsCanon(jcsContract(t)), cb = enc.encode(cj);
      rows.push({ name: t.name, cj, cb, contract: hex(await sha(cb)), extras: hex(await sha(enc.encode(jcsCanon(jcsExtras(t))))) });
    }
    rows.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : byteCmp(a.cb, b.cb)));
    return { alg: "jcs-v1", spec: JCS_V1_SPEC, count: rows.length,
      tools_sha256: "sha256-" + b64(await sha(enc.encode("[" + rows.map((r) => r.cj).join(",") + "]"))),
      extras_sha256: await extrasSet(tools),
      tools: rows.map((r) => ({ name: r.name, contract: r.contract, extras: r.extras })) };
  } catch (e) { return { alg: "jcs-v1", spec: JCS_V1_SPEC, tools_sha256: null, reason: String((e && e.message) || e).slice(0, 120) }; }
}
