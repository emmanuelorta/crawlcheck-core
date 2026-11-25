// Outside-witness verification for the CrawlCheck answer log (C2SP tlog-checkpoint, tlog-cosignature, RFC 6962 proofs).
// The log publishes one tree over every signed answer and signs its head as a checkpoint: three lines (origin, tree size,
// base64 root) and an Ed25519 signature line from the log's key. A witness that has checked the log only ever grew adds
// its own cosignature line. With this module a client checks, offline:
//   1. the checkpoint is signed by the log key it pinned (verifyCheckpoint);
//   2. how many of the witnesses IT pinned cosigned that exact checkpoint, and whether that meets its quorum;
//   3. an answer's leaf is in the tree the checkpoint commits to (verifyInclusion / verifyAnswerInLog);
//   4. a later checkpoint extends an earlier one (verifyConsistency).
// A cosignature from a key the caller did not pin counts for nothing. The witness list ships EMPTY: until a witness is
// pinned, "witnessed" is false and a quorum above zero is not met. Zero dependencies; WebCrypto only.
export const LOG_ORIGIN = "crawlcheck.io/log";
export const LOG_VKEY = "crawlcheck.io/log+4b13e34e+AdysJh4Ix53TtkimkZ22ciVKyLSkE7Fe66ocUkTfWcpe";
/** Witness verifier keys (cosignature/v1, key type 0x04) this SDK version trusts by default. None yet. */
export const WITNESS_VKEYS = Object.freeze([]);

const enc = (s) => new TextEncoder().encode(s);
const sha256 = async (u8) => new Uint8Array(await crypto.subtle.digest("SHA-256", u8));
function cat(...a) { let n = 0; for (const x of a) n += x.length; const o = new Uint8Array(n); let k = 0; for (const x of a) { o.set(x, k); k += x.length; } return o; }
function b64(u8) { let s = ""; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s); }
function unb64(s) {   // canonical standard base64 only
  if (typeof s !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4) return null;
  let b; try { b = atob(s); } catch { return null; } const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
  return b64(u) === s ? u : null;
}
const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
function unhex(h) { if (typeof h !== "string" || !/^([0-9a-f]{2})*$/.test(h)) return null; const o = new Uint8Array(h.length / 2); for (let i = 0; i < o.length; i++) o[i] = parseInt(h.substr(i * 2, 2), 16); return o; }
function eq(a, b) { if (!a || !b || a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }
async function edVerify(pub, sig, msg) { try { const k = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]); return await crypto.subtle.verify({ name: "Ed25519" }, k, sig, msg); } catch { return false; } }

/** Parse a verifier key "<name>+<8 hex key id>+<base64(type byte || 32-byte key)>"; null unless the key id matches. */
export async function parseVkey(vkey) {
  const m = /^([^+\s]+)\+([0-9a-f]{8})\+([A-Za-z0-9+/=]+)$/.exec(String(vkey || "")); if (!m) return null;
  const k = unb64(m[3]); if (!k || k.length !== 33) return null;
  const id = (await sha256(cat(enc(m[1] + "\n"), k.slice(0, 1), k.slice(1)))).slice(0, 4);
  return hex(id) === m[2] ? { name: m[1], id: m[2], type: k[0], pub: k.slice(1), vkey: String(vkey) } : null;
}
/** Parse a checkpoint note into its body and signature lines. Returns { error } when it is not one. */
export function parseCheckpoint(note) {
  if (typeof note !== "string" || /[\u0000-\u0009\u000b-\u001f]/.test(note)) return { error: "not a text note" };
  const k = note.lastIndexOf("\n\n"); if (k < 0) return { error: "no signature block" };
  const text = note.slice(0, k + 1), sp = note.slice(k + 2); if (!sp || !sp.endsWith("\n")) return { error: "signature lines must end in a newline" };
  const sigs = [];
  for (const l of sp.slice(0, -1).split("\n")) { const m = /^\u2014 ([^\s+]+) ([A-Za-z0-9+/=]+)$/.exec(l); if (!m) return { error: "malformed signature line" }; const b = unb64(m[2]); if (!b || b.length < 5) return { error: "malformed signature" }; sigs.push({ name: m[1], id: hex(b.slice(0, 4)), sig: b.slice(4) }); }
  const ls = text.slice(0, -1).split("\n"); if (ls.length < 3 || ls.some((x) => x === "")) return { error: "a checkpoint is at least three non-empty lines" };
  if (!/^(0|[1-9][0-9]{0,15})$/.test(ls[1]) || !Number.isSafeInteger(Number(ls[1]))) return { error: "bad tree size line" };
  const root = unb64(ls[2]); if (!root || root.length !== 32) return { error: "bad root hash line" };
  return { text, origin: ls[0], size: Number(ls[1]), root, sigs };
}
/**
 * Verify a checkpoint: the pinned log key signed it, and count cosignatures from the pinned witnesses.
 * opts: { logVkey = LOG_VKEY, witnesses = WITNESS_VKEYS, quorum = 0 }.
 * ok is true only when the log signature verifies AND at least `quorum` distinct pinned witnesses cosigned.
 */
export async function verifyCheckpoint(note, opts = {}) {
  const out = { ok: false, origin: null, size: null, root: null, log_signed: false, cosigned_by: [], witnesses_pinned: 0, quorum: 0, quorum_met: false, witnessed: false };
  const logVkey = opts.logVkey ?? LOG_VKEY, wl = opts.witnesses ?? WITNESS_VKEYS, quorum = opts.quorum ?? 0;
  if (!Number.isInteger(quorum) || quorum < 0) return { ...out, why: "quorum must be a whole number, zero or more" };
  out.quorum = quorum;
  const cp = parseCheckpoint(note); if (cp.error) return { ...out, why: cp.error };
  const lk = await parseVkey(logVkey); if (!lk || lk.type !== 1) return { ...out, why: "the log key is not an Ed25519 verifier key" };
  out.origin = cp.origin; out.size = cp.size; out.root = b64(cp.root);
  if (cp.origin !== lk.name) return { ...out, why: "the checkpoint's origin is not the pinned log" };
  const msg = enc(cp.text);
  for (const s of cp.sigs) if (s.name === lk.name && s.id === lk.id && s.sig.length === 64 && await edVerify(lk.pub, s.sig, msg)) out.log_signed = true;
  if (!out.log_signed) return { ...out, why: "no valid signature from the pinned log key" };
  const seen = new Set(), pinned = new Set();
  for (const v of wl) {
    const wk = await parseVkey(v); if (!wk || wk.type !== 4) continue;
    if (pinned.has(wk.name + "+" + wk.id)) continue; pinned.add(wk.name + "+" + wk.id); out.witnesses_pinned++;   // a witness listed twice is one witness
    for (const s of cp.sigs) {
      if (s.name !== wk.name || s.id !== wk.id || s.sig.length !== 72) continue;
      const t = new DataView(s.sig.buffer, s.sig.byteOffset, 8).getBigUint64(0, false);
      if (await edVerify(wk.pub, s.sig.slice(8), enc("cosignature/v1\ntime " + t + "\n" + cp.text))) { seen.add(wk.name + "+" + wk.id); out.cosigned_by.push({ name: wk.name, time: Number(t) }); break; }
    }
  }
  out.witnessed = out.cosigned_by.length > 0; out.quorum_met = out.cosigned_by.length >= quorum; out.ok = out.quorum_met;
  if (!out.ok) out.why = "cosigned by " + out.cosigned_by.length + " pinned witness(es), quorum is " + quorum;
  return out;
}
const node = async (l, r) => sha256(cat(new Uint8Array([1]), l, r));
const asHash = (x) => { const u = x instanceof Uint8Array ? x : (typeof x === "string" ? (/^[0-9a-f]{64}$/.test(x) ? unhex(x) : unb64(x)) : null); return u && u.length === 32 ? u : null; };
/** RFC 6962 audit path check: leaf (hex or base64 or bytes) at `index` of a tree of `treeSize` leaves hashes up `path` to `root`. */
export async function verifyInclusion(leaf, index, treeSize, path, root) {
  const lh = asHash(leaf), rt = asHash(root); if (!lh || !rt || !Array.isArray(path)) return false;
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(treeSize) || index < 0 || index >= treeSize) return false;
  let fn = BigInt(index), sn = BigInt(treeSize) - 1n, r = lh;
  for (const p0 of path) { const p = asHash(p0); if (!p || sn === 0n) return false;
    if ((fn & 1n) || fn === sn) { r = await node(p, r); if (!(fn & 1n)) while (!(fn & 1n) && fn !== 0n) { fn >>= 1n; sn >>= 1n; } }
    else r = await node(r, p);
    fn >>= 1n; sn >>= 1n; }
  return sn === 0n && eq(r, rt);
}
/** RFC 6962 consistency check: the tree of `second` leaves with root `root2` extends the tree of `first` leaves with root `root1`. */
export async function verifyConsistency(first, second, root1, root2, proof) {
  const h1 = asHash(root1), h2 = asHash(root2); if (!h1 || !h2 || !Array.isArray(proof)) return false;
  if (!Number.isSafeInteger(first) || !Number.isSafeInteger(second) || first < 1 || first > second) return false;
  if (first === second) return proof.length === 0 && eq(h1, h2);
  let pr = proof.map(asHash); if (!pr.length || pr.some((x) => !x)) return false;
  let f = BigInt(first), s = BigInt(second); if ((f & (f - 1n)) === 0n) pr = [h1].concat(pr);
  let fn = f - 1n, sn = s - 1n; while (fn & 1n) { fn >>= 1n; sn >>= 1n; }
  let fr = pr[0], sr = pr[0];
  for (let i = 1; i < pr.length; i++) { const c = pr[i]; if (sn === 0n) return false;
    if ((fn & 1n) || fn === sn) { fr = await node(c, fr); sr = await node(c, sr); if (!(fn & 1n)) while (!(fn & 1n) && fn !== 0n) { fn >>= 1n; sn >>= 1n; } }
    else sr = await node(sr, c);
    fn >>= 1n; sn >>= 1n; }
  return sn === 0n && eq(fr, h1) && eq(sr, h2);
}
/**
 * Check one answer against the witnessed tree. `doc` is what GET https://crawlcheck.io/log/inclusion?leaf=<leaf hash> returns
 * ({ leaf_hash, index, tree_size, path, checkpoint }); `leafHash` is the leaf the caller computed or was given for the answer.
 * The root is taken from the VERIFIED checkpoint, never from the document's own "root" field.
 */
export async function verifyAnswerInLog(doc, leafHash, opts = {}) {
  const cp = await verifyCheckpoint(doc && doc.checkpoint, opts);
  const out = { ok: false, included: false, checkpoint: cp };
  if (!cp.log_signed) return { ...out, why: cp.why };
  if (!doc || doc.tree_size !== cp.size) return { ...out, why: "the proof is for another tree size than the checkpoint" };
  if (leafHash != null && String(leafHash).toLowerCase() !== String(doc.leaf_hash).toLowerCase()) return { ...out, why: "the proof is for another leaf" };
  out.included = await verifyInclusion(doc.leaf_hash, doc.index, doc.tree_size, doc.path, cp.root);
  if (!out.included) return { ...out, why: "the audit path does not lead to the checkpoint's root" };
  out.ok = cp.ok; if (!out.ok) out.why = cp.why;
  return out;
}
