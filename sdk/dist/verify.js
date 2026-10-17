// crawlcheck-verify.mjs — verifies a CrawlCheck evidence bundle with no call to crawlcheck.io.
// Zero dependencies. Node 20+:  node crawlcheck-verify.mjs bundle.json
// Browser or Node module:        import { verifyBundle } from "./crawlcheck-verify.mjs"
//
// Also verifies a remediation receipt (node crawlcheck-verify.mjs receipt.json): receipt_hash, key_id, signature, order;
// and an evidence export (node crawlcheck-verify.mjs export.json): export_hash, key_id, signature, then every bundle and receipt inside it.
// And a dispute resolution (node crawlcheck-verify.mjs resolution.json): resolution_hash, key_id, signature,
// verdict_derivable (re-runs the published decision table over the recorded readings), readings_after_dispute.
// And a data inventory, export part or deletion record (node crawlcheck-verify.mjs deletion.json): document_hash, key_id, signature.
// What it checks, each from the bytes inside the bundle:
//   manifest_hash      sha256(manifest.body) equals manifest.sha256
//   key_id             the RFC 7638 thumbprint of the public key equals the signature's key id
//   signature          Ed25519 over "crawlcheck-meg-manifest-v1\n" + manifest sha256
//   subject_hash       sha256(record.subject) equals the record digest (the leaf)
//   subject_binds      the subject names this report, and its meg field names this manifest
//   merkle_path        the leaf folds along the path to the day's root
//   ots_commits_root   the .ots file timestamps exactly that root
//   ots_attestations   the op chain evaluated: pending calendars, or the Bitcoin block and the merkle root it commits to
//   experience_root    (manifest v3) the manifest's sealed root over its fetches recomputes from the fetches it lists
//   decision_root      (manifest v3) the sealed root over the decisions recomputes from the decision leaves (licence bundles)
//   lineage_root       (manifest v3) the sealed root over the extracted business facts recomputes from their leaves (licence bundles)
// A check that cannot run (a withheld subject, an unsealed day) is null with the reason, never a pass.
// Every result also separates the questions a single "verified" used to answer at once (vt1, 2026-10-06):
//   integrity_valid   no check over the bytes failed (hashes, signature, proof paths)
//   issuer_trusted    the signing key is in CrawlCheck's published key directory: true / false, or null offline
//   accepted          integrity_valid AND issuer_trusted === true. Act on this, never on verified alone.
//   accepted_strict   accepted AND every check ran (legacy and pre-manifest records stay false: less was sealed)
//   assurance         "complete" or "partial", with unavailable[] naming the checks that could not run
// Offline, issuer_trusted is null and accepted is false. Close it with --online (fetches the key directory) or
// pass the published key ids yourself: verifyReceipt(doc, { publishedKids: [...] }).
// What it cannot do offline: read a Bitcoin block header. It prints the block height and the merkle root the
// proof commits to; compare that value with any Bitcoin node or block explorer.
const MEG_SIG_PREFIX = "crawlcheck-meg-manifest-v1\n";
const OTS_MAGIC = [0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94];
const TAG_BITCOIN = "0588960d73d71901", TAG_PENDING = "83dfe30d2ef90c8e", TAG_LITECOIN = "06869a0d73d71b45";
const subtle = globalThis.crypto && globalThis.crypto.subtle;
const enc = new TextEncoder();
const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
const unhex = (h) => { const s = String(h || ""); const o = new Uint8Array(s.length >> 1); for (let i = 0; i < o.length; i++)
    o[i] = parseInt(s.substr(i * 2, 2), 16); return o; };
const sha256 = async (u8) => new Uint8Array(await subtle.digest("SHA-256", u8));
const b64 = (s) => { const t = String(s || "").replace(/-/g, "+").replace(/_/g, "/"); const p = t.padEnd(Math.ceil(t.length / 4) * 4, "="); const bin = atob(p); const o = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++)
    o[i] = bin.charCodeAt(i); return o; };
const b64u = (u8) => { let s = ""; for (const b of u8)
    s += String.fromCharCode(b); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
const cat = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a, 0); o.set(b, a.length); return o; };
// The same canonical JSON the observer hashes: keys sorted at every level, no whitespace, undefined as null.
export function canon(v) {
    if (v === null || typeof v !== "object")
        return JSON.stringify(v === undefined ? null : v);
    if (Array.isArray(v))
        return "[" + v.map(canon).join(",") + "]";
    return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
}
// The same Merkle tree the daily seal uses: leaves sorted as hex, parent = SHA-256(left || right), odd node paired with itself.
export async function merkleRootHex(hexLeaves) {
    if (!hexLeaves.length)
        return "";
    let level = hexLeaves.slice().sort();
    while (level.length > 1) {
        const next = [];
        for (let i = 0; i < level.length; i += 2)
            next.push(hex(await sha256(cat(unhex(level[i]), unhex(level[i + 1] === undefined ? level[i] : level[i + 1])))));
        level = next;
    }
    return level[0];
}
const leafHex = async (o) => hex(await sha256(enc.encode(canon(o))));
// ── OpenTimestamps: parse the detached proof and evaluate every branch ─────────
function reader(u8) {
    let i = 0;
    return {
        left: () => u8.length - i,
        byte() { if (i >= u8.length)
            throw new Error("ots: truncated"); return u8[i++]; },
        bytes(n) { if (i + n > u8.length)
            throw new Error("ots: truncated"); const o = u8.slice(i, i + n); i += n; return o; },
        varuint() { let v = 0, s = 0, b; do {
            b = this.byte();
            v += (b & 0x7f) * Math.pow(2, s);
            s += 7;
        } while (b & 0x80); return v; },
        varbytes() { return this.bytes(this.varuint()); }
    };
}
async function otsBranch(rd, msg, out, depth) {
    if (depth > 256)
        throw new Error("ots: too deep");
    const one = async (tag) => {
        if (tag === 0x00) {
            const t = hex(rd.bytes(8)), payload = rd.varbytes();
            if (t === TAG_BITCOIN) {
                const pr = reader(payload);
                out.push({ kind: "bitcoin", height: pr.varuint(), commits_to_le: hex(msg), merkle_root: hex(msg.slice().reverse()) });
            }
            else if (t === TAG_PENDING) {
                const pr = reader(payload);
                out.push({ kind: "pending", calendar: new TextDecoder().decode(pr.varbytes()) });
            }
            else if (t === TAG_LITECOIN) {
                const pr = reader(payload);
                out.push({ kind: "litecoin", height: pr.varuint() });
            }
            else
                out.push({ kind: "unknown", tag: t });
            return;
        }
        let next;
        if (tag === 0x08)
            next = await sha256(msg);
        else if (tag === 0xf0)
            next = cat(msg, rd.varbytes());
        else if (tag === 0xf1)
            next = cat(rd.varbytes(), msg);
        else if (tag === 0xf2)
            next = msg.slice().reverse();
        else if (tag === 0xf3)
            next = enc.encode(hex(msg));
        else
            throw new Error("ots: op 0x" + tag.toString(16) + " is not supported by this verifier");
        await otsBranch(rd, next, out, depth + 1);
    };
    let tag = rd.byte();
    while (tag === 0xff) {
        await one(rd.byte());
        tag = rd.byte();
    }
    await one(tag);
}
export async function otsInspect(u8) {
    const rd = reader(u8);
    const magic = rd.bytes(OTS_MAGIC.length);
    if (!OTS_MAGIC.every((b, i) => magic[i] === b))
        throw new Error("not an OpenTimestamps proof (magic bytes differ)");
    const version = rd.varuint();
    if (version !== 1)
        throw new Error("ots: unsupported version " + version);
    const op = rd.byte();
    if (op !== 0x08)
        throw new Error("ots: file hash is not sha256");
    const digest = rd.bytes(32);
    const attestations = [];
    await otsBranch(rd, digest, attestations, 0);
    return { digest: hex(digest), attestations };
}
// ── the bundle ────────────────────────────────────────────────────────────────
async function verifyBundle0(b) {
    if (!subtle)
        throw new Error("this runtime has no WebCrypto (crypto.subtle)");
    const checks = [];
    const C = (id, ok, why, extra) => checks.push(Object.assign({ id, ok, why }, extra || {}));
    if (!b || b.kind !== "crawlcheck-evidence-bundle")
        throw new Error("not a CrawlCheck evidence bundle");
    const rep = b.report || {}, man = b.manifest || null, rec = b.record || {}, seal = b.seal || {};
    // 1. manifest bytes
    let manObj = null;
    if (!man)
        C("manifest_hash", null, "this record predates evidence manifests (2026-09-20)");
    else if (!man.body)
        C("manifest_hash", null, man.body_missing || "manifest body not included");
    else {
        const h = hex(await sha256(enc.encode(man.body)));
        C("manifest_hash", h === man.sha256, h === man.sha256 ? "manifest body hashes to " + h.slice(0, 16) + "…" : "manifest body hashes to " + h + ", bundle says " + man.sha256);
        try {
            manObj = JSON.parse(man.body);
        }
        catch (e) {
            manObj = null;
        }
    }
    // 2. key id + signature
    const sg = man && man.signature, key = man && man.key;
    if (!sg)
        C("key_id", null, "the manifest is unsigned (recorded before signing began, 2026-09-23)"), C("signature", null, "no signature to check");
    else if (!key || !key.jwk)
        C("key_id", null, "the signing key is not in the bundle (retired or unknown); look it up by id " + sg.kid), C("signature", null, "no key to check against");
    else {
        const thumb = b64u(await sha256(enc.encode(JSON.stringify({ crv: key.jwk.crv, kty: key.jwk.kty, x: key.jwk.x }))));
        C("key_id", thumb === sg.kid, thumb === sg.kid ? "public key thumbprint (RFC 7638) is the key id " + sg.kid.slice(0, 12) + "…; the same id is published in " + (key.published_in || "the key directory") : "thumbprint " + thumb + " does not match key id " + sg.kid);
        const msg = MEG_SIG_PREFIX + man.sha256;
        if (sg.message && sg.message !== msg)
            C("signature", false, "the signed message does not name this manifest");
        else {
            let ok = false;
            try {
                const pk = await subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: key.jwk.x }, { name: "Ed25519" }, false, ["verify"]);
                ok = await subtle.verify({ name: "Ed25519" }, pk, b64(sg.sig), enc.encode(msg));
            }
            catch (e) {
                C("signature", null, "this runtime cannot verify Ed25519: " + (e && e.message || e));
                ok = null;
            }
            if (ok !== null)
                C("signature", ok, ok ? "Ed25519 signature over the manifest digest verifies" : "signature does NOT verify");
        }
    }
    // 3. subject
    let subj = null;
    if (!rec.digest)
        C("subject_hash", null, "no record digest in the bundle");
    else if (!rec.subject)
        C("subject_hash", null, rec.subject_withheld || "subject not included");
    else {
        const h = hex(await sha256(enc.encode(rec.subject)));
        C("subject_hash", h === rec.digest, h === rec.digest ? "the sealed subject hashes to the record digest" : "subject hashes to " + h + ", digest is " + rec.digest);
        try {
            subj = JSON.parse(rec.subject);
        }
        catch (e) {
            subj = null;
        }
    }
    if (!subj)
        C("subject_binds", null, "needs the subject");
    else {
        const idOk = !rep.id || subj.id === rep.id, domOk = !rep.domain || subj.domain === rep.domain;
        const mOk = man ? subj.meg === man.sha256 : !("meg" in subj);
        C("subject_binds", idOk && domOk && mOk, (idOk ? "names report " + subj.id : "names report " + subj.id + ", bundle says " + rep.id) + (domOk ? ", domain " + subj.domain : ", domain mismatch") +
            (man ? (mOk ? ", and commits to this manifest" : ", but its meg field " + subj.meg + " is not this manifest") : ""));
    }
    // 4. merkle path
    if (seal.state !== "sealed")
        C("merkle_path", null, "the day is not sealed: " + (seal.why || seal.state || "unknown"));
    else {
        let h = unhex(rec.digest);
        for (const s of seal.path || [])
            h = await sha256(s.side === "right" ? cat(h, unhex(s.hash)) : cat(unhex(s.hash), h));
        const got = hex(h);
        C("merkle_path", got === seal.root, got === seal.root ? "the digest folds to the root of " + seal.day + " (" + (seal.path || []).length + " steps, " + (seal.leaves_that_day || "?") + " leaves that day)" : "the path folds to " + got + ", not the root " + seal.root);
    }
    // 5. timestamp
    let att = [];
    if (seal.state !== "sealed")
        C("ots_commits_root", null, "no seal yet"), C("ots_attestations", null, "no seal yet");
    else if (!seal.ots_base64)
        C("ots_commits_root", null, "the day's .ots bytes are not in the bundle"), C("ots_attestations", null, "no .ots");
    else {
        try {
            const o = await otsInspect(b64(seal.ots_base64));
            att = o.attestations;
            C("ots_commits_root", o.digest === seal.root, o.digest === seal.root ? "the timestamp proof is over exactly this root" : "the .ots timestamps " + o.digest + ", not the root " + seal.root);
            const btc = att.filter((a) => a.kind === "bitcoin"), pend = att.filter((a) => a.kind === "pending");
            if (btc.length)
                C("ots_attestations", true, "anchored in Bitcoin block " + Array.from(new Set(btc.map((a) => a.height))).join(", ") + "; the proof commits the root into merkle root " + btc[0].merkle_root + " - compare it with that block's header on any Bitcoin node", { bitcoin: btc });
            else if (pend.length)
                C("ots_attestations", null, "submitted to " + pend.map((a) => a.calendar).join(", ") + ", not yet confirmed in a Bitcoin block (usually within a few hours); download the bundle again later", { pending: pend });
            else
                C("ots_attestations", false, "the proof carries no attestation");
        }
        catch (e) {
            C("ots_commits_root", false, String(e && e.message || e));
            C("ots_attestations", null, "could not parse the proof");
        }
    }
    // 6. sealed roots (manifest v3)
    const roots = manObj && manObj.roots;
    const rootCheck = async (id, label, sealed, objs, missingWhy) => {
        if (!roots)
            return C(id, null, "the manifest predates sealed roots (manifest v3, 2026-09-30)");
        if (!sealed)
            return C(id, null, "the manifest carries no " + label + " root");
        if (!Array.isArray(objs))
            return C(id, null, missingWhy);
        const got = await merkleRootHex(await Promise.all(objs.map(leafHex)));
        const want = sealed.root || "";
        C(id, got === want && objs.length === sealed.n, got === want && objs.length === sealed.n ? objs.length + " " + label + " leaves recompute to the sealed root" : "the " + label + " leaves give " + (got || "(empty)").slice(0, 16) + "… over " + objs.length + ", the manifest sealed " + want.slice(0, 16) + "… over " + sealed.n);
    };
    await rootCheck("experience_root", "fetch", roots && roots.experiences, manObj && Array.isArray(manObj.experiences) ? manObj.experiences : null, "the manifest body is not in the bundle");
    await rootCheck("decision_root", "decision", roots && roots.decisions, rec.decision_leaves, rec.leaves_withheld || "decision leaves not included");
    await rootCheck("lineage_root", "lineage", roots && roots.lineage, rec.lineage_leaves, rec.leaves_withheld || "lineage leaves not included");
    const ran = checks.filter((c) => c.ok !== null), failed = checks.filter((c) => c.ok === false);
    return {
        verified: ran.length > 0 && failed.length === 0,
        summary: failed.length ? failed.length + " check(s) FAILED" : ran.length + " of " + checks.length + " checks ran and passed; " + (checks.length - ran.length) + " could not run (reasons given)",
        report: rep, checks,
        experiences: manObj && Array.isArray(manObj.experiences) ? manObj.experiences.length : null,
        note: "Every check above used only bytes inside the bundle. Only the Bitcoin block header has to come from outside, and from any source you trust."
    };
}
// ── remediation receipts ─────────────────────────────────────────────────────────────────────────────────
// A receipt joins the record before a fix, the declared fix, when it went live, the record after it and the
// verification verdict, and is signed with the observer's Ed25519 key over sha256(canonical JSON of everything but
// receipt_id and signature). Change any field and receipt_hash fails; swap the key and key_id fails.
const RCPT_SIG_PREFIX = "crawlcheck-receipt-v1\n";
async function verifyReceipt0(rc) {
    if (!subtle)
        throw new Error("this runtime has no WebCrypto (crypto.subtle)");
    const checks = [];
    const C = (id, ok, why) => checks.push({ id, ok, why });
    if (!rc || rc.kind !== "crawlcheck-remediation-receipt" || !rc.signature)
        throw new Error("not a CrawlCheck remediation receipt");
    const body = {};
    for (const k of Object.keys(rc))
        if (k !== "receipt_id" && k !== "signature")
            body[k] = rc[k];
    const sha = hex(await sha256(enc.encode(canon(body))));
    C("receipt_hash", sha === rc.signature.receipt_sha256 && rc.receipt_id === "rc1:" + sha, sha === rc.signature.receipt_sha256 ? "the receipt hashes to its id " + sha.slice(0, 16) + "…" : "the receipt hashes to " + sha + ", it claims " + rc.signature.receipt_sha256 + " - a field was changed");
    const jwk = rc.issuer && rc.issuer.key && rc.issuer.key.jwk;
    if (!jwk || !jwk.x) {
        C("key_id", null, "no key in the receipt");
        C("signature", null, "no key to check against");
    }
    else {
        const thumb = b64u(await sha256(enc.encode(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }))));
        C("key_id", thumb === rc.signature.kid, thumb === rc.signature.kid ? "public key thumbprint (RFC 7638) is the key id " + thumb.slice(0, 12) + "…; the same id is published in " + (rc.issuer.key.published_in || "the key directory") : "thumbprint " + thumb + " does not match key id " + rc.signature.kid);
        const msg = RCPT_SIG_PREFIX + sha;
        let ok = null;
        try {
            const pk = await subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: jwk.x }, { name: "Ed25519" }, false, ["verify"]);
            ok = rc.signature.message === msg && await subtle.verify({ name: "Ed25519" }, pk, b64(rc.signature.sig), enc.encode(msg));
        }
        catch (e) {
            ok = null;
            C("signature", null, "this runtime cannot verify Ed25519: " + (e && e.message || e));
        }
        if (ok !== null)
            C("signature", ok, ok ? "Ed25519 signature over the receipt digest verifies" : "signature does NOT verify over this content");
    }
    C("key_published", null, "offline this cannot be decided: compare key id " + (rc.signature.kid || "?") + " with the ids published at " + ((rc.issuer && rc.issuer.key && rc.issuer.key.published_in) || "the key directory") + " (a receipt re-signed with any other key passes every other check here)");
    const b = rc.before || {}, a = rc.after || {};
    C("order", !!(b.scanned_at && a.scanned_at && Date.parse(b.scanned_at) < Date.parse(a.scanned_at)), b.scanned_at && a.scanned_at ? "before " + b.scanned_at + " precedes after " + a.scanned_at : "a scan time is missing");
    const ran = checks.filter((c) => c.ok !== null), failed = checks.filter((c) => c.ok === false);
    return { verified: ran.length > 0 && failed.length === 0, summary: failed.length ? failed.length + " check(s) FAILED" : ran.length + " of " + checks.length + " checks ran and passed",
        receipt: { id: rc.receipt_id, domain: rc.subject && rc.subject.domain, verdict: rc.verification && rc.verification.verdict, before: b.report_id, after: a.report_id }, checks,
        note: "Every check used only the receipt itself. To confirm the key is CrawlCheck's, compare its id with " + ((rc.issuer && rc.issuer.key && rc.issuer.key.published_in) || "the published key directory") + "; to see the evidence behind each side, verify the two reports' bundles." };
}
// ── evidence exports ─────────────────────────────────────────────────────────────────────────────────────
// An export is one signed file for a domain and a period: records[] each carrying a full evidence bundle,
// receipts[], the certificate days and the seals. The file is signed over sha256(canonical JSON of everything but
// export_sha256 and signature); then every bundle and every receipt inside it is verified exactly as it would be on
// its own. One altered byte anywhere fails export_hash; one altered bundle fails its own checks.
const EXPORT_SIG_PREFIX = "crawlcheck-evidence-export-v1\n";
async function verifyExport0(x) {
    if (!subtle)
        throw new Error("this runtime has no WebCrypto (crypto.subtle)");
    const checks = [];
    const C = (id, ok, why) => checks.push({ id, ok, why });
    if (!x || x.kind !== "crawlcheck-evidence-export")
        throw new Error("not a CrawlCheck evidence export");
    const body = {};
    for (const k of Object.keys(x))
        if (k !== "export_sha256" && k !== "signature")
            body[k] = x[k];
    const sha = hex(await sha256(enc.encode(canon(body))));
    if (!x.signature) {
        C("export_hash", sha === x.export_sha256, sha === x.export_sha256 ? "the file hashes to its stated digest " + sha.slice(0, 16) + "…" : "the file hashes to " + sha + ", it states " + x.export_sha256 + " - a field was changed");
        C("signature", null, "the export is unsigned (the observer had no signing key when it was made)");
    }
    else {
        C("export_hash", sha === x.export_sha256 && x.signature.export_sha256 === sha, sha === x.export_sha256 ? "the file hashes to its stated digest " + sha.slice(0, 16) + "…" : "the file hashes to " + sha + ", it states " + x.export_sha256 + " - a field was changed");
        const jwk = x.signature.key && x.signature.key.jwk;
        if (!jwk || !jwk.x) {
            C("key_id", null, "no key in the export");
            C("signature", null, "no key to check against");
        }
        else {
            const thumb = b64u(await sha256(enc.encode(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }))));
            C("key_id", thumb === x.signature.kid, thumb === x.signature.kid ? "public key thumbprint (RFC 7638) is the key id " + thumb.slice(0, 12) + "…; the same id is published in " + (x.signature.key.published_in || "the key directory") : "thumbprint " + thumb + " does not match key id " + x.signature.kid);
            const msg = EXPORT_SIG_PREFIX + sha;
            let ok = null;
            try {
                const pk = await subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: jwk.x }, { name: "Ed25519" }, false, ["verify"]);
                ok = x.signature.message === msg && await subtle.verify({ name: "Ed25519" }, pk, b64(x.signature.sig), enc.encode(msg));
            }
            catch (e) {
                ok = null;
                C("signature", null, "this runtime cannot verify Ed25519: " + (e && e.message || e));
            }
            if (ok !== null)
                C("signature", ok, ok ? "Ed25519 signature over the export digest verifies" : "signature does NOT verify over this content");
        }
        C("key_published", null, "offline this cannot be decided: compare key id " + (x.signature.kid || "?") + " with the ids published at " + ((x.signature.key && x.signature.key.published_in) || "the key directory"));
    }
    const records = [];
    for (const rec of (Array.isArray(x.records) ? x.records : [])) {
        if (!rec || !rec.bundle) {
            records.push({ id: rec && rec.id, verified: null, failed: [], why: (rec && rec.missing) || "no bundle" });
            continue;
        }
        let v = null, why = null;
        try {
            v = await verifyBundle(rec.bundle);
        }
        catch (e) {
            why = String(e && e.message || e);
        }
        const same = !!(v && rec.bundle.report && rec.bundle.report.id === rec.id && rec.bundle.report.domain === x.domain);
        records.push({ id: rec.id, scanned_at: rec.scanned_at, verified: v ? (v.verified && same) : null, failed: v ? v.checks.filter((c) => c.ok === false).map((c) => c.id).concat(same ? [] : ["bundle_names_another_record"]) : [], ran: v ? v.checks.filter((c) => c.ok !== null).length : 0, why });
    }
    const receipts = [];
    for (const rc of (Array.isArray(x.receipts) ? x.receipts : [])) {
        let v = null, why = null;
        try {
            v = await verifyReceipt(rc);
        }
        catch (e) {
            why = String(e && e.message || e);
        }
        receipts.push({ id: rc && rc.receipt_id, verified: v ? v.verified : null, failed: v ? v.checks.filter((c) => c.ok === false).map((c) => c.id) : [], why });
    }
    const rf = records.filter((r) => r.verified === false).length, cf = receipts.filter((r) => r.verified === false).length;
    C("records", records.length ? rf === 0 : null, records.length ? (rf ? rf + " of " + records.length + " bundles FAILED" : records.length + " bundle" + (records.length === 1 ? "" : "s") + " inside the file verified on their own (" + records.filter((r) => r.verified === true).length + " fully, " + records.filter((r) => r.verified === null).length + " with checks that could not run)") : "the file carries no records");
    C("receipts", receipts.length ? cf === 0 : null, receipts.length ? (cf ? cf + " of " + receipts.length + " receipts FAILED" : receipts.length + " receipt" + (receipts.length === 1 ? "" : "s") + " verified") : "the file carries no receipts");
    const cnt = x.counts || {};
    C("counts", (Array.isArray(x.records) ? x.records.length : 0) === ((cnt.records || 0) + (cnt.missing || 0)) && (Array.isArray(x.receipts) ? x.receipts.length : 0) === (cnt.receipts || 0), "the file's own counts match what it carries (" + (Array.isArray(x.records) ? x.records.length : 0) + " records, " + (Array.isArray(x.receipts) ? x.receipts.length : 0) + " receipts)");
    const ran = checks.filter((c) => c.ok !== null), failed = checks.filter((c) => c.ok === false);
    return { verified: ran.length > 0 && failed.length === 0, summary: failed.length ? failed.length + " check(s) FAILED" : ran.length + " of " + checks.length + " checks ran and passed",
        export: { domain: x.domain, window: x.window, records: records.length, receipts: receipts.length, generated_at: x.generated_at }, checks, records, receipts,
        note: "Every check used only the file itself. To confirm the key is CrawlCheck's, compare its id with " + ((x.signature && x.signature.key && x.signature.key.published_in) || "the published key directory") + "." };
}
// ── dispute resolutions ──────────────────────────────────────────────────────────────────────────────────
// A resolution records a dispute against one finding, the three readings that settled it (the rule replayed over
// the disputed record's sealed bytes, the primary observer's fresh audit, every independent observer's reading) and
// the verdict. It is signed like a receipt. verdict_derivable runs the published decision table (dspVerdict, the
// same function the Worker runs) over the recorded readings: a resolution whose verdict was edited, or whose
// readings were edited to fit it, fails here even before the signature does.
const DSP_SIG_PREFIX = "crawlcheck-dispute-resolution-v1\n";
export function dspVerdict(m) {
    // The published decision table. Inputs are only what the resolution itself records, so a verifier can re-derive
    // the verdict from the record: replay of the rule over the bytes the disputed scan received, the primary
    // observer's fresh re-measurement, and every independent observer's reading after the dispute was filed.
    const rp = m && m.replay ? m.replay.reproduces : null;
    const obs = (m && Array.isArray(m.observers)) ? m.observers : [];
    const prim = obs.filter(function (o) { return o && o.role === "primary"; })[0] || null;
    const ind = obs.filter(function (o) { return o && o.role === "independent"; });
    if (rp === false)
        return { verdict: "corrected", effect: "withdrawn", rule: "the rule, run again over the exact bytes the disputed scan received, does not hold: the finding was wrong when it was made" };
    if (!prim || prim.finding_present === null || prim.finding_present === undefined)
        return { verdict: "inconclusive", effect: "stands_unresolved", rule: "the primary observer could not re-measure the site" };
    const decided = ind.filter(function (o) { return o.finding_present === true || o.finding_present === false; });
    const agreeIn = ind.filter(function (o) { return o.finding_present !== true && o.finding_present !== false && o.inputs_agree === true; });
    const differIn = ind.filter(function (o) { return o.finding_present !== true && o.finding_present !== false && o.inputs_agree === false; });
    if (!decided.length && !agreeIn.length && !differIn.length)
        return { verdict: "inconclusive", effect: "stands_unresolved", rule: "no independent observer gave a usable reading before the deadline" };
    if (decided.some(function (o) { return o.finding_present !== prim.finding_present; }) || differIn.length)
        return { verdict: "vantage_dependent", effect: "stands_with_scope", rule: "an independent network received something different from the primary observer: the finding holds only for the network that saw it" };
    if (prim.finding_present === true)
        return { verdict: "upheld", effect: "stands", rule: "the rule holds over the original bytes and the condition is still present from every network that re-measured it" };
    if (rp === true)
        return { verdict: "fixed_since", effect: "stands_for_record", rule: "the rule holds over the original bytes, and every network now finds the condition gone: correct when made, fixed since" };
    return { verdict: "no_longer_observed", effect: "stands_for_record", rule: "every network now finds the condition gone, and the original bytes could not be re-checked, so whether it was ever wrong cannot be decided" };
}
async function verifyResolution0(x) {
    if (!subtle)
        throw new Error("this runtime has no WebCrypto (crypto.subtle)");
    const checks = [];
    const C = (id, ok, why) => checks.push({ id, ok, why });
    if (!x || x.kind !== "crawlcheck-dispute-resolution" || !x.signature)
        throw new Error("not a CrawlCheck dispute resolution");
    const body = {};
    for (const k of Object.keys(x))
        if (k !== "resolution_id" && k !== "signature")
            body[k] = x[k];
    const sha = hex(await sha256(enc.encode(canon(body))));
    C("resolution_hash", sha === x.signature.resolution_sha256 && x.resolution_id === "dr1:" + sha, sha === x.signature.resolution_sha256 ? "the resolution hashes to its id " + sha.slice(0, 16) + "…" : "the resolution hashes to " + sha + ", it claims " + x.signature.resolution_sha256 + " - a field was changed");
    const jwk = x.issuer && x.issuer.key && x.issuer.key.jwk;
    if (!jwk || !jwk.x) {
        C("key_id", null, "no key in the resolution");
        C("signature", null, "no key to check against");
    }
    else {
        const thumb = b64u(await sha256(enc.encode(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }))));
        C("key_id", thumb === x.signature.kid, thumb === x.signature.kid ? "public key thumbprint (RFC 7638) is the key id " + thumb.slice(0, 12) + "…; the same id is published in " + (x.issuer.key.published_in || "the key directory") : "thumbprint " + thumb + " does not match key id " + x.signature.kid);
        const msg = DSP_SIG_PREFIX + sha;
        let ok = null;
        try {
            const pk = await subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: jwk.x }, { name: "Ed25519" }, false, ["verify"]);
            ok = x.signature.message === msg && await subtle.verify({ name: "Ed25519" }, pk, b64(x.signature.sig), enc.encode(msg));
        }
        catch (e) {
            ok = null;
            C("signature", null, "this runtime cannot verify Ed25519: " + (e && e.message || e));
        }
        if (ok !== null)
            C("signature", ok, ok ? "Ed25519 signature over the resolution digest verifies" : "signature does NOT verify over this content");
    }
    C("key_published", null, "offline this cannot be decided: compare key id " + (x.signature.kid || "?") + " with the ids published at " + ((x.issuer && x.issuer.key && x.issuer.key.published_in) || "the key directory"));
    const dv = dspVerdict(x.remeasurement || {});
    const said = x.decision || {};
    C("verdict_derivable", dv.verdict === said.verdict && dv.effect === said.effect, "the decision table over the recorded readings gives " + dv.verdict + " / " + dv.effect + "; the record says " + (said.verdict || "?") + " / " + (said.effect || "?"));
    const obs = (x.remeasurement && x.remeasurement.observers) || [];
    const t0 = x.dispute && Date.parse(x.dispute.ownership && x.dispute.ownership.at || x.dispute.filed_at);
    const late = obs.filter((o) => o && o.at && isFinite(t0) && Date.parse(o.at) < t0);
    C("readings_after_dispute", obs.length ? late.length === 0 : null, obs.length ? (late.length ? late.length + " reading(s) predate the dispute: a re-measurement must come after it" : "every reading (" + obs.length + ") was taken after the dispute was accepted") : "no readings recorded");
    const ran = checks.filter((c) => c.ok !== null), failed = checks.filter((c) => c.ok === false);
    return { verified: ran.length > 0 && failed.length === 0, summary: failed.length ? failed.length + " check(s) FAILED" : ran.length + " of " + checks.length + " checks ran and passed",
        resolution: { id: x.resolution_id, dispute: x.dispute_id, domain: x.subject && x.subject.domain, code: x.subject && x.subject.finding && x.subject.finding.code, verdict: said.verdict, effect: said.effect, observers: obs.map((o) => o.observer_id + "@" + (o.network_class || "?")) }, checks,
        note: "Every check used only the resolution itself. To confirm the key is CrawlCheck's, compare its id with " + ((x.issuer && x.issuer.key && x.issuer.key.published_in) || "the published key directory") + "; to check a reading, open the record or the signed observation it links." };
}
// tl1: the Resolve log's leaf content and RFC 9162 inclusion check (the same rules the log publishes).
function tlContentV(doc) {
    const a = doc && doc.actions || {}, acts = {};
    Object.keys(a).sort().forEach((k) => { const x = a[k] || {}; acts[k] = { decision: x.decision || null, doubts: (Array.isArray(x.doubts) ? x.doubts : []).slice().sort() }; });
    return { log: "crawlcheck-resolve-log-v1", domain: doc && doc.domain || null, status: doc && doc.status || null, actions: acts,
        report: doc && doc.evidence && doc.evidence.report || null, observed_at: doc && doc.freshness && doc.freshness.observed_at || null,
        incident: doc && doc.incident && doc.incident.since || null, impersonation: doc && doc.impersonation && doc.impersonation.verdict === "suspected" ? "suspected" : null,
        high_risk_pending: doc && doc.high_risk_fields && Array.isArray(doc.high_risk_fields.pending) ? doc.high_risk_fields.pending.map((p) => p.field).sort() : [] };
}
export async function rfcRootV(leafHex, index, size, path) {
    if (!(size > 0) || !(index >= 0) || index >= size)
        return null;
    let fn = index, sn = size - 1, r = unhex(leafHex);
    for (const p of path) {
        if (sn === 0)
            return null;
        if ((fn & 1) === 1 || fn === sn) {
            r = await sha256(cat(cat(new Uint8Array([1]), unhex(p)), r));
            if ((fn & 1) === 0) {
                while ((fn & 1) === 0 && fn !== 0) {
                    fn >>= 1;
                    sn >>= 1;
                }
            }
        }
        else
            r = await sha256(cat(cat(new Uint8Array([1]), r), unhex(p)));
        fn >>= 1;
        sn >>= 1;
    }
    return sn === 0 ? hex(r) : null;
}
// tv1: threshold-signed verdicts. Every signer is checked on its own: its Ed25519 signature over its envelope, the
// binding of its key to its identity (GitHub's RS256 token, a self-signed enrolment, or the published key directory),
// and the field values recomputed from its envelope. The verdict holds when signers on at least k distinct networks pass.
const TV_OBS_PREFIX = "crawlcheck-observation-v1\n", TV_ENROL_PREFIX = "crawlcheck-observer-enrol-v1\n";
function tvFinalV(u) { try {
    const x = new URL(u);
    return x.hostname.toLowerCase().replace(/^www\./, "") + (x.pathname.replace(/\/+$/, "") || "/");
}
catch (e) {
    return null;
} }
export function tvReachV(envelope) {
    return (envelope && Array.isArray(envelope.fetches) ? envelope.fetches : []).map((f) => ({ identity: String(f.identity), status: typeof f.status === "number" ? f.status : null, final: f.url_final ? tvFinalV(f.url_final) : null, failed: !!f.error }))
        .sort((a, b) => (a.identity < b.identity ? -1 : a.identity > b.identity ? 1 : 0));
}
async function tvEd(x, msg, sig) { try {
    const pk = await subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x }, { name: "Ed25519" }, false, ["verify"]);
    return await subtle.verify({ name: "Ed25519" }, pk, b64(sig), enc.encode(msg));
}
catch (e) {
    return null;
} }
async function tvJwt(token, jwk) {
    const p = String(token || "").split(".");
    if (p.length !== 3 || !jwk || jwk.kty !== "RSA")
        return { ok: false };
    let h, c;
    try {
        h = JSON.parse(new TextDecoder().decode(b64(p[0])));
        c = JSON.parse(new TextDecoder().decode(b64(p[1])));
    }
    catch (e) {
        return { ok: false };
    }
    if (h.alg !== "RS256" || (jwk.kid && h.kid !== jwk.kid))
        return { ok: false, claims: c };
    try {
        const k = await subtle.importKey("jwk", { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
        return { ok: await subtle.verify("RSASSA-PKCS1-v1_5", k, b64(p[2]), enc.encode(p[0] + "." + p[1])), claims: c, kid: h.kid };
    }
    catch (e) {
        return { ok: null, claims: c };
    }
}
export async function verifyThresholdSigners(x) {
    const st = x.statement || {}, want = canon(st.values || []), rows = [];
    for (const s of Array.isArray(x.signers) ? x.signers : []) {
        const r = { observer_id: s.observer_id, network: s.network && s.network.class || null, signature: false, binding: false, values_match: false, why: [] };
        const ev = s.envelope || {}, key = ev.key || {};
        r.signature = !!(await tvEd(key.x, TV_OBS_PREFIX + canon(ev), s.sig));
        if (!r.signature)
            r.why.push("signature does not verify under the envelope key");
        const b = s.binding || {};
        if (b.kind === "github_oidc") {
            const j = await tvJwt(b.token, b.github_key), c = j.claims || {};
            const aud = "crawlcheck-observer:" + b64u(await sha256(b64(key.x || "")));
            r.binding = j.ok === true && c.iss === "https://token.actions.githubusercontent.com" && c.repository === b.repository && String(c.job_workflow_ref || c.workflow_ref || "").indexOf(b.workflow_ref_prefix || "\u0000") === 0 && (Array.isArray(c.aud) ? c.aud : [c.aud]).includes(aud) && (!c.runner_environment || c.runner_environment === "github-hosted");
            r.github_kid = j.kid || null;
            if (!r.binding)
                r.why.push("GitHub token does not bind this key to the observer workflow");
        }
        else if (b.kind === "enrolled_ed25519") {
            const q = b.enrolment && b.enrolment.request;
            r.binding = !!(b.key && b.key.x === key.x && q && q.observer_id === s.observer_id && q.key && q.key.x === key.x && await tvEd(key.x, TV_ENROL_PREFIX + canon(q), b.enrolment.sig));
            if (!r.binding)
                r.why.push("the key is not the one this observer enrolled with");
        }
        else if (b.kind === "published_key_directory") {
            const thumb = b64u(await sha256(enc.encode(JSON.stringify({ crv: "Ed25519", kty: "OKP", x: key.x }))));
            r.binding = thumb === b.kid && thumb === (x.signature && x.signature.kid);
            r.kid = thumb;
            if (!r.binding)
                r.why.push("key thumbprint is not the stated (published) key id");
        }
        else
            r.why.push("unknown binding " + b.kind);
        r.values_match = canon(tvReachV(ev)) === want;
        if (!r.values_match)
            r.why.push("the values in this envelope differ from the statement");
        r.passes = r.signature && r.binding && r.values_match;
        rows.push(r);
    }
    return rows;
}
// ── data inventories, export parts and deletion records ─────────────────────────────────────────────────────────
// Signed over sha256(canonical JSON of every field except sha256 and signature) with the prefix below. A deletion
// record carries counts per family and the digest of the sorted deleted-key list, never the data.
const DATA_SIG_PREFIX = "crawlcheck-data-v1\n";
async function verifyDataDoc0(x) {
    if (!subtle)
        throw new Error("this runtime has no WebCrypto (crypto.subtle)");
    const checks = [];
    const C = (id, ok, why) => checks.push({ id, ok, why });
    // 1.7.0: every kind the service signs with this scheme verifies (field checks, opt-out records, AI-visibility and what-moved
    // readings were refused by the old fixed list though their signatures were valid); trust still rests on key_published.
    if (!x || !/^crawlcheck-[a-z0-9]+(-[a-z0-9]+){0,6}$/.test(String(x.kind)) || !x.signature || !x.signature.message || String(x.signature.message).indexOf(DATA_SIG_PREFIX) !== 0)
        throw new Error("not a signed CrawlCheck document (kind crawlcheck-*, signed with the crawlcheck-data-v1 scheme)");
    const body = {};
    for (const k of Object.keys(x))
        if (k !== "sha256" && k !== "signature")
            body[k] = x[k];
    const sha = hex(await sha256(enc.encode(canon(body))));
    C("document_hash", sha === x.sha256, sha === x.sha256 ? "the document hashes to its stated digest " + sha.slice(0, 16) + "…" : "the document hashes to " + sha + ", it states " + x.sha256 + " - a field was changed");
    const jwk = x.signature.key && x.signature.key.jwk;
    if (!jwk || !jwk.x) {
        C("key_id", null, "no key in the document");
        C("signature", null, "no key to check against");
    }
    else {
        const thumb = b64u(await sha256(enc.encode(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }))));
        C("key_id", thumb === x.signature.kid, thumb === x.signature.kid ? "public key thumbprint (RFC 7638) is the key id " + thumb.slice(0, 12) + "…" : "thumbprint " + thumb + " does not match key id " + x.signature.kid);
        const msg = DATA_SIG_PREFIX + sha;
        let ok = null;
        try {
            const pk = await subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: jwk.x }, { name: "Ed25519" }, false, ["verify"]);
            ok = x.signature.message === msg && await subtle.verify({ name: "Ed25519" }, pk, b64(x.signature.sig), enc.encode(msg));
        }
        catch (e) {
            ok = null;
            C("signature", null, "this runtime cannot verify Ed25519: " + (e && e.message || e));
        }
        if (ok !== null)
            C("signature", ok, ok ? "Ed25519 signature over the document digest verifies" : "signature does NOT verify over this content");
    }
    C("key_published", null, "offline this cannot be decided: compare key id " + (x.signature.kid || "?") + " with the ids published at " + ((x.signature.key && x.signature.key.published_in) || "the key directory"));
    if (x.kind === "crawlcheck-data-export-part" && x.inventory) {
        let iv = null;
        try {
            iv = await verifyDataDoc(x.inventory);
        }
        catch (e) {
            iv = null;
        }
        C("inventory", !!(iv && iv.verified && x.inventory.sha256 === x.inventory_sha256), iv && iv.verified ? "the part carries the signed inventory it names" : "the inventory inside this part does not verify or is not the one named");
    }
    if (x.kind === "crawlcheck-decision") {
        const r = x.resolve || {};
        C("resolve_bound", /^[0-9a-f]{64}$/.test(String(r.sha256 || "")) && typeof r.kid === "string" && r.kid.length > 0, /^[0-9a-f]{64}$/.test(String(r.sha256 || "")) ? "the decision names the resolve answer it was made from (" + String(r.sha256).slice(0, 16) + "…), signed by key " + String(r.kid).slice(0, 12) + "… (online, it must be a published key)" : "the decision does not name a resolve answer digest");
        C("decision_known", ["allow", "warn", "require_confirmation", "block", "unsupported"].indexOf(x.decision) >= 0, "decision is " + x.decision);
    }
    if (x.kind === "crawlcheck-snapshot") {
        const ps = Array.isArray(x.parts) ? x.parts : [];
        C("parts", ps.length > 0 && ps.every((p) => /^part-\d{4}\.ndjson\.gz$/.test(String(p.path)) && /^[0-9a-f]{64}$/.test(String(p.sha256)) && p.records > 0) && ps.reduce((a, p) => a + p.records, 0) === x.records, ps.reduce((a, p) => a + (p.records || 0), 0) === x.records ? ps.length + " parts, " + x.records + " records; check each downloaded part with sha256sum against its sha256, then each line with this tool" : "the parts' record counts do not add up to records (" + x.records + ")");
    }
    if (x.kind === "crawlcheck-resolve" && Array.isArray(x.absences)) { // sa1: every absence states what was checked, from where and when
        const bad = x.absences.filter((a) => !(a && a.what && (a.result === "absent" || a.result === "none") && a.at && !isNaN(Date.parse(a.at)) && a.from && a.from.observer && typeof a.scope === "string" && Array.isArray(a.checked) && a.checked.length && a.checked.every((c) => c && c.method && (a.result !== "absent" || c.status === undefined || c.status === 404 || c.status === 410))));
        C("absences_scoped", bad.length === 0, x.absences.length + " absence record(s)" + (x.absences.length ? " (" + x.absences.map((a) => a.what).join(", ") + ")" : "") + (bad.length ? "; " + bad.length + " lack a definite check, a time, a vantage or a scope" : ", each naming what was requested, the answer, the vantage and the time"));
    }
    if (x.kind === "crawlcheck-resolve" && x.transparency) { // tl1: the answer's place in the Resolve transparency log
        const t = x.transparency, leaf = hex(await sha256(cat(new Uint8Array([0]), enc.encode(canon(tlContentV(x))))));
        C("log_leaf", leaf === t.leaf_hash, leaf === t.leaf_hash ? "the answer's decision content hashes to its log leaf " + leaf.slice(0, 16) + "…" : "the decision content hashes to " + leaf + ", the answer names " + t.leaf_hash);
        if (t.state === "included" && t.sth) {
            const root = await rfcRootV(leaf, t.index, t.batch_size, t.path || []);
            C("log_inclusion", root !== null && root === t.sth.batch_root, root === t.sth.batch_root ? "the leaf folds along its " + (t.path || []).length + "-step path to batch " + t.batch + "'s root (RFC 9162)" : "the inclusion path does NOT lead to the signed batch root");
            let sv = null;
            try {
                sv = await verifyDataDoc0(t.sth);
            }
            catch (e) {
                sv = null;
            }
            const same = true; // kp3: the log head may be signed by the log key; online, its key must be published (trustOf)
            C("log_head_signature", !!(sv && sv.verified) && t.sth.kind === "crawlcheck-log-sth" && t.sth.batch === t.batch && same, sv && sv.verified ? "batch " + t.batch + "'s signed tree head verifies (tree size " + t.sth.tree_size + ", chained to " + String(t.sth.prev_sth_sha256 || "genesis").slice(0, 16) + "…)" : "the signed tree head does NOT verify");
        }
        else
            C("log_inclusion", null, "pending: the leaf is queued and merged within " + (t.merged_within_minutes || 30) + " minutes; fetch the proof at " + (t.proof || "the log"));
    }
    if (x.kind === "crawlcheck-resolve-as-of") { // ah1: the answer in force at as_of, as signed then
        let av = null;
        try {
            av = await verifyDataDoc0(x.answer);
        }
        catch (e) {
            av = null;
        }
        C("answer_signature", !!(av && av.verified) && !!x.answer && x.answer.kind === "crawlcheck-resolve" && x.answer.domain === x.domain, av && av.verified ? "the archived answer verifies on its own (signed " + (x.answer.signature && x.answer.signature.signed_at) + ")" : "the archived answer does NOT verify");
        const leaf = x.answer ? hex(await sha256(cat(new Uint8Array([0]), enc.encode(canon(tlContentV(x.answer)))))) : null;
        C("answer_leaf", leaf === x.leaf_hash, leaf === x.leaf_hash ? "the answer's decision content is leaf " + String(leaf).slice(0, 16) + "…" : "the answer's content hashes to " + leaf + ", not the stated leaf");
        const w = x.in_force || {}, t = Date.parse(x.as_of);
        C("in_force_window", Date.parse(w.from) <= t && (w.until == null || t < Date.parse(w.until)), "as_of " + x.as_of + " falls in [" + w.from + ", " + (w.until || "now") + ")");
        const pr = x.log_inclusion;
        if (pr && pr.sth) {
            const root = await rfcRootV(x.leaf_hash, pr.index, pr.batch_size, pr.path || []);
            let sv = null;
            try {
                sv = await verifyDataDoc0(pr.sth);
            }
            catch (e) {
                sv = null;
            }
            C("log_inclusion", root !== null && root === pr.sth.batch_root && !!(sv && sv.verified), root === pr.sth.batch_root ? "the leaf is in batch " + pr.batch + " of the signed log (head created " + pr.sth.created_at + ")" : "the inclusion proof does NOT reach the signed batch root");
        }
        else
            C("log_inclusion", null, "not merged into the log yet; merged within 30 minutes of first appearing");
    }
    if (x.kind === "crawlcheck-threshold-verdict") { // tv1
        const rows = await verifyThresholdSigners(x), k = x.threshold && x.threshold.k || 2;
        rows.forEach((r) => C("signer:" + r.observer_id, r.passes, r.passes ? "signature, key binding (" + (x.signers.find((s) => s.observer_id === r.observer_id).binding.kind) + ") and recomputed " + (x.statement && x.statement.family) + " values all check (network " + r.network + ")" : r.why.join("; ")));
        const nets = new Set(rows.filter((r) => r.passes).map((r) => r.network));
        C("threshold", nets.size >= k, nets.size + " distinct network(s) signed identical values (" + [...nets].join(", ") + "); the verdict needs " + k);
        C("key_bindings_online", null, "offline the bindings are checked against keys the document carries; online, compare the GitHub key id with " + "https://token.actions.githubusercontent.com/.well-known/jwks and enrolled keys with https://crawlcheck.io/.well-known/crawlcheck-observers.json");
    }
    if (x.kind === "crawlcheck-deletion-record")
        C("counts", (x.deleted || []).reduce((a, f) => a + (f.keys || 0), 0) === x.deleted_total, "the per-family counts add up to deleted_total (" + x.deleted_total + ")");
    const ran = checks.filter((c) => c.ok !== null), failed = checks.filter((c) => c.ok === false);
    return { verified: ran.length > 0 && failed.length === 0, summary: failed.length ? failed.length + " check(s) FAILED" : ran.length + " of " + checks.length + " checks ran and passed", document: { kind: x.kind, domain: x.domain, sha256: x.sha256 }, checks };
}
// ── command line ─────────────────────────────────────────────────────────────
// Run as a script under ANY file name (a browser saves a second download as "crawlcheck-verify (1).mjs"); imported, it
// stays a library. The old test matched the file name only, so a renamed copy exited 0 having checked nothing.
// vt1: integrity, issuer trust and completeness, reported apart. Same semantics as @crawlcheck/sdk and the Python package.
// kp3 (2026-10-10): keys a document leans on besides its own signer (the resolve answer a decision names, the log head
// an answer carries). Since keys are separated by purpose these can differ; online, every one must be published.
export function relatedKids(x) {
    const out = [];
    try {
        if (x && x.kind === "crawlcheck-decision" && x.resolve && x.resolve.kid)
            out.push(x.resolve.kid);
        const t = x && x.transparency;
        if (t && t.sth && t.sth.signature && t.sth.signature.kid)
            out.push(t.sth.signature.kid);
        if (x && x.kind === "crawlcheck-resolve-as-of") {
            if (x.answer && x.answer.signature && x.answer.signature.kid)
                out.push(x.answer.signature.kid);
            const p = x.log_inclusion;
            if (p && p.sth && p.sth.signature && p.sth.signature.kid)
                out.push(p.sth.signature.kid);
        }
    }
    catch (e) { }
    return out.filter((k, i) => typeof k === "string" && out.indexOf(k) === i);
}
export function trustOf(res, kid, publishedKids, related) {
    let checks = Array.isArray(res && res.checks) ? res.checks : [];
    let issuer = null;
    if (Array.isArray(publishedKids)) {
        const __rel = (related || []).filter((k) => k !== kid), __miss = __rel.filter((k) => publishedKids.indexOf(k) < 0);
        issuer = !!kid && publishedKids.indexOf(kid) > -1 && __miss.length === 0;
        if (!!kid && publishedKids.indexOf(kid) > -1 && __miss.length) {
            const kc0 = { id: "key_published", ok: false, why: "the document is signed by a published key, but it leans on key " + __miss.join(", ") + ", which is NOT published: reject this document" };
            checks = checks.some((c) => c.id === "key_published") ? checks.map((c) => c.id === "key_published" ? kc0 : c) : checks.concat([kc0]);
        }
        else {
            const kc = { id: "key_published", ok: issuer, why: issuer ? "key id " + kid + " is in the published key directory" : !kid ? "this document carries no signature, so its issuer cannot be authenticated" : "key id " + kid + " is NOT in the published key directory: reject this document" };
            checks = checks.some((c) => c.id === "key_published") ? checks.map((c) => c.id === "key_published" ? kc : c) : checks.concat([kc]);
        }
    }
    const ran = checks.filter((c) => c.ok !== null), failed = checks.filter((c) => c.ok === false);
    const unavailable = checks.filter((c) => c.ok === null && c.id !== "key_published").map((c) => c.id);
    const verified = ran.length > 0 && failed.length === 0;
    const integrity_valid = ran.some((c) => c.id !== "key_published") && checks.filter((c) => c.id !== "key_published").every((c) => c.ok !== false);
    const accepted = integrity_valid && issuer === true;
    return Object.assign({}, res, { checks, verified, summary: failed.length ? failed.length + " check(s) FAILED" : ran.length + " of " + checks.length + " checks ran and passed",
        integrity_valid, issuer_trusted: issuer, accepted, accepted_strict: accepted && unavailable.length === 0,
        assurance: unavailable.length ? "partial" : "complete", unavailable });
}
// The published Ed25519 key ids (RFC 7638 thumbprints) from the observer's key directory.
export async function publishedKeyIds(base) {
    const r = await fetch(String(base || "https://crawlcheck.io").replace(/\/+$/, "") + "/.well-known/http-message-signatures-directory");
    if (!r.ok)
        throw new Error("key directory answered HTTP " + r.status);
    const d = await r.json(), out = [];
    for (const k of (d && d.keys) || []) {
        if (!k || !k.x)
            continue;
        out.push(b64u(await sha256(enc.encode(JSON.stringify({ crv: k.crv, kty: k.kty, x: k.x })))));
    }
    return out;
}
const kidOf = (o) => (o && o.signature && o.signature.kid) || (o && o.manifest && o.manifest.signature && o.manifest.signature.kid) || undefined;
export async function verifyBundle(b, opts) { return trustOf(await verifyBundle0(b), b && b.manifest && b.manifest.signature && b.manifest.signature.kid, opts && opts.publishedKids); }
export async function verifyReceipt(rc, opts) { return trustOf(await verifyReceipt0(rc), rc && rc.signature && rc.signature.kid, opts && opts.publishedKids); }
export async function verifyExport(x, opts) { return trustOf(await verifyExport0(x), kidOf(x), opts && opts.publishedKids); }
export async function verifyResolution(x, opts) { return trustOf(await verifyResolution0(x), kidOf(x), opts && opts.publishedKids); }
// dns1: a Resolve-over-DNS TXT record (ccr1). Strings joined without spaces; quotes from dig output are stripped.
async function verifyDnsTxt0(txt) {
    if (!subtle)
        throw new Error("this runtime has no WebCrypto (crypto.subtle)");
    const checks = [], C = (id, ok, why) => checks.push({ id, ok, why });
    const t = String(txt || "").trim().replace(/"\s*"/g, "").replace(/^"|"$/g, "").replace(/\;/g, ";");
    const i = t.lastIndexOf(";s="), body = i > 0 ? t.slice(0, i) : "", sig = i > 0 ? t.slice(i + 3) : "";
    const f = {};
    body.split(";").forEach((p) => { const j = p.indexOf("="); if (j > 0)
        f[p.slice(0, j)] = p.slice(j + 1); });
    C("format", f.v === "ccr1" && !!f.d && !!f.k && !!f.x && !!sig, f.v === "ccr1" ? "ccr1 record for " + (f.d || "?") + " (" + (f.st || "?") + ")" : "not a ccr1 record");
    if (f.x && f.k) {
        const thumb = b64u(await sha256(enc.encode(JSON.stringify({ crv: "Ed25519", kty: "OKP", x: f.x }))));
        C("key_id", thumb === f.k, thumb === f.k ? "public key thumbprint (RFC 7638) is the key id " + thumb.slice(0, 12) + "…" : "thumbprint " + thumb + " does not match key id " + f.k);
        let ok = null;
        try {
            const pk = await subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: f.x }, { name: "Ed25519" }, false, ["verify"]);
            ok = await subtle.verify({ name: "Ed25519" }, pk, b64(sig), enc.encode("crawlcheck-dns-v1\n" + body));
        }
        catch (e) {
            ok = null;
            C("signature", null, "this runtime cannot verify Ed25519: " + (e && e.message || e));
        }
        if (ok !== null)
            C("signature", ok, ok ? "Ed25519 signature over the record verifies" : "signature does NOT verify over this record");
    }
    const fu = Date.parse(f.f || "");
    C("fresh", isFinite(fu) ? fu > Date.now() : false, isFinite(fu) ? (fu > Date.now() ? "fresh until " + f.f : "expired at " + f.f + ": ask again") : "no fresh_until");
    C("key_published", null, "offline this cannot be decided: compare key id " + (f.k || "?") + " with the ids published at https://crawlcheck.io/.well-known/http-message-signatures-directory");
    return { record: f, decisions: { read: f.read || null, cite: f.cite || null, connect: f.connect || null, transact: f.transact || null }, checks };
}
export async function verifyDnsTxt(txt, opts) { const r = await verifyDnsTxt0(txt); return trustOf(r, r.record && r.record.k, opts && opts.publishedKids); }
export async function verifyDataDoc(x, opts) { return trustOf(await verifyDataDoc0(x), kidOf(x), opts && opts.publishedKids, relatedKids(x)); }
const isMain = typeof process !== "undefined" && !!(process.argv && process.argv[1]) && await (async () => { try {
    const { pathToFileURL } = await import("node:url");
    const { realpathSync } = await import("node:fs");
    return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
}
catch (e) {
    return false;
} })();
if (isMain) {
    const online = process.argv.includes("--online");
    if (process.argv.includes("--dns")) { // dns1: a Resolve-over-DNS TXT record
        let txt = process.argv.slice(2).filter((a) => a !== "--online" && a !== "--dns").join(" ");
        if (!txt) {
            const { readFileSync } = await import("node:fs");
            txt = readFileSync(0, "utf8");
        }
        let kd;
        if (online) {
            try {
                kd = await publishedKeyIds();
            }
            catch (e) {
                console.log("could not read the published key directory: " + e.message);
            }
        }
        const r = await verifyDnsTxt(txt, { publishedKids: kd });
        console.log("CrawlCheck Resolve over DNS: " + (r.record.d || "?") + " " + (r.record.st || "?") + " · read " + r.decisions.read + " · cite " + r.decisions.cite + " · connect " + r.decisions.connect + " · transact " + r.decisions.transact);
        for (const c of r.checks)
            console.log((c.ok === true ? "PASS" : c.ok === false ? "FAIL" : " -- ") + "  " + c.id.padEnd(23) + c.why);
        console.log(r.summary);
        console.log(r.accepted ? "ACCEPTED" : "NOT ACCEPTED" + (r.integrity_valid && r.issuer_trusted === null ? ": issuer unknown offline (run with --online)" : ""));
        process.exit(r.checks.some((c) => c.ok === false) ? 1 : 0);
    }
    const f = process.argv.slice(2).filter((a) => a !== "--online")[0];
    if (!f) {
        console.log("usage: node crawlcheck-verify.mjs [--online] [--dns \"<ccr1 TXT record>\"] <bundle.json | receipt.json | export.json | resolution.json | deletion.json | answer.json | decision.json | manifest.json>");
        process.exit(2);
    }
    const { readFile } = await import("node:fs/promises");
    const doc = JSON.parse(await readFile(f, "utf8"));
    const isRc = doc && (doc.kind === "crawlcheck-remediation-receipt" || (doc.receipt && doc.receipt.kind === "crawlcheck-remediation-receipt"));
    const isEx = doc && doc.kind === "crawlcheck-evidence-export";
    const isDr = doc && doc.kind === "crawlcheck-dispute-resolution";
    const isDt = doc && /^crawlcheck-(data-inventory|data-export-part|deletion-record|resolve|decision|snapshot|visitor|conduct|traffic-index|anchor|anchor-check|content-clock|origin|claims|read-equivalence|rights|rights-feed|mcp-scan|mcp-lock|mcp-lock-check|mcp-shadow|mcp-auth|impersonation|task-canaries|agent-safety-benchmark|compliance-pack|share-of-preflight|incident|revocations|high-risk|log-sth|threshold-verdict|resolve-as-of)$/.test(String(doc.kind));
    let kids;
    if (online) {
        try {
            kids = await publishedKeyIds();
        }
        catch (e) {
            console.log("could not read the published key directory: " + e.message);
        }
    }
    const vo = { publishedKids: kids };
    const res = isDt ? await verifyDataDoc(doc, vo) : isDr ? await verifyResolution(doc, vo) : isEx ? await verifyExport(doc, vo) : isRc ? await verifyReceipt(doc.kind ? doc : doc.receipt, vo) : await verifyBundle(doc, vo);
    const mark = (ok) => ok === true ? "PASS" : ok === false ? "FAIL" : " -- ";
    if (isDt)
        console.log("CrawlCheck " + doc.kind.replace("crawlcheck-", "").replace(/-/g, " ") + ": " + (doc.domain || "?") + " " + String(doc.sha256 || "").slice(0, 16) + "…");
    else if (isDr)
        console.log("CrawlCheck dispute resolution: " + (res.resolution.id || "?").slice(0, 24) + "… " + (res.resolution.domain || "") + " " + (res.resolution.code || "") + " verdict " + (res.resolution.verdict || "?"));
    else if (isEx)
        console.log("CrawlCheck evidence export: " + (res.export.domain || "?") + " " + (res.export.window ? res.export.window.from + " to " + res.export.window.to : "") + " (" + res.export.records + " records, " + res.export.receipts + " receipts)");
    else if (isRc)
        console.log("CrawlCheck remediation receipt: " + (res.receipt.id || "?") + " " + (res.receipt.domain || "") + " verdict " + (res.receipt.verdict || "?"));
    else
        console.log("CrawlCheck evidence bundle: " + (res.report.id || "?") + " " + (res.report.domain || "") + " scanned " + (res.report.scanned_at || "?"));
    for (const c of res.checks)
        console.log(mark(c.ok) + "  " + c.id.padEnd(23) + c.why);
    if (isEx)
        for (const r of res.records)
            console.log(mark(r.verified) + "    record " + String(r.id || "?").padEnd(14) + (r.failed && r.failed.length ? "failed: " + r.failed.join(", ") : (r.why || (r.ran + " checks ran"))));
    if (isEx)
        for (const r of res.receipts)
            console.log(mark(r.verified) + "    receipt " + String(r.id || "?").slice(0, 20) + (r.failed && r.failed.length ? " failed: " + r.failed.join(", ") : ""));
    console.log(res.summary);
    console.log("integrity " + (res.integrity_valid ? "valid" : "NOT valid") + " · issuer " + (res.issuer_trusted === true ? "trusted (key published)" : res.issuer_trusted === false ? "NOT trusted (key not published)" : "not checked offline: run with --online") + " · assurance " + res.assurance + (res.unavailable.length ? " (" + res.unavailable.join(", ") + " could not run)" : ""));
    console.log(res.accepted ? (res.accepted_strict ? "ACCEPTED" : "ACCEPTED, partial assurance") : "NOT ACCEPTED" + (res.integrity_valid && res.issuer_trusted === null ? ": issuer unknown offline" : ""));
    process.exit(res.checks.some((c) => c.ok === false) ? 1 : 0);
}
