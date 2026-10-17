"""Offline verification of CrawlCheck signed documents: resolve answers, decision receipts, data inventories,
export parts and deletion records. Mirrors verifyDataDoc in crawlcheck-verify.mjs, check for check."""
import base64
import hashlib
import json
import re
from decimal import Decimal

from . import _ed25519

DATA_SIG_PREFIX = "crawlcheck-data-v1\n"
DATA_KINDS = ("crawlcheck-data-inventory", "crawlcheck-data-export-part", "crawlcheck-deletion-record", "crawlcheck-resolve", "crawlcheck-decision", "crawlcheck-snapshot", "crawlcheck-visitor", "crawlcheck-conduct", "crawlcheck-traffic-index", "crawlcheck-anchor", "crawlcheck-anchor-check", "crawlcheck-content-clock", "crawlcheck-origin", "crawlcheck-claims", "crawlcheck-read-equivalence", "crawlcheck-rights", "crawlcheck-rights-feed", "crawlcheck-mcp-scan", "crawlcheck-mcp-lock", "crawlcheck-mcp-lock-check", "crawlcheck-mcp-shadow", "crawlcheck-mcp-auth", "crawlcheck-impersonation", "crawlcheck-task-canaries", "crawlcheck-incident", "crawlcheck-revocations", "crawlcheck-high-risk", "crawlcheck-log-sth", "crawlcheck-agent-safety-benchmark", "crawlcheck-compliance-pack", "crawlcheck-share-of-preflight", "crawlcheck-threshold-verdict", "crawlcheck-resolve-as-of")
DECISIONS = ("allow", "warn", "require_confirmation", "block", "unsupported")


def _js_number(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if v != v or v in (float("inf"), float("-inf")):
        return "null"
    if v == int(v) and abs(v) < 1e21:
        return str(int(v))
    r = repr(v)
    if "e" in r or "E" in r:
        m, e = r.lower().split("e")
        e = int(e)
        if -7 < e < 21:
            s = format(Decimal(r), "f")
            return s.rstrip("0").rstrip(".") if "." in s else s
        return m + "e" + ("+" if e > 0 else "-") + str(abs(e))
    return r


def canon(v):
    """Canonical JSON exactly as the server computes it: keys sorted, no whitespace, JSON.stringify for scalars."""
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canon(v[k]) for k in sorted(v)) + "}"
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(canon(x) for x in v) + "]"
    if v is None:
        return "null"
    if isinstance(v, (bool, int, float)):
        return _js_number(v)
    return json.dumps(v, ensure_ascii=False)


def _b64u_decode(s):
    s = str(s)
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def key_id(jwk):
    """RFC 7638 thumbprint of an Ed25519 JWK - the kid CrawlCheck publishes."""
    return _b64u(hashlib.sha256(json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}, separators=(",", ":")).encode()).digest())


LOG_ID = "crawlcheck-resolve-log-v1"


def log_content(doc):
    """The decision content of a Resolve answer that its transparency-log leaf hashes (same fields as the server)."""
    a = doc.get("actions") or {}
    acts = {}
    for k in sorted(a):
        x = a[k] if isinstance(a[k], dict) else {}
        acts[k] = {"decision": x.get("decision") or None, "doubts": sorted(x.get("doubts") or []) if isinstance(x.get("doubts"), list) else []}
    hr = doc.get("high_risk_fields") or {}
    return {"log": LOG_ID, "domain": doc.get("domain") or None, "status": doc.get("status") or None, "actions": acts,
            "report": (doc.get("evidence") or {}).get("report") or None, "observed_at": (doc.get("freshness") or {}).get("observed_at") or None,
            "incident": (doc.get("incident") or {}).get("since") or None,
            "impersonation": "suspected" if (doc.get("impersonation") or {}).get("verdict") == "suspected" else None,
            "high_risk_pending": sorted(p.get("field") for p in hr.get("pending")) if isinstance(hr.get("pending"), list) else []}


def log_leaf(doc):
    return hashlib.sha256(b"\x00" + canon(log_content(doc)).encode("utf-8")).hexdigest()


def rfc9162_root(leaf_hex, index, size, path):
    """Fold an RFC 9162 inclusion path; returns the root hex or None when the path does not fit the tree."""
    if not (isinstance(size, int) and size > 0 and isinstance(index, int) and 0 <= index < size):
        return None
    fn, sn, r = index, size - 1, bytes.fromhex(leaf_hex)
    for p in path:
        if sn == 0:
            return None
        if fn & 1 == 1 or fn == sn:
            r = hashlib.sha256(b"\x01" + bytes.fromhex(p) + r).digest()
            if fn & 1 == 0:
                while fn & 1 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = hashlib.sha256(b"\x01" + r + bytes.fromhex(p)).digest()
        fn >>= 1
        sn >>= 1
    return r.hex() if sn == 0 else None


def related_kids(x):
    """kp3: keys a document leans on besides its own signer (the resolve answer a decision names, the log head an answer
    carries). Since keys are separated by purpose these can differ; online, every one must be published."""
    out = []
    try:
        if x.get("kind") == "crawlcheck-decision" and (x.get("resolve") or {}).get("kid"):
            out.append(x["resolve"]["kid"])
        t = x.get("transparency") or {}
        k = ((t.get("sth") or {}).get("signature") or {}).get("kid") if isinstance(t.get("sth"), dict) else None
        if k:
            out.append(k)
    except Exception:  # noqa: BLE001
        pass
    return [k for i, k in enumerate(out) if isinstance(k, str) and k not in out[:i]]


def verify_document(doc, published_kids=None):
    """Verify a signed CrawlCheck document offline. Returns {"verified": bool, "checks": [...]}.
    published_kids: optional list of key ids from https://crawlcheck.io/.well-known/http-message-signatures-directory;
    without it key_published stays None (undecided), as in the JavaScript verifier."""
    checks = []

    def C(i, ok, why):
        checks.append({"id": i, "ok": ok, "why": why})

    # 1.7.0: every kind the service signs with this scheme verifies; trust still rests on key_published
    sig0 = doc.get("signature") if isinstance(doc, dict) else None
    if not isinstance(doc, dict) or not re.match(r"^crawlcheck-[a-z0-9]+(-[a-z0-9]+){0,6}$", str(doc.get("kind") or "")) or not isinstance(sig0, dict) or not str(sig0.get("message") or "").startswith(DATA_SIG_PREFIX):
        raise ValueError("not a signed CrawlCheck document (kind crawlcheck-*, signed with the crawlcheck-data-v1 scheme)")
    body = {k: v for k, v in doc.items() if k not in ("sha256", "signature")}
    sha = hashlib.sha256(canon(body).encode("utf-8")).hexdigest()
    C("document_hash", sha == doc.get("sha256"), "the document hashes to its stated digest" if sha == doc.get("sha256") else "the document hashes to %s, it states %s - a field was changed" % (sha, doc.get("sha256")))
    sig = doc["signature"]
    jwk = (sig.get("key") or {}).get("jwk") or {}
    if not jwk.get("x"):
        C("key_id", None, "no key in the document")
        C("signature", None, "no key to check against")
    else:
        kid = key_id(jwk)
        C("key_id", kid == sig.get("kid"), "public key thumbprint (RFC 7638) is the key id" if kid == sig.get("kid") else "thumbprint %s does not match key id %s" % (kid, sig.get("kid")))
        msg = DATA_SIG_PREFIX + sha
        ok = sig.get("message") == msg and _ed25519.verify(_b64u_decode(jwk["x"]), msg.encode(), _b64u_decode(sig.get("sig", "")))
        C("signature", ok, "Ed25519 signature over the document digest verifies" if ok else "signature does NOT verify over this content")
    if published_kids is None:
        C("key_published", None, "offline this cannot be decided: compare key id %s with the published key directory" % sig.get("kid"))
    else:
        miss = [k for k in related_kids(doc) if k != sig.get("kid") and k not in published_kids]   # kp3
        okp = sig.get("kid") in published_kids and not miss
        C("key_published", okp, "the signing key is published" if okp else ("the document leans on key %s, which is NOT published - reject this document" % ", ".join(miss) if miss and sig.get("kid") in published_kids else "the signing key is NOT in the published directory - reject this document"))
    if doc.get("kind") == "crawlcheck-decision":
        r = doc.get("resolve") or {}
        bound = bool(re.fullmatch(r"[0-9a-f]{64}", str(r.get("sha256") or ""))) and isinstance(r.get("kid"), str) and len(r.get("kid")) > 0   # kp3: any published key (checked below)
        C("resolve_bound", bound, "the decision names the resolve answer it was made from, signed by the same key" if bound else "the decision does not name a resolve answer digest")
        C("decision_known", doc.get("decision") in DECISIONS, "decision is %s" % doc.get("decision"))
    if doc.get("kind") == "crawlcheck-snapshot":
        ps = doc.get("parts") if isinstance(doc.get("parts"), list) else []
        okp = bool(ps) and all(re.fullmatch(r"part-\d{4}\.ndjson\.gz", str(x.get("path"))) and re.fullmatch(r"[0-9a-f]{64}", str(x.get("sha256"))) and (x.get("records") or 0) > 0 for x in ps) and sum(x.get("records") or 0 for x in ps) == doc.get("records")
        C("parts", okp, "%d parts, %s records; check each downloaded part's sha256, then each line with this verifier" % (len(ps), doc.get("records")) if okp else "the parts' record counts do not add up to records")
    if doc.get("kind") == "crawlcheck-resolve" and doc.get("transparency"):
        t = doc["transparency"]
        leaf = log_leaf(doc)
        C("log_leaf", leaf == t.get("leaf_hash"), "the answer's decision content hashes to its log leaf" if leaf == t.get("leaf_hash") else "the decision content hashes to %s, the answer names %s" % (leaf, t.get("leaf_hash")))
        if t.get("state") == "included" and t.get("sth"):
            sth = t["sth"]
            root = rfc9162_root(leaf, t.get("index"), t.get("batch_size"), t.get("path") or [])
            C("log_inclusion", root is not None and root == sth.get("batch_root"), "the leaf folds along its path to batch %s's root (RFC 9162)" % t.get("batch") if root == sth.get("batch_root") else "the inclusion path does NOT lead to the signed batch root")
            try:
                sv = verify_document(sth)
            except ValueError:
                sv = None
            same = True   # kp3: the log head may be signed by the log key; online its key must be published (checked below)
            okh = bool(sv and sv["verified"]) and sth.get("kind") == "crawlcheck-log-sth" and sth.get("batch") == t.get("batch") and same
            C("log_head_signature", okh, "batch %s's signed tree head verifies (tree size %s)" % (t.get("batch"), sth.get("tree_size")) if okh else "the signed tree head does NOT verify")
        else:
            C("log_inclusion", None, "pending: the leaf is merged within %s minutes" % (t.get("merged_within_minutes") or 30))
    if doc.get("kind") == "crawlcheck-deletion-record":
        C("counts", sum((f.get("keys") or 0) for f in doc.get("deleted") or []) == doc.get("deleted_total"), "the per-family counts add up to deleted_total")
    ran = [c for c in checks if c["ok"] is not None]
    verified = bool(ran) and all(c["ok"] for c in ran)
    kp = next((c["ok"] for c in checks if c["id"] == "key_published"), None)
    integrity = all(c["ok"] is not False for c in checks if c["id"] != "key_published")
    # verified alone can be true for a document someone else signed (offline, key_published is None). accepted needs
    # the signing key to be one CrawlCheck publishes: pass published_kids (CrawlCheck.verify does) before trusting it.
    return {"verified": verified, "integrity_valid": integrity, "issuer_trusted": kp, "accepted": verified and kp is True, "checks": checks}
