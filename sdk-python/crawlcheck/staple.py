"""Stapled Resolve and Resolve over DNS: verify a ccr1 record offline (CrawlCheck-Staple header or
<domain>._v.crawlcheck.io TXT). Key id = RFC 7638 thumbprint of the key, the key is one CrawlCheck publishes, the
Ed25519 signature covers the record, the record names the host (or a parent domain) and fresh_until is in the future.
An expired or foreign staple is never valid."""
import re
import time
from datetime import datetime

from . import _ed25519
from .verify import key_id, _b64u_decode

STAPLE_PREFIX = "crawlcheck-dns-v1\n"


def parse_staple(record):
    t = re.sub(r'"\s*"', "", str(record or "").strip()).strip('"')
    i = t.rfind(";s=")
    body, sig = (t[:i], t[i + 3:]) if i > 0 else ("", "")
    f = {}
    for p in body.split(";"):
        j = p.find("=")
        if j > 0:
            f[p[:j]] = p[j + 1:]
    return f, body, sig


def staple_from_headers(headers):
    """The CrawlCheck-Staple value from a header mapping (case-insensitive), or None."""
    for k, v in (headers or {}).items():
        if str(k).lower() == "crawlcheck-staple":
            return v
    return None


def _ts(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None


def staple_check(record, host, published_kids, now=None):
    """Returns {valid, reason, expired, record, decisions}; never raises."""
    out = {"valid": False, "reason": None, "expired": False, "record": None, "decisions": None}
    try:
        f, body, sig = parse_staple(record)
        out["record"] = f
        if f.get("v") != "ccr1" or not f.get("d") or not f.get("k") or not f.get("x") or not sig:
            out["reason"] = "not a ccr1 record"
            return out
        out["decisions"] = {k: f.get(k) for k in ("read", "cite", "connect", "transact")}
        fu = _ts(f.get("f"))
        if fu is None or fu <= (now if now is not None else time.time()):
            out["expired"] = True
            out["reason"] = "expired at %s: ask CrawlCheck instead" % f.get("f")
            return out
        h = re.sub(r"^www\.", "", str(host or "").lower()).rstrip(".")
        d = f["d"].lower()
        if not h:
            out["reason"] = "no host given: a staple is only valid for the host it was served by"
            return out
        if h != d and not h.endswith("." + d):
            out["reason"] = "the staple names %s, not %s" % (d, h)
            return out
        if key_id({"crv": "Ed25519", "kty": "OKP", "x": f["x"]}) != f["k"]:
            out["reason"] = "key id does not match the public key"
            return out
        if not published_kids or f["k"] not in published_kids:
            out["reason"] = "key %s is not one CrawlCheck publishes" % f["k"]
            return out
        if not _ed25519.verify(_b64u_decode(f["x"]), (STAPLE_PREFIX + body).encode(), _b64u_decode(sig)):
            out["reason"] = "signature does not verify"
            return out
        out["valid"] = True
        out["reason"] = "valid until " + f["f"]
        return out
    except Exception as e:  # never raises
        out["reason"] = "could not check: %s" % e
        return out
