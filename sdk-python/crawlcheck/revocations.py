"""Offline revocations (rvd1): hold CrawlCheck's signed revocation list and refuse a listed domain for a listed action
with no network call. A store is plain JSON; persist it between runs. Apply only a document whose signature was checked
(CrawlCheck.sync_revocations does that). https://crawlcheck.io/docs/api#revocations"""
import time


def new_revocation_store():
    """An empty store."""
    return {"v": 1, "generated_at": None, "seq": None, "synced_at": None, "revoked": {}}


def _norm(d):
    d = str(d or "").strip().lower().rstrip(".")
    return d[4:] if d.startswith("www.") else d


def _ms(v):
    from .client import _iso_ms
    return _iso_ms(v)


def apply_revocations(store, doc, now=None):
    """Apply a verified crawlcheck-revocations document. A full list (since None) replaces the store; a delta replaces
    each revoked entry it carries and removes each cleared or lifted one. A delta that is not complete, starts after
    the list held, or is older than it, is refused: fetch the full list. Returns {applied, full, added, removed, reason}."""
    out = {"applied": False, "full": False, "added": 0, "removed": 0, "reason": None}
    if not isinstance(store, dict) or store.get("v") != 1:
        out["reason"] = "not a revocation store (new_revocation_store())"
        return out
    if not isinstance(doc, dict) or doc.get("kind") != "crawlcheck-revocations" or not isinstance(doc.get("revoked"), list):
        out["reason"] = "not a crawlcheck-revocations document"
        return out
    held, gen = _ms(store.get("generated_at")), _ms(doc.get("generated_at"))
    if held is not None and gen is not None and gen < held:
        out["reason"] = "older than the list already held"
        return out
    full = not doc.get("since")
    if not full and doc.get("delta_complete") is False:
        out["reason"] = "the delta does not reach back to %s: fetch the full list" % doc.get("since")
        return out
    if not full and held is not None and (_ms(doc.get("since")) or 0) > held:
        out["reason"] = "the delta starts after the list held (%s): fetch the full list" % store.get("generated_at")
        return out
    nxt = {} if full else dict(store["revoked"])
    for l in doc.get("cleared") or []:
        d = _norm((l or {}).get("domain"))
        if d and d in nxt:
            del nxt[d]
            out["removed"] += 1
    for e in doc["revoked"]:
        d = _norm((e or {}).get("domain"))
        if not d or not isinstance(e.get("actions"), list):
            continue
        if d not in nxt:
            out["added"] += 1
        nxt[d] = {"actions": list(e["actions"]), "causes": list(e.get("causes") or []), "state": e.get("state"), "since": e.get("since"), "updated_at": e.get("updated_at")}
    if full:
        out["removed"] = len([d for d in store["revoked"] if d not in nxt])
    store["revoked"] = nxt
    store["generated_at"] = doc.get("generated_at")
    store["seq"] = None if doc.get("seq") is None else str(doc.get("seq"))
    store["synced_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime((now / 1000.0) if now else time.time()))
    out["applied"], out["full"] = True, full
    return out


def revoked_for(store, domain, action=None):
    """The entry that revokes this domain (or a parent domain) for this action, or None. Reading and citing are never
    revoked by this list."""
    if not isinstance(store, dict) or not store.get("revoked"):
        return None
    labels = _norm(domain).split(".")
    for i in range(len(labels) - 1):
        d = ".".join(labels[i:])
        e = store["revoked"].get(d)
        if e and (not action or action in e.get("actions", [])):
            return dict(e, domain=d)
    return None
