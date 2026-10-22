"""Split-view detection for the CrawlCheck Resolve transparency log (same rules as the JavaScript SDK's log.js).

A log that shows one client a different history than another has to sign two heads for one batch, or a head that does
not chain to the one before. A store keeps every signed tree head a client sees and checks each new one against its
neighbours; clients swap heads (log_heads / log_gossip); and log_check walks the chain from the head an outside witness
co-signed (a GitHub Actions OIDC token whose audience is the head's digest, signed by GitHub's key) down to the heads
this client holds. A fork carries both signed heads: two documents with CrawlCheck's own signature that cannot both be true.
Standard library only; the store is plain JSON (persist it between runs)."""
import base64
import datetime
import hashlib
import json

from .verify import verify_document, LOG_ID

GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_OIDC_JWKS = GITHUB_OIDC_ISSUER + "/.well-known/jwks"
WITNESS_REPOSITORY = "emmanuelorta/crawlcheck"
WITNESS_WORKFLOW_PREFIX = "emmanuelorta/crawlcheck/.github/workflows/log-witness.yml@refs/heads/"
MAX_HEADS = 2000


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def new_log_store():
    return {"v": 1, "log_id": LOG_ID, "heads": {}, "forks": [], "witnessed": None}


def _fork(store, kind, batch, a, b, why):
    f = {"kind": kind, "batch": batch, "why": why, "a": a, "b": b, "detected_at": _now(),
         "proof": "both documents carry CrawlCheck's own signature and cannot both belong to one append-only log; publish them or send them to https://crawlcheck.io/api/v1/log/gossip"}
    key = (kind, (a or {}).get("sha256"), (b or {}).get("sha256"))
    if not any((x["kind"], (x.get("a") or {}).get("sha256"), (x.get("b") or {}).get("sha256")) == key for x in store["forks"]):
        store["forks"].append(f)
    return {"state": "fork", "fork": f}


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def log_observe(store, sth, published_kids=None, max_heads=MAX_HEADS):
    """Check one signed tree head against the store and keep it. Returns {"state": "new"|"known"|"fork"|"invalid", ...}."""
    if not isinstance(sth, dict) or sth.get("kind") != "crawlcheck-log-sth" or not _is_int(sth.get("batch")) or sth["batch"] < 0:
        return {"state": "invalid", "why": "not a signed tree head"}
    try:
        v = verify_document(sth, published_kids)
    except ValueError:
        v = None
    if not v or not v["verified"]:
        return {"state": "invalid", "why": "the head does not verify"}
    if sth.get("log_id") != store.get("log_id", LOG_ID):
        return {"state": "invalid", "why": "a head of another log"}
    k = sth["batch"]
    bs, fi, ts, pv = sth.get("batch_size"), sth.get("first_index"), sth.get("tree_size"), sth.get("prev_sth_sha256")
    arith = _is_int(bs) and bs > 0 and _is_int(fi) and _is_int(ts) and ts == fi + bs and (k > 0 or (fi == 0 and pv is None)) and (k == 0 or (isinstance(pv, str) and len(pv) == 64))
    if not arith:
        return _fork(store, "inconsistent_head", k, sth, sth, "batch %d: a signed head whose sizes or chain link are malformed" % k)
    heads = store["heads"]
    have = heads.get(str(k))
    if have:
        if have["sha256"] == sth["sha256"]:
            return {"state": "known"}
        return _fork(store, "two_heads_for_one_batch", k, have["sth"], sth, "batch %d has two signed heads: %s… and %s…" % (k, have["sha256"][:16], sth["sha256"][:16]))
    prev, nxt = heads.get(str(k - 1)), heads.get(str(k + 1))
    if prev and pv != prev["sha256"]:
        return _fork(store, "chain_break", k, prev["sth"], sth, "batch %d does not chain to the batch %d head this client holds" % (k, k - 1))
    if prev and fi != prev["tree_size"]:
        return _fork(store, "size_mismatch", k, prev["sth"], sth, "batch %d starts at %d, batch %d ended at %d" % (k, fi, k - 1, prev["tree_size"]))
    if nxt and nxt["prev_sth_sha256"] != sth["sha256"]:
        return _fork(store, "chain_break", k + 1, sth, nxt["sth"], "the batch %d head this client holds does not chain to this batch %d head" % (k + 1, k))
    if nxt and nxt["first_index"] != ts:
        return _fork(store, "size_mismatch", k + 1, sth, nxt["sth"], "batch %d starts at %d, this head ends at %d" % (k + 1, nxt["first_index"], ts))
    heads[str(k)] = {"batch": k, "sha256": sth["sha256"], "first_index": fi, "batch_size": bs, "tree_size": ts, "prev_sth_sha256": pv, "created_at": sth.get("created_at"), "sth": sth}
    ks = sorted(int(x) for x in heads)
    while len(ks) > max_heads:
        del heads[str(ks.pop(0))]
    return {"state": "new"}


def log_observe_answer(store, answer, published_kids=None):
    t = (answer or {}).get("transparency") if isinstance(answer, dict) else None
    if t and t.get("state") == "included" and t.get("sth"):
        return log_observe(store, t["sth"], published_kids)
    return {"state": "none"}


def log_heads(store, limit=50):
    return [store["heads"][str(k)]["sth"] for k in sorted((int(x) for x in store["heads"]), reverse=True)[:limit]]


def log_gossip(store, sths, published_kids=None):
    before = len(store["forks"])
    results = []
    for s in sths or []:
        r = log_observe(store, s, published_kids)
        r.update({"batch": (s or {}).get("batch") if isinstance(s, dict) else None, "sha256": (s or {}).get("sha256") if isinstance(s, dict) else None})
        results.append(r)
    return {"forks": store["forks"][before:], "results": results}


# --- the outside witness: GitHub OIDC JWT, RS256 (RSASSA-PKCS1-v1_5 with SHA-256) ---
def _b64u(s):
    s = str(s)
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _rs256_verify(n, e, signing_input, sig):
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    m = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    t = _SHA256_PREFIX + hashlib.sha256(signing_input).digest()
    expect = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return k >= len(t) + 11 and m == expect


def verify_witness_token(token, sth_sha256, jwks):
    """Verify the witness co-signature (exp is not checked: the token records what the witness saw when it ran).
    Returns {"ok": True|False|None, "why": ..., "claims": ...}; None when GitHub no longer publishes the signing key."""
    parts = str(token or "").split(".")
    if len(parts) != 3:
        return {"ok": False, "why": "not a JWT"}
    try:
        h = json.loads(_b64u(parts[0]))
        c = json.loads(_b64u(parts[1]))
    except ValueError:
        return {"ok": False, "why": "unreadable token"}
    if h.get("alg") != "RS256":
        return {"ok": False, "why": "unexpected algorithm %s" % h.get("alg")}
    jwk = next((k for k in (jwks or {}).get("keys", []) if k.get("kid") == h.get("kid")), None)
    if not jwk:
        return {"ok": None, "why": "GitHub no longer publishes key %s; the co-signature cannot be checked now" % h.get("kid"), "claims": c}
    n, e = int.from_bytes(_b64u(jwk["n"]), "big"), int.from_bytes(_b64u(jwk["e"]), "big")
    if not _rs256_verify(n, e, (parts[0] + "." + parts[1]).encode(), _b64u(parts[2])):
        return {"ok": False, "why": "GitHub's signature does NOT verify", "claims": c}
    if c.get("iss") != GITHUB_OIDC_ISSUER:
        return {"ok": False, "why": "issuer is %s" % c.get("iss"), "claims": c}
    if c.get("repository") != WITNESS_REPOSITORY or not str(c.get("job_workflow_ref") or "").startswith(WITNESS_WORKFLOW_PREFIX):
        return {"ok": False, "why": "issued to %s, not the log-witness workflow" % c.get("job_workflow_ref"), "claims": c}
    if c.get("runner_environment") and c.get("runner_environment") != "github-hosted":
        return {"ok": False, "why": "not a GitHub-hosted runner", "claims": c}
    aud = c.get("aud") if isinstance(c.get("aud"), list) else [c.get("aud")]
    if "crawlcheck-sth:" + str(sth_sha256) not in aud:
        return {"ok": False, "why": "the token's audience does not name this head", "claims": c}
    return {"ok": True, "why": "GitHub signed a token for run %s of the log-witness workflow, audience this head's digest" % c.get("run_id"), "claims": c}


def _age_minutes(iso):
    try:
        t = datetime.datetime.strptime(str(iso)[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
        return (datetime.datetime.now(datetime.timezone.utc) - t).total_seconds() / 60
    except ValueError:
        return None


def _walk_heads(get, hi, lo):
    """Signed heads for batches hi down to lo, newest first. Since 1.9.0 one request per 200 batches (/api/v1/log/sths);
    a server without that route is walked one head per request as before."""
    out = []
    if hi < lo:
        return out
    k = hi
    while k >= lo:
        n = min(200, k - lo + 1)
        try:
            d = get("/api/v1/log/sths?to=%d&n=%d" % (k, n))
        except Exception:
            d = None
        sths = d.get("sths") if isinstance(d, dict) else None
        if not isinstance(sths, list):
            break
        got = {s["batch"]: s for s in sths if isinstance(s, dict) and _is_int(s.get("batch"))}
        for b in range(k, k - n, -1):
            if b in got:
                out.append(got[b])
        k -= n
    while k >= lo:   # fallback: one head per request
        try:
            d = get("/api/v1/log/sth/%d" % k)
        except Exception:
            d = None
        if d and d.get("sth"):
            out.append(d["sth"])
        k -= 1
    return out


def log_check(store, get, published_kids=None, jwks=None, fetch_jwks=None, post=None, max_walk=200, max_unwitnessed_minutes=120):
    """Online split-view check. get(path) returns parsed JSON from crawlcheck.io; post(path, body) reports heads to
    /api/v1/log/gossip (optional). Same steps as the JavaScript logCheck."""
    before = len(store["forks"])
    lg = get("/api/v1/log")
    if lg and lg.get("head"):
        log_observe(store, lg["head"], published_kids)
    witnessed = None
    try:
        w = get("/api/v1/log/witness/latest")
    except Exception:
        w = None
    if w and _is_int(w.get("batch")):
        doc = get("/api/v1/log/sth/%d" % w["batch"]) or {}
        sth = doc.get("sth")
        rec = (doc.get("witnesses") or [w])[0]
        keys = jwks if jwks is not None else (fetch_jwks() if fetch_jwks else None)
        tv = verify_witness_token(rec.get("token"), (sth or {}).get("sha256"), keys) if keys else {"ok": None, "why": "no GitHub key set given"}
        r = log_observe(store, sth, published_kids) if sth else {"state": "invalid"}
        claims = tv.get("claims") or {}
        witnessed = {"batch": w["batch"], "sha256": (sth or {}).get("sha256"), "at": rec.get("at"), "run_id": claims.get("run_id") or (rec.get("run") or {}).get("run_id"), "token": tv["ok"], "why": tv["why"], "observed": r["state"]}
        if tv["ok"] is False:
            witnessed["warning"] = "the witness record does not carry a valid GitHub co-signature for this head"
        if tv["ok"] is True and r["state"] != "invalid":
            store["witnessed"] = {"batch": w["batch"], "sha256": sth["sha256"], "at": witnessed["at"], "run_id": witnessed["run_id"]}
        held = [int(k) for k in store["heads"] if int(k) < w["batch"]]
        lo = max(min(held), w["batch"] - max_walk) if held else w["batch"]
        for sth_k in _walk_heads(get, w["batch"] - 1, lo):
            log_observe(store, sth_k, published_kids)
    wb = store["witnessed"]["batch"] if store.get("witnessed") else -1
    unw = [{"batch": int(k), "sha256": store["heads"][k]["sha256"], "created_at": store["heads"][k]["created_at"]} for k in sorted(store["heads"], key=int) if int(k) > wb]
    stale = [u for u in unw if u["created_at"] and (_age_minutes(u["created_at"]) or 0) > max_unwitnessed_minutes]
    forks = store["forks"][before:]
    if post:
        sths = log_heads(store, 20)
        for f in forks:
            sths.append(f["a"])
            if f["b"] is not f["a"]:
                sths.append(f["b"])
        try:
            post("/api/v1/log/gossip", {"sths": sths[:50]})
        except Exception:
            pass
    n = len(store["forks"])
    if n:
        summary = "SPLIT VIEW: %d pair(s) of contradicting signed heads" % n
    elif stale:
        summary = "no fork seen, but %d head(s) older than %d min are not covered by a witness" % (len(stale), max_unwitnessed_minutes)
    else:
        summary = "consistent: every head this client holds is on one chain" + (" up to the head GitHub's witness co-signed (batch %d)" % witnessed["batch"] if witnessed and witnessed["token"] is True else "")
    return {"consistent": n == 0, "forks": forks, "all_forks": n, "witnessed": witnessed, "unwitnessed": unw, "stale_unwitnessed": stale, "summary": summary}
