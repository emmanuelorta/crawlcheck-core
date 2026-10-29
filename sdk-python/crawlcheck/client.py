"""HTTP client for the CrawlCheck API. Standard library only."""
import hashlib
import json
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

from .verify import verify_document, key_id, canon, key_policy_from, apply_key_policy
from . import log as _log
from .staple import staple_check, staple_from_headers
from .revocations import new_revocation_store, apply_revocations, revoked_for

VERSION = "1.11.0"
ACTIONS = ("read", "cite", "connect", "transact", "administer")


RECEIPT_HEADER = "CrawlCheck-Receipt"
# The longest a receipt may stay valid, per action (seconds), and the most clock skew it may claim. https://crawlcheck.io/spec/guard
ACTION_MAX_LIFETIME_S = {"read": 86400, "cite": 86400, "connect": 3600, "transact": 300, "administer": 300}
MAX_CLOCK_SKEW_S = 300
_DECISIONS = ("allow", "warn", "require_confirmation", "block", "unsupported")


def _iso_ms(v):
    if not isinstance(v, str):
        return None
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})", v)
    if not m:
        return None
    import calendar
    t = calendar.timegm((int(m[1]), int(m[2]), int(m[3]), int(m[4]), int(m[5]), int(m[6]), 0, 0, 0)) * 1000
    if m[7]:
        t += int((m[7] + "000")[:3])
    if m[8] != "Z":
        sg = 1 if m[8][0] == "+" else -1
        t -= sg * (int(m[8][1:3]) * 60 + int(m[8][4:6])) * 60000
    return t


def check_decision(receipt, domain, action, nonce=None, now=None, operation=None):
    """Is this receipt about the operation you are about to perform? Returns (ok, why[]). Checks the scope only: kind,
    domain, action, nonce, time window, per-action lifetime, known decision, resolve binding. The signature and issuer
    are checked by verify_document; guard() runs both. now: ms since epoch (testing clock)."""
    why = []
    r = receipt
    if not isinstance(r, dict):
        return False, ["no receipt: CrawlCheck sent %s" % ("nothing" if r is None else type(r).__name__)]
    if r.get("kind") != "crawlcheck-decision" or r.get("v") != 1:
        why.append("not a v1 decision receipt (kind %s, v %s)" % (r.get("kind"), r.get("v")))
    wd = normalize_domain(domain)
    if not wd or normalize_domain(r.get("domain")) != wd:
        why.append("the receipt is for %s, not %s" % (r.get("domain"), domain))
    if str(r.get("action")) != str(action):
        why.append("the receipt is for action %s, not %s" % (r.get("action"), action))
    if operation and canon(r.get("operation")) != canon(operation):
        why.append("the receipt is for another operation (%s)" % canon(r.get("operation"))[:120] if r.get("operation") else "the receipt is not scoped to an operation, and this request named one")
    if nonce and r.get("nonce") != nonce:
        why.append("the receipt carries another request's nonce (replayed)" if r.get("nonce") else "the receipt does not carry the nonce this request sent")
    now = time.time() * 1000 if now is None else now
    try:
        sk = float(r.get("clock_skew_s") or 0)
    except (TypeError, ValueError):
        sk = 0
    skew = min(max(sk, 0), MAX_CLOCK_SKEW_S) * 1000
    at, exp = _iso_ms(r.get("decided_at")), _iso_ms(r.get("expires_at"))
    if at is None or exp is None:
        why.append("decided_at or expires_at missing")
    else:
        if now > exp + skew:
            why.append("expired at %s" % r.get("expires_at"))
        if at > now + skew:
            why.append("decided in the future (%s): check the clock" % r.get("decided_at"))
        mx = ACTION_MAX_LIFETIME_S.get(str(action))
        if mx is None:
            why.append("unknown action %s" % action)
        elif exp - at > mx * 1000 + 1000:
            why.append("valid for %d s; a %s receipt may last at most %d s" % (round((exp - at) / 1000), action, mx))
    if r.get("decision") not in _DECISIONS:
        why.append("unknown decision %s" % r.get("decision"))
    rs = r.get("resolve") if isinstance(r.get("resolve"), dict) else {}
    if not re.fullmatch(r"[0-9a-f]{64}", str(rs.get("sha256") or "")):
        why.append("the receipt names no resolve answer")
    return (not why), why


def normalize_domain(v):
    """The domain the way CrawlCheck hashes and stores it: lowercased, no scheme, no leading www., no path or port."""
    d = re.sub(r"^https?://", "", str(v or "").strip().lower())
    d = re.sub(r":\d+$", "", re.sub(r"[/?#].*$", "", re.sub(r"^www\.", "", d)))
    return d if re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", d) else ""


def tool_operation(tool, scopes=None):
    """The operation for calling an MCP tool: its name, the sha256 of its definition (as in the lockfile) and the scopes you will use."""
    from .lock import lock_tool_hash
    o = {"tool": str((tool or {}).get("name") or ""), "tool_schema_sha256": lock_tool_hash(tool)}
    if scopes:
        o["scopes"] = list(scopes)
    return o


def receipt_header(receipt):
    """The header an agent sends with its request so the site can see it checked first: {"CrawlCheck-Receipt": "v=1; sha256=..."}."""
    return {RECEIPT_HEADER: "v=1; sha256=" + receipt["sha256"]}


class CrawlCheckError(Exception):
    def __init__(self, status, body):
        self.status, self.body = status, body
        msg = body.get("error") if isinstance(body, dict) else None
        if not msg and isinstance(body, dict) and body.get("errors"):
            msg = "; ".join(body["errors"])
        super().__init__("HTTP %s: %s" % (status, msg or str(body)[:200]))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _no_redirect_request(method, url, headers, data, timeout):
    op = urllib.request.build_opener(_NoRedirect)
    try:
        with op.open(urllib.request.Request(url, data=data, headers=headers, method=method), timeout=timeout) as r:
            return r.status, dict(r.headers.items()), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()), e.read()


class CrawlCheck:
    """client = CrawlCheck(key=None)   # a licence key is optional; it unlocks full findings for licensed domains"""

    def __init__(self, key=None, base="https://crawlcheck.io", timeout=30, log_store=None, revocation_store=None, private_lookups=False):
        self.key, self.base, self.timeout = key, base.rstrip("/"), timeout
        self._kids = None
        self._kp = None   # conf2: (read time, key policy)
        self.last_guard = None
        # Transparency-log store: every Resolve answer's signed tree head is checked against it. Plain JSON - persist
        # it between runs (json.dump(client.log, f)) and pass it back as log_store= to catch a split view across runs.
        self.log = log_store if log_store is not None else _log.new_log_store()
        # Revocation store: sync_revocations() fills it; guard() refuses a listed domain for a listed action with no
        # network call. Plain JSON - persist it (json.dump(client.revocations, f)) and pass it back as revocation_store=.
        self.revocations = revocation_store if revocation_store is not None else new_revocation_store()
        # Private mode: resolve() and resolve_for() send only a 2-hex prefix of sha256(domain), never the domain. A domain
        # with no public measurement raises CrawlCheckError(404) instead of a just-in-time answer (which would name it).
        # preflight() and guard() still name the domain: a receipt is bound to it.
        self.private_lookups = bool(private_lookups)

    def _req(self, method, path, query=None, body=None):
        url = self.base + path + ("?" + urllib.parse.urlencode({k: v for k, v in (query or {}).items() if v is not None}) if query else "")
        h = {"user-agent": "crawlcheck-python/" + VERSION, "accept": "application/json"}
        if self.key:
            h["x-crawlcheck-key"] = self.key
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h["content-type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=h, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            try:
                b = json.loads(raw)
            except ValueError:
                b = {"error": raw[:300]}
            raise CrawlCheckError(e.code, b) from None

    # --- read before acting ---
    def resolve_for(self, domain, staple=None, headers=None):
        """The verdict for a domain, preferring a valid staple the site sent (staple=, or the CrawlCheck-Staple entry of
        headers=): no request to CrawlCheck is made when it verifies. An expired, foreign or invalid staple is ignored
        and the signed answer is fetched instead. Returns {source, decisions, staple[, answer]}."""
        rec = staple or (staple_from_headers(headers) if headers else None)
        chk = None
        if rec:
            try:
                kids = self.published_key_ids()
            except Exception:
                kids = []
            chk = staple_check(rec, normalize_domain(domain) or domain, kids)
            if chk["valid"]:
                return {"source": "staple", "decisions": chk["decisions"], "staple": chk}
        a = self.resolve(domain)
        acts = (a or {}).get("actions") or {}
        dec = {k: (acts.get(k) or {}).get("decision") for k in ("read", "cite", "connect", "transact")}
        return {"source": "network", "decisions": dec, "staple": chk, "answer": a}

    def resolve(self, domain):
        """The signed ResolveV1 answer: crawl policy, delivery, machine files, capabilities, entity, findings, freshness and a decision per action."""
        if self.private_lookups:   # pfx2: only the hash prefix leaves this machine
            p = self.resolve_private(domain)
            if not p["ready"]:
                raise CrawlCheckError(503, {"error": p.get("why") or "the prefix index is not built yet"})
            if not p["found"]:
                raise CrawlCheckError(404, {"error": "CrawlCheck holds no public measurement of %s; in private mode the domain is never sent, so no just-in-time answer is made" % domain})
            if not p["accepted"]:
                raise CrawlCheckError(502, {"error": "the answer in the bucket did not verify: %s" % (p["verification"] or {}).get("summary")})
            a = p["answer"]
        else:
            a = self._req("GET", "/api/v1/resolve", {"domain": domain})
        try:
            _log.log_observe_answer(self.log, a)
        except Exception:
            pass
        return a

    def resolve_batch(self, domains):
        """Up to 100 domains in one call; each answer is a full signed ResolveV1 document."""
        r = self._req("POST", "/api/v1/resolve", body={"domains": list(domains)})
        for a in (r or {}).get("answers") or []:
            try:
                _log.log_observe_answer(self.log, a)
            except Exception:
                pass
        return r

    def preflight(self, domain, action="read", agent=None, template=None, policy=None, operation=None, nonce=None, mcp=None):
        """The policy engine: a signed decision receipt (allow | warn | require_confirmation | block | unsupported).
        policy keys: max_age_hours, on_warn (warn|require_confirmation|block), require_entity, human_approval[], allow[], deny[].
        A policy can only make the decision stricter."""
        b = {"domain": domain, "action": action}
        if agent:
            b["agent"] = agent
        if template:
            b["template"] = template
        if policy:
            b["policy"] = policy
        if operation:
            b["operation"] = operation
        if nonce:
            b["nonce"] = nonce
        if mcp and mcp.get("url"):
            # tscope1: an MCP server on this domain and its approved lockfile tools_sha256; the signed receipt's
            # "assessed" block then names the endpoint and tool state it covered, and changed tools come back as block.
            b["mcp"] = {k: mcp[k] for k in ("url", "tools_sha256") if mcp.get(k)}
        return self._req("POST", "/api/v1/preflight", body=b)

    def changes(self, since=None, domain=None, limit=100):
        return self._req("GET", "/api/v1/changes", {"since": since, "domain": domain, "limit": limit})

    def outcome(self, domain, action, status=None, blocked=None, challenged=None, agent=None, resolve_sha256=None, **extra):
        """Report what happened after acting. Outcomes are kept apart from the signed record and never rewrite it."""
        b = dict(extra, domain=domain, action=action)
        for k, v in (("status", status), ("blocked", blocked), ("challenged", challenged), ("agent", agent), ("resolve_sha256", resolve_sha256)):
            if v is not None:
                b[k] = v
        return self._req("POST", "/api/v1/outcome", body=b)

    def domain(self, domain):
        """The registry record (RDAP) and lifecycle of a domain."""
        return self._req("GET", "/api/v1/domain", {"domain": domain})

    def scan(self, domain):
        return self._req("POST", "/api/scan", body={"domain": domain})

    def machine_record(self, report_id, fmt=None):
        return self._req("GET", "/api/v1/machine-record", {"id": report_id, "format": fmt})

    # --- verification ---
    def published_key_ids(self, refresh=False):
        if self._kids is None or refresh:
            d = self._req("GET", "/.well-known/http-message-signatures-directory")
            self._kids = [k.get("kid") or key_id(k) for k in d.get("keys", [])]
        return self._kids

    def published_key_policy(self, refresh=False):
        """conf2: the key directory and rotation record, read now (cached 10 minutes), as the signing policy reads them.
        Without the rotation record retired and compromised keys are unknown and only keys still in the directory pass."""
        if refresh or self._kp is None or time.time() - self._kp[0] > 600:
            d = self._req("GET", "/.well-known/http-message-signatures-directory")
            try:
                rot = self._req("GET", "/.well-known/security-key-rotation.json")
            except Exception:  # noqa: BLE001 - optional
                rot = None
            kp = key_policy_from(d, rot if isinstance(rot, dict) else None)
            kp["source"], kp["read_at"] = "online", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self._kp = (time.time(), kp)
        return self._kp[1]

    def verify(self, doc, online_keys=True, key_policy=None):
        """Verify a signed document. With online_keys (or a pinned key_policy from key_policy_from), the signing key must
        also be published and the signing policy (purpose, retired, compromised) must accept it."""
        kp = key_policy or (self.published_key_policy() if online_keys else None)
        v = verify_document(doc, kp["kids"] if kp else None)
        return apply_key_policy(v, doc, kp) if kp and isinstance(doc, dict) and doc.get("signature") else v

    def sync_revocations(self, full=False):
        """Fetch the signed revocation list (a ?since= delta when the store already holds one), verify it (integrity and
        a published signing key) and apply it. A delta that no longer reaches back is replaced by the full list; nothing
        is applied from a document that does not verify. Returns {applied, full, added, removed, reason, total, generated_at}."""
        st = self.revocations
        since = None if (full or not st.get("generated_at")) else st["generated_at"]
        doc = self._req("GET", "/api/v1/revocations", {"since": since} if since else None)

        def res(r, v=None):
            return dict(r, total=len(st["revoked"]), generated_at=st.get("generated_at"), verification=v)
        v = self.verify(doc)
        if not v.get("accepted"):
            return res({"applied": False, "full": not since, "added": 0, "removed": 0, "reason": "the revocation list did not verify: %s" % v.get("summary")}, v)
        r = apply_revocations(st, doc)
        if not r["applied"] and doc.get("since"):
            doc = self._req("GET", "/api/v1/revocations")
            v = self.verify(doc)
            if not v.get("accepted"):
                return res({"applied": False, "full": True, "added": 0, "removed": 0, "reason": "the full revocation list did not verify: %s" % v.get("summary")}, v)
            r = apply_revocations(st, doc)
        return res(r, v)

    def guard(self, domain, action="read", agent=None, template=None, policy=None, confirm=None, allow_warn=False, nonce=None, now=None, operation=None):
        """Preflight, verify the receipt, check it is for THIS operation, and return (proceed: bool, receipt). Proceeds on
        allow; warn only with allow_warn=True; require_confirmation only if confirm(receipt) returns True; block,
        unsupported and every failure never (fail closed: an error, an unreachable CrawlCheck, a malformed, foreign,
        expired, replayed or out-of-scope receipt all return (False, receipt or None)). Why: client.last_guard["why"].
        Passes the acceptance suite at https://crawlcheck.io/spec/guard"""
        nonce = nonce or secrets.token_hex(16)

        def no(why, rc=None):
            self.last_guard = {"proceed": False, "why": why, "domain": domain, "action": action}
            return False, rc
        rv = revoked_for(self.revocations, normalize_domain(domain) or domain, action)   # rvd1: refused offline, before any request
        if rv:
            no(["%s is on CrawlCheck's signed revocation list for %s (%s%s; list of %s)" % (rv["domain"], action, ", ".join(rv.get("causes") or []) or rv.get("state") or "revoked", ", since " + rv["since"] if rv.get("since") else "", self.revocations.get("generated_at"))])
            self.last_guard["revoked"] = rv
            return False, None
        try:
            b = {"domain": domain, "action": action, "nonce": nonce}
            for k, v in (("agent", agent), ("template", template), ("policy", policy), ("operation", operation)):
                if v:
                    b[k] = v
            rc = self._req("POST", "/api/v1/preflight", body=b)
        except Exception as e:  # noqa: BLE001 - every failure refuses
            return no(["CrawlCheck did not give a decision: %s" % e])
        if self.log.get("forks"):   # the log has shown this client two contradicting histories (see client.log["forks"])
            return no(["the transparency log has shown this client two histories (split view)"], rc)
        ok, why = check_decision(rc, domain, action, nonce=nonce, now=now, operation=operation)
        if not isinstance(rc, dict):
            return no(why)
        try:
            v = self.verify(rc)
        except Exception as e:  # noqa: BLE001
            return no(["the receipt could not be verified: %s" % e] + why, rc)
        bad = [c["id"] for c in v.get("checks", []) if c.get("ok") is False and c.get("id") not in ("key_published", "key_purpose")]
        if bad:
            why.append("integrity failed: " + ", ".join(bad))
        if not v.get("accepted") and not bad:
            why.append("signed by a key that is not in CrawlCheck's published key directory" if v.get("issuer_trusted") is not True else
                       "the signing policy rejects this key for a decision receipt: " + next((c["why"] for c in v["checks"] if c["id"] == "key_purpose"), ""))
        if why:
            return no(why, rc)
        d = rc.get("decision")
        proceed = d == "allow" or (d == "warn" and bool(allow_warn))
        if d == "require_confirmation" and confirm is not None:
            try:
                proceed = confirm(rc) is True
            except Exception:  # noqa: BLE001
                proceed = False
        if not proceed:
            why.append("decision is warn and allow_warn is not set" if d == "warn" else
                       ("a human did not confirm" if confirm is not None else "decision is require_confirmation and no confirm was given") if d == "require_confirmation" else "decision is %s" % d)
        self.last_guard = {"proceed": proceed, "why": why, "domain": domain, "action": action, "verified": bool(v.get("accepted"))}   # 1.11.0: same field the JS tool returns
        return proceed, rc

    def guarded_fetch(self, url, action="read", method="GET", headers=None, data=None, allow_warn=False, confirm=None, max_hops=10, transport=None, now=None, nonce=None, timeout=None):
        """An HTTP request with the check where the action runs: guard() before the first request and again before every
        redirect hop to a new domain. The site is contacted only after its domain proceeds; a refused hop is never
        requested. Redirects are followed by hand (GET/HEAD only), to http(s) only, at most max_hops. The receipt header
        goes only to the domain it names. Returns {"proceed", "status", "headers", "body", "url", "hops", "why"}.
        transport(method, url, headers, data) -> (status, headers_dict, body_bytes) replaces urllib (tests)."""
        transport = transport or (lambda m, u, h, d: _no_redirect_request(m, u, h, d, timeout or self.timeout))
        method = method.upper()
        hops, seen, cur = [], {}, url

        def out(proceed, why, status=None, hdrs=None, body=None):
            return {"proceed": proceed, "status": status, "headers": hdrs, "body": body, "url": cur, "hops": hops, "why": why}
        for _ in range(max_hops + 1):
            u = urllib.parse.urlsplit(cur)
            if u.scheme not in ("http", "https"):
                return out(False, ["refused a %s: URL" % (u.scheme or "schemeless")])
            dom = normalize_domain(u.hostname or "")
            if not dom:
                return out(False, ["not a public domain name: %s" % u.hostname])
            key = method + " " + cur   # op1: each hop's receipt names that exact request
            if key not in seen:
                p, rc = self.guard(dom, action, allow_warn=allow_warn, confirm=confirm, now=now, nonce=nonce, operation={"method": method, "url": cur})
                seen[key] = (p, rc, list(self.last_guard.get("why") or []))
            p, rc, why = seen[key]
            hop = {"url": cur, "domain": dom, "proceed": p, "decision": rc.get("decision") if isinstance(rc, dict) else None, "why": why}
            hops.append(hop)
            if not p:
                return out(False, ["%s: %s" % (dom, "; ".join(why) or "refused")])
            h = dict(headers or {})
            h.update(receipt_header(rc))
            status, rh, body = transport(method, cur, h, data)
            hop["status"] = status
            loc = {k.lower(): v for k, v in (rh or {}).items()}.get("location")
            if status not in (301, 302, 303, 307, 308) or not loc:
                return out(True, [], status, rh, body)
            if method not in ("GET", "HEAD"):
                return out(True, ["redirect not followed for %s" % method], status, rh, body)
            cur = urllib.parse.urljoin(cur, loc)
        return out(False, ["more than %d redirects" % max_hops])

    # --- split-view detection (1.0.5) ---
    def log_check(self, report=True, max_walk=200, max_unwitnessed_minutes=120):
        """The current head, GitHub's witness co-signature on the last witnessed head, and the chain from it down to every
        head this client holds. Reports the heads it holds to /api/v1/log/gossip unless report=False."""
        def jwks():
            with urllib.request.urlopen(urllib.request.Request(_log.GITHUB_OIDC_JWKS, headers={"user-agent": "crawlcheck-python/" + VERSION}), timeout=self.timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        return _log.log_check(self.log, lambda p: self._req("GET", p), published_kids=self.published_key_ids(), fetch_jwks=jwks,
                              post=(lambda p, b: self._req("POST", p, body=b)) if report else None, max_walk=max_walk, max_unwitnessed_minutes=max_unwitnessed_minutes)

    def log_gossip(self, sths):
        """Check heads another client sent (their log_heads) against this client's store."""
        return _log.log_gossip(self.log, sths)

    # --- private lookup and receipt headers (1.0.3) ---
    def field_check(self, domain, field, value):
        """One signed verdict on a business fact (phone, address, hours, service_area) against what the business publishes."""
        return self._req("GET", "/api/v1/field-check", {"domain": normalize_domain(domain), "field": field, "value": value})

    def mcp_lock(self, url):
        """A signed lockfile for an MCP server (CrawlCheck reads tools/list; no tool is called). Check it with check_lock before every connect."""
        return self._req("GET", "/api/v1/mcp/lock", {"url": url})

    def mcp_lock_check(self, lock, url=None):
        """Read the server's tools now through CrawlCheck and compare with a lockfile; signed answer. For an offline check use check_lock."""
        return self._req("POST", "/api/v1/mcp/lock/check", None, {"lock": lock, "url": url or (lock.get("server") or {}).get("url")})

    def mcp_scan(self, target):
        """Tool-poisoning scan of a server URL (str) or a tools/list result (list)."""
        if isinstance(target, str):
            return self._req("GET", "/api/v1/mcp/scan", {"url": target})
        return self._req("POST", "/api/v1/mcp/scan", None, {"tools": target})

    def resolve_private(self, domain, prefix_len=2):
        """Look a domain up without sending it: only the first prefix_len hex characters of sha256(domain) leave this
        machine (one more character per 413, up to 8). Returns {"found", "ready", "in_bucket", "answer", "verification", "accepted"}. found False with ready
        True means CrawlCheck holds no public measurement of the domain."""
        d = normalize_domain(domain)
        if not d:
            raise ValueError("not a domain name: %r" % domain)
        if not 2 <= prefix_len <= 8:
            raise ValueError("prefix_len must be 2 to 8")
        h = hashlib.sha256(d.encode()).hexdigest()
        n = prefix_len
        while True:
            try:
                r = self._req("GET", "/api/v1/resolve-prefix/" + h[:n])
                break
            except CrawlCheckError as e:
                if e.status == 503:
                    return {"found": False, "ready": False, "in_bucket": None, "answer": None, "verification": None, "accepted": False, "why": "the prefix index is not built yet"}
                if e.status == 413 and n < 8:
                    # more than 100 measured domains share the prefix (the corpus grows): one more hex character, still never the domain
                    n += 1
                    continue
                raise
        hit = next((a for a in r.get("answers", []) if a.get("domain_sha256") == h), None)
        if not hit:
            return {"found": False, "ready": True, "in_bucket": r.get("in_bucket"), "answer": None, "verification": None, "accepted": False}
        ans = hit["answer"]
        v = self.verify(ans)
        return {"found": True, "ready": True, "in_bucket": r.get("in_bucket"), "answer": ans, "verification": v, "accepted": bool(v["accepted"]) and normalize_domain(ans.get("domain")) == d}

    def receipt_header(self, receipt):
        """{"CrawlCheck-Receipt": "v=1; sha256=..."} for a decision receipt from preflight() or guard()."""
        return receipt_header(receipt)

    def check_receipt_header(self, header_value, host):
        """For sites: check a CrawlCheck-Receipt header received with a request to host. accept is True only when
        CrawlCheck holds the receipt, it names host, has not expired, its decision is allow or warn, and its signature
        verifies with a published key."""
        m = re.search(r"sha256=([0-9a-fA-F]{64})", header_value or "") or re.fullmatch(r"\s*([0-9a-fA-F]{64})\s*", header_value or "")
        if not m:
            return {"accept": False, "why": "no receipt digest in the header", "check": None, "verification": None}
        sha, h = m.group(1).lower(), normalize_domain(host)
        try:
            r = self._req("GET", "/api/v1/decisions/" + sha, {"host": h})
        except CrawlCheckError as e:
            if e.status == 404:
                return {"accept": False, "why": "CrawlCheck holds no receipt with that digest", "check": e.body, "verification": None}
            raise
        rc = r.get("receipt") or {}
        v = self.verify(rc)
        ok = bool(r.get("accept")) and bool(v["accepted"]) and rc.get("sha256") == sha and normalize_domain(rc.get("domain")) == h
        return {"accept": ok, "why": r.get("reason"), "check": r, "verification": v}
