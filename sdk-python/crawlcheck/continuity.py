"""Tool-interface continuity (https://crawlcheck.io/spec/continuity), 1.12.0. The same contract as the JS SDK's
continuity.js, record for record: the shared golden file (tests/fixtures/continuity.json) must reproduce byte for byte,
record_sha256 included.

The promise, and only this one: an agent does not silently proceed with a changed tool definition when the operator's
policy requires renewed approval. continuity_check() compares the tools a server offers now with the approved baseline
(an mcp-lockfile, ideally with lock["parts"]), classifies every difference, applies the operator's policy and returns a
record of what was compared, which policy decided, and what the runtime was told to do.

It does NOT establish that a tool is harmless, that its publisher is honest, that the code behind an unchanged
description is unchanged, that a user authorised a call, or that no prompt injection exists.

Modes: observe (record only; outcome is always proceed), review (every change goes to a person; integrity failures still
deny), enforce (the policy applies). Effects, weakest to strongest: proceed, proceed_recorded, refresh, pause_tool, pause, deny.
"""
import hashlib
import json
import math
import os
from datetime import datetime, timezone

from . import _ed25519
from .verify import canon, key_policy_check, _b64u, _b64u_decode
from .jcs import jcs_v1

CONTINUITY_EFFECTS = ["proceed", "proceed_recorded", "refresh", "pause_tool", "pause", "deny"]
CONTINUITY_CHANGE_CLASSES = ["tool_added", "tool_removed", "description_changed", "schema_changed", "annotations_changed", "tool_changed"]
CONTINUITY_FAILURE_CLASSES = ["evidence_expired", "signature_invalid", "key_unknown", "key_retired", "server_identity_mismatch", "server_unavailable",
                              "tool_list_truncated", "response_malformed", "baseline_stale", "policy_version_mismatch", "check_timeout", "service_unavailable", "decision_refused", "baseline_untrusted"]
_INTEGRITY = ["signature_invalid", "key_unknown", "key_retired", "server_identity_mismatch", "baseline_untrusted"]
CONTINUITY_DEFAULT_POLICY = {
    "v": 1, "id": "crawlcheck-continuity-default", "max_baseline_age_days": 90,
    "effects": {
        "unchanged": "proceed", "tool_added": "pause_tool", "tool_removed": "proceed", "description_changed": "pause_tool", "schema_changed": "pause_tool",
        "annotations_changed": "pause_tool", "tool_changed": "pause_tool", "evidence_expired": "refresh", "signature_invalid": "deny", "key_unknown": "deny",
        "key_retired": "deny", "server_identity_mismatch": "deny", "server_unavailable": "pause", "tool_list_truncated": "pause", "response_malformed": "pause",
        "baseline_stale": "pause", "policy_version_mismatch": "pause", "check_timeout": "pause", "service_unavailable": "pause", "decision_refused": "deny",
        "baseline_untrusted": "deny",
    },
}
_WHY = {
    "tool_added": "a tool the baseline does not list is offered", "tool_removed": "a tool in the baseline is no longer offered",
    "description_changed": "the tool's description differs from the approved one", "schema_changed": "the tool's input schema differs from the approved one",
    "annotations_changed": "the tool's annotations differ from the approved ones", "tool_changed": "the tool differs from the approved one (the baseline has no per-part hashes, so the part is unknown)",
    "evidence_expired": "the evidence is past its validity window", "signature_invalid": "a signature over the evidence does not verify",
    "key_unknown": "the evidence is signed by a key that is not published", "key_retired": "the signing policy rejects the key for this object at its signing time",
    "server_identity_mismatch": "the server answering is not the one the baseline names", "server_unavailable": "the server could not be reached, so nothing was compared",
    "tool_list_truncated": "the tool list is incomplete (a further page was not read)", "response_malformed": "the tool list could not be parsed",
    "baseline_stale": "the approved baseline is older than the policy allows", "policy_version_mismatch": "the policy in force is not the version the deployment expects",
    "check_timeout": "the check did not finish in time", "service_unavailable": "the verification service could not be reached; the local fallback applies",
    "decision_refused": "CrawlCheck's signed decision for the server's host did not allow the connection",
    "baseline_untrusted": "the approved baseline is not trusted: its signature does not verify, its key is neither CrawlCheck's nor a given operator key, or it is unsigned where a signed one is required",
}
_CLAIMS = "interface continuity at this check point: the offered tool definitions were compared with the approved baseline. Not code attestation, not a judgement that any tool is harmless, not user authorisation."


def _h(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _iso(ms):
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (int(ms) % 1000)


def _ms(s):
    if not isinstance(s, str) or not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000.0
    except ValueError:
        return None


def _now_ms():
    return datetime.now(timezone.utc).timestamp() * 1000.0


def _schema(t):
    t = t or {}
    return t.get("inputSchema") if t.get("inputSchema") is not None else t.get("input_schema")


def lock_tool_parts(tool):
    """Per-part hashes of one tool, so a change can be named (description, schema, annotations)."""
    t = tool or {}
    return {"description_sha256": _h(canon(t.get("description"))), "schema_sha256": _h(canon(_schema(t))), "annotations_sha256": _h(canon(t.get("annotations")))}


def lock_parts(tools):
    """parts for a lockfile: {tool name: lock_tool_parts(tool)}, for every tool given. Store it as lock["parts"] next to lock["tools"]."""
    return {str((t or {}).get("name") or "")[:120]: lock_tool_parts(t) for t in (tools or [])}


# The most tools a v1 (lk) lockfile hashes; CrawlCheck's lockfile endpoint hashes the same. A longer list is compared on its
# first LOCK_V1_MAX_TOOLS tools and the read is marked incomplete (tool_list_truncated), never cut silently.
LOCK_V1_MAX_TOOLS = 300


def _jcs_baseline(lock):
    """The lockfile's jcs-v1 block when it can be compared on (a digest, and a per-tool row for every tool it counted)."""
    J = (lock or {}).get("jcs_v1") if isinstance(lock, dict) else None
    if isinstance(J, dict) and J.get("alg") == "jcs-v1" and isinstance(J.get("tools_sha256"), str) and J["tools_sha256"] \
            and isinstance(J.get("tools"), list) and not isinstance(J.get("count"), bool) and len(J["tools"]) == J.get("count"):
        return J
    return None


def _tool_hash(t):
    t = t or {}
    return _h(canon({"name": t.get("name"), "description": t.get("description"), "inputSchema": _schema(t), "annotations": t.get("annotations")}))


def continuity_policy(p=None):
    """The policy in force: the default with the operator's values over it, and its sha256 (what the record names)."""
    base = CONTINUITY_DEFAULT_POLICY
    given = p if isinstance(p, dict) else {}
    effects = dict(base["effects"])
    for k, v in (given.get("effects") or {}).items():
        if k not in base["effects"]:
            raise ValueError("unknown continuity class: " + k)
        if v not in CONTINUITY_EFFECTS:
            raise ValueError("unknown effect for %s: %s" % (k, v))
        effects[k] = v
    override = given.get("allow_integrity_override") is True
    for k in _INTEGRITY:
        if effects[k] != "deny" and not override:
            raise ValueError(k + " must stay deny (set allow_integrity_override to change it, and the record will say so)")
    mba = given.get("max_baseline_age_days")
    ok_num = isinstance(mba, (int, float)) and not isinstance(mba, bool) and math.isfinite(mba)
    pol = {"v": 1, "id": str(given.get("id") or base["id"]), "max_baseline_age_days": mba if ok_num else base["max_baseline_age_days"], "effects": effects, "allow_integrity_override": override}
    pol["sha256"] = _h(canon(pol))
    return pol


def _rank(e):
    return CONTINUITY_EFFECTS.index(e)


def _exc_for(exceptions, cls, tool, now):
    for x in exceptions or []:
        if not isinstance(x, dict):
            continue
        if x.get("class") not in (cls, "*"):
            continue
        xt = x.get("tool")
        if not (xt == tool or (not xt and not tool) or xt == "*"):
            continue
        u = x.get("until")
        if u:
            um = _ms(u)
            if um is None or not um > now:
                continue
        return x
    return None


def _mode_effect(mode, cls, eff):
    if mode == "review" and eff not in ("proceed", "proceed_recorded"):
        return "deny" if cls in _INTEGRITY else "pause"
    return eff


def _finish(rec, mode):
    would, eff = "proceed", "proceed"
    for e in rec["events"]:
        if _rank(e["policy_effect"]) > _rank(would):
            would = e["policy_effect"]
        if _rank(e["effect"]) > _rank(eff):
            eff = e["effect"]
    rec["would"] = would
    rec["enforced"] = mode != "observe"
    rec["outcome"] = "proceed" if mode == "observe" or eff in ("pause_tool", "proceed_recorded") else eff
    rec["paused_tools"] = [] if mode == "observe" else [e["tool"] for e in rec["events"] if e["effect"] == "pause_tool" and e["tool"]]
    why = []
    for e in rec["events"]:
        if e["class"] == "unchanged":
            continue
        s = (e["tool"] + ": " if e["tool"] else "") + e["why"] + " -> " + e["effect"]
        if e.get("exception"):
            s += " (exception by " + (e["exception"].get("by") or "?") + ")"
        why.append(s)
    rec["why"] = why or ["the offered tools match the approved baseline"]
    rec["record_sha256"] = _h(canon(rec))
    return rec


def _base(opts, pol, mode):
    now = opts.get("now")
    return {"kind": "crawlcheck-continuity-record", "v": 1, "checked_at": _iso(now if now is not None else _now_ms()), "mode": mode, "server": opts.get("server"),
            "policy": {"id": pol["id"], "sha256": pol["sha256"], "integrity_override": pol["allow_integrity_override"]}, "claims": _CLAIMS, "events": []}


def _ev(rec, pol, mode, cls, tool, exceptions, now, detail=None):
    pe = pol["effects"][cls]
    eff = _mode_effect(mode, cls, pe)
    ex = _exc_for(exceptions, cls, tool, now) if cls not in _INTEGRITY else None
    if ex and eff != "deny":
        eff = "proceed_recorded"
    e = {"class": cls, "tool": tool, "why": _WHY.get(cls, cls), "policy_effect": pe, "effect": eff}
    if ex:
        e["exception"] = {"by": ex.get("by"), "reason": ex.get("reason"), "until": ex.get("until")}
    if detail:
        e["detail"] = detail
    rec["events"].append(e)


def _strip(u):
    return str(u).rstrip("/")


def continuity_check(lock, tools, mode="enforce", policy=None, exceptions=None, complete=True, server=None, server_identity=None, expect_policy_sha256=None, now=None, baseline_trust=None, digest=None):
    """Compare the offered tools with the approved baseline and apply the policy. complete=False when tools/list returned a
    nextCursor you did not follow. server: the URL checked; server_identity: the URL the baseline was approved for.
    digest: "lk-v1" to compare on the v1 hashes even when the lockfile carries jcs_v1; by default a lockfile with jcs_v1
    is compared on jcs-v1, over every tool. A v1 comparison of more than LOCK_V1_MAX_TOOLS tools is marked incomplete."""
    if mode not in ("observe", "review", "enforce"):
        raise ValueError("mode must be observe, review or enforce")
    pol = continuity_policy(policy)
    now = _now_ms() if now is None else now
    opts = {"now": now, "server": server}
    rec = _base(opts, pol, mode)
    if not isinstance(tools, list):
        _ev(rec, pol, mode, "response_malformed", None, exceptions, now)
        return _finish(rec, mode)
    J = None if digest == "lk-v1" else _jcs_baseline(lock)
    if J:
        return _jcs_check(rec, pol, mode, lock, J, tools, complete is not False, server, server_identity, expect_policy_sha256, exceptions, now, baseline_trust)
    capped = len(tools) > LOCK_V1_MAX_TOOLS
    complete = complete is not False and not capped
    rows = [{"name": str((t or {}).get("name") or "")[:120], "sha256": _tool_hash(t), "t": t} for t in tools[:LOCK_V1_MAX_TOOLS]]
    cur = {}
    for r in rows:
        cur[r["name"]] = r
    list_hash = _h("\n".join(sorted(r["sha256"] for r in rows)))
    lock = lock or {}
    was = {r["name"]: r["sha256"] for r in lock.get("tools") or []}
    appr = _ms(lock.get("approved_at"))
    srv = (lock.get("server") or {}).get("url") if isinstance(lock.get("server"), dict) else None
    rec["baseline"] = {"tools_sha256": lock.get("tools_sha256"), "approved_at": lock.get("approved_at"), "age_days": int(math.floor((now - appr) / 864e5)) if appr is not None else None,
                       "server": srv, "per_part": bool(lock.get("parts")), "trust": baseline_trust}
    rec["observed"] = {"tools_sha256": list_hash, "count": len(rows), "complete": complete}
    if capped:
        rec["observed"]["offered"] = len(tools)
    if expect_policy_sha256 and expect_policy_sha256 != pol["sha256"]:
        _ev(rec, pol, mode, "policy_version_mismatch", None, exceptions, now, "expected %s, in force %s" % (expect_policy_sha256, pol["sha256"]))
    want = server_identity if server_identity is not None else srv
    if want and server and _strip(want) != _strip(server):
        _ev(rec, pol, mode, "server_identity_mismatch", None, exceptions, now, "baseline approved for %s, checked %s" % (want, server))
    if rec["baseline"]["age_days"] is not None and rec["baseline"]["age_days"] > pol["max_baseline_age_days"]:
        _ev(rec, pol, mode, "baseline_stale", None, exceptions, now, "%d days old; the policy allows %s" % (rec["baseline"]["age_days"], pol["max_baseline_age_days"]))
    if not complete:
        _ev(rec, pol, mode, "tool_list_truncated", None, exceptions, now, "the server offers %d tools; a v1 lockfile hashes the first %d" % (len(tools), LOCK_V1_MAX_TOOLS) if capped else None)
    for n in sorted(n for n in cur if n not in was):
        _ev(rec, pol, mode, "tool_added", n, exceptions, now)
    if complete:
        for n in sorted(n for n in was if n not in cur):
            _ev(rec, pol, mode, "tool_removed", n, exceptions, now)
    parts = lock.get("parts") or None
    for n in sorted(n for n in cur if n in was and was[n] != cur[n]["sha256"]):
        P = parts.get(n) if parts else None
        if not P:
            _ev(rec, pol, mode, "tool_changed", n, exceptions, now)
            continue
        q = lock_tool_parts(cur[n]["t"])
        any_ = False
        for part, cls in (("description_sha256", "description_changed"), ("schema_sha256", "schema_changed"), ("annotations_sha256", "annotations_changed")):
            if q[part] != P.get(part):
                _ev(rec, pol, mode, cls, n, exceptions, now)
                any_ = True
        if not any_:
            _ev(rec, pol, mode, "tool_changed", n, exceptions, now, "the name or a field outside description, schema and annotations changed")
    if not rec["events"]:
        rec["events"].append({"class": "unchanged", "tool": None, "why": "the offered tools match the approved baseline", "policy_effect": pol["effects"]["unchanged"],
                              "effect": _mode_effect(mode, "unchanged", pol["effects"]["unchanged"])})
    return _finish(rec, mode)


def _u16key(s):
    return s.encode("utf-16-be", "surrogatepass")


def _jcs_check(rec, pol, mode, lock, J, tools, complete, server, server_identity, expect_policy_sha256, exceptions, now, baseline_trust):
    """1.15.0: the comparison on jcs-v1 (https://crawlcheck.io/spec/mcp-lockfile#jcs-v1), used when the lockfile carries a
    jcs_v1 block (every CrawlCheck lockfile since 2026-11-07). Every tool is digested (no cap). A moved contract digest is
    named description_changed / schema_changed from lock["parts"] when it has them; a moved extras digest is
    annotations_changed when the annotations moved, otherwise tool_changed (title, icons, _meta or another member)."""
    cj = jcs_v1(tools)
    appr = _ms(lock.get("approved_at"))
    srv = (lock.get("server") or {}).get("url") if isinstance(lock.get("server"), dict) else None
    rec["baseline"] = {"alg": "jcs-v1", "tools_sha256": J["tools_sha256"], "extras_sha256": J.get("extras_sha256"), "approved_at": lock.get("approved_at"),
                       "age_days": int(math.floor((now - appr) / 864e5)) if appr is not None else None, "server": srv, "per_part": bool(lock.get("parts")), "trust": baseline_trust}
    rec["observed"] = {"alg": "jcs-v1", "tools_sha256": cj["tools_sha256"], "extras_sha256": None if cj["tools_sha256"] is None else cj["extras_sha256"], "count": len(tools), "complete": complete}
    if expect_policy_sha256 and expect_policy_sha256 != pol["sha256"]:
        _ev(rec, pol, mode, "policy_version_mismatch", None, exceptions, now, "expected %s, in force %s" % (expect_policy_sha256, pol["sha256"]))
    want = server_identity if server_identity is not None else srv
    if want and server and _strip(want) != _strip(server):
        _ev(rec, pol, mode, "server_identity_mismatch", None, exceptions, now, "baseline approved for %s, checked %s" % (want, server))
    if rec["baseline"]["age_days"] is not None and rec["baseline"]["age_days"] > pol["max_baseline_age_days"]:
        _ev(rec, pol, mode, "baseline_stale", None, exceptions, now, "%d days old; the policy allows %s" % (rec["baseline"]["age_days"], pol["max_baseline_age_days"]))
    if cj["tools_sha256"] is None:
        _ev(rec, pol, mode, "response_malformed", None, exceptions, now, "the tool list has no jcs-v1 digest: " + cj["reason"])
        return _finish(rec, mode)
    names = [r["name"] for r in cj["tools"]]
    dups = []
    for i in range(1, len(names)):
        if names[i - 1] == names[i] and names[i] not in dups:
            dups.append(names[i])
    if dups:
        _ev(rec, pol, mode, "response_malformed", None, exceptions, now, "the tool list names a tool more than once: " + ", ".join(dups[:10]))
        return _finish(rec, mode)
    if not complete:
        _ev(rec, pol, mode, "tool_list_truncated", None, exceptions, now)
    was = {r["name"]: r for r in J["tools"] if isinstance(r, dict) and isinstance(r.get("name"), str)}
    cur = {r["name"]: r for r in cj["tools"]}
    raw = {t["name"]: t for t in tools}
    n0 = len(rec["events"])
    for n in sorted((n for n in cur if n not in was), key=_u16key):
        _ev(rec, pol, mode, "tool_added", n, exceptions, now)
    if complete:
        for n in sorted((n for n in was if n not in cur), key=_u16key):
            _ev(rec, pol, mode, "tool_removed", n, exceptions, now)
    parts = lock.get("parts") or None
    for n in sorted((n for n in cur if n in was), key=_u16key):
        a, b = was[n], cur[n]
        dc, dx = a.get("contract") != b["contract"], a.get("extras") != b["extras"]
        if not dc and not dx:
            continue
        P = parts.get(n) if isinstance(parts, dict) else None
        q = lock_tool_parts(raw[n]) if P else None
        moved = []
        if dc and P and q["description_sha256"] != P.get("description_sha256"):
            _ev(rec, pol, mode, "description_changed", n, exceptions, now)
            moved.append("d")
        if dc and P and q["schema_sha256"] != P.get("schema_sha256"):
            _ev(rec, pol, mode, "schema_changed", n, exceptions, now)
            moved.append("s")
        if dx and P and q["annotations_sha256"] != P.get("annotations_sha256"):
            _ev(rec, pol, mode, "annotations_changed", n, exceptions, now)
            moved.append("a")
        rest = []
        if dc and "d" not in moved and "s" not in moved:
            rest.append("the contract changed outside description and inputSchema (outputSchema)" if P else "the contract (description, inputSchema or outputSchema) changed")
        if dx and "a" not in moved:
            rest.append("a member outside the contract changed (title, icons, _meta or another; not annotations)" if P else "a member outside the contract changed (title, annotations, icons, _meta or another)")
        if rest:
            _ev(rec, pol, mode, "tool_changed", n, exceptions, now, "; ".join(rest))
    if complete and len(rec["events"]) == n0 and (cj["tools_sha256"] != J["tools_sha256"] or (cj["extras_sha256"] or "") != (J.get("extras_sha256") or "")):
        _ev(rec, pol, mode, "response_malformed", None, exceptions, now, "the tool set's jcs-v1 digest differs from the approved one, but no single tool's does")
    if not rec["events"]:
        rec["events"].append({"class": "unchanged", "tool": None, "why": "the offered tools match the approved baseline", "policy_effect": pol["effects"]["unchanged"],
                              "effect": _mode_effect(mode, "unchanged", pol["effects"]["unchanged"])})
    return _finish(rec, mode)


def continuity_failure(cls, mode="enforce", policy=None, exceptions=None, server=None, detail=None, now=None):
    """The record for a check that could not compare anything (server, evidence or service failed)."""
    if cls not in CONTINUITY_FAILURE_CLASSES:
        raise ValueError("unknown failure class: " + str(cls))
    pol = continuity_policy(policy)
    now = _now_ms() if now is None else now
    rec = _base({"now": now, "server": server}, pol, mode)
    rec["baseline"] = None
    rec["observed"] = None
    _ev(rec, pol, mode, cls, None, exceptions, now, detail)
    return _finish(rec, mode)


def acceptance_of(receipt, verification, scope, allow_warn=False, confirmed=None, lock=None):
    """The separate acceptance questions for one decision receipt (same contract as the JS acceptanceOf). scope: the
    {"fields": ...} from decision_scope(). policy_result: proceed | pause | deny. Never act on integrity_valid alone."""
    r = receipt if isinstance(receipt, dict) else {}
    v = verification or {}
    f = (scope or {}).get("fields") or {}
    why = []
    res = r.get("resolve") if isinstance(r.get("resolve"), dict) else None
    out = {
        "integrity_valid": v.get("integrity_valid") is True, "issuer_trusted": v.get("issuer_trusted"), "key_policy_valid": v.get("key_policy_valid"),
        "freshness_valid": all(f.get(k) is True for k in ("times_present", "not_expired", "not_future", "lifetime_ok")),
        "subject_matches": all(f.get(k) is True for k in ("kind_ok", "domain_matches", "action_matches", "decision_known", "resolve_bound")),
        "operation_matches": f.get("operation_matches"), "replay_safe": f.get("nonce_matches"), "baseline_matches": None,
        "assessment_complete": isinstance(v.get("unavailable"), list) and len(v["unavailable"]) == 0 and bool(res) and res.get("status") == "measured",
        "decision": r.get("decision") if isinstance(r.get("decision"), str) else None,
        "policy_source": (r.get("authority") or {}).get("policy_source") or None if isinstance(r.get("authority"), dict) else None,
        "evidence_level": (r.get("evidence_assurance") or {}).get("level") or None if isinstance(r.get("evidence_assurance"), dict) else None,
        "policy_result": "deny", "accepted": False, "why": why,
    }
    if isinstance(lock, dict) and lock.get("kind") == "crawlcheck-continuity-record":
        out["baseline_matches"] = all(e.get("class") == "unchanged" for e in lock.get("events") or [])
    elif isinstance(lock, dict) and lock.get("verdict"):
        out["baseline_matches"] = lock.get("verdict") == "unchanged"
    elif isinstance(r.get("assessed"), dict) and r["assessed"].get("expected_tools_sha256"):
        out["baseline_matches"] = r["assessed"].get("matches")
    if not out["integrity_valid"]:
        why.append("integrity: a check over the receipt's bytes failed or none ran")
    if out["issuer_trusted"] is not True:
        why.append("issuer: not checked (no published key ids)" if out["issuer_trusted"] is None else "issuer: the signing key is not published")
    if out["key_policy_valid"] is False:
        why.append("key policy: the key may not sign this object at its signing time")
    if not out["freshness_valid"]:
        why.append("freshness: expired, dated in the future, missing times, or longer-lived than the action allows")
    if not out["subject_matches"]:
        why.append("subject: the receipt is for another domain, action or answer, or its decision is unknown")
    if out["operation_matches"] is False:
        why.append("operation: the receipt is scoped to another operation")
    if out["replay_safe"] is False:
        why.append("replay: the receipt does not carry this request's nonce")
    d = out["decision"]
    if why:
        out["policy_result"] = "deny"
    elif out["baseline_matches"] is False:
        out["policy_result"] = "pause"
        why.append("baseline: the tools differ from the approved baseline; re-approve before proceeding")
    elif d == "allow":
        out["policy_result"] = "proceed"
    elif d == "warn":
        out["policy_result"] = "proceed" if allow_warn else "pause"
        if not allow_warn:
            why.append("decision is warn and warn is not allowed")
    elif d == "require_confirmation":
        out["policy_result"] = "proceed" if confirmed is True else "pause"
        if confirmed is not True:
            why.append("a person must confirm")
    else:
        out["policy_result"] = "deny"
        why.append("decision is %s" % d)
    out["accepted"] = out["policy_result"] == "proceed"
    return out


def continuity_class_of(proceed, receipt, acceptance, why):
    """Which failure class a refused guard is (for continuity_failure)."""
    w = "; ".join(why or [])
    if not isinstance(receipt, dict):
        import re
        return "check_timeout" if re.search(r"timed? ?out|abort", w, re.I) else "service_unavailable"
    A = acceptance
    if A:
        if not A.get("integrity_valid"):
            return "signature_invalid"
        if A.get("issuer_trusted") is not True:
            return "key_unknown"
        if A.get("key_policy_valid") is False:
            return "key_retired"
        if not A.get("freshness_valid"):
            return "evidence_expired"
        if not A.get("subject_matches") or A.get("operation_matches") is False or A.get("replay_safe") is False:
            return "server_identity_mismatch"
    return "decision_refused"


# -- signed baseline (1.14.0) ---------------------------------------------------------------------------------------------
# Whoever can edit the approved lockfile can approve their own tools. So the baseline's signature is checked once, when a
# gate is created (startup), before anything is compared against it. Same contract as the JS SDK's verifyLockBaseline:
#   verified         signed by CrawlCheck (/api/v1/mcp/lock, kind crawlcheck-mcp-lock, scheme crawlcheck-data-v1) with a
#                    CrawlCheck key: the pinned ids below, published_kids, or key_policy (key_policy_from(directory)).
#                    lock["parts"] added after signing is not covered, so it is dropped.
#   operator_signed  signed with sign_lock() by a key in operator_keys (the operator's Ed25519 public keys).
#   unsigned         no signature. Accepted unless require_signed_baseline (default: on when operator_keys are given).
#   invalid          a signature that does not verify, a changed lockfile, or a key that is neither: baseline_untrusted.
CRAWLCHECK_LOCK_KIDS = ("1hHmE3fo1rg5Ig70wuFtJ5wBc7G-sUTgUJkxyPWFRps", "hcIAczGf-8EFBnkunmZlvFWnD2nHHeHeC9cM4BTiBVo")
_DATA_PREFIX = "crawlcheck-data-v1\n"
_OP_PREFIX = "crawlcheck-lock-operator-v1\n"


def _thumb(x):
    return _b64u(hashlib.sha256(json.dumps({"crv": "Ed25519", "kty": "OKP", "x": str(x)}, separators=(",", ":")).encode()).digest())


def _ed_ok(x, msg, sig):
    try:
        return _ed25519.verify(_b64u_decode(x), msg.encode("utf-8"), _b64u_decode(sig))
    except Exception:  # noqa: BLE001 - a malformed key or signature is a signature that does not verify
        return False


def _without(o, keys):
    return {k: v for k, v in o.items() if k not in keys}


def _x_of(k):
    if isinstance(k, str):
        return k
    if isinstance(k, dict) and isinstance(k.get("x"), str):
        return k["x"]
    return None


def _seed_of(private_key):
    if isinstance(private_key, (bytes, bytearray)):
        return bytes(private_key)
    if isinstance(private_key, dict) and isinstance(private_key.get("d"), str):
        return _b64u_decode(private_key["d"])
    raise ValueError("private_key must be an Ed25519 private JWK with d (see new_operator_key) or the 32-byte seed")


def new_operator_key():
    """A new operator signing key: {"private_key": JWK (keep it away from the agent), "public_key": {kty, crv, x} (pass it
    in operator_keys), "kid"}."""
    seed = os.urandom(32)
    x = _b64u(_ed25519.public_key(seed))
    return {"private_key": {"kty": "OKP", "crv": "Ed25519", "x": x, "d": _b64u(seed)}, "public_key": {"kty": "OKP", "crv": "Ed25519", "x": x}, "kid": _thumb(x)}


def sign_lock(lock, private_key):
    """The operator's signature over the canonical lockfile (every field but operator_signature). Returns a copy with
    lock["operator_signature"]. private_key: an Ed25519 private JWK ({kty, crv, x, d}) or the 32-byte seed."""
    if not isinstance(lock, dict) or not isinstance(lock.get("tools"), list):
        raise ValueError("lock must be an mcp-lockfile (a dict with a tools list)")
    seed = _seed_of(private_key)
    x = _b64u(_ed25519.public_key(seed))
    if isinstance(private_key, dict) and private_key.get("x") not in (None, x):
        raise ValueError("private_key: x is not the public key of d")
    body = _without(lock, ("operator_signature",))
    message = _OP_PREFIX + _h(canon(body))
    out = dict(body)
    out["operator_signature"] = {"v": 1, "alg": "Ed25519", "kid": _thumb(x), "message": message, "sig": _b64u(_ed25519.sign(seed, message.encode("utf-8")))}
    return out


def _has_parts(L):
    return isinstance(L, dict) and isinstance(L.get("parts"), dict) and len(L["parts"]) > 0


def verify_lock_baseline(lock, operator_keys=None, key_policy=None, published_kids=None, trusted_kids=None):
    """Is this baseline the one CrawlCheck or the operator signed? Returns {"trust": verified | operator_signed | unsigned |
    invalid, "signer", "kid", "why", "parts_used", "lock"}; lock is the baseline to compare against (unsigned parts
    removed). Offline; no network."""
    def R(trust, signer, kid, why, L):
        return {"trust": trust, "signer": signer, "kid": kid, "why": why, "parts_used": _has_parts(L), "lock": L if L is not None else lock}
    if not isinstance(lock, dict) or not isinstance(lock.get("tools"), list):
        return R("invalid", None, None, "the baseline is not an mcp-lockfile (an object with a tools array)", None)
    op = lock.get("operator_signature")
    okeys = [x for x in (_x_of(k) for k in (operator_keys or [])) if x]
    if op is not None and (okeys or lock.get("signature") is None):
        if not okeys:
            return R("invalid", None, None, "the baseline carries an operator signature, but no operator key was given to check it", None)
        if not isinstance(op, dict) or op.get("alg") != "Ed25519" or not all(isinstance(op.get(k), str) for k in ("kid", "sig", "message")):
            return R("invalid", None, None, "the operator signature is malformed", None)
        x = None
        for k in okeys:
            if _thumb(k) == op["kid"]:
                x = k
        if not x:
            return R("invalid", None, op["kid"], "the operator signature is by key %s, which is not one of the operator keys given" % op["kid"], None)
        sha = _h(canon(_without(lock, ("operator_signature",))))
        if op["message"] != _OP_PREFIX + sha:
            return R("invalid", "operator", op["kid"], "the baseline was changed after the operator signed it (it hashes to %s)" % sha, None)
        if not _ed_ok(x, op["message"], op["sig"]):
            return R("invalid", "operator", op["kid"], "the operator signature does not verify", None)
        return R("operator_signed", "operator", op["kid"], "signed by operator key " + op["kid"], lock)
    s = lock.get("signature")
    if s is None:
        return R("unsigned", None, None, "the baseline carries no signature", lock)
    if lock.get("kind") != "crawlcheck-mcp-lock" or not isinstance(s, dict) or not str(s.get("message") or "").startswith(_DATA_PREFIX):
        return R("invalid", None, None, "the signature is not a CrawlCheck lockfile signature (kind crawlcheck-mcp-lock, scheme crawlcheck-data-v1)", None)
    kid = s.get("kid") if isinstance(s.get("kid"), str) else None
    L, stated = lock, lock.get("sha256")
    sha = _h(canon(_without(lock, ("sha256", "signature", "operator_signature"))))
    if sha != stated and "parts" in lock:
        sha2 = _h(canon(_without(lock, ("sha256", "signature", "operator_signature", "parts"))))
        if sha2 == stated:
            sha, L = sha2, _without(lock, ("parts",))
    if sha != stated:
        return R("invalid", "crawlcheck", kid, "the baseline was changed after it was signed (it hashes to %s, the signature covers %s)" % (sha, "null" if stated is None else str(stated)), None)
    if s.get("message") != _DATA_PREFIX + str(stated):
        return R("invalid", "crawlcheck", kid, "the signature does not cover this baseline's digest", None)
    jx = ((s.get("key") or {}).get("jwk") or {}).get("x") if isinstance(s.get("key"), dict) else None
    if not isinstance(jx, str):
        return R("invalid", "crawlcheck", kid, "the signature carries no key", None)
    if _thumb(jx) != kid:
        return R("invalid", "crawlcheck", kid, "the signing key's thumbprint is not its stated key id", None)
    if not _ed_ok(jx, s["message"], s.get("sig") or ""):
        return R("invalid", "crawlcheck", kid, "the signature does not verify", None)
    if key_policy is not None:
        kp = key_policy_check(lock, key_policy)
        if kp.get("ok") is not True:
            return R("invalid", "crawlcheck", kid, "the key policy rejects the signing key: " + str(kp.get("why")), None)
    else:
        ids = published_kids if published_kids is not None else trusted_kids if trusted_kids is not None else CRAWLCHECK_LOCK_KIDS
        if kid not in ids:
            return R("invalid", "crawlcheck", kid, "the baseline is signed by key %s, which is not a CrawlCheck key" % kid, None)
    return R("verified", "crawlcheck", kid, "signed by CrawlCheck key " + kid + ("; lock.parts was added after signing and is not used" if L is not lock else ""), L)


def baseline_refusal(b, require_signed):
    """Why a baseline is refused (None when it is accepted)."""
    if not b:
        return "the baseline was not checked"
    if b["trust"] == "invalid":
        return b["why"]
    if b["trust"] == "unsigned" and require_signed:
        return "the baseline is unsigned and a signed one is required"
    return None
