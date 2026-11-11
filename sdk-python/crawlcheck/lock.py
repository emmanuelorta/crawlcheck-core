"""MCP tool lockfile (https://crawlcheck.io/spec/mcp-lockfile): pin the tools you approved, refuse a server whose tools changed.
A tool's hash is sha256 of the canonical JSON of {name, description, inputSchema, annotations}; the list hash is sha256 of the
sorted tool hashes joined by newlines. No network, no key: the same arithmetic the server uses."""
import hashlib

from .verify import canon
from .jcs import jcs_v1

# The most tools a v1 lockfile hashes (CrawlCheck's lockfile endpoint hashes the same); a longer list is marked incomplete.
LOCK_V1_MAX_TOOLS = 300


def _h(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def lock_tool_hash(tool):
    t = tool or {}
    schema = t.get("inputSchema") if t.get("inputSchema") is not None else t.get("input_schema")
    return _h(canon({"name": t.get("name"), "description": t.get("description"), "inputSchema": schema, "annotations": t.get("annotations")}))


def lock_from_tools(tools):
    """1.15.0: also jcs_v1 (the jcs-v1 digests over every tool), and complete False with offered when the list is longer
    than a v1 lockfile hashes (LOCK_V1_MAX_TOOLS)."""
    allt = list(tools or [])
    rows = [{"name": str((t or {}).get("name") or "")[:120], "sha256": lock_tool_hash(t)} for t in allt[:LOCK_V1_MAX_TOOLS]]
    rows.sort(key=lambda r: (r["name"], r["sha256"]))
    out = {"tools": rows, "tools_sha256": _h("\n".join(sorted(r["sha256"] for r in rows))), "count": len(rows), "complete": len(allt) <= LOCK_V1_MAX_TOOLS, "jcs_v1": jcs_v1(allt)}
    if not out["complete"]:
        out["offered"] = len(allt)
    return out


def check_lock(lock, tools):
    """Compare a lockfile with the tools a server lists now. Anything added, removed or changed -> decision "block"."""
    now = lock_from_tools(tools)
    was = {r["name"]: r["sha256"] for r in (lock or {}).get("tools", [])}
    cur = {r["name"]: r["sha256"] for r in now["tools"]}
    added = [n for n in cur if n not in was]
    removed = [n for n in was if n not in cur]
    modified = [n for n in cur if n in was and was[n] != cur[n]]
    same = (lock or {}).get("tools_sha256") == now["tools_sha256"] and not (added or removed or modified)
    a, b = (lock or {}).get("jcs_v1"), now["jcs_v1"]
    jc = {"alg": "jcs-v1", "current_tools_sha256": b.get("tools_sha256"), "current_extras_sha256": None if b.get("tools_sha256") is None else b.get("extras_sha256")}
    if isinstance(a, dict) and isinstance(a.get("tools_sha256"), str) and a["tools_sha256"]:
        jc["approved_tools_sha256"] = a["tools_sha256"]
        jc["contract_unchanged"] = bool(b.get("tools_sha256")) and a["tools_sha256"] == b.get("tools_sha256")
        jc["extras_unchanged"] = (a.get("extras_sha256") or None) == (b.get("extras_sha256") or None)
    if not now["complete"]:   # never connect on part of a list
        return {"verdict": "incomplete", "decision": "block", "approved_tools_sha256": (lock or {}).get("tools_sha256", ""), "current_tools_sha256": now["tools_sha256"],
                "added": added, "removed": [], "modified": modified, "jcs_v1": jc, "offered": now["offered"]}
    return {"verdict": "unchanged" if same else "changed", "decision": "connect" if same else "block",
            "approved_tools_sha256": (lock or {}).get("tools_sha256", ""), "current_tools_sha256": now["tools_sha256"],
            "added": added, "removed": removed, "modified": modified, "jcs_v1": jc}
