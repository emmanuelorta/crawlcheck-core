"""mcp-tool-set-digest/1 (https://github.com/alexar76/mcp-tool-set-digest, draft of 2026-11-12), 1.16.0.

The shared definition of the two tool-list digests, written down by HISTOR's author from the construction CrawlCheck
publishes as jcs-v1. In the ordinary case the values equal lock["jcs_v1"]. They part only where jcs-v1 repairs or bounds
the input and this definition gives no digest:
  TSD-TOOL    an element is not a JSON object, or has no non-empty string name       -> neither digest
  TSD-TEXT    a string or member name holds a surrogate without its pair             -> the digest covering it
  TSD-NUMBER  a number with no IEEE 754 double (1e400)                               -> the digest covering it
  TSD-NAME    two tools share a name and both carry extras                           -> the extras digest
  TSD-PAGE    the list is not complete                                               -> neither digest
  TSD-DEPTH   an array or object nested deeper than TSD_MAX_DEPTH (512) levels,
              counting the tools array as level 1                                    -> the digest covering it
TSD-DEPTH is a reader limit, not a code of /1 yet: without it a deep list either exhausted the stack or gave a
digest in one SDK and not the other (1.16.4). Nothing is repaired, skipped or cut here, and the two digests are
computed apart. Parse the JSON text with json.loads as it is (it reads 1e400 as inf, which is refused here); the JS
SDK's tsd.js gives the same answers."""
import base64
import hashlib

from .jcs import _JcsError, _norm16, _num, _str, _u16

TSD_SPEC = "mcp-tool-set-digest/1"
TSD_MAX_DEPTH = 512   # arrays and objects; the tools array is level 1, a tool object level 2 (same bound in tsd.js)
_CONTRACT = ("name", "description", "inputSchema", "outputSchema")


class ToolSetDigestError(ValueError):
    def __init__(self, code, detail, tool=None):
        super().__init__(code + ": " + detail)
        self.code = code
        self.tool = tool


def _lone(s):
    return any(0xD800 <= ord(c) <= 0xDFFF for c in _norm16(s))


def _s(s):
    if _lone(s):
        raise ToolSetDigestError("TSD-TEXT", "a string holds a surrogate without its pair")
    return _str(s)


def tsd_canonical(v, level=1):
    """RFC 8785 text of a parsed JSON value. Raises ToolSetDigestError (TSD-TEXT, TSD-NUMBER, TSD-DEPTH) where it has
    none. level is the nesting level of v itself (1 = the tools array). Iterative, so the depth bound and not the
    interpreter's stack decides how deep a value may go; errors surface in document order."""
    out = []
    todo = [(0, v, level)]   # (0, value, level) to write a value, (1, text, 0) to write text, (2, name, 0) a member name
    while todo:
        kind, x, lv = todo.pop()
        if kind == 1:
            out.append(x)
            continue
        if kind == 2:
            out.append(_s(x) + ":")
            continue
        if x is None:
            out.append("null")
        elif x is True:
            out.append("true")
        elif x is False:
            out.append("false")
        elif isinstance(x, str):
            out.append(_s(x))
        elif isinstance(x, (int, float)):
            try:
                out.append(_num(x))
            except _JcsError:
                raise ToolSetDigestError("TSD-NUMBER", "a number with no IEEE 754 double")
        elif isinstance(x, (list, tuple, dict)):
            if lv > TSD_MAX_DEPTH:
                raise ToolSetDigestError("TSD-DEPTH", "nested deeper than %d levels" % TSD_MAX_DEPTH)
            if isinstance(x, dict):
                for k in x:
                    if not isinstance(k, str):
                        raise TypeError("a member name is not a string")
                keys = sorted(x.keys(), key=_u16)
                todo.append((1, "}", 0))
                for i in range(len(keys) - 1, -1, -1):
                    todo.append((0, x[keys[i]], lv + 1))
                    todo.append((2, keys[i], 0))
                    if i:
                        todo.append((1, ",", 0))
                todo.append((1, "{", 0))
            else:
                todo.append((1, "]", 0))
                for i in range(len(x) - 1, -1, -1):
                    todo.append((0, x[i], lv + 1))
                    if i:
                        todo.append((1, ",", 0))
                todo.append((1, "[", 0))
        else:
            raise TypeError(type(x).__name__ + " is not a JSON value")
    return "".join(out)


def _tool(t):
    if not isinstance(t, dict):
        raise ToolSetDigestError("TSD-TOOL", "a tool entry is not a JSON object")
    n = t.get("name")
    if not isinstance(n, str) or not n:
        raise ToolSetDigestError("TSD-TOOL", "a tool entry has no non-empty string name")
    return t


def tsd_contract_entry(tool):
    """A tool's contract entry (section 4)."""
    t = _tool(tool)
    o = {"name": t["name"], "description": t["description"] if isinstance(t.get("description"), str) else "",
         "inputSchema": t["inputSchema"] if isinstance(t.get("inputSchema"), dict) else {}}
    if isinstance(t.get("outputSchema"), dict):
        o["outputSchema"] = t["outputSchema"]
    return o


def _sri(text):
    return "sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def _named(e, t):
    if e.tool is None and isinstance(t, dict) and isinstance(t.get("name"), str) and t["name"] and not _lone(t["name"]):
        e.tool = t["name"]
    return e


def _contract(tools):
    rows = []
    for t in tools:
        try:
            e = tsd_contract_entry(t)
            text = tsd_canonical(e, 2)
        except ToolSetDigestError as err:
            raise _named(err, t)
        rows.append((_u16(e["name"]), text.encode("utf-8"), text))
    rows.sort(key=lambda r: (r[0], r[1]))
    text = "[" + ",".join(r[2] for r in rows) + "]"
    return {"digest": _sri(text), "canonical": text}


def _extras_of(t):
    return {k: v for k, v in t.items() if k not in _CONTRACT}


def _extras(tools):
    per = {}
    for item in tools:
        t = _tool(item)
        x = _extras_of(t)
        if not x:
            continue
        if t["name"] in per:
            raise ToolSetDigestError("TSD-NAME", "two tools share a name and both carry extras",
                                     None if _lone(t["name"]) else t["name"])
        per[t["name"]] = x
    if not per:
        return {"digest": None}
    parts = []
    for n in sorted(per.keys(), key=_u16):
        try:
            parts.append(_s(n) + ":" + tsd_canonical(per[n], 2))
        except ToolSetDigestError as err:
            raise _named(err, {"name": n})
    text = '{"tools":{' + ",".join(parts) + "}}"
    return {"digest": _sri(text), "canonical": text}


def tool_set_digest(tools, partial=False, per_tool=False):
    """The two digests of a complete tools/list result (every page joined). Each side is {"digest", "canonical"} or
    {"error": "TSD-...", "tool"?}; extras is {"digest": None} when no tool carries a member outside the contract."""
    out = {"spec": TSD_SPEC, "contract": None, "extras": None}
    if partial:
        out["contract"] = {"error": "TSD-PAGE"}
        out["extras"] = {"error": "TSD-PAGE"}
        return out
    if not isinstance(tools, (list, tuple)):
        out["contract"] = {"error": "TSD-TOOL"}
        out["extras"] = {"error": "TSD-TOOL"}
        return out
    # Section 10: a set-level fault (TSD-TOOL) is found before any value is written, so it wins over
    # TSD-TEXT / TSD-NUMBER in an earlier entry.
    try:
        for item in tools:
            _tool(item)
    except ToolSetDigestError as e:
        r = {"error": e.code, "tool": e.tool} if e.tool else {"error": e.code}
        out["contract"] = r
        out["extras"] = dict(r)
        return out
    for kind, fn in (("contract", _contract), ("extras", _extras)):
        try:
            out[kind] = fn(tools)
        except ToolSetDigestError as e:
            out[kind] = {"error": e.code, "tool": e.tool} if e.tool else {"error": e.code}
    if per_tool and out["contract"].get("digest"):
        rows = []
        for t in tools:
            row = {"name": t["name"],
                   "contract": hashlib.sha256(tsd_canonical(tsd_contract_entry(t), 2).encode("utf-8")).hexdigest()}
            try:
                row["extras"] = hashlib.sha256(tsd_canonical(_extras_of(t), 2).encode("utf-8")).hexdigest()
            except ToolSetDigestError as e:
                row["extras"] = None
                row["extras_error"] = e.code
            rows.append(row)
        out["tools"] = rows
    return out
