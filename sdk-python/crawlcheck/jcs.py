"""jcs-v1 tool-list digests (https://crawlcheck.io/spec/mcp-lockfile#jcs-v1), 1.15.0. The same construction the lockfile
endpoint publishes as lock["jcs_v1"] and the JS SDK's jcs.js computes, byte for byte (the shared golden file
tests/fixtures/jcs-v1.json holds the endpoint's own answers).

  contract  {name, description, inputSchema, outputSchema}: description "" when absent or not a string, inputSchema {}
            when absent or not an object, outputSchema only when the server sent an object. RFC 8785, SHA-256 (hex).
  extras    every other member (title, annotations, icons, execution, _meta, vendor members), strings cleaned (NUL and
            unpaired surrogates -> U+FFFD), nesting past 12 levels -> "...". RFC 8785, SHA-256 (hex).
  tools_sha256   SRI sha256 over the RFC 8785 array of contracts sorted by name (UTF-16 code units; ties by bytes).
  extras_sha256  SRI sha256 over {"tools": {name: extras}} for the tools that carry extras ("" when none do), with
                 "oversized" (one tool's extras > 16,384 bytes) and "omitted" (past 262,144 bytes in all).
A tool with no name, or a number with no IEEE 754 double, makes the list not digestible: tools_sha256 None and a reason.
No list is cut: every tool given is digested and listed."""
import base64
import hashlib
import math
from decimal import Decimal

JCS_V1_SPEC = "https://crawlcheck.io/spec/mcp-lockfile#jcs-v1"
_NUM_ERR = "a number with no IEEE 754 double"


class _JcsError(ValueError):
    pass


def _norm16(s):
    """The string as JavaScript sees it: surrogate pairs joined, unpaired surrogates kept."""
    return s.encode("utf-16-be", "surrogatepass").decode("utf-16-be", "surrogatepass")


def _u16(s):
    return _norm16(s).encode("utf-16-be", "surrogatepass")


_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _str(s):
    """JSON.stringify for a string: the short escapes, other controls as \\u00xx, unpaired surrogates as \\udxxx."""
    out = ['"']
    for c in _norm16(s):
        o = ord(c)
        if c in _ESC:
            out.append(_ESC[c])
        elif o < 0x20 or 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)
        else:
            out.append(c)
    out.append('"')
    return "".join(out)


def _num(v):
    """A number as ECMAScript writes it (Number::toString)."""
    if isinstance(v, int):
        if abs(v) < 2 ** 53:
            return str(v)
        try:
            v = float(v)
        except OverflowError:
            raise _JcsError(_NUM_ERR)
    if not math.isfinite(v):
        raise _JcsError(_NUM_ERR)
    if v == 0:
        return "0"
    sign = "-" if v < 0 else ""
    t = Decimal(repr(abs(v))).normalize().as_tuple()
    s = "".join(str(d) for d in t.digits)
    k = len(s)
    n = t.exponent + k
    if k <= n <= 21:
        r = s + "0" * (n - k)
    elif 0 < n <= 21:
        r = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        r = "0." + "0" * (-n) + s
    else:
        e = n - 1
        r = (s if k == 1 else s[0] + "." + s[1:]) + "e" + ("+" if e > 0 else "-") + str(abs(e))
    return sign + r


def jcs_canon(v):
    """RFC 8785 canonical JSON (keys in UTF-16 code-unit order, ECMAScript number form, no whitespace)."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return _str(v)
    if isinstance(v, (int, float)):
        return _num(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(jcs_canon(x) for x in v) + "]"
    if isinstance(v, dict):
        ks = sorted(v.keys(), key=_u16)
        return "{" + ",".join(_str(k) + ":" + jcs_canon(v[k]) for k in ks) + "}"
    raise _JcsError("not a JSON value")


def _is_obj(x):
    return isinstance(x, dict)


def jcs_contract(t):
    """A tool's contract: what the model reads and the call takes or returns."""
    o = {"name": t.get("name"), "description": t["description"] if isinstance(t.get("description"), str) else "",
         "inputSchema": t["inputSchema"] if _is_obj(t.get("inputSchema")) else {}}
    if _is_obj(t.get("outputSchema")):
        o["outputSchema"] = t["outputSchema"]
    return o


def _clean_s(s):
    s = _norm16(str(s))
    return "".join("�" if (c == "\x00" or 0xD800 <= ord(c) <= 0xDFFF) else c for c in s)


def _clean(v, d):
    if d > 12:
        return "…"
    if isinstance(v, str):
        return _clean_s(v)
    if isinstance(v, (list, tuple)):
        return [_clean(x, d + 1) for x in v]
    if isinstance(v, dict):
        return {_clean_s(k): _clean(x, d + 1) for k, x in v.items()}
    return v


def jcs_extras(t):
    """A tool's extras: every member beyond name, description, inputSchema and outputSchema."""
    return _clean({k: x for k, x in (t or {}).items() if k not in ("name", "description", "inputSchema", "outputSchema")}, 0)


def _sha(b):
    return hashlib.sha256(b).digest()


def _sri(b):
    return "sha256-" + base64.b64encode(_sha(b)).decode()


def _named(t):
    return isinstance(t, dict) and isinstance(t.get("name"), str) and t.get("name") != ""


def _extras_set(tools):
    per = {}
    for t in tools or []:
        if not _named(t):
            continue
        x = jcs_extras(t)
        if x:
            per[_clean_s(t["name"])] = x
    names = sorted(per)
    if not names:
        return ""
    body, over, omit, used = {"tools": {}}, {}, [], 0
    for n in names:
        sz = len(jcs_canon(per[n]).encode("utf-8"))
        if sz > 16384:
            over[n] = sz
            continue
        if used + sz > 262144:
            omit.append(n)
            continue
        body["tools"][n] = per[n]
        used += sz
    if over:
        body["oversized"] = over
    if omit:
        body["omitted"] = omit
    return _sri(jcs_canon(body).encode("utf-8"))


def jcs_v1(tools, partial=False):
    """The jcs-v1 digests of a tools/list result (every page). partial=True when a page was not read (the list is then not
    digested). Returns {alg, spec, count, tools_sha256, extras_sha256, tools: [{name, contract, extras}]} or
    {alg, spec, tools_sha256: None, reason}."""
    if partial:
        return {"alg": "jcs-v1", "spec": JCS_V1_SPEC, "tools_sha256": None, "reason": "the tool list has more pages than were read; a partial list is not digested"}
    try:
        rows = []
        for t in tools or []:
            if not _named(t):
                return {"alg": "jcs-v1", "spec": JCS_V1_SPEC, "tools_sha256": None, "reason": "a tool has no name"}
            cj = jcs_canon(jcs_contract(t))
            cb = cj.encode("utf-8")
            rows.append({"name": t["name"], "cj": cj, "cb": cb, "contract": _sha(cb).hex(), "extras": _sha(jcs_canon(jcs_extras(t)).encode("utf-8")).hex()})
        rows.sort(key=lambda r: (_u16(r["name"]), r["cb"]))
        return {"alg": "jcs-v1", "spec": JCS_V1_SPEC, "count": len(rows),
                "tools_sha256": _sri(("[" + ",".join(r["cj"] for r in rows) + "]").encode("utf-8")),
                "extras_sha256": _extras_set(tools),
                "tools": [{"name": r["name"], "contract": r["contract"], "extras": r["extras"]} for r in rows]}
    except (_JcsError, RecursionError) as e:
        return {"alg": "jcs-v1", "spec": JCS_V1_SPEC, "tools_sha256": None, "reason": str(e)[:120]}
