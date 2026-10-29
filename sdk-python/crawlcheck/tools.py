"""Agent tools (1.6.0; crawlcheck_verify_fact and decision facts 1.7.0): CrawlCheck as tools any agent framework can register, so the check happens inside the
agent's own tool loop. crawlcheck_check_site returns the signed, verified decision for an action on a site (with the business facts the site
publishes); crawlcheck_verify_fact checks one phone, address, hours or service-area value against the business;
crawlcheck_fetch fetches a page only after its domain (and every redirect hop) proceeds. Both fail closed, like guard().
tools_for() shapes them for OpenAI function calling, Anthropic tool use or an MCP server; each tool's parameters are
plain JSON Schema, so LangChain (StructuredTool.from_function with args_schema=...) and others take them as they are."""
import json
from urllib.parse import urlparse
from .client import normalize_domain
from .verify import verify_document

_ACTIONS = ["read", "cite", "connect", "transact", "administer"]
_FACT_FIELDS = ["phone", "address", "hours", "service_area"]


def _domain(v):
    s = str(v or "").strip()
    try:
        return normalize_domain(urlparse(s).hostname if "://" in s else s) or ""
    except Exception:
        return ""


def agent_tools(cc, agent=None, allow_warn=False, confirm=None, max_chars=20000):
    """Return [{"name", "description", "parameters", "execute"}] for crawlcheck_check_site, crawlcheck_verify_fact and crawlcheck_fetch."""
    def check_site(args):
        args = args or {}
        raw = args.get("action")
        # 1.10.1: an action that is given but not one of the five fails closed (it used to fall back to "read").
        if raw not in (None, "") and raw not in _ACTIONS:
            return {"proceed": False, "why": ["unknown action: %s (use read, cite, connect, transact or administer)" % raw]}
        domain, action = _domain(args.get("site")), raw or "read"
        if not domain:
            return {"proceed": False, "why": ["not a public domain name: %s" % args.get("site")]}
        try:
            proceed, receipt = cc.guard(domain, action, agent=agent, allow_warn=allow_warn, confirm=confirm)
        except Exception as e:
            return {"domain": domain, "action": action, "proceed": False, "why": ["CrawlCheck did not give a decision: %s" % e]}
        rc = receipt or {}
        last = getattr(cc, "last_guard", None) or {}
        return {"domain": domain, "action": action, "proceed": bool(proceed), "decision": rc.get("decision"), "why": last.get("why", []),
                "reasons": [s.get("why") for s in rc.get("steps", []) if isinstance(s, dict) and s.get("why")], "reason_codes": rc.get("reason_codes", []),
                "receipt_sha256": rc.get("sha256"), "verified": bool(last.get("verified")), "alternatives": rc.get("alternatives"), "facts": rc.get("facts")}

    def verify_fact(args):
        args = args or {}
        domain, field, value = _domain(args.get("site")), str(args.get("field") or ""), str(args.get("value") or "").strip()[:200]
        if not domain:
            return {"ok": False, "why": ["not a public domain name: %s" % args.get("site")]}
        if field not in _FACT_FIELDS or not value:
            return {"ok": False, "why": ["give field (phone, address, hours or service_area) and value"]}
        try:
            doc = cc.field_check(domain, field, value)
        except Exception as e:
            return {"ok": False, "domain": domain, "field": field, "value": value, "why": [str(e)]}
        try:
            v = verify_document(doc)
            ok = bool(v.get("verified"))
        except Exception:
            ok = False
        out = dict(doc)
        out.update({"ok": True, "verified": ok})
        return out

    def fetch(args):
        args = args or {}
        if args.get("action") not in (None, "", "read", "cite"):
            return {"proceed": False, "url": str(args.get("url") or ""), "why": ["unknown action: %s (use read or cite)" % args.get("action")]}
        r = cc.guarded_fetch(str(args.get("url") or ""), action="cite" if args.get("action") == "cite" else "read", allow_warn=allow_warn, confirm=confirm)
        hops = [{"url": h.get("url"), "domain": h.get("domain"), "decision": h.get("decision"), "proceed": h.get("proceed"), "status": h.get("status")} for h in r.get("hops", [])]
        if not r.get("proceed") or r.get("body") is None:
            return {"proceed": False, "url": r.get("url"), "why": r.get("why", []), "hops": hops}
        body = r["body"]
        text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body)
        ct = next((v for k, v in (r.get("headers") or {}).items() if str(k).lower() == "content-type"), None)
        return {"proceed": True, "url": r.get("url"), "status": r.get("status"), "content_type": ct, "text": text[:max_chars], "truncated": len(text) > max_chars, "chars": len(text), "hops": hops}

    return [
        {"name": "crawlcheck_check_site",
         "description": "Before acting on a website, get CrawlCheck's signed decision for that action: allow, warn, require_confirmation, block or unsupported, with the reasons. Use it before reading, citing, connecting to, buying from or administering a site you have not checked. proceed is false whenever the site should not be used for that action.",
         "parameters": {"type": "object", "additionalProperties": False, "required": ["site"], "properties": {
             "site": {"type": "string", "description": "The site's domain or any URL on it, e.g. example.com or https://example.com/page"},
             "action": {"type": "string", "enum": _ACTIONS, "description": "What you are about to do: read (default), cite, connect (an API or MCP server), transact (pay, book, submit personal data) or administer"}}},
         "execute": check_site},
        {"name": "crawlcheck_verify_fact",
         "description": "Check one fact you hold about a business against what the business itself publishes: its phone number, street address, opening hours or a place it serves. Returns CrawlCheck's signed verdict (published now, published before, or not this business, and who does publish it). Use it before giving someone a phone number, address or hours, especially ones that came from an AI answer or a directory.",
         "parameters": {"type": "object", "additionalProperties": False, "required": ["site", "field", "value"], "properties": {
             "site": {"type": "string", "description": "The business's website domain or any URL on it"},
             "field": {"type": "string", "enum": _FACT_FIELDS, "description": "Which fact the value is"},
             "value": {"type": "string", "description": "The value you hold, e.g. (720) 555-0100, 1200 Main St, Mon 8am, or a city name"}}},
         "execute": verify_fact},
        {"name": "crawlcheck_fetch",
         "description": "Fetch a web page only if CrawlCheck allows reading that site; every redirect to a new domain is checked again before it is followed. Returns the page text (truncated) or, when refused, why. Prefer this over a plain fetch for sites you have not checked.",
         "parameters": {"type": "object", "additionalProperties": False, "required": ["url"], "properties": {
             "url": {"type": "string", "description": "The http(s) URL to fetch"},
             "action": {"type": "string", "enum": ["read", "cite"], "description": "read (default) or cite, if the text will be quoted back to someone"}}},
         "execute": fetch},
    ]


def tools_for(fmt, tools):
    """Shape agent_tools() for "openai", "anthropic" or "mcp". Returns (tool_definitions, call) where call(name, args)
    runs a tool by name; args may be a dict or the JSON string a model returned."""
    by = {t["name"]: t for t in tools}

    def call(name, args):
        t = by.get(name)
        if not t:
            return {"proceed": False, "why": ["no CrawlCheck tool named %s" % name]}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except ValueError:
                args = {}
        return t["execute"](args or {})

    if fmt == "openai":
        defs = [{"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["parameters"]}} for t in tools]
    elif fmt == "anthropic":
        defs = [{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]} for t in tools]
    elif fmt == "mcp":
        defs = [{"name": t["name"], "description": t["description"], "inputSchema": t["parameters"], "annotations": {"readOnlyHint": True, "openWorldHint": True}} for t in tools]
    else:
        raise ValueError("format must be openai, anthropic or mcp")
    return defs, call
