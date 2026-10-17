"""Agent tools (1.6.0): CrawlCheck as two tools any agent framework can register, so the check happens inside the
agent's own tool loop. crawlcheck_check_site returns the signed, verified decision for an action on a site;
crawlcheck_fetch fetches a page only after its domain (and every redirect hop) proceeds. Both fail closed, like guard().
tools_for() shapes them for OpenAI function calling, Anthropic tool use or an MCP server; each tool's parameters are
plain JSON Schema, so LangChain (StructuredTool.from_function with args_schema=...) and others take them as they are."""
import json
from urllib.parse import urlparse
from .client import normalize_domain

_ACTIONS = ["read", "cite", "connect", "transact", "administer"]


def _domain(v):
    s = str(v or "").strip()
    try:
        return normalize_domain(urlparse(s).hostname if "://" in s else s) or ""
    except Exception:
        return ""


def agent_tools(cc, agent=None, allow_warn=False, confirm=None, max_chars=20000):
    """Return [{"name", "description", "parameters", "execute"}] for crawlcheck_check_site and crawlcheck_fetch."""
    def check_site(args):
        args = args or {}
        domain, action = _domain(args.get("site")), args.get("action") if args.get("action") in _ACTIONS else "read"
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
                "receipt_sha256": rc.get("sha256"), "alternatives": rc.get("alternatives")}

    def fetch(args):
        args = args or {}
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
