"""Preflight as an MCP client extension (https://crawlcheck.io/spec/mcp-preflight). Reference middleware for the MCP
Python SDK: the check runs in the protocol path, before `initialize` reaches a server and before every `tools/call`.

    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    from crawlcheck import CrawlCheck
    from crawlcheck.mcp import McpPreflight, with_preflight

    cc = CrawlCheck()
    pf = McpPreflight(cc, confirm=ask_the_user)
    await pf.before_connect(url)          # McpPreflightRefused here, before any transport is opened, when the host's
                                          # "connect" decision is block, unsupported, unverifiable, or unconfirmed
    async with streamable_http_client(url) as (read, write):
        async with with_preflight(ClientSession(read, write), cc, server_url=url, preflight=pf) as s:
            await s.initialize()          # not decided twice; with lock= the listed tools are checked here
            await s.call_tool("search")   # refused before tools/call when the tool is outside the lock or unconfirmed

(A refusal raised inside the transport's context arrives wrapped in an ExceptionGroup; catch it with
`except* McpPreflightRefused`, or decide first as above.)

connect:    the server host is decided with action "connect" (template safe_mcp_tool). With lock=, the tools listed after
            initialize must match the approved lockfile or the session is refused. tools/call: the connect receipt must
            be unexpired (else the host is decided again); a tool outside the lockfile is refused; with confirm_destructive,
            a tool annotated destructive asks confirm(). Nothing here calls a tool or reads arguments; a refused request is
            never sent."""
import inspect
import time
from datetime import datetime
from urllib.parse import urlparse

from .client import normalize_domain
from .lock import check_lock


class McpPreflightRefused(Exception):
    def __init__(self, stage, why, receipt=None, lock=None):
        Exception.__init__(self, "MCP preflight refused %s: %s" % (stage, why))
        self.stage, self.why, self.receipt, self.lock = stage, why, receipt, lock


def _host(url):
    try:
        return normalize_domain(urlparse(url).hostname or "")
    except Exception:
        return ""


def _ts(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None


def _destructive(ann):
    if not isinstance(ann, dict):
        return False
    return ann.get("destructiveHint") is True or (ann.get("readOnlyHint") is False and ann.get("openWorldHint") is True)


async def _maybe_await(v):
    return await v if inspect.isawaitable(v) else v


class McpPreflight:
    """The hooks, for any client stack: before_connect(url), after_connect(tools), before_tool_call(name, annotations)."""

    def __init__(self, cc, template="safe_mcp_tool", policy=None, agent=None, confirm=None, allow_warn=False, lock=None,
                 confirm_destructive=False, max_age_s=None, local="allow", tool_receipts="write", scopes=None):
        self.cc, self.template, self.policy, self.agent = cc, template, policy, agent
        self.confirm, self.allow_warn, self.lock, self.confirm_destructive = confirm, allow_warn, lock, confirm_destructive
        self.max_age_s, self.local = max_age_s, local
        self.tool_receipts, self.scopes = tool_receipts, scopes   # 1.4.0: per-call receipts ("write" | "all" | "none")
        self.url = self.host = self.receipt = self.lock_check = self.approved = None
        self.decided_at = 0.0

    def _fresh(self):
        if not self.receipt:
            return False
        exp = _ts(self.receipt.get("expires_at"))
        if exp is not None and time.time() > exp:
            return False
        if self.max_age_s and time.time() - self.decided_at > self.max_age_s:
            return False
        return True

    async def _decide(self, host):
        rc = self.cc.preflight(host, "connect", agent=self.agent, template=self.template, policy=self.policy)
        self.receipt, self.decided_at = rc, time.time()
        return await self._judge(rc, host, "connect")

    async def _judge(self, rc, host, stage, operation=None):
        d = rc.get("decision")
        step = ((rc.get("steps") or [{}])[0] or {}).get("why", "")
        if self.cc.log.get("forks"):
            raise McpPreflightRefused(stage, "the transparency log showed two histories; no answer is trusted", rc)
        from .client import check_decision
        ok, why = check_decision(rc, host, "connect", operation=operation)
        if not ok:
            raise McpPreflightRefused(stage, "; ".join(why), rc)
        v = self.cc.verify(rc)
        if not v.get("accepted"):
            raise McpPreflightRefused(stage, "the decision receipt did not verify" if not v.get("verified") else "the receipt was signed with a key CrawlCheck does not publish", rc)
        if d == "allow" or (d == "warn" and self.allow_warn):
            return rc
        if d == "require_confirmation":
            if self.confirm and bool(await _maybe_await(self.confirm(rc))):
                return rc
            raise McpPreflightRefused(stage, "a human must confirm and none did", rc)
        if d == "warn":
            raise McpPreflightRefused(stage, "warn without allow_warn", rc)
        if d == "unsupported":
            raise McpPreflightRefused(stage, "nothing vouches for a connection to %s (%s)" % (host, step), rc)
        raise McpPreflightRefused(stage, "decision %s (%s)" % (d, step), rc)

    async def before_connect(self, url):
        if not url:
            if self.local == "refuse":
                raise McpPreflightRefused("connect", "a local (stdio) server cannot be resolved and local='refuse'")
            self.url = self.host = None
            return None
        host = _host(url)
        if not host:
            raise McpPreflightRefused("connect", "not a server URL: %s" % url)
        if self.host == host and self._fresh():   # already decided (before the transport was opened): not asked twice
            return self.receipt
        self.url, self.host = url, host
        return await self._decide(host)

    async def after_connect(self, tools):
        if not self.lock:
            self.approved = None
            return None
        lc = check_lock(self.lock, tools or [])
        self.lock_check = lc
        self.approved = set(t.get("name") for t in self.lock.get("tools", []))
        if lc["decision"] != "connect":
            raise McpPreflightRefused("connect", "the server's tools differ from the approved lockfile (added %d, removed %d, modified %d)"
                                      % (len(lc["added"]), len(lc["removed"]), len(lc["modified"])), self.receipt, lc)
        return lc

    async def before_tool_call(self, name, annotations=None, tool=None):
        if self.host and not self._fresh():
            await self._decide(self.host)
        if self.approved is not None and name not in self.approved:
            raise McpPreflightRefused("tools/call", "tool %s is not in the approved lockfile" % name, self.receipt, self.lock_check)
        if self.confirm_destructive and _destructive(annotations):
            ok = bool(await _maybe_await(self.confirm(dict(self.receipt or {}, tool=name, annotations=annotations)))) if self.confirm else False
            if not ok:
                raise McpPreflightRefused("tools/call", "tool %s is annotated destructive and no human confirmed" % name, self.receipt)
        ro = bool(annotations and annotations.get("readOnlyHint") is True) if isinstance(annotations, dict) else False
        if self.host and (self.tool_receipts == "all" or (self.tool_receipts == "write" and not ro)):   # a receipt for this exact tool call
            from .client import tool_operation
            op = tool_operation(tool, self.scopes) if tool else dict({"tool": str(name)}, **({"scopes": list(self.scopes)} if self.scopes else {}))
            try:
                rc = self.cc.preflight(self.host, "connect", agent=self.agent, template=self.template, policy=self.policy, operation=op)
            except McpPreflightRefused:
                raise
            except Exception as e:  # noqa: BLE001 - fail closed
                raise McpPreflightRefused("tools/call", "no receipt for tool %s: %s" % (name, e))
            await self._judge(rc, self.host, "tools/call", operation=op)
            return rc
        return self.receipt


def _tool_dict(t):
    if isinstance(t, dict):
        return t
    out = {}
    for k in ("name", "description", "inputSchema", "annotations"):
        v = getattr(t, k, None)
        if v is not None and not isinstance(v, (str, int, float, bool, list, dict, type(None))):
            v = v.model_dump() if hasattr(v, "model_dump") else dict(v)
        out[k] = v
    return out


class with_preflight:
    """Wrap an MCP ClientSession (or anything with initialize(), call_tool(name, arguments) and list_tools()): initialize
    and call_tool run the hooks first. Usable as an async context manager exactly like the session it wraps; the hooks
    are at .preflight."""

    def __init__(self, session, cc, server_url=None, preflight=None, **opts):
        self._s, self.server_url = session, server_url
        self.preflight = preflight or McpPreflight(cc, **opts)
        self._tools = {}

    async def __aenter__(self):
        if hasattr(self._s, "__aenter__"):
            await self._s.__aenter__()
        return self

    async def __aexit__(self, *a):
        if hasattr(self._s, "__aexit__"):
            return await self._s.__aexit__(*a)

    async def initialize(self, *a, **k):
        await self.preflight.before_connect(self.server_url)
        r = await self._s.initialize(*a, **k)
        if self.preflight.lock or self.preflight.confirm_destructive or self.preflight.tool_receipts != "none":
            tools = []
            try:
                lt = await self._s.list_tools()
                tools = [_tool_dict(t) for t in (getattr(lt, "tools", None) or (lt.get("tools") if isinstance(lt, dict) else []) or [])]
            except Exception:
                tools = []
            self._tools = {t.get("name"): t for t in tools}
            if self.preflight.lock or self.preflight.confirm_destructive:
                await self.preflight.after_connect(tools)   # a refusal propagates; the caller's context manager closes the session
        return r

    async def call_tool(self, name, arguments=None, *a, **k):
        t = self._tools.get(name) or {}
        await self.preflight.before_tool_call(name, t.get("annotations"), t or None)
        return await self._s.call_tool(name, arguments, *a, **k)

    def __getattr__(self, n):
        return getattr(self._s, n)
