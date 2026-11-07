"""OpenAI Agents SDK adapter (1.11.0): CrawlCheck's agent tools as FunctionTools for openai-agents. 1.13.0: with_continuity()
wraps an agents.mcp server so every tool-list fetch is checked against an approved lockfile (see the foot of this file).

    from agents import Agent, Runner
    from crawlcheck import CrawlCheck
    from crawlcheck.openai_agents import crawlcheck_tools
    agent = Agent(name="researcher", instructions="...", tools=crawlcheck_tools(CrawlCheck(key="cc_...")))

Same three tools as crawlcheck.langchain; they fail closed (a malformed argument string is refused, never guessed).
The checks run in a worker thread so the agent's event loop is not blocked. Needs openai-agents; this package itself
still has no dependencies."""
import asyncio, json
from .tools import agent_tools


def crawlcheck_tools(cc=None, agent=None, allow_warn=False, confirm=None, max_chars=20000):
    """Return [agents.FunctionTool] for crawlcheck_check_site, crawlcheck_verify_fact and crawlcheck_fetch."""
    try:
        from agents import FunctionTool
    except ImportError as e:  # pragma: no cover
        raise ImportError("crawlcheck.openai_agents needs openai-agents: pip install openai-agents") from e
    if cc is None:
        from .client import CrawlCheck
        cc = CrawlCheck()
    out = []
    for t in agent_tools(cc, agent=agent, allow_warn=allow_warn, confirm=confirm, max_chars=max_chars):
        async def invoke(ctx, args, _execute=t["execute"]):
            try:
                a = json.loads(args) if args else {}
            except ValueError:
                return json.dumps({"proceed": False, "why": ["the tool arguments were not valid JSON"]})
            if not isinstance(a, dict):
                return json.dumps({"proceed": False, "why": ["the tool arguments must be a JSON object"]})
            r = await asyncio.to_thread(_execute, a)
            return json.dumps(r, default=str)
        out.append(FunctionTool(name=t["name"], description=t["description"], params_json_schema=t["parameters"], on_invoke_tool=invoke, strict_json_schema=False))
    return out


# ── tool-interface continuity for agents.mcp servers (1.13.0, https://crawlcheck.io/spec/continuity) ──────────────────
#
#     from agents import Agent
#     from agents.mcp import MCPServerStreamableHttp
#     from crawlcheck.openai_agents import with_continuity
#
#     async with MCPServerStreamableHttp(params={"url": url}) as server:
#         guarded = with_continuity(server, lock, mode="observe")      # or "review" / "enforce"
#         agent = Agent(name="a", instructions="...", mcp_servers=[guarded])
#
# Every list_tools() the Agents SDK makes is compared with the approved lockfile. observe: recorded (guarded.gate.records,
# on_record=, log_path=, the "crawlcheck.continuity" logger) and passed through. review/enforce: changed tools are withheld
# (and a call to one is refused) until confirm() re-approves them; a pause or deny raises ContinuityRefused.

_CLS = None


def _server_class():
    global _CLS
    if _CLS is not None:
        return _CLS
    try:
        from agents.mcp import MCPServer
    except ImportError as e:  # pragma: no cover
        raise ImportError("crawlcheck.openai_agents.with_continuity needs openai-agents: pip install openai-agents") from e

    class ContinuityMCPServer(MCPServer):
        """An agents.mcp.MCPServer that runs the continuity check on every tool-list fetch. Everything else is the
        wrapped server's (approval policy, tool filter, guardrails, structured content, resources, prompts)."""

        def __init__(self, inner, gate):   # MCPServer.__init__ is not called: its settings are read from the inner server
            self.__dict__["_inner"], self.__dict__["gate"] = inner, gate

        def __getattr__(self, k):
            return getattr(self.__dict__["_inner"], k)

        @property
        def name(self):
            return self._inner.name

        @property
        def _error_name(self):
            return getattr(self._inner, "_error_name", self._inner.name)

        @property
        def cached_tools(self):
            c = self._inner.cached_tools
            return None if c is None else self.gate.allowed(c)

        async def connect(self):
            return await self._inner.connect()

        async def cleanup(self):
            return await self._inner.cleanup()

        async def __aenter__(self):
            await self._inner.__aenter__()
            return self

        async def __aexit__(self, *exc):
            return await self._inner.__aexit__(*exc)

        async def list_tools(self, run_context=None, agent=None):
            try:
                tools = await self._inner.list_tools(run_context, agent)
            except Exception as e:
                await self.gate.afail("server_unavailable", e)
                raise
            await self.gate.acheck(tools, complete=True)   # the Agents SDK reads every page or raises
            return self.gate.allowed(tools)

        async def call_tool(self, tool_name, arguments, meta=None):
            self.gate.call_ok(tool_name)
            if meta is None:
                return await self._inner.call_tool(tool_name, arguments)
            return await self._inner.call_tool(tool_name, arguments, meta)

        async def list_prompts(self):
            return await self._inner.list_prompts()

        async def get_prompt(self, name, arguments=None):
            return await self._inner.get_prompt(name, arguments)

        async def list_resources(self, *a, **k):
            return await self._inner.list_resources(*a, **k)

        async def list_resource_templates(self, *a, **k):
            return await self._inner.list_resource_templates(*a, **k)

        async def read_resource(self, *a, **k):
            return await self._inner.read_resource(*a, **k)

        def _get_needs_approval_for_tool(self, *a, **k):
            return self._inner._get_needs_approval_for_tool(*a, **k)

        def _get_failure_error_function(self, *a, **k):
            return self._inner._get_failure_error_function(*a, **k)

    _CLS = ContinuityMCPServer
    return _CLS


def _server_url(server):
    p = getattr(server, "params", None)
    if isinstance(p, dict) and p.get("url"):
        return str(p["url"])
    return None


def with_continuity(server, lock, mode="observe", policy=None, exceptions=None, confirm=None, on_record=None, log_path=None,
                    server_url=None, server_identity=None, expect_policy_sha256=None, gate=None, baseline=None):
    """Wrap an agents.mcp server (MCPServerStdio, MCPServerSse, MCPServerStreamableHttp or your own) so every tool-list
    fetch runs continuity_check against lock. server_url defaults to the server's params["url"] (HTTP transports); the
    lock's server.url must match it or the check reports server_identity_mismatch (deny outside observe)."""
    from .continuity_gate import ContinuityGate
    g = gate or ContinuityGate(lock, mode=mode, policy=policy, exceptions=exceptions, server=server_url or _server_url(server),
                               server_identity=server_identity, expect_policy_sha256=expect_policy_sha256, confirm=confirm,
                               on_record=on_record, log_path=log_path, **(baseline or {}))
    return _server_class()(server, g)
