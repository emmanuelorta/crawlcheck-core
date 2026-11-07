"""CrewAI adapter (1.11.0): CrawlCheck's agent tools as CrewAI tools.

    from crawlcheck import CrawlCheck
    from crawlcheck.crewai import crawlcheck_tools
    tools = crawlcheck_tools(CrawlCheck(key="cc_..."))   # a free key: POST https://crawlcheck.io/api/v1/keys/free
    researcher = Agent(role="...", goal="...", backstory="...", tools=tools)

Same three tools as crawlcheck.langchain (crawlcheck_check_site, crawlcheck_verify_fact, crawlcheck_fetch); they fail
closed. Needs crewai; this package itself still has no dependencies."""
import json
from .tools import agent_tools
from .llama_index import _schema_model


def crawlcheck_tools(cc=None, agent=None, allow_warn=False, confirm=None, max_chars=20000):
    """Return [crewai BaseTool] for crawlcheck_check_site, crawlcheck_verify_fact and crawlcheck_fetch."""
    try:
        from crewai.tools import BaseTool
    except ImportError as e:  # pragma: no cover
        raise ImportError("crawlcheck.crewai needs crewai: pip install crewai") from e
    if cc is None:
        from .client import CrawlCheck
        cc = CrawlCheck()
    out = []
    for t in agent_tools(cc, agent=agent, allow_warn=allow_warn, confirm=confirm, max_chars=max_chars):
        def _run(self, _execute=t["execute"], **kwargs):
            return json.dumps(_execute({k: v for k, v in kwargs.items() if v is not None}), default=str)
        from pydantic import BaseModel
        cls = type("CrawlCheck_" + t["name"], (BaseTool,), {
            "__module__": __name__, "__qualname__": "CrawlCheck_" + t["name"],
            "__annotations__": {"name": str, "description": str, "args_schema": type[BaseModel]},
            "name": t["name"], "description": t["description"],
            "args_schema": _schema_model(t["name"] + "_args", t["parameters"]),
            "_run": _run})
        out.append(cls())
    return out


# ── tool-interface continuity for crewai_tools.MCPServerAdapter (1.13.0, https://crawlcheck.io/spec/continuity) ──────
#
#     from crewai import Agent
#     from crewai_tools import MCPServerAdapter
#     from crawlcheck.crewai import with_continuity
#
#     with with_continuity(MCPServerAdapter(server_params), lock, mode="observe") as tools:   # or review / enforce
#         agent = Agent(role="...", goal="...", backstory="...", tools=tools)
#
# The tool list is read once per .tools access, compared with the approved lockfile, and the CrewAI tools are built from
# exactly the definitions that were compared. observe: recorded and passed through. review/enforce: changed tools are
# left out until confirm() re-approves them; a pause or deny raises ContinuityRefused (and the server is stopped).


class _Guarded:
    def __init__(self, adapter, gate):
        self.adapter, self.gate = adapter, gate

    def _raw(self):
        """(tools, complete) read over the adapter's own session, every page. None when the internals are not there."""
        import asyncio
        a = getattr(self.adapter, "_adapter", None)
        sessions, loop = getattr(a, "sessions", None), getattr(a, "loop", None)
        if not sessions or loop is None:
            return None

        async def pages(s):
            out, cur, seen = [], None, set()
            while True:
                r = await (s.list_tools(cursor=cur) if cur else s.list_tools())
                out.extend(r.tools or [])
                nxt = getattr(r, "nextCursor", None)
                if not nxt or nxt in seen or len(seen) >= 100:
                    return out, not nxt
                seen.add(nxt)
                cur = nxt
        res = []
        for s in sessions:
            res.append((s, asyncio.run_coroutine_threadsafe(pages(s), loop).result(timeout=getattr(a, "connect_timeout", 30) or 30)))
        return res

    @property
    def tools(self):
        import copy
        from functools import partial
        try:
            from crewai_tools.adapters.tool_collection import ToolCollection
            from crewai.utilities.string_utils import sanitize_tool_name
        except ImportError as e:  # pragma: no cover
            raise ImportError("crawlcheck.crewai.with_continuity needs crewai-tools with MCP: pip install 'crewai-tools[mcp]'") from e
        try:
            raw = self._raw()
        except Exception as e:
            self.gate.fail("server_unavailable", e)
            raise
        a = self.adapter._adapter
        if raw is None:   # unknown adapter internals: check what the adapter built from
            built = list(self.adapter.tools)
            mcp_tools = [t for ts in (getattr(a, "mcp_tools", None) or []) for t in ts]
            self.gate.check(mcp_tools, complete=True)
            keep = {sanitize_tool_name(t.name) for t in self.gate.allowed(mcp_tools)}
            return ToolCollection([t for t in built if t.name in keep])
        allt = [t for _, (ts, _c) in raw for t in ts]
        complete = all(c for _, (_ts, c) in raw)
        self.gate.check([copy.deepcopy(t) for t in allt], complete=complete)
        allowed = {id(t) for t in self.gate.allowed(allt)}

        def call(session, name, arguments=None):
            import asyncio
            return asyncio.run_coroutine_threadsafe(session.call_tool(name, arguments), a.loop).result()
        built = [a.adapter.adapt(partial(call, s, t.name), copy.deepcopy(t)) for s, (ts, _c) in raw for t in ts if id(t) in allowed]
        col = ToolCollection(built)
        names = getattr(self.adapter, "_tool_names", None)
        return col.filter_by_names(names) if names else col

    def start(self):
        self.adapter.start()
        return self

    def stop(self):
        return self.adapter.stop()

    def __enter__(self):
        self.adapter.__enter__()
        try:
            return self.tools
        except BaseException:
            self.adapter.__exit__(None, None, None)
            raise

    def __exit__(self, *exc):
        return self.adapter.__exit__(*exc)


def with_continuity(adapter, lock, mode="observe", policy=None, exceptions=None, confirm=None, on_record=None, log_path=None,
                    server_url=None, server_identity=None, expect_policy_sha256=None, gate=None):
    """Wrap a crewai_tools.MCPServerAdapter (not yet started) so its tools are checked against lock. The returned object
    has .tools, .start(), .stop(), works as a context manager, and keeps the records at .gate.records. server_url
    defaults to the adapter's serverparams["url"] (HTTP transports)."""
    from .continuity_gate import ContinuityGate
    sp = getattr(adapter, "_serverparams", None)
    url = server_url or (sp.get("url") if isinstance(sp, dict) else None)
    g = gate or ContinuityGate(lock, mode=mode, policy=policy, exceptions=exceptions, server=url, server_identity=server_identity,
                               expect_policy_sha256=expect_policy_sha256, confirm=confirm, on_record=on_record, log_path=log_path)
    return _Guarded(adapter, g)
