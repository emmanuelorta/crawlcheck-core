"""LangChain adapter (1.10.0): CrawlCheck's agent tools as LangChain tools.

    from crawlcheck import CrawlCheck
    from crawlcheck.langchain import crawlcheck_tools
    tools = crawlcheck_tools(CrawlCheck(key="cc_..."))   # a free key: POST https://crawlcheck.io/api/v1/keys/free

Three tools: crawlcheck_check_site (signed allow/warn/block decision before reading, citing, connecting to,
paying or administering a site), crawlcheck_verify_fact (a phone, address, hours or service area checked against
what the business publishes) and crawlcheck_fetch (fetches a page only after its domain, and every redirect hop,
proceeds). They fail closed. Needs langchain-core; this package itself still has no dependencies."""
import json
from .tools import agent_tools


def crawlcheck_tools(cc=None, agent=None, allow_warn=False, confirm=None, max_chars=20000):
    """Return [StructuredTool] for crawlcheck_check_site, crawlcheck_verify_fact and crawlcheck_fetch."""
    try:
        from langchain_core.tools import StructuredTool
    except ImportError as e:  # pragma: no cover
        raise ImportError("crawlcheck.langchain needs langchain-core: pip install langchain-core") from e
    if cc is None:
        from .client import CrawlCheck
        cc = CrawlCheck()
    out = []
    for t in agent_tools(cc, agent=agent, allow_warn=allow_warn, confirm=confirm, max_chars=max_chars):
        def run(_execute=t["execute"], **kwargs):
            return json.dumps(_execute(kwargs), default=str)
        out.append(StructuredTool.from_function(func=run, name=t["name"], description=t["description"], args_schema=t["parameters"]))
    return out


# ── tool-interface continuity for langchain-mcp-adapters (1.13.0, https://crawlcheck.io/spec/continuity) ─────────────
#
#     from langchain_mcp_adapters.client import MultiServerMCPClient
#     from crawlcheck.langchain import load_mcp_tools_with_continuity
#
#     client = MultiServerMCPClient({"shop": {"transport": "streamable_http", "url": url}})
#     tools = await load_mcp_tools_with_continuity(client, lock, server_name="shop", mode="observe")
#     # or, with your own session:  await load_mcp_tools_with_continuity(session, lock, mode="enforce")
#
# The list is read once (every page), compared with the approved lockfile, and the LangChain tools are converted from
# exactly the definitions that were compared. observe: recorded and passed through. review/enforce: changed tools are
# left out until confirm() re-approves them; a pause or deny raises ContinuityRefused.


async def _all_tools(session):
    out, cur, seen = [], None, set()
    while True:
        r = await session.list_tools(cursor=cur)
        out.extend(r.tools or [])
        nxt = getattr(r, "nextCursor", None)
        if not nxt or nxt in seen or len(seen) >= 1000:
            return out, not nxt
        seen.add(nxt)
        cur = nxt


async def load_mcp_tools_with_continuity(source, lock, server_name=None, mode="observe", policy=None, exceptions=None, confirm=None,
                                         on_record=None, log_path=None, server_url=None, server_identity=None, expect_policy_sha256=None,
                                         gate=None, **load_kwargs):
    """load_mcp_tools with the continuity check. source: a MultiServerMCPClient (server_name required when it has more
    than one server) or an initialised mcp ClientSession. load_kwargs go to convert_mcp_tool_to_langchain_tool
    (callbacks, tool_interceptors, tool_name_prefix, handle_tool_errors). Pass gate= (a ContinuityGate) to keep the
    records across loads; otherwise read them from on_record / log_path."""
    import copy
    try:
        from langchain_mcp_adapters.tools import convert_mcp_tool_to_langchain_tool
    except ImportError as e:  # pragma: no cover
        raise ImportError("crawlcheck.langchain.load_mcp_tools_with_continuity needs langchain-mcp-adapters: pip install langchain-mcp-adapters") from e
    from .continuity_gate import ContinuityGate
    conns = getattr(source, "connections", None)
    connection = None
    if isinstance(conns, dict):
        if server_name is None:
            if len(conns) != 1:
                raise ValueError("server_name is required: the client has %d servers and the lockfile is for one" % len(conns))
            server_name = next(iter(conns))
        connection = conns[server_name]
        for k in ("callbacks", "tool_interceptors", "tool_name_prefix", "handle_tool_errors"):
            if k not in load_kwargs and getattr(source, k, None) is not None:
                load_kwargs[k] = getattr(source, k)
    url = server_url or (connection.get("url") if isinstance(connection, dict) else None)
    g = gate or ContinuityGate(lock, mode=mode, policy=policy, exceptions=exceptions, server=url, server_identity=server_identity,
                               expect_policy_sha256=expect_policy_sha256, confirm=confirm, on_record=on_record, log_path=log_path)
    try:
        if connection is not None:
            async with source.session(server_name) as s:
                tools, complete = await _all_tools(s)
        else:
            tools, complete = await _all_tools(source)
    except Exception as e:
        await g.afail("server_unavailable", e)
        raise
    await g.acheck([copy.deepcopy(t) for t in tools], complete=complete)
    session = None if connection is not None else source
    return [convert_mcp_tool_to_langchain_tool(session, t, connection=connection, server_name=server_name, **load_kwargs)
            for t in g.allowed(tools)]
