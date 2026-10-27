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
