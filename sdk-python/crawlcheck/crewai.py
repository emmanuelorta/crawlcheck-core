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
