"""LlamaIndex adapter (1.10.0): CrawlCheck's agent tools as LlamaIndex FunctionTools.

    from crawlcheck import CrawlCheck
    from crawlcheck.llama_index import crawlcheck_tools
    tools = crawlcheck_tools(CrawlCheck(key="cc_..."))   # a free key: POST https://crawlcheck.io/api/v1/keys/free

Same three tools as crawlcheck.langchain; they fail closed. Needs llama-index-core; this package itself still has
no dependencies."""
import json
from typing import Literal, Optional
from .tools import agent_tools


def _schema_model(name, params):
    from pydantic import Field, create_model
    req = set(params.get("required") or [])
    fields = {}
    for k, p in (params.get("properties") or {}).items():
        typ = Literal[tuple(p["enum"])] if p.get("enum") else str
        if k in req:
            fields[k] = (typ, Field(..., description=p.get("description", "")))
        else:
            fields[k] = (Optional[typ], Field(None, description=p.get("description", "")))
    return create_model(name, **fields)


def crawlcheck_tools(cc=None, agent=None, allow_warn=False, confirm=None, max_chars=20000):
    """Return [FunctionTool] for crawlcheck_check_site, crawlcheck_verify_fact and crawlcheck_fetch."""
    try:
        from llama_index.core.tools import FunctionTool
    except ImportError as e:  # pragma: no cover
        raise ImportError("crawlcheck.llama_index needs llama-index-core: pip install llama-index-core") from e
    if cc is None:
        from .client import CrawlCheck
        cc = CrawlCheck()
    out = []
    for t in agent_tools(cc, agent=agent, allow_warn=allow_warn, confirm=confirm, max_chars=max_chars):
        def run(_execute=t["execute"], **kwargs):
            return json.dumps(_execute({k: v for k, v in kwargs.items() if v is not None}), default=str)
        out.append(FunctionTool.from_defaults(fn=run, name=t["name"], description=t["description"], fn_schema=_schema_model(t["name"] + "_args", t["parameters"])))
    return out
