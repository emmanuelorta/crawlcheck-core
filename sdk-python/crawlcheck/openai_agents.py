"""OpenAI Agents SDK adapter (1.11.0): CrawlCheck's agent tools as FunctionTools for openai-agents.

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
