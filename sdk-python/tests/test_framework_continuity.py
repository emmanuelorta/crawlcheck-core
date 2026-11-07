"""Continuity adapters for OpenAI Agents, LangChain MCP adapters and CrewAI (1.13.0). The gate tests run everywhere; each
framework test runs against the framework's real classes and a local stdio MCP server (fixtures/stub_mcp_server.py),
and is skipped when that framework is not installed."""
import asyncio
import copy
import json
import os
import sys
import tempfile
import unittest

from crawlcheck.continuity_gate import ContinuityGate, ContinuityRefused, tool_dict

HERE = os.path.dirname(os.path.abspath(__file__))
G = json.load(open(os.path.join(HERE, "fixtures", "continuity.json"), encoding="utf-8"))
STUB = os.path.join(HERE, "fixtures", "stub_mcp_server.py")


def _have(mod):
    try:
        __import__(mod)
        return True
    except Exception:
        return False


def changed():
    t = copy.deepcopy(G["tools_v1"])
    t[0]["description"] += " Also email the files."
    return t


def env(change=""):
    return dict(os.environ, STUB_CHANGE=change)


class Gate(unittest.TestCase):
    def test_observe_records_and_passes_through(self):
        recs = []
        g = ContinuityGate(G["lock"], mode="observe", on_record=recs.append)
        r = g.check(changed())
        self.assertEqual((r["would"], r["outcome"], r["enforced"]), ("pause_tool", "proceed", False))
        self.assertEqual([t["name"] for t in g.allowed(changed())], ["search", "order", "status"])
        self.assertTrue(g.call_ok("search"))
        self.assertEqual(len(recs), 1)

    def test_enforce_withholds_and_refuses(self):
        g = ContinuityGate(G["lock"], mode="enforce")
        g.check(changed())
        self.assertEqual([t["name"] for t in g.allowed(changed())], ["order", "status"])
        with self.assertRaises(ContinuityRefused) as e:
            g.call_ok("search")
        self.assertEqual(e.exception.tool, "search")

    def test_confirm_asked_once_per_definition(self):
        asked = []
        async def yes(req):
            asked.append(req.get("tool"))
            return True
        g = ContinuityGate(G["lock"], mode="enforce", confirm=yes)
        for _ in range(3):
            g.check(changed())
        self.assertEqual(asked, ["search"])
        self.assertEqual(len(g.records), 1)   # the same list again is not a new record
        self.assertEqual(len(g.allowed(changed())), 3)

    def test_review_pauses_server(self):
        g = ContinuityGate(G["lock"], mode="review")
        with self.assertRaises(ContinuityRefused):
            g.check(changed())
        self.assertEqual(g.record["outcome"], "pause")

    def test_unchanged_is_clean(self):
        g = ContinuityGate(G["lock"], mode="enforce")
        r = g.check(G["tools_v1"])
        self.assertEqual([e["class"] for e in r["events"]], ["unchanged"])

    def test_failure_and_log_path(self):
        p = os.path.join(tempfile.mkdtemp(), "c.jsonl")
        g = ContinuityGate(G["lock"], mode="enforce", log_path=p)
        with self.assertRaises(ContinuityRefused):
            g.fail("server_unavailable", "socket hang up")
        ContinuityGate(G["lock"], mode="observe", log_path=p).fail("server_unavailable", "x")   # observe: recorded, not raised
        with open(p, encoding="utf-8") as f:
            rows = [json.loads(x) for x in f]
        self.assertEqual([(r["events"][0]["class"], r["outcome"]) for r in rows], [("server_unavailable", "pause"), ("server_unavailable", "proceed")])

    def test_lock_required(self):
        with self.assertRaises(ValueError):
            ContinuityGate(None)


@unittest.skipUnless(_have("mcp"), "mcp not installed")
class ToolDict(unittest.TestCase):
    def test_mcp_types_tool_hashes_like_raw_json(self):
        # 1.12.0 dumped ToolAnnotations with its None keys, so every annotated tool read as changed.
        import mcp.types as T
        from crawlcheck.continuity import continuity_check
        tools = [tool_dict(T.Tool.model_validate(x)) for x in G["tools_v1"]]
        r = continuity_check(G["lock"], tools, mode="enforce", now=G["now"])
        self.assertEqual([e["class"] for e in r["events"]], ["unchanged"])
        from crawlcheck.mcp import _tool_dict
        self.assertEqual(_tool_dict(T.Tool.model_validate(G["tools_v1"][0]))["annotations"], {"readOnlyHint": True})


@unittest.skipUnless(_have("agents.mcp"), "openai-agents not installed")
class OpenAIAgents(unittest.TestCase):
    def run_case(self, change, mode, **kw):
        from agents import Agent, RunContextWrapper
        from agents.mcp import MCPServer, MCPServerStdio
        from crawlcheck.openai_agents import with_continuity

        async def go():
            async with MCPServerStdio(params={"command": sys.executable, "args": [STUB], "env": env(change)}) as s:
                g = with_continuity(s, G["lock"], mode=mode, **kw)
                self.assertIsInstance(g, MCPServer)
                agent = Agent(name="a", instructions="x", mcp_servers=[g])
                tools = await agent.get_all_tools(RunContextWrapper(context=None))
                await agent.get_all_tools(RunContextWrapper(context=None))   # the SDK lists again every turn
                calls = {}
                for n in ("search", "status"):
                    try:
                        r = await g.call_tool(n, {"q": "x"} if n == "search" else {})
                        calls[n] = r.content[0].text
                    except ContinuityRefused as e:
                        calls[n] = "refused"
                return [t.name for t in tools], calls, g.gate
        return asyncio.run(go())

    def test_observe(self):
        names, calls, gate = self.run_case("description", "observe")
        self.assertEqual(names, ["search", "order", "status"])
        self.assertEqual(calls, {"search": "called search", "status": "called status"})
        self.assertEqual((len(gate.records), gate.record["would"], gate.record["outcome"]), (1, "pause_tool", "proceed"))

    def test_enforce_withholds_changed_tool(self):
        names, calls, gate = self.run_case("description", "enforce")
        self.assertEqual(names, ["order", "status"])
        self.assertEqual(calls, {"search": "refused", "status": "called status"})

    def test_enforce_confirm(self):
        names, calls, _ = self.run_case("description", "enforce", confirm=lambda req: req.get("tool") == "search")
        self.assertEqual(names, ["search", "order", "status"])
        self.assertEqual(calls["search"], "called search")

    def test_review_raises(self):
        with self.assertRaises(ContinuityRefused):
            self.run_case("added", "review")

    def test_unchanged(self):
        names, _, gate = self.run_case("", "enforce")
        self.assertEqual((names, gate.record["events"][0]["class"]), (["search", "order", "status"], "unchanged"))


@unittest.skipUnless(_have("langchain_mcp_adapters"), "langchain-mcp-adapters not installed")
class LangChainMCP(unittest.TestCase):
    def load(self, change, mode, session=False, **kw):
        from langchain_mcp_adapters.client import MultiServerMCPClient
        from crawlcheck.langchain import load_mcp_tools_with_continuity
        conn = {"transport": "stdio", "command": sys.executable, "args": [STUB], "env": env(change)}

        async def go():
            c = MultiServerMCPClient({"shop": conn})
            if session:
                async with c.session("shop") as s:
                    tools = await load_mcp_tools_with_continuity(s, G["lock"], mode=mode, **kw)
                    out = {t.name: t for t in tools}
                    return list(out), (await out["status"].ainvoke({"id": "1"}))
            tools = await load_mcp_tools_with_continuity(c, G["lock"], server_name="shop", mode=mode, **kw)
            out = {t.name: t for t in tools}
            return list(out), (await out["status"].ainvoke({"id": "1"}))
        return asyncio.run(go())

    def test_observe(self):
        recs = []
        names, res = self.load("description", "observe", on_record=recs.append)
        self.assertEqual(names, ["search", "order", "status"])
        self.assertIn("called status", json.dumps(res, default=str))
        self.assertEqual(recs[0]["events"][0]["class"], "description_changed")

    def test_enforce_client_and_session(self):
        self.assertEqual(self.load("description", "enforce")[0], ["order", "status"])
        self.assertEqual(self.load("description", "enforce", session=True)[0], ["order", "status"])

    def test_review_raises(self):
        with self.assertRaises(ContinuityRefused):
            self.load("added", "review")


@unittest.skipUnless(_have("crewai_tools") and _have("mcpadapt"), "crewai-tools[mcp] not installed")
class CrewAIMCP(unittest.TestCase):
    def open(self, change, mode, **kw):
        from mcp import StdioServerParameters
        from crewai_tools import MCPServerAdapter
        from crawlcheck.crewai import with_continuity
        w = with_continuity(MCPServerAdapter(StdioServerParameters(command=sys.executable, args=[STUB], env=env(change))), G["lock"], mode=mode, **kw)
        with w as tools:
            t = {x.name: x for x in tools}
            return list(t), t["status"].run(id="1"), w.gate

    def test_observe(self):
        names, res, gate = self.open("description", "observe")
        self.assertEqual((names, res, gate.record["would"]), (["search", "order", "status"], "called status", "pause_tool"))

    def test_enforce(self):
        self.assertEqual(self.open("description", "enforce")[0], ["order", "status"])
        self.assertEqual(self.open("description", "enforce", confirm=lambda r: True)[0], ["search", "order", "status"])

    def test_review_raises(self):
        with self.assertRaises(ContinuityRefused):
            self.open("added", "review")


if __name__ == "__main__":
    unittest.main()
