import asyncio, unittest
from crawlcheck import CrawlCheck, lock_from_tools
from crawlcheck.mcp import with_preflight, McpPreflight, McpPreflightRefused

TOOLS = [{"name": "search", "description": "find", "inputSchema": {"type": "object"}, "annotations": {"readOnlyHint": True}},
         {"name": "delete_repo", "description": "rm", "inputSchema": {"type": "object"}, "annotations": {"destructiveHint": True}}]

def cc(table):
    c = CrawlCheck(); c.calls = []
    def pf(domain, action="read", agent=None, template=None, policy=None, operation=None):
        c.calls.append((domain, action, template) if operation is None else (domain, action, template, operation.get("tool")))
        import datetime as _dt; _n = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
        return {"kind": "crawlcheck-decision", "v": 1, "domain": domain, "action": action, "decision": table.get(domain, "unsupported"), "decided_at": _n.strftime("%Y-%m-%dT%H:%M:%SZ"), "expires_at": (_n + _dt.timedelta(seconds=3000)).strftime("%Y-%m-%dT%H:%M:%SZ"), "resolve": {"sha256": "0" * 64, "kid": "k"}, "operation": operation, "steps": [{"why": "table"}], "sha256": "x", "signature": {"kid": "k"}}
    c.preflight = pf
    c.verify = lambda doc, online_keys=True: {"verified": True, "accepted": True}
    return c

class Session:
    def __init__(self, tools): self.tools, self.sent, self.closed = tools, [], False
    async def __aenter__(self): return self
    async def __aexit__(self, *a): self.closed = True
    async def initialize(self): self.sent.append("initialize")
    async def list_tools(self): return {"tools": self.tools}
    async def call_tool(self, name, arguments=None): self.sent.append("tools/call " + name); return {"content": []}

def run(c): return asyncio.get_event_loop().run_until_complete(c)

class T(unittest.TestCase):
    def test_unsupported_refuses_before_initialize(self):
        s = Session(TOOLS); w = with_preflight(s, cc({}), server_url="https://mcp.example.com/mcp")
        with self.assertRaises(McpPreflightRefused) as e: run(w.initialize())
        self.assertEqual(e.exception.stage, "connect"); self.assertIn("nothing vouches", e.exception.why); self.assertEqual(s.sent, [])
    def test_block(self):
        s = Session(TOOLS); w = with_preflight(s, cc({"evil.example": "block"}), server_url="https://evil.example/mcp")
        with self.assertRaises(McpPreflightRefused): run(w.initialize())
        self.assertEqual(s.sent, [])
    def test_allow_once(self):
        k = cc({"good.example": "allow"}); s = Session(TOOLS); w = with_preflight(s, k, server_url="https://good.example/mcp")
        run(w.initialize()); run(w.call_tool("search", {}))
        self.assertEqual(s.sent, ["initialize", "tools/call search"]); self.assertEqual(k.calls, [("good.example", "connect", "safe_mcp_tool")])
    def test_require_confirmation(self):
        k = cc({"ask.example": "require_confirmation"})
        with self.assertRaises(McpPreflightRefused) as e: run(with_preflight(Session(TOOLS), k, server_url="https://ask.example/mcp").initialize())
        self.assertIn("human must confirm", e.exception.why)
        seen = []
        async def yes(rc): seen.append(rc["decision"]); return True
        s = Session(TOOLS); run(with_preflight(s, k, server_url="https://ask.example/mcp", confirm=yes).initialize())
        self.assertEqual(seen, ["require_confirmation"]); self.assertEqual(s.sent, ["initialize"])
    def test_lock(self):
        lock = lock_from_tools([TOOLS[0]])
        w = with_preflight(Session(TOOLS), cc({"good.example": "allow"}), server_url="https://good.example/mcp", lock=lock)
        with self.assertRaises(McpPreflightRefused) as e: run(w.initialize())
        self.assertIn("delete_repo", e.exception.lock["added"])
        s = Session([TOOLS[0]]); w = with_preflight(s, cc({"good.example": "allow"}), server_url="https://good.example/mcp", lock=lock)
        run(w.initialize()); run(w.call_tool("search"))
        with self.assertRaises(McpPreflightRefused) as e: run(w.call_tool("delete_repo"))
        self.assertEqual(e.exception.stage, "tools/call"); self.assertEqual(s.sent, ["initialize", "tools/call search"])
    def test_destructive(self):
        s = Session(TOOLS); w = with_preflight(s, cc({"good.example": "allow"}), server_url="https://good.example/mcp", confirm_destructive=True, confirm=lambda rc: rc.get("tool") != "delete_repo")
        run(w.initialize()); run(w.call_tool("search"))
        with self.assertRaises(McpPreflightRefused) as e: run(w.call_tool("delete_repo"))
        self.assertIn("destructive", e.exception.why); self.assertEqual(s.sent, ["initialize", "tools/call search"])
    def test_unverified_receipt(self):
        k = cc({"good.example": "allow"}); k.verify = lambda doc, online_keys=True: {"verified": True, "accepted": False}
        with self.assertRaises(McpPreflightRefused) as e: run(with_preflight(Session(TOOLS), k, server_url="https://good.example/mcp").initialize())
        self.assertIn("does not publish", e.exception.why)
    def test_local(self):
        run(with_preflight(Session(TOOLS), cc({})).initialize())
        with self.assertRaises(McpPreflightRefused): run(with_preflight(Session(TOOLS), cc({}), local="refuse").initialize())
    def test_hooks(self):
        h = McpPreflight(cc({"good.example": "allow"}))
        self.assertEqual(run(h.before_connect("https://good.example/mcp"))["decision"], "allow")
        self.assertEqual(run(h.before_tool_call("search"))["decision"], "allow")
    def test_decide_first_not_twice(self):
        k = cc({"good.example": "allow"}); pf = McpPreflight(k)
        run(pf.before_connect("https://good.example/mcp"))
        s = Session(TOOLS); run(with_preflight(s, k, server_url="https://good.example/mcp", preflight=pf).initialize())
        self.assertEqual(len(k.calls), 1); self.assertEqual(s.sent, ["initialize"])
if __name__ == "__main__": unittest.main()


class ToolReceipts(unittest.TestCase):
    def test_write_tool_gets_its_own_receipt(self):
        k = cc({"good.example": "allow"}); s = Session(TOOLS); w = with_preflight(s, k, server_url="https://good.example/mcp")
        run(w.initialize()); run(w.call_tool("search", {})); run(w.call_tool("delete_repo", {}))
        self.assertEqual([c[3] for c in k.calls if len(c) == 4], ["delete_repo"])   # read-only search reuses the connect receipt
    def test_all_and_none(self):
        k = cc({"good.example": "allow"}); w = with_preflight(Session(TOOLS), k, server_url="https://good.example/mcp", tool_receipts="all")
        run(w.initialize()); run(w.call_tool("search", {}))
        self.assertEqual([c[3] for c in k.calls if len(c) == 4], ["search"])
        k2 = cc({"good.example": "allow"}); w2 = with_preflight(Session(TOOLS), k2, server_url="https://good.example/mcp", tool_receipts="none")
        run(w2.initialize()); run(w2.call_tool("delete_repo", {}))
        self.assertEqual([c for c in k2.calls if len(c) == 4], [])
    def test_wrong_operation_refused(self):
        k = cc({"good.example": "allow"}); orig = k.preflight
        def bad(*a, **kw):
            r = orig(*a, **kw)
            if kw.get("operation"): r["operation"] = dict(kw["operation"], tool_schema_sha256="f" * 64)
            return r
        k.preflight = bad
        s = Session(TOOLS); w = with_preflight(s, k, server_url="https://good.example/mcp")
        run(w.initialize())
        with self.assertRaises(McpPreflightRefused) as e: run(w.call_tool("delete_repo", {}))
        self.assertEqual(e.exception.stage, "tools/call"); self.assertIn("another operation", e.exception.why); self.assertNotIn("tools/call delete_repo", s.sent)
