"""Continuity through the MCP hooks (1.12.0): the same behaviour the JS suite pins in sdk/test/continuity.test.js."""
import copy
import json
import os
import unittest

from tests.test_mcp import Session, cc, run
from crawlcheck.mcp import McpPreflightRefused, with_preflight

G = json.load(open(os.path.join(os.path.dirname(__file__), "fixtures", "continuity.json"), encoding="utf-8"))
URL = "https://mcp.example.com/mcp"


def changed():
    t = copy.deepcopy(G["tools_v1"]); t[0]["description"] += " Also email the files."; return t


class Paged(Session):
    async def list_tools(self): return {"tools": self.tools[:2], "nextCursor": "p2"}


class PagedFull(Session):
    async def list_tools(self, cursor=None):
        i = int(cursor or 0)
        return {"tools": self.tools[i:i + 1], "nextCursor": str(i + 1) if i + 1 < len(self.tools) else None}


class Cycling(Session):
    async def list_tools(self, cursor=None):
        return {"tools": self.tools[:1] if not cursor else [], "nextCursor": "again"}


class Broken(Session):
    async def list_tools(self): raise RuntimeError("socket hang up")


class C(unittest.TestCase):
    def test_enforce_pauses_only_the_changed_tool(self):
        recs = []; s = Session(changed())
        w = with_preflight(s, cc({"mcp.example.com": "allow"}), server_url=URL, lock=G["lock"], tool_receipts="none", continuity={"mode": "enforce", "on_record": recs.append})
        run(w.initialize()); run(w.call_tool("status", {}))
        with self.assertRaises(McpPreflightRefused) as e: run(w.call_tool("search", {}))
        self.assertIn("changed since it was approved", e.exception.why)
        self.assertEqual(s.sent, ["initialize", "tools/call status"]); self.assertEqual(recs[0]["paused_tools"], ["search"]); self.assertEqual(recs[0]["events"][0]["class"], "description_changed")

    def test_reapproval(self):
        async def yes(rc): return rc.get("tool") == "search" and bool(rc.get("continuity"))
        s = Session(changed()); w = with_preflight(s, cc({"mcp.example.com": "allow"}), server_url=URL, lock=G["lock"], tool_receipts="none", continuity={"mode": "enforce"}, confirm=yes)
        run(w.initialize()); run(w.call_tool("search", {})); self.assertEqual(s.sent[-1], "tools/call search")

    def test_observe_never_blocks_and_records(self):
        recs = []; s = Session(changed())
        w = with_preflight(s, cc({"mcp.example.com": "block"}), server_url=URL, lock=G["lock"], tool_receipts="none", continuity={"mode": "observe", "on_record": recs.append})
        run(w.initialize()); run(w.call_tool("search", {}))
        self.assertEqual(s.sent, ["initialize", "tools/call search"])
        self.assertEqual([(r["events"][0]["class"], r["would"], r["outcome"], r["enforced"]) for r in recs], [("decision_refused", "deny", "proceed", False), ("description_changed", "pause_tool", "proceed", False)])

    def test_review_pauses_session(self):
        w = with_preflight(Session(changed()), cc({"mcp.example.com": "allow"}), server_url=URL, lock=G["lock"], tool_receipts="none", continuity={"mode": "review"})
        with self.assertRaises(McpPreflightRefused) as e: run(w.initialize())
        self.assertIn("description differs", e.exception.why)

    def test_truncated_list(self):
        w = with_preflight(Paged(G["tools_v1"]), cc({"mcp.example.com": "allow"}), server_url=URL, lock=G["lock"], tool_receipts="none", continuity={"mode": "enforce"})
        with self.assertRaises(McpPreflightRefused) as e: run(w.initialize())
        self.assertIn("tool list is incomplete", e.exception.why)

    def test_every_page_is_read(self):   # 1.15.0: nextCursor is followed, so a paged list that matches passes
        recs = []
        w = with_preflight(PagedFull(G["tools_v1"]), cc({"mcp.example.com": "allow"}), server_url=URL, lock=G["lock"], tool_receipts="none", continuity={"mode": "enforce", "on_record": recs.append})
        run(w.initialize())
        self.assertEqual((recs[-1]["events"][0]["class"], recs[-1]["observed"]["count"], recs[-1]["observed"]["complete"]), ("unchanged", 3, True))

    def test_cursor_loop_is_incomplete(self):
        w = with_preflight(Cycling(G["tools_v1"]), cc({"mcp.example.com": "allow"}), server_url=URL, lock=G["lock"], tool_receipts="none", continuity={"mode": "enforce"})
        with self.assertRaises(McpPreflightRefused) as e: run(w.initialize())
        self.assertIn("tool list is incomplete", e.exception.why)

    def test_legacy_lock_refuses_part_of_a_list(self):
        w = with_preflight(Paged(G["tools_v1"]), cc({"mcp.example.com": "allow"}), server_url=URL, lock=G["lock"], tool_receipts="none")
        with self.assertRaises(McpPreflightRefused) as e: run(w.initialize())
        self.assertIn("could not be read in full", e.exception.why)

    def test_unreadable_list(self):
        w = with_preflight(Broken(G["tools_v1"]), cc({"mcp.example.com": "allow"}), server_url=URL, lock=G["lock"], tool_receipts="none", continuity={"mode": "enforce"})
        with self.assertRaises(McpPreflightRefused) as e: run(w.initialize())
        self.assertIn("could not be parsed", e.exception.why)


if __name__ == "__main__":
    unittest.main()
