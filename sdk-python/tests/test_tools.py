import json, unittest
from crawlcheck import CrawlCheck, agent_tools, tools_for


class ToolsTest(unittest.TestCase):
    def setUp(self):
        self.tools = agent_tools(CrawlCheck())

    def test_shapes(self):
        self.assertEqual([t["name"] for t in self.tools], ["crawlcheck_check_site", "crawlcheck_verify_fact", "crawlcheck_fetch"])
        oa, _ = tools_for("openai", self.tools)
        an, _ = tools_for("anthropic", self.tools)
        mc, _ = tools_for("mcp", self.tools)
        self.assertEqual(oa[0]["function"]["parameters"], self.tools[0]["parameters"])
        self.assertEqual(an[1]["input_schema"], self.tools[1]["parameters"])
        self.assertEqual(mc[0]["inputSchema"]["type"], "object")

    def test_fail_closed_offline(self):
        _, call = tools_for("openai", self.tools)
        self.assertFalse(call("crawlcheck_check_site", json.dumps({"site": "not a domain"}))["proceed"])
        self.assertFalse(call("nope", {})["proceed"])

    def test_live_decision(self):
        r = self.tools[0]["execute"]({"site": "https://crawlcheck.io/pricing", "action": "transact"})
        self.assertEqual(r["domain"], "crawlcheck.io")
        self.assertIn(r["decision"], ["allow", "warn", "require_confirmation", "block", "unsupported"])
        self.assertRegex(str(r["receipt_sha256"]), r"^[0-9a-f]{64}$")

    def test_live_fetch(self):
        r = self.tools[2]["execute"]({"url": "https://crawlcheck.io/llms.txt"})
        if r["proceed"]:
            self.assertEqual(r["status"], 200)
            self.assertGreater(len(r["text"]), 100)
        else:
            self.assertTrue(r["why"])


if __name__ == "__main__":
    unittest.main()


class VerifyFactTest(unittest.TestCase):
    def test_bad_input(self):
        t = agent_tools(CrawlCheck())[1]
        self.assertFalse(t["execute"]({"site": "not a domain", "field": "phone", "value": "1"})["ok"])
        self.assertFalse(t["execute"]({"site": "example.com", "field": "email", "value": "x"})["ok"])

    def test_live_signed(self):
        r = agent_tools(CrawlCheck())[1]["execute"]({"site": "crawlcheck.io", "field": "phone", "value": "(720) 555-0100"})
        if r.get("ok"):
            self.assertEqual(r["kind"], "crawlcheck-field-check")
            self.assertTrue(r["verified"])
        else:
            self.assertTrue(r["why"])
