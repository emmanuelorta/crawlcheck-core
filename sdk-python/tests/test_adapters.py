"""LangChain / LlamaIndex adapters (1.10.0). Skipped when the framework is not installed; offline (a stub client)."""
import json, unittest


class _Stub:
    last_guard = {"why": []}
    def guard(self, domain, action, **kw):
        return (domain != "blocked.example"), {"decision": "allow" if domain != "blocked.example" else "block", "steps": [], "reason_codes": []}


def _have(mod):
    try:
        __import__(mod)
        return True
    except Exception:
        return False


@unittest.skipUnless(_have("langchain_core"), "langchain-core not installed")
class LangChainAdapter(unittest.TestCase):
    def test_tools_and_fail_closed(self):
        from crawlcheck.langchain import crawlcheck_tools
        t = crawlcheck_tools(_Stub())
        self.assertEqual([x.name for x in t], ["crawlcheck_check_site", "crawlcheck_verify_fact", "crawlcheck_fetch"])
        self.assertTrue(json.loads(t[0].invoke({"site": "example.com"}))["proceed"])
        self.assertFalse(json.loads(t[0].invoke({"site": "blocked.example", "action": "transact"}))["proceed"])
        self.assertFalse(json.loads(t[0].invoke({"site": "not a domain"}))["proceed"])


@unittest.skipUnless(_have("llama_index.core"), "llama-index-core not installed")
class LlamaIndexAdapter(unittest.TestCase):
    def test_tools_and_fail_closed(self):
        from crawlcheck.llama_index import crawlcheck_tools
        t = crawlcheck_tools(_Stub())
        self.assertEqual([x.metadata.name for x in t], ["crawlcheck_check_site", "crawlcheck_verify_fact", "crawlcheck_fetch"])
        self.assertTrue(json.loads(t[0].call(site="example.com").content)["proceed"])
        self.assertFalse(json.loads(t[0].call(site="blocked.example", action="transact").content)["proceed"])


if __name__ == "__main__":
    unittest.main()


class UnknownActionFailsClosed(unittest.TestCase):
    """1.10.1: a given action outside the five fails closed instead of becoming read (no network call)."""
    def test_check_site_and_fetch(self):
        from crawlcheck.tools import agent_tools
        t = agent_tools(_Stub())
        r = t[0]["execute"]({"site": "example.com", "action": "pay"})
        self.assertFalse(r["proceed"]); self.assertIn("unknown action: pay", r["why"][0])
        self.assertTrue(t[0]["execute"]({"site": "example.com"})["proceed"])
        f = t[2]["execute"]({"url": "https://example.com/", "action": "transact"})
        self.assertFalse(f["proceed"])
