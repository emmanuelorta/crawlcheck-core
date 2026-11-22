"""TSD-DEPTH (1.16.4): a reader limit of 512 levels of arrays and objects, the tools array being level 1. Before it,
Python raised RecursionError from about 500 levels while the JS SDK still gave a digest, so the two SDKs disagreed."""
import unittest

from crawlcheck.tsd import TSD_MAX_DEPTH, tool_set_digest, tsd_canonical


def nested(n):
    v = []
    for _ in range(n - 1):
        v = [v]
    return v


class DepthTest(unittest.TestCase):
    def test_bound_is_512(self):
        self.assertEqual(TSD_MAX_DEPTH, 512)

    def test_contract_edge(self):
        # tools 1, tool 2, inputSchema 3, so n arrays under inputSchema.x end at level n + 3
        ok = tool_set_digest([{"name": "a", "inputSchema": {"x": nested(509)}}])
        self.assertTrue(ok["contract"]["digest"].startswith("sha256-"))
        over = tool_set_digest([{"name": "a", "inputSchema": {"x": nested(510)}}])
        self.assertEqual(over["contract"], {"error": "TSD-DEPTH", "tool": "a"})
        self.assertEqual(over["extras"], {"digest": None})

    def test_extras_edge_keeps_contract(self):
        ok = tool_set_digest([{"name": "a", "x": nested(510)}])
        self.assertTrue(ok["extras"]["digest"].startswith("sha256-"))
        over = tool_set_digest([{"name": "a", "x": nested(511)}])
        self.assertEqual(over["extras"], {"error": "TSD-DEPTH", "tool": "a"})
        self.assertTrue(over["contract"]["digest"].startswith("sha256-"))

    def test_no_stack_exhaustion(self):
        r = tool_set_digest([{"name": "a", "inputSchema": {"x": nested(100000)}}])
        self.assertEqual(r["contract"]["error"], "TSD-DEPTH")

    def test_canonical_level_and_order(self):
        self.assertEqual(tsd_canonical({"b": [1, {"d": None, "c": True}], "a": "x"}), '{"a":"x","b":[1,{"c":true,"d":null}]}')
        with self.assertRaises(Exception) as cm:
            tsd_canonical(nested(513))
        self.assertEqual(cm.exception.code, "TSD-DEPTH")
        self.assertEqual(tsd_canonical(nested(512)), "[" * 512 + "]" * 512)
        # document order decides which code is reported: the earlier member's number before the later member's text
        with self.assertRaises(Exception) as cm:
            tsd_canonical({"a": float("inf"), "b": "\ud800"})
        self.assertEqual(cm.exception.code, "TSD-NUMBER")


if __name__ == "__main__":
    unittest.main()
