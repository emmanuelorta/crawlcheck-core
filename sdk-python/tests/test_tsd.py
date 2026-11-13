"""mcp-tool-set-digest/1: the 68 published vectors (github.com/alexar76/mcp-tool-set-digest, Apache-2.0 OR MIT), the
canonical texts they carry, the equal / differ pairs, and equality with jcs-v1 in the ordinary case."""
import json
import os
import unittest

from crawlcheck import tool_set_digest, tsd_canonical, ToolSetDigestError, jcs_v1, TSD_SPEC

V = json.load(open(os.path.join(os.path.dirname(__file__), "fixtures", "tool-set-digest-vectors.json"), encoding="utf-8"))


def key(side):
    return "E:" + side["error"] if side.get("error") else str(side.get("digest"))


class TestToolSetDigest(unittest.TestCase):
    def test_vectors(self):
        self.assertEqual(len(V["vectors"]), 68)
        self.assertEqual(TSD_SPEC, "mcp-tool-set-digest/1")
        got = {}
        for v in V["vectors"]:
            r = got[v["id"]] = tool_set_digest(json.loads(v["tools"]))
            for k in ("contract", "extras"):
                self.assertEqual(key(r[k]), key(v[k]), v["id"] + " " + k)
                if "canonical" in v[k]:
                    self.assertEqual(r[k]["canonical"], v[k]["canonical"], v["id"] + " " + k + " canonical")
        for p in V["equal"]:
            self.assertEqual(key(got[p["ids"][0]][p["digest"]]), key(got[p["ids"][1]][p["digest"]]), p["ids"])
        for p in V["differ"]:
            self.assertNotEqual(key(got[p["ids"][0]][p["digest"]]), key(got[p["ids"][1]][p["digest"]]), p["ids"])

    def test_sides_are_computed_apart(self):
        r = tool_set_digest([{"name": "a", "title": "\ud800"}])
        self.assertTrue(r["contract"]["digest"])
        self.assertEqual(r["extras"], {"error": "TSD-TEXT", "tool": "a"})
        p = tool_set_digest([{"name": "a"}], partial=True)
        self.assertEqual([p["contract"], p["extras"]], [{"error": "TSD-PAGE"}, {"error": "TSD-PAGE"}])

    def test_nothing_is_repaired(self):
        with self.assertRaises(ToolSetDigestError) as c:
            tsd_canonical("\udc00")
        self.assertEqual(c.exception.code, "TSD-TEXT")
        with self.assertRaises(ToolSetDigestError) as c:
            tsd_canonical({"a": float("inf")})
        self.assertEqual(c.exception.code, "TSD-NUMBER")
        self.assertEqual(tsd_canonical({"b": 1.0, "a": -0.0, "c": 1e21}), '{"a":0,"b":1,"c":1e+21}')

    def test_equals_jcs_v1_in_the_ordinary_case(self):
        tools = [{"name": "read_file", "title": "Read file", "description": "Read a file from disk.",
                  "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
                  "annotations": {"readOnlyHint": True}}, {"name": "b", "description": "x"}]
        t, j = tool_set_digest(tools, per_tool=True), jcs_v1(tools)
        self.assertEqual(t["contract"]["digest"], j["tools_sha256"])
        self.assertEqual(t["extras"]["digest"], j["extras_sha256"])
        self.assertEqual(sorted((x["name"], x["contract"], x["extras"]) for x in t["tools"]),
                         sorted((x["name"], x["contract"], x["extras"]) for x in j["tools"]))


if __name__ == "__main__":
    unittest.main()
