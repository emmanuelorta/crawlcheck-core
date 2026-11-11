"""jcs-v1 (1.15.0): the digests must equal what CrawlCheck's lockfile endpoint signs, for the spec's vectors, the edge
cases and a live lockfile. The golden file is shared with the JS SDK (sdk/test/fixtures/jcs-v1.json)."""
import base64
import copy
import json
import os
import unittest
import zlib

from crawlcheck import jcs_v1, jcs_canon, jcs_contract, lock_from_tools, check_lock, continuity_check, LOCK_V1_MAX_TOOLS

G = json.load(open(os.path.join(os.path.dirname(__file__), "fixtures", "jcs-v1.json"), encoding="utf-8"))


def tools_of(c):
    if "tools_json" in c:
        return json.loads(c["tools_json"])
    return json.loads(zlib.decompress(base64.b64decode(c["tools_json_deflate_b64"])).decode("utf-8"))


def many(n):
    return [{"name": "t%03d" % i, "description": "Tool %d." % i, "inputSchema": {"type": "object"}} for i in range(n)]


class Jcs(unittest.TestCase):
    def test_golden_endpoint_answers(self):
        for c in G["cases"]:
            with self.subTest(c["name"]):
                self.assertEqual(jcs_v1(tools_of(c)), c["expect"])

    def test_live_lockfile(self):
        self.assertEqual(jcs_v1(G["live"]["tools"]), G["live"]["lock_jcs_v1"])

    def test_spec_vectors(self):
        V = G["spec_vectors"]
        t = tools_of(next(c for c in G["cases"] if c["name"] == "spec_read_file"))
        self.assertEqual(jcs_v1([])["tools_sha256"], V["empty_list_tools_sha256"])
        self.assertEqual(jcs_canon(jcs_contract(t[0])), V["read_file"]["canonical_contract"])
        r = jcs_v1(t)
        self.assertEqual((r["tools"][0]["contract"], r["tools"][0]["extras"], r["tools_sha256"], r["extras_sha256"]),
                         (V["read_file"]["contract"], V["read_file"]["extras"], V["read_file"]["tools_sha256"], V["read_file"]["extras_sha256"]))

    def test_empty_and_absent_description_are_one_contract(self):
        d = {c["name"]: c["expect"]["tools_sha256"] for c in G["cases"]}
        self.assertEqual(d["description_absent"], d["description_empty"])
        self.assertEqual(d["description_absent"], d["description_null"])
        self.assertEqual(d["inputschema_absent"], d["inputschema_empty"])
        self.assertNotEqual(d["outputschema_empty"], d["inputschema_empty"])

    def test_partial_not_digested(self):
        self.assertIsNone(jcs_v1([{"name": "a"}], partial=True)["tools_sha256"])

    def test_v1_cap_is_marked(self):
        self.assertEqual(LOCK_V1_MAX_TOOLS, 300)
        a = lock_from_tools(many(300))
        self.assertTrue(a["complete"]); self.assertNotIn("offered", a)
        b = lock_from_tools(many(301))
        self.assertEqual((b["complete"], b["offered"], b["count"], b["jcs_v1"]["count"], len(b["jcs_v1"]["tools"])), (False, 301, 300, 301, 301))
        c = check_lock(b, many(301))
        self.assertEqual((c["verdict"], c["decision"], c["jcs_v1"]["contract_unchanged"]), ("incomplete", "block", True))

    def test_check_lock_reports_jcs(self):
        t = many(3); lk = lock_from_tools(t); t2 = copy.deepcopy(t); t2[1]["title"] = "New title"
        c = check_lock(lk, t2)
        self.assertEqual((c["verdict"], c["jcs_v1"]["contract_unchanged"], c["jcs_v1"]["extras_unchanged"]), ("unchanged", True, False))

    def test_continuity_uses_jcs(self):
        t = many(3); lk = lock_from_tools(t); lock = {"tools_sha256": lk["tools_sha256"], "tools": lk["tools"], "jcs_v1": lk["jcs_v1"]}
        t2 = copy.deepcopy(t); t2[0]["title"] = "Renamed"
        r = continuity_check(lock, t2, now=1793145600000)
        self.assertEqual(r["baseline"]["alg"], "jcs-v1")
        self.assertEqual([(e["class"], e["tool"]) for e in r["events"]], [("tool_changed", "t000")])
        r2 = continuity_check(lock, t2, now=1793145600000, digest="lk-v1")
        self.assertEqual(r2["events"][0]["class"], "unchanged"); self.assertNotIn("alg", r2["baseline"])


if __name__ == "__main__":
    unittest.main()
