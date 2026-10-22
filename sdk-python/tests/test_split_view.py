"""Split-view detection: a forced fork of the Resolve log (made by the Worker's own log code in a test harness) is
detected offline; the live log checks out consistent with GitHub's witness co-signature."""
import json
import os
import unittest

from crawlcheck import CrawlCheck, new_log_store, log_observe, log_gossip, log_heads, verify_witness_token
from crawlcheck.log import _walk_heads

F = json.load(open(os.path.join(os.path.dirname(__file__), "fixtures", "split-view.json")))


class SplitView(unittest.TestCase):
    def test_gossip_detects_fork(self):
        a, b = new_log_store(), new_log_store()
        for s in F["A"]:
            self.assertEqual(log_observe(a, s, [F["kid"]])["state"], "new")
        for s in F["B"]:
            log_observe(b, s, [F["kid"]])
        self.assertFalse(a["forks"] or b["forks"])
        g = log_gossip(a, log_heads(b), [F["kid"]])
        self.assertEqual(sorted("%s@%d" % (f["kind"], f["batch"]) for f in g["forks"]), ["two_heads_for_one_batch@1", "two_heads_for_one_batch@2"])

    def test_chain_break(self):
        c = new_log_store()
        log_observe(c, F["A"][1])
        r = log_observe(c, F["B"][2])
        self.assertEqual((r["state"], r["fork"]["kind"]), ("fork", "chain_break"))

    def test_tampered_head_is_invalid(self):
        s = dict(F["B"][1], batch_root="0" * 64)
        self.assertEqual(log_observe(new_log_store(), s)["state"], "invalid")

    def test_witness_token_binds_one_head(self):
        self.assertIs(verify_witness_token(F["witness"]["token"], F["A"][2]["sha256"], F["jwks"])["ok"], True)
        self.assertIs(verify_witness_token(F["witness"]["token"], F["B"][2]["sha256"], F["jwks"])["ok"], False)

    def test_walk_heads_batched_and_fallback(self):
        """1.9.0: 200 heads per request through /api/v1/log/sths; an older server is walked one head per request."""
        import re
        calls = []

        def batched(p):
            calls.append(p)
            m = re.search(r"sths\?to=(\d+)&n=(\d+)", p)
            if not m:
                raise RuntimeError("404")
            to, n = int(m.group(1)), int(m.group(2))
            return {"sths": [{"kind": "crawlcheck-log-sth", "batch": to - i} for i in range(n)]}

        r = _walk_heads(batched, 449, 0)
        self.assertEqual(len(r), 450)
        self.assertEqual([x["batch"] for x in r[:2]], [449, 448])
        self.assertEqual(r[449]["batch"], 0)
        self.assertEqual(calls, ["/api/v1/log/sths?to=449&n=200", "/api/v1/log/sths?to=249&n=200", "/api/v1/log/sths?to=49&n=50"])
        del calls[:]

        def old(p):
            calls.append(p)
            m = re.search(r"sth/(\d+)$", p)
            if not m:
                raise RuntimeError("404")
            return {"sth": {"kind": "crawlcheck-log-sth", "batch": int(m.group(1))}}

        r = _walk_heads(old, 4, 2)
        self.assertEqual([x["batch"] for x in r], [4, 3, 2])
        self.assertEqual(len(calls), 4)
        self.assertEqual(_walk_heads(batched, 3, 4), [])

    def test_live_log_consistent_and_witnessed(self):
        c = CrawlCheck()
        c.resolve("github.com")
        r = c.log_check(report=False)
        self.assertTrue(r["consistent"], r["summary"])
        self.assertIs(r["witnessed"]["token"], True, r["witnessed"])
