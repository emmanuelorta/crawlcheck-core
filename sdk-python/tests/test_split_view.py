"""Split-view detection: a forced fork of the Resolve log (made by the service's own log code in a test harness) is
detected offline; the live log checks out consistent with GitHub's witness co-signature."""
import json
import os
import unittest

from crawlcheck import CrawlCheck, new_log_store, log_observe, log_gossip, log_heads, verify_witness_token
from crawlcheck.log import _walk_heads, GITHUB_OIDC_JWKS

F = json.load(open(os.path.join(os.path.dirname(__file__), "fixtures", "split-view.json")))


SELFTEST = {"user-agent": "crawlcheck-selftest sdk-python-tests"}   # our own runs: the adoption meter counts them as ours


def _get(url):
    import urllib.request
    with urllib.request.urlopen(urllib.request.Request(url, headers=dict(SELFTEST, accept="application/json")), timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


class SplitView(unittest.TestCase):
    def test_gossip_detects_fork(self):
        a, b = new_log_store(), new_log_store()
        # The harness key is not one a release ships, so its id alone does not say it signs log heads: the policy does.
        from crawlcheck import key_policy_from
        kp = key_policy_from({"keys": [dict(F["A"][0]["signature"]["key"]["jwk"], crawlcheck_purpose="log heads", crawlcheck_signs_from="2026-10-01T00:00:00Z")]})
        self.assertEqual(kp["kids"], [F["kid"]])
        self.assertEqual(log_observe(new_log_store(), F["A"][0], [F["kid"]])["state"], "invalid", "key ids alone: a listed key of unknown purpose signs no log head")
        for s in F["A"]:
            self.assertEqual(log_observe(a, s, key_policy=kp)["state"], "new")
        for s in F["B"]:
            log_observe(b, s, key_policy=kp)
        self.assertFalse(a["forks"] or b["forks"])
        g = log_gossip(a, log_heads(b), key_policy=kp)
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
        # The fixture's token is synthetic and issued to an example repository: its signature holds, and it is not the witness.
        fx = verify_witness_token(F["witness"]["token"], F["A"][2]["sha256"], F["jwks"])
        self.assertIs(fx["ok"], False)
        self.assertIn("not the witness workflow", fx["why"])
        # The witness's own token is read from the live log with the keys GitHub publishes: valid for its head, refused for another.
        w, jwks = _get("https://crawlcheck.io/api/v1/log/witness/latest"), _get(GITHUB_OIDC_JWKS)
        self.assertIs(verify_witness_token(w["token"], w["sth_sha256"], jwks)["ok"], True)
        self.assertIs(verify_witness_token(w["token"], F["B"][2]["sha256"], jwks)["ok"], False)

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
        c = CrawlCheck(headers=SELFTEST)
        c.resolve("github.com")
        r = c.log_check(report=False)
        self.assertTrue(r["consistent"], r["summary"])
        self.assertIs(r["witnessed"]["token"], True, r["witnessed"])
