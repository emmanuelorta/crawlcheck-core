"""Offline revocations (rvd1): sync the signed list and its ?since= delta; guard() refuses a listed domain for a listed
action with the network cut. Fixtures are signed by the Worker's own code with a throwaway key."""
import copy, json, os, unittest
from crawlcheck import CrawlCheck, new_revocation_store, apply_revocations, revoked_for, key_id
F = json.load(open(os.path.join(os.path.dirname(__file__), "fixtures", "revocations.json")))
KIDS = [k.get("kid") or key_id(k) for k in F["directory"]["keys"]]


def client(state):
    c = CrawlCheck()
    c.published_key_ids = lambda refresh=False: KIDS

    def fake(m, p, q=None, b=None):
        if state.get("cut"):
            raise OSError("network cut")
        if p == "/.well-known/http-message-signatures-directory":   # conf2: verify() reads the key policy, not only the ids
            return copy.deepcopy(F["directory"])
        if p == "/.well-known/security-key-rotation.json":
            raise OSError("no rotation record in this fixture")
        state["calls"].append((p, dict(q or {})))
        if p == "/api/v1/revocations":
            return copy.deepcopy(F["delta"] if (q or {}).get("since") else F["full"])
        raise AssertionError("unexpected request " + p)
    c._req = fake
    return c


class T(unittest.TestCase):
    def test_sync_delta_and_offline_guard(self):
        st = {"calls": []}
        c = client(st)
        a = c.sync_revocations()
        self.assertTrue(a["applied"], a["reason"]); self.assertTrue(a["full"]); self.assertEqual(a["total"], 2)
        self.assertIsNotNone(revoked_for(c.revocations, "shop.example", "transact"))
        self.assertIsNone(revoked_for(c.revocations, "shop.example", "connect"))
        b = c.sync_revocations()
        self.assertTrue(b["applied"], b["reason"]); self.assertFalse(b["full"]); self.assertEqual((b["added"], b["removed"]), (1, 1))
        self.assertTrue(st["calls"][-1][1].get("since"))
        self.assertIsNone(revoked_for(c.revocations, "shop.example", "transact"))
        st["cut"] = True
        ok, rc = c.guard("checkout.paypa1.com", "transact")
        self.assertFalse(ok); self.assertIsNone(rc); self.assertEqual(c.last_guard["revoked"]["domain"], "paypa1.com")
        self.assertIn("revocation list", c.last_guard["why"][0])
        ok, _ = c.guard("xn--pple-43d.com", "connect")
        self.assertFalse(ok); self.assertEqual(c.last_guard["revoked"]["causes"], ["impersonation_suspected"])
        ok, _ = c.guard("paypa1.com", "read")
        self.assertFalse(ok); self.assertNotIn("revoked", c.last_guard)   # read is never revoked; network cut still fails closed

    def test_tampered_never_applied(self):
        c = CrawlCheck(); c.published_key_ids = lambda refresh=False: KIDS
        bad = copy.deepcopy(F["full"]); bad["revoked"] = []
        c._req = lambda m, p, q=None, b=None: bad
        r = c.sync_revocations()
        self.assertFalse(r["applied"]); self.assertIn("did not verify", r["reason"]); self.assertEqual(r["total"], 0)

    def test_store_rules(self):
        s = new_revocation_store()
        self.assertTrue(apply_revocations(s, F["full"])["applied"])
        s2 = json.loads(json.dumps(s))
        self.assertIsNotNone(revoked_for(s2, "www.shop.example", "transact"))
        self.assertFalse(apply_revocations(s2, dict(F["delta"], delta_complete=False))["applied"])
        self.assertIn("starts after", apply_revocations(s2, dict(F["delta"], since="2999-01-01T00:00:00.000Z", generated_at="2999-01-02T00:00:00.000Z"))["reason"])
        self.assertIn("older", apply_revocations(s2, dict(F["full"], generated_at="2000-01-01T00:00:00.000Z"))["reason"])

    def test_private_mode(self):
        import hashlib
        from crawlcheck import CrawlCheckError
        h = hashlib.sha256(b"example-shop.com").hexdigest()
        calls = []
        c = CrawlCheck(private_lookups=True); c.published_key_ids = lambda refresh=False: KIDS

        def fake(m, p, q=None, b=None):
            if p == "/.well-known/http-message-signatures-directory":   # conf2: names no domain, so it is not a lookup
                return copy.deepcopy(F["directory"])
            if p == "/.well-known/security-key-rotation.json":
                raise OSError("no rotation record in this fixture")
            calls.append(p + json.dumps(q or {}))
            if p.startswith("/api/v1/resolve-prefix/"):
                return {"in_bucket": 2, "answers": [{"domain_sha256": "0" * 64, "answer": {}}, {"domain_sha256": h, "answer": copy.deepcopy(F["resolve"])}]}
            raise AssertionError("unexpected request " + p)
        c._req = fake
        a = c.resolve("example-shop.com")
        self.assertEqual(a["domain"], "example-shop.com")
        self.assertEqual(calls[0], "/api/v1/resolve-prefix/" + h[:2] + "{}")
        r = c.resolve_for("example-shop.com"); self.assertEqual(r["source"], "network"); self.assertTrue(r["decisions"]["read"])
        with self.assertRaises(CrawlCheckError) as e:
            c.resolve("not-in-bucket.com")
        self.assertEqual(e.exception.status, 404)
        self.assertFalse(any("example-shop" in x or "not-in-bucket" in x for x in calls), calls)


if __name__ == "__main__":
    unittest.main()
