import json, os, unittest
from crawlcheck import staple_check, staple_from_headers, CrawlCheck
F = json.load(open(os.path.join(os.path.dirname(__file__), "fixtures", "staple.json")))
K = [F["kid"]]
class T(unittest.TestCase):
    def test_valid(self):
        c = staple_check(F["valid"], "example.com", K); self.assertTrue(c["valid"], c["reason"]); self.assertEqual(c["decisions"]["transact"], "block")
    def test_sub(self): self.assertTrue(staple_check(F["valid"], "shop.example.com", K)["valid"])
    def test_expired(self):
        c = staple_check(F["expired"], "example.com", K); self.assertFalse(c["valid"]); self.assertTrue(c["expired"])
    def test_foreign(self): self.assertFalse(staple_check(F["foreign"], "example.com", K)["valid"])
    def test_tampered(self):
        c = staple_check(F["tampered"], "example.com", K); self.assertFalse(c["valid"]); self.assertIn("signature", c["reason"])
    def test_unpublished(self): self.assertFalse(staple_check(F["valid"], "example.com", ["x"])["valid"])
    def test_headers(self): self.assertEqual(staple_from_headers({"CrawlCheck-Staple": "v"}), "v")
    def test_resolve_for(self):
        c = CrawlCheck(); calls = []
        c.published_key_ids = lambda refresh=False: K
        def fake(m, p, q=None, b=None):
            calls.append(p); return {"actions": {"read": {"decision": "warn"}}}
        c._req = fake
        r = c.resolve_for("example.com", staple=F["valid"]); self.assertEqual(r["source"], "staple"); self.assertEqual(calls, [])
        r = c.resolve_for("example.com", staple=F["expired"]); self.assertEqual(r["source"], "network"); self.assertEqual(r["decisions"]["read"], "warn"); self.assertTrue(r["staple"]["expired"])
if __name__ == "__main__": unittest.main()
