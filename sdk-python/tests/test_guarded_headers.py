"""hdr1: caller headers stay on the origin the caller named; after a redirect elsewhere only the allowlist travels."""
import unittest
from crawlcheck import client as C

H = {"Authorization": "Bearer secret", "Cookie": "sid=1", "X-Api-Key": "k", "Accept": "text/html", "User-Agent": "t/1"}


SELFTEST = {"user-agent": "crawlcheck-selftest sdk-python-tests"}   # our own runs: the adoption meter counts them as ours


def run(mapping, url="https://a.example/x"):
    seen = []

    def transport(method, u, h, data):
        seen.append((u, {k.lower(): v for k, v in h.items()}))
        to = mapping.get(u)
        return (302, {"Location": to}, b"") if to else (200, {}, b"ok")

    cc = C.CrawlCheck(headers=SELFTEST)
    cc.last_guard = {"why": []}
    cc.guard = lambda *a, **k: (True, {"decision": "allow"})
    orig = C.receipt_header
    C.receipt_header = lambda rc: {"crawlcheck-receipt": "r"}
    try:
        r = cc.guarded_fetch(url, headers=H, transport=transport)
    finally:
        C.receipt_header = orig
    return r, seen


class GuardedHeaders(unittest.TestCase):
    def test_other_host_drops_credentials(self):
        r, seen = run({"https://a.example/x": "https://b.example/y"})
        self.assertTrue(r["proceed"]); self.assertEqual(len(seen), 2)
        self.assertEqual(seen[0][1]["authorization"], "Bearer secret")
        for k in ("authorization", "cookie", "x-api-key"):
            self.assertNotIn(k, seen[1][1])
        self.assertEqual(seen[1][1]["accept"], "text/html"); self.assertEqual(seen[1][1]["user-agent"], "t/1")
        self.assertEqual(seen[1][1]["crawlcheck-receipt"], "r")

    def test_same_origin_keeps_everything(self):
        _, seen = run({"https://a.example/x": "https://a.example/y"})
        self.assertEqual(seen[1][1]["authorization"], "Bearer secret"); self.assertEqual(seen[1][1]["x-api-key"], "k")

    def test_scheme_and_port_are_other_origins(self):
        for to in ("http://a.example/y", "https://a.example:8443/y"):
            _, seen = run({"https://a.example/x": to})
            self.assertNotIn("authorization", seen[1][1], to); self.assertNotIn("cookie", seen[1][1], to)

    def test_headers_return_on_the_first_origin(self):
        _, seen = run({"https://a.example/x": "https://b.example/y", "https://b.example/y": "https://a.example/z"})
        self.assertNotIn("authorization", seen[1][1]); self.assertEqual(seen[2][1]["authorization"], "Bearer secret")

    def test_allowlist_has_no_credential_header(self):
        for k in ("authorization", "cookie", "proxy-authorization"):
            self.assertNotIn(k, C.GUARDED_SAFE_HEADERS)


if __name__ == "__main__":
    unittest.main()
