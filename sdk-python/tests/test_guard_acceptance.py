"""The guard() acceptance suite (https://crawlcheck.io/spec/guard) against this package.
CC_SDK_PATH=<dir containing the crawlcheck package> runs it against another copy (CI uses the one installed from PyPI)."""
import json, os, socket, sys, threading, unittest, calendar, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

if os.environ.get("CC_SDK_PATH"):
    sys.path.insert(0, os.environ["CC_SDK_PATH"])
from crawlcheck import CrawlCheck  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CANDIDATES = [os.environ.get("CC_GUARD_CASES") or "", os.path.join(HERE, "..", "..", "spec", "guard-acceptance", "cases.json"), os.path.join(HERE, "fixtures", "guard-acceptance.json")]
SUITE = json.load(open([p for p in CANDIDATES if p and os.path.exists(p)][0]))
STATE = {"case": None, "asked": []}


def ms(iso):
    return calendar.timegm(time.strptime(iso[:19], "%Y-%m-%dT%H:%M:%S")) * 1000 + int(iso[20:23] or 0)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, status, text):
        b = text.encode()
        self.send_response(status); self.send_header("content-type", "application/json"); self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        if self.path == "/.well-known/http-message-signatures-directory":
            return self._send(200, json.dumps(SUITE["directory"]))
        self._send(404, "{}")

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        b = json.loads(self.rfile.read(n) or b"{}")
        cc = STATE["case"]["crawlcheck"]
        if self.path != "/api/v1/preflight":
            return self._send(404, "{}")
        STATE["asked"].append(b.get("domain"))
        if "by_op" in cc:
            o = b.get("operation") or {}
            r = cc["by_op"].get("%s %s" % (o.get("method"), o.get("url")))
            return self._send(200, json.dumps(r)) if r else self._send(404, '{"error":"none"}')
        if "by_domain" in cc:
            r = cc["by_domain"].get(b.get("domain"))
            return self._send(200, json.dumps(r)) if r else self._send(404, '{"error":"none"}')
        self._send(cc.get("status", 200), cc["text"] if "text" in cc else json.dumps(cc["body"]))


SRV = ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=SRV.serve_forever, daemon=True).start()
BASE = "http://127.0.0.1:%d" % SRV.server_address[1]
_s = socket.socket(); _s.bind(("127.0.0.1", 0)); DEAD = "http://127.0.0.1:%d" % _s.getsockname()[1]; _s.close()


def make(c):
    def t(self):
        STATE["case"], STATE["asked"] = c, []
        q = c["request"]
        cc = CrawlCheck(base=DEAD if c["crawlcheck"].get("unreachable") else BASE, timeout=5)
        confirm = None if q.get("confirm") is None else (lambda rc, v=q["confirm"]: v)
        kw = dict(allow_warn=q["allow_warn"], confirm=confirm, nonce=q["nonce"], now=ms(q["now"]))
        if q.get("operation") and not q.get("url"):
            kw["operation"] = q["operation"]
        if q.get("url"):
            self.assertTrue(hasattr(cc, "guarded_fetch"), "this package has no guarded fetch, so nothing re-checks redirects")
            fetched, header_to, sites = [], [], c.get("sites") or {}

            def transport(method, url, headers, data):
                fetched.append(url)
                if any(k.lower() == "crawlcheck-receipt" for k in headers):
                    from urllib.parse import urlsplit
                    header_to.append(urlsplit(url).hostname)
                s = sites.get(url)
                if not s:
                    return 404, {}, b"not in fixture"
                return s["status"], ({"Location": s["location"]} if s.get("location") else {}), (s.get("body") or "").encode()
            r = cc.guarded_fetch(q["url"], action=q["action"], max_hops=q["max_hops"], transport=transport, **kw)
            self.assertEqual(r["proceed"], c["expect"]["proceed"], "proceed; why: %s" % r["why"])
            if "fetched" in c["expect"]:
                self.assertEqual(fetched, c["expect"]["fetched"])
            if "fetched_count" in c["expect"]:
                self.assertEqual(len(fetched), c["expect"]["fetched_count"])
            if "receipt_header_to" in c["expect"]:
                self.assertEqual(header_to, c["expect"]["receipt_header_to"])
        else:
            try:
                p, rc = cc.guard(q["domain"], q["action"], **kw)
                why = (getattr(cc, "last_guard", None) or {}).get("why")
            except TypeError:
                raise
            except Exception as e:  # a raise is a refusal: the caller cannot act on it
                p, why = False, [str(e)]
            self.assertEqual(p, c["expect"]["proceed"], "proceed; why: %s" % why)
            if not p:
                self.assertTrue(why, "a refusal says why")
    t.__doc__ = c["id"] + ": " + c["title"]
    return t


class GuardAcceptance(unittest.TestCase):
    pass


for _c in SUITE["cases"]:
    setattr(GuardAcceptance, "test_" + _c["id"].replace("-", "_"), make(_c))

if __name__ == "__main__":
    unittest.main()
