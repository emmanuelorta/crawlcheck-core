"""Release audit additions to the fail-closed verifier: a document whose signed body states no time, and a listed key
id this release does not ship. Same cases as the JS SDK's test/verification-audit.test.js. Offline only: every key here
is generated inside the test and thrown away. CC_SDK_PATH=<dir> runs it against another copy."""
import hashlib, json, os, sys, time, unittest

if os.environ.get("CC_SDK_PATH"):
    sys.path.insert(0, os.environ["CC_SDK_PATH"])
from crawlcheck import CrawlCheck, CrawlCheckError, verify_document, canon, key_id, key_policy_from, apply_key_policy, pinned_key_policy, CRAWLCHECK_KEY_IDS  # noqa: E402
from crawlcheck import _ed25519 as E  # noqa: E402
from crawlcheck import log as L  # noqa: E402
from crawlcheck.continuity import verify_lock_baseline  # noqa: E402
from crawlcheck.verify import _b64u  # noqa: E402

PREFIX = "crawlcheck-data-v1\n"
BACK = "2026-10-20T00:00:00Z"   # inside both retired keys' signing windows


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def mk():
    seed = os.urandom(32)
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64u(E.public_key(seed))}
    return {"seed": seed, "jwk": jwk, "kid": key_id(jwk)}


def sign(body, key, signed_at="now"):
    """signed_at: the (unsigned) signature.signed_at; None leaves it out."""
    sha = hashlib.sha256(canon(body).encode("utf-8")).hexdigest()
    msg = PREFIX + sha
    s = {"v": 1, "alg": "Ed25519", "kid": key["kid"], "message": msg, "key": {"jwk": key["jwk"]}, "sig": _b64u(E.sign(key["seed"], msg.encode()))}
    if signed_at is not None:
        s["signed_at"] = iso(time.time()) if signed_at == "now" else signed_at
    d = dict(body)
    d.update({"sha256": sha, "signature": s})
    return d


DOC, DECISION, LOGKEY, RETIRED_DOC, RETIRED_LOG, FIFTH = mk(), mk(), mk(), mk(), mk(), mk()
DIRECTORY = {"keys": [
    dict(DOC["jwk"], crawlcheck_purpose="documents", crawlcheck_signs_from="2026-10-11T00:00:00Z"),
    dict(DECISION["jwk"], crawlcheck_purpose="decisions", crawlcheck_signs_from="2026-11-09T17:00:00Z"),
    dict(LOGKEY["jwk"], crawlcheck_purpose="log heads", crawlcheck_signs_from="2026-11-09T17:00:00Z")]}
ROTATION = {"retired": [
    {"thumbprint": RETIRED_DOC["kid"], "purpose": "documents", "crawlcheck_signs_from": "2026-10-11T00:00:00Z", "stopped_signing_at": "2026-11-01T00:00:00Z"},
    {"thumbprint": RETIRED_LOG["kid"], "purpose": "log heads", "crawlcheck_signs_from": "2026-10-11T00:00:00Z", "stopped_signing_at": "2026-11-01T00:00:00Z"}], "compromised": []}
KP = key_policy_from(DIRECTORY, ROTATION)


def claims(**o):
    return dict({"kind": "crawlcheck-claims", "v": 1, "domain": "site.example"}, **o)


def answer(**o):
    return dict({"kind": "crawlcheck-resolve", "v": 1, "domain": "site.example", "status": "measured", "actions": {"read": {"decision": "allow", "doubts": []}}}, **o)


def decision(**o):
    return dict({"kind": "crawlcheck-decision", "v": 1, "domain": "site.example", "action": "read", "decision": "allow", "expires_at": "2099-01-01T00:00:00Z", "resolve": {"sha256": "a" * 64, "kid": DOC["kid"]}}, **o)


def head(key, batch, signed_at="now", created_at="now"):
    b = {"kind": "crawlcheck-log-sth", "v": 1, "log_id": "crawlcheck-resolve-log-v1", "batch": batch, "first_index": batch, "batch_size": 1, "tree_size": batch + 1,
         "batch_root": "a" * 64, "prev_sth_sha256": "c" * 64 if batch else None}
    if created_at is not None:
        b["created_at"] = iso(time.time()) if created_at == "now" else created_at
    return sign(b, key, signed_at=signed_at)


def policy(doc):
    return apply_key_policy(verify_document(doc), doc, KP)


class Offline(CrawlCheck):
    """A client whose every request is answered from memory."""
    def __init__(self, signer=None, **kw):
        super().__init__(base="https://cc.test", **kw)
        self._signer = signer

    def _req(self, method, path, query=None, body=None):
        if path == "/.well-known/http-message-signatures-directory":
            return DIRECTORY
        if path == "/.well-known/security-key-rotation.json":
            return ROTATION
        if path == "/api/v1/preflight" and self._signer:
            q = body or query or {}
            return sign(decision(domain=q.get("domain"), action=q.get("action"), nonce=q.get("nonce"), decided_at=iso(time.time() - 2), expires_at=iso(time.time() + 120), steps=[]), self._signer)
        raise CrawlCheckError(404, path, {"error": "not in this test"})


class Audit(unittest.TestCase):
    def test_no_time_in_the_signed_body_never_rests_on_the_unsigned_field(self):
        for signed_at in (BACK, None):   # set back into the key's window, and left out: neither may carry the document
            for label, doc in (("a document under a retired key", sign(claims(), RETIRED_DOC, signed_at)),
                               ("a Resolve answer under a retired key", sign(answer(), RETIRED_DOC, signed_at)),
                               ("a decision under a retired key", sign(decision(), RETIRED_DOC, signed_at)),
                               ("a decision under the documents key", sign(decision(), DOC, signed_at)),
                               ("a document under the log-head key", sign(claims(), LOGKEY, signed_at)),
                               ("a document under the decisions key", sign(claims(), DECISION, signed_at))):
                v, w, at = policy(doc), Offline().verify(doc), " (signed_at %s)" % signed_at
                self.assertIs(v["accepted"], False, label + at)
                self.assertIs(v["key_policy_valid"], False, label + at)
                self.assertIs(w["accepted"], False, label + ", through the client" + at)
            for label, key in (("a retired log-head key", RETIRED_LOG), ("a retired documents key", RETIRED_DOC), ("the documents key", DOC), ("the decisions key", DECISION)):
                h, st = head(key, 40, signed_at=signed_at, created_at=None), L.new_log_store()
                self.assertEqual(L.log_observe(st, h, key_policy=KP)["state"], "invalid", "a head with no created_at under " + label)
                self.assertEqual(len(st["heads"]), 0)
                cc = Offline()
                self.assertEqual(cc.log_gossip([h])["results"][0]["state"], "invalid")
                self.assertEqual(len(cc.log["heads"]), 0, "the client keeps nothing")
                self.assertEqual(len(cc.log_ignored), 1)
            lock = sign({"kind": "crawlcheck-mcp-lock", "v": 1, "server": {"url": "https://mcp.site.example/mcp"}, "tools": [{"name": "a", "sha256": "b" * 64}], "tools_sha256": "c" * 64}, RETIRED_DOC, signed_at)
            self.assertEqual(verify_lock_baseline(lock, key_policy=KP)["trust"], "invalid")
        # controls: nothing changes for a key the policy accepts now, nor for a retired key whose document states its time in the body
        v = policy(sign(claims(), DOC))
        self.assertIs(v["accepted"], True)
        self.assertIs(v["key_policy_valid"], True)
        v = policy(sign(claims(), DOC, signed_at=None))
        self.assertIs(v["accepted"], True, "a live key of the right purpose, no time anywhere: accepted, partial")
        self.assertFalse(v["accepted_strict"])
        v = policy(sign(claims(generated_at=BACK), RETIRED_DOC, BACK))
        self.assertIs(v["accepted"], True, "a retired key, body time inside its window")
        self.assertEqual(v["key_policy_code"], "ok")
        self.assertEqual(L.log_observe(L.new_log_store(), head(LOGKEY, 5), key_policy=KP)["state"], "new")
        ok, _rc = Offline(signer=DECISION).guard("site.example", "read")   # a decision the service really makes still passes guard
        self.assertTrue(ok)

    def test_a_listed_key_id_this_release_does_not_ship_has_no_known_purpose(self):
        kids = list(CRAWLCHECK_KEY_IDS) + [FIFTH["kid"]]
        d = sign(decision(decided_at=iso(time.time() - 2), resolve={"sha256": "a" * 64, "kid": CRAWLCHECK_KEY_IDS[1]}), FIFTH)
        v = verify_document(d, kids)
        self.assertIs(v["accepted"], True, "the caller listed the key: accepted")
        self.assertIs(v["accepted_strict"], False, "but never strict")
        self.assertEqual(v["assurance"], "partial")
        self.assertIsNone(v["key_policy_valid"])
        self.assertEqual(v["key_policy_code"], "purpose_unknown")
        c = next(x for x in v["checks"] if x["id"] == "key_purpose")
        self.assertIsNone(c["ok"])
        self.assertIn("key policy", c["why"])
        self.assertIs(verify_document(d, list(CRAWLCHECK_KEY_IDS))["accepted"], False, "not on the list: refused as before")
        st = L.new_log_store()
        r = L.log_observe(st, head(FIFTH, 3), published_kids=kids)   # a log head under such a key is not kept on its id alone
        self.assertEqual(r["state"], "invalid")
        self.assertIn("key_policy", r["why"])
        self.assertEqual(len(st["heads"]), 0)
        named = pinned_key_policy()
        named["keys"][FIFTH["kid"]] = {"purpose": "log heads", "start": 0}
        named["kids"].append(FIFTH["kid"])
        self.assertEqual(L.log_observe(L.new_log_store(), head(FIFTH, 3), key_policy=named)["state"], "new", "control: the policy says what the key signs")

    def test_canonical_member_order_is_utf16_code_units(self):
        self.assertEqual(canon(json.loads('{"\\uffff":1,"\\ud83d\\ude00":2,"a":3}')), '{"a":3,"\U0001f600":2,"￿":1}')
        self.assertEqual(canon({"b": 1, "a": {"10": 1, "9": 2, "é": 3, "z": 4}}), '{"a":{"10":1,"9":2,"z":4,"é":3},"b":1}')


if __name__ == "__main__":
    unittest.main()
