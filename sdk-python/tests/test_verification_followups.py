"""Follow-ups to the fail-closed verifier: the time the signing policy reads, which log heads a client keeps, the command
line's exit status, documents with unusual member names, and what "pinned" means. Same cases as the JS SDK's
test/verification-followups.test.js. Offline except the outside-witness test (it reads the live log): every key here is generated inside the test and thrown away.
CC_SDK_PATH=<dir> runs it against another copy."""
import base64, hashlib, io, json, os, sys, tempfile, unittest
from contextlib import redirect_stdout

if os.environ.get("CC_SDK_PATH"):
    sys.path.insert(0, os.environ["CC_SDK_PATH"])
import crawlcheck  # noqa: E402
from crawlcheck import CrawlCheck, CrawlCheckError, verify_document, canon, key_id, key_policy_from, apply_key_policy, CRAWLCHECK_KEY_IDS  # noqa: E402
from crawlcheck import _ed25519 as E  # noqa: E402
from crawlcheck import log as L  # noqa: E402
from crawlcheck import verify as V  # noqa: E402
from crawlcheck.__main__ import main as cli_main  # noqa: E402
from crawlcheck.verify import _b64u  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
PREFIX = "crawlcheck-data-v1\n"


def _load(*names):
    for p in names:
        if os.path.exists(p):
            with open(p, encoding="utf-8") as fh:
                return json.load(fh)
    raise FileNotFoundError(names[0])


GUARD = _load(os.path.join(HERE, "..", "..", "spec", "guard-acceptance", "cases.json"), os.path.join(HERE, "fixtures", "guard-acceptance.json"))
SPLIT = _load(os.path.join(HERE, "fixtures", "split-view.json"))


def mk():
    seed = os.urandom(32)
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64u(E.public_key(seed))}
    return {"seed": seed, "jwk": jwk, "kid": key_id(jwk)}


def sign(body, key, kid=None, signed_at="2026-11-20T00:00:00Z"):
    """A document in the crawlcheck-data-v1 scheme. signed_at: the (unsigned) signature.signed_at, None to leave it out."""
    sha = hashlib.sha256(canon(body).encode("utf-8")).hexdigest()
    msg = PREFIX + sha
    s = {"v": 1, "alg": "Ed25519", "kid": kid or key["kid"], "message": msg, "key": {"jwk": key["jwk"]}, "sig": _b64u(E.sign(key["seed"], msg.encode()))}
    if signed_at is not None:
        s["signed_at"] = signed_at
    d = dict(body)
    d.update({"sha256": sha, "signature": s})
    return d


DOC, DECISION, LOGKEY, RETIRED, EVIL = mk(), mk(), mk(), mk(), mk()
DIRECTORY = {"keys": [
    dict(DOC["jwk"], crawlcheck_purpose="documents", crawlcheck_signs_from="2026-10-11T00:00:00Z"),
    dict(DECISION["jwk"], crawlcheck_purpose="decisions", crawlcheck_signs_from="2026-11-09T17:00:00Z"),
    dict(LOGKEY["jwk"], crawlcheck_purpose="log heads", crawlcheck_signs_from="2026-11-09T17:00:00Z")]}
ROTATION = {"retired": [{"thumbprint": RETIRED["kid"], "purpose": "documents", "crawlcheck_signs_from": "2026-10-11T00:00:00Z", "stopped_signing_at": "2026-11-01T00:00:00Z"}], "compromised": []}
KP = key_policy_from(DIRECTORY, ROTATION)


def answer(**o):
    return dict({"kind": "crawlcheck-resolve", "v": 1, "domain": "site.example", "status": "measured", "actions": {"read": {"decision": "allow", "doubts": []}}}, **o)


def decision(**o):
    return dict({"kind": "crawlcheck-decision", "v": 1, "domain": "site.example", "action": "read", "decision": "allow", "expires_at": "2099-01-01T00:00:00Z", "resolve": {"sha256": "a" * 64, "kid": DOC["kid"]}}, **o)


def policy(doc):
    return apply_key_policy(verify_document(doc), doc, KP)


def head(key, batch, root, signed_at="2026-11-20T00:00:00Z", created_at="2026-11-20T00:00:00Z"):
    return sign({"kind": "crawlcheck-log-sth", "v": 1, "log_id": "crawlcheck-resolve-log-v1", "batch": batch, "first_index": batch, "batch_size": 1, "tree_size": batch + 1,
                 "batch_root": root, "prev_sth_sha256": "c" * 64 if batch else None, "created_at": created_at}, key, signed_at=signed_at)


class Offline(CrawlCheck):
    """A client whose every request is answered from memory. directory=False: the key directory cannot be read."""
    def __init__(self, extra=None, directory=None, rotation=None, **kw):
        super().__init__(base="https://cc.test", **kw)
        self._extra, self._dir, self._rot = extra or {}, DIRECTORY if directory is None else directory, ROTATION if rotation is None else rotation

    def _req(self, method, path, query=None, body=None):
        if path == "/.well-known/http-message-signatures-directory":
            if self._dir is False:
                raise CrawlCheckError(503, path, {"error": "unreachable in this test"})
            return self._dir
        if path == "/.well-known/security-key-rotation.json":
            return self._rot
        if path in self._extra:
            return self._extra[path]
        raise CrawlCheckError(404, path, {"error": "not in this test"})


class Followups(unittest.TestCase):
    def test_signed_at_cannot_move_a_document_earlier_than_its_signed_body(self):
        v = policy(sign(answer(answered_at="2026-10-20T00:00:00Z"), RETIRED, signed_at="2026-10-20T00:00:00Z"))   # control
        self.assertTrue(v["accepted"])
        self.assertEqual(v["key_policy_code"], "ok")
        v = policy(sign(answer(answered_at="2026-11-20T00:00:00Z"), RETIRED, signed_at="2026-10-20T00:00:00Z"))
        self.assertFalse(v["accepted"], "a retired key must not be accepted for a body dated after it stopped")
        self.assertEqual(v["key_policy_code"], "key_retired")
        v = policy(sign(decision(decided_at="2026-11-20T00:00:00Z"), DOC, signed_at="2026-11-01T00:00:00Z"))
        self.assertFalse(v["accepted"])
        self.assertEqual(v["key_policy_code"], "key_wrong_purpose")
        v = policy(sign(decision(decided_at="2026-11-20T00:00:00Z"), DECISION, signed_at="2026-11-20T00:00:03Z"))   # control
        self.assertTrue(v["accepted"], [c for c in v["checks"] if c["ok"] is False])
        self.assertEqual(V.signed_at_of({"answered_at": "2026-11-20T00:00:00Z", "signature": {"signed_at": "2026-10-20T00:00:00Z"}}), V._kp_ms("2026-11-20T00:00:00Z"))
        self.assertEqual(V.signed_at_of({"generated_at": "2026-11-20T00:00:00Z", "signature": {"signed_at": "2026-11-20T00:00:05Z"}}), V._kp_ms("2026-11-20T00:00:05Z"), "later is allowed")

    def test_a_pass_resting_only_on_the_unsigned_time_is_not_a_pass(self):
        v = policy(sign(decision(), DOC, signed_at="2026-11-01T00:00:00Z"))
        self.assertIs(v["key_policy_valid"], False)
        self.assertEqual(v["key_policy_code"], "no_signing_time")
        self.assertFalse(v["accepted"])
        v = policy(sign({"kind": "crawlcheck-claims", "v": 1, "domain": "site.example"}, RETIRED, signed_at="2026-10-20T00:00:00Z"))
        self.assertIs(v["key_policy_valid"], False)
        self.assertEqual(v["key_policy_code"], "no_signing_time")
        self.assertIs(v["accepted"], False, "not accepted, whatever signed_at says")
        self.assertFalse(v["accepted_strict"])
        v = policy(sign({"kind": "crawlcheck-claims", "v": 1, "domain": "site.example"}, DOC, signed_at="2026-11-20T00:00:00Z"))   # control
        self.assertIs(v["key_policy_valid"], True)
        self.assertTrue(v["accepted"])
        v = policy(head(DOC, 3, "d" * 64, signed_at="2026-11-01T00:00:00Z", created_at="2026-11-01T00:00:00Z"))
        self.assertIs(v["key_policy_valid"], True, "a documents key signed log heads before the log-head key started")
        v = policy(head(DOC, 3, "d" * 64, signed_at="2026-11-01T00:00:00Z", created_at="2026-11-20T00:00:00Z"))
        self.assertIs(v["key_policy_valid"], False, "and not after, whatever signed_at says")
        self.assertEqual(v["key_policy_code"], "key_wrong_purpose")

    def test_the_client_keeps_a_head_only_when_a_published_log_key_signed_it(self):
        cc = Offline()
        fa, fb = head(EVIL, 7, "a" * 64), head(EVIL, 7, "b" * 64)
        g = cc.log_gossip([fa, fb])
        self.assertEqual([r["state"] for r in g["results"]], ["invalid", "invalid"])
        self.assertEqual((len(g["forks"]), len(cc.log["forks"]), len(cc.log["heads"])), (0, 0, 0), "two self-signed heads are not a fork, and neither is kept")
        self.assertEqual(len(cc.log_ignored), 2)
        self.assertEqual(cc.log_ignored[0]["batch"], 7)

        def with_head(sth):
            return sign(answer(answered_at="2026-11-20T00:00:00Z", transparency={"state": "included", "sth": sth}), DOC)
        c2 = Offline({"/api/v1/resolve": with_head(fa)})
        c2.resolve("site.example")
        self.assertEqual(len(c2.log["heads"]), 0, "resolve() must not keep a head from an unknown key")
        self.assertEqual(len(c2.log_ignored), 1)
        good = head(LOGKEY, 7, "e" * 64)
        c3 = Offline({"/api/v1/resolve": with_head(good)})
        c3.resolve("site.example")
        self.assertEqual(c3.log["heads"]["7"]["sha256"], good["sha256"])
        self.assertIs(c3.log["heads"]["7"]["issuer_checked"], True)
        c3.log_gossip([fa])
        self.assertEqual(len(c3.log["forks"]), 0)
        self.assertEqual(c3.log_gossip([head(DECISION, 9, "f" * 64)])["results"][0]["state"], "invalid", "a published key of another purpose")
        g2 = c3.log_gossip([head(LOGKEY, 7, "9" * 64)])
        self.assertEqual(len(g2["forks"]), 1)
        self.assertIs(g2["forks"][0]["issuer_checked"], True)
        c4 = Offline(directory=False)   # the directory cannot be read: the ids this release ships, never "any key"
        self.assertEqual(c4.log_gossip([good])["results"][0]["state"], "invalid")
        self.assertEqual(len(c4.log["heads"]), 0)

    def test_unchecked_heads_have_no_standing_and_a_saved_store_is_rechecked(self):
        a, b, real = head(EVIL, 4, "a" * 64), head(EVIL, 4, "b" * 64), head(LOGKEY, 4, "e" * 64)
        bare = L.new_log_store()
        L.log_observe(bare, a)
        f = L.log_observe(bare, b)
        self.assertEqual(f["state"], "fork")
        self.assertIs(f["fork"]["issuer_checked"], False)
        self.assertIn("NOT checked", f["fork"]["proof"])
        mixed = L.new_log_store()
        L.log_observe(mixed, a)
        self.assertEqual(L.log_observe(mixed, real, key_policy=KP)["state"], "new")
        self.assertEqual((len(mixed["forks"]), mixed["heads"]["4"]["sha256"]), (0, real["sha256"]))
        self.assertEqual(L.log_observe(mixed, b)["state"], "invalid")
        self.assertEqual(len(mixed["forks"]), 0)
        self.assertEqual(L.log_prune(bare, key_policy=KP), {"forks_dropped": 1, "heads_dropped": 1})
        two = L.new_log_store()
        L.log_observe(two, real)
        L.log_observe(two, head(LOGKEY, 4, "9" * 64))
        L.log_prune(two, key_policy=KP)
        self.assertEqual(len(two["forks"]), 1)
        self.assertIs(two["forks"][0]["issuer_checked"], True)
        with self.assertRaises(ValueError):
            L.log_prune(L.new_log_store())
        planted = L.new_log_store()
        L.log_observe(planted, a)
        L.log_observe(planted, b)
        self.assertEqual(len(planted["forks"]), 1)
        c = next(x for x in GUARD["cases"] if x["id"] == "allow")
        q = c["request"]
        cc = Offline({"/api/v1/preflight": c["crawlcheck"]["body"]}, directory=GUARD["directory"], rotation=GUARD["rotation"], log_store=planted)
        ok, _rc = cc.guard(q["domain"], q["action"], nonce=q["nonce"], now=V._kp_ms(q["now"]))
        self.assertTrue(ok, cc.last_guard.get("why"))
        self.assertEqual(len(planted["forks"]), 0)

    def test_command_line_exits_zero_only_when_accepted(self):
        class Fake(Offline):
            def __init__(self, **kw):
                super().__init__({"/api/v1/preflight": Followups.receipt})
        real_cc, crawlcheck.__main__.CrawlCheck = crawlcheck.__main__.CrawlCheck, Fake
        try:
            for doc, want, label in ((sign(decision(decided_at="2026-11-20T00:00:00Z"), EVIL), 1, "a receipt nobody at CrawlCheck signed"),
                                     (sign(decision(decided_at="2026-11-20T00:00:00Z"), DECISION), 0, "a receipt the decisions key signed")):
                Followups.receipt = doc
                out = io.StringIO()
                with redirect_stdout(out):
                    code = cli_main(["preflight", "site.example", "read"])
                self.assertEqual(code, want, label + ": " + out.getvalue())
                self.assertEqual("NOT ACCEPTED" in out.getvalue(), want == 1, label)
                with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
                    json.dump(doc, fh)
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(cli_main(["verify", fh.name]), want, "verify: " + label)
                os.unlink(fh.name)
        finally:
            crawlcheck.__main__.CrawlCheck = real_cc

    def test_every_member_is_hashed_whatever_its_name(self):
        signed = sign(answer(answered_at="2026-11-20T00:00:00Z"), DOC)
        self.assertTrue(verify_document(signed, KP["kids"])["accepted"])
        text = json.dumps(signed)
        for member in ('"__proto__":{"admin":true}', '"constructor":{"prototype":{"x":1}}', '"toString":"x"', '"hasOwnProperty":1'):
            v = verify_document(json.loads("{" + member + "," + text[1:]), KP["kids"])
            self.assertIs(next(c["ok"] for c in v["checks"] if c["id"] == "document_hash"), False, member)
            self.assertFalse(v["accepted"], member)
        # duplicate members: the parser keeps the last one, and that is the one that is hashed (as in JavaScript)
        self.assertFalse(verify_document(json.loads(text[:-1] + ',"domain":"other.example"}'), KP["kids"])["accepted"])
        self.assertTrue(verify_document(json.loads('{"domain":"other.example",' + text[1:]), KP["kids"])["accepted"])
        odd = json.loads('{"kind":"crawlcheck-claims","v":1,"domain":"site.example","generated_at":"2026-11-20T00:00:00Z","__proto__":{"a":1},"constructor":"c","nested":{"__proto__":{"b":2},"constructor":{"d":3}}}')
        ok = sign(odd, DOC)
        self.assertTrue(verify_document(ok, KP["kids"])["accepted"])
        ok["__proto__"] = {"a": 2}
        self.assertFalse(verify_document(ok, KP["kids"])["accepted"])
        # the canonical bytes of such a document are the ones the JavaScript verifier hashes
        self.assertEqual(canon(odd), '{"__proto__":{"a":1},"constructor":"c","domain":"site.example","generated_at":"2026-11-20T00:00:00Z","kind":"crawlcheck-claims","nested":{"__proto__":{"b":2},"constructor":{"d":3}},"v":1}')

    def test_pinned_means_a_verifying_signature_and_key_ids_still_carry_purposes(self):
        named = sign(answer(answered_at="2026-11-20T00:00:00Z"), EVIL, kid=CRAWLCHECK_KEY_IDS[1])
        self.assertIs(verify_document(named)["issuer_pinned"], False, "a claimed key id is not a pinned issuer")
        lock = _load(os.path.join(HERE, "..", "..", "sdk", "test", "fixtures", "lock-signed.json"), os.path.join(HERE, "fixtures", "lock-signed.json")) if any(
            os.path.exists(p) for p in (os.path.join(HERE, "..", "..", "sdk", "test", "fixtures", "lock-signed.json"), os.path.join(HERE, "fixtures", "lock-signed.json"))) else None
        if lock is not None:
            v = verify_document(lock)
            self.assertIs(v["issuer_pinned"], True)
            self.assertFalse(v["accepted"], "offline is never accepted")
            v = verify_document(lock, list(CRAWLCHECK_KEY_IDS))
            self.assertTrue(v["accepted"])
            self.assertFalse(any(c["id"] == "key_purpose" for c in v["checks"]), "nothing is added when the purpose fits")
        pin = crawlcheck.pinned_key_policy()
        self.assertEqual(sorted(pin["kids"]), sorted(CRAWLCHECK_KEY_IDS))
        self.assertEqual(crawlcheck.pinned_key_policy([CRAWLCHECK_KEY_IDS[0], "unknown"])["kids"], [CRAWLCHECK_KEY_IDS[0]])
        log_kid = next(k for k in pin["kids"] if pin["keys"][k]["purpose"] == "log heads")
        wrong = sign(decision(decided_at="2026-11-20T00:00:00Z"), EVIL, kid=log_kid)
        r = verify_document(wrong, list(CRAWLCHECK_KEY_IDS))
        kpur = next((c for c in r["checks"] if c["id"] == "key_purpose"), None)
        self.assertTrue(kpur is not None and kpur["ok"] is False, "key ids only must still apply the purposes of the ids this release knows")
        self.assertEqual(r["key_policy_code"], "key_wrong_purpose")
        self.assertFalse(r["accepted"])

    def test_witness_identity_is_recognised_without_naming_it(self):
        # The witness states its identity in the token the live log serves; the fixture's token names an example repository.
        import urllib.request
        def get(url):
            with urllib.request.urlopen(urllib.request.Request(url, headers={"user-agent": "crawlcheck-selftest sdk-python-tests", "accept": "application/json"}), timeout=30) as r:
                return json.loads(r.read().decode("utf-8"))
        self.assertIs(L.verify_witness_token(SPLIT["witness"]["token"], SPLIT["A"][2]["sha256"], SPLIT["jwks"])["ok"], False, "an example repository is not the witness")
        live = get("https://crawlcheck.io/api/v1/log/witness/latest")
        tok = live["token"]
        p = tok.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
        self.assertIs(L.verify_witness_token(tok, live["sth_sha256"], get(L.GITHUB_OIDC_JWKS))["ok"], True)
        with open(L.__file__, encoding="utf-8") as fh:
            self.assertNotIn(str(claims["repository"]), fh.read(), "log.py names the witness repository")
        self.assertEqual(L._sha256_hex(claims["repository"]), L._WITNESS_REPOSITORY_SHA256)
        ref = str(claims["job_workflow_ref"])
        self.assertEqual(L._sha256_hex(ref[:ref.find("@refs/heads/")]), L._WITNESS_WORKFLOW_SHA256)


if __name__ == "__main__":
    unittest.main()
