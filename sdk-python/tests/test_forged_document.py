"""Forged signed documents must be refused: every acceptance field fails closed when the signature was not actually
checked against a key CrawlCheck publishes. Offline only: every key here is generated inside the test and thrown away.
Same cases as the JS SDK's test/forged-document.test.js. CC_SDK_PATH=<dir> runs it against another copy."""
import copy, hashlib, io, json, os, sys, tempfile, unittest
from contextlib import redirect_stdout

if os.environ.get("CC_SDK_PATH"):
    sys.path.insert(0, os.environ["CC_SDK_PATH"])
import crawlcheck  # noqa: E402
from crawlcheck import CrawlCheck, CrawlCheckError, verify_document, canon, key_id, key_policy_from, apply_key_policy  # noqa: E402
from crawlcheck import _ed25519 as E  # noqa: E402
from crawlcheck.log import new_log_store, log_observe  # noqa: E402
from crawlcheck.tools import agent_tools  # noqa: E402
from crawlcheck.verify import _b64u, log_leaf  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD = json.load(open([p for p in (os.path.join(HERE, "..", "..", "spec", "guard-acceptance", "cases.json"), os.path.join(HERE, "fixtures", "guard-acceptance.json")) if os.path.exists(p)][0]))
PREFIX = "crawlcheck-data-v1\n"


def mk():
    seed = os.urandom(32)
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64u(E.public_key(seed))}
    return {"seed": seed, "jwk": jwk, "kid": key_id(jwk)}


def sign(body, key, kid=None, with_key=True, sig=True, signed_at="2026-11-20T00:00:00Z"):
    """A document in the crawlcheck-data-v1 scheme. kid: the key id it claims; with_key False leaves the public key out
    (a dict puts that key in instead); sig: a string in place of the signature, False to leave it out."""
    sha = hashlib.sha256(canon(body).encode("utf-8")).hexdigest()
    msg = PREFIX + sha
    s = {"v": 1, "alg": "Ed25519", "kid": kid or key["kid"], "message": msg, "signed_at": signed_at}
    if with_key is not False:
        s["key"] = {"jwk": with_key if isinstance(with_key, dict) else key["jwk"]}
    if sig is not False:
        s["sig"] = sig if isinstance(sig, str) else _b64u(E.sign(key["seed"], msg.encode()))
    d = dict(body)
    d.update({"sha256": sha, "signature": s})
    return d


REAL, EVIL, DECISION, LOGKEY, RETIRED, BURNT = mk(), mk(), mk(), mk(), mk(), mk()
DIRECTORY = {"keys": [
    dict(REAL["jwk"], crawlcheck_purpose="documents", crawlcheck_signs_from="2026-10-11T00:00:00Z"),
    dict(DECISION["jwk"], crawlcheck_purpose="decisions", crawlcheck_signs_from="2026-11-09T17:00:00Z"),
    dict(LOGKEY["jwk"], crawlcheck_purpose="log heads", crawlcheck_signs_from="2026-11-09T17:00:00Z"),
    dict(BURNT["jwk"], crawlcheck_purpose="documents", crawlcheck_signs_from="2026-10-11T00:00:00Z")]}
ROTATION = {"retired": [{"thumbprint": RETIRED["kid"], "purpose": "documents", "crawlcheck_signs_from": "2026-10-11T00:00:00Z", "stopped_signing_at": "2026-11-01T00:00:00Z"}],
            "compromised": [{"thumbprint": BURNT["kid"], "compromised_since": "2026-11-15T00:00:00Z"}]}
KIDS = [REAL["kid"], DECISION["kid"], LOGKEY["kid"]]
KP = key_policy_from(DIRECTORY, ROTATION)


def answer(domain="victim.example"):
    return {"kind": "crawlcheck-resolve", "v": 1, "domain": domain, "status": "measured",
            "actions": {"read": {"decision": "allow", "doubts": []}, "transact": {"decision": "allow", "doubts": []}},
            "freshness": {"observed_at": "2026-11-20T00:00:00Z", "fresh_until": "2099-01-01T00:00:00Z"}}


class Offline(CrawlCheck):
    """A client whose every request is answered from memory: the key directory, the rotation record, and any extra path."""
    def __init__(self, extra=None, directory=None, rotation=None):
        super().__init__(base="https://cc.test")
        self._extra, self._dir, self._rot = extra or {}, directory or DIRECTORY, rotation or ROTATION

    def _req(self, method, path, query=None, body=None):
        if path == "/.well-known/http-message-signatures-directory":
            return self._dir
        if path == "/.well-known/security-key-rotation.json":
            return self._rot
        if path in self._extra:
            return self._extra[path]
        raise CrawlCheckError(404, path, {"error": "not in this test"})


def every_path(doc):
    """Every way this package can be asked "is this document CrawlCheck's?"."""
    return {"offline": verify_document(doc), "kids": verify_document(doc, KIDS),
            "policy": apply_key_policy(verify_document(doc, KP["kids"]), doc, KP), "client": Offline().verify(doc)}


class Forged(unittest.TestCase):
    def refused(self, r, label):
        for path, v in r.items():
            self.assertIsNot(v.get("accepted"), True, "%s / %s: accepted" % (label, path))
            self.assertIsNot(v.get("accepted_strict"), True, "%s / %s: accepted_strict" % (label, path))
            if path != "offline":
                self.assertIs(v["verified"], False, "%s / %s: verified" % (label, path))

    def test_control_genuine_answer(self):
        r = every_path(sign(answer(), REAL))
        self.assertIs(r["offline"]["verified"], True)
        self.assertIs(r["offline"]["accepted"], False)
        self.assertIsNone(r["offline"]["issuer_trusted"])
        for p in ("kids", "policy", "client"):
            for k in ("verified", "accepted", "integrity_valid", "issuer_trusted"):
                self.assertIs(r[p][k], True, "%s %s" % (p, k))
        self.assertIs(r["client"]["key_policy_valid"], True)

    def test_foreign_key_transparency_removed(self):
        doc = sign(answer(), EVIL)   # self-consistent: the foreign key, its own key id, no transparency field
        self.assertNotIn("transparency", doc)
        r = every_path(doc)
        self.refused(r, "foreign key")
        self.assertIs(r["offline"]["accepted"], False, "offline is never accepted")
        self.assertIs(r["offline"]["issuer_pinned"], False, "offline, the key is not one this release knows as CrawlCheck's")
        self.assertIs(r["kids"]["issuer_trusted"], False)
        self.assertIs(r["client"]["issuer_trusted"], False)

    def test_foreign_key_is_not_verified_by_the_agent_tool(self):
        doc = dict(sign({"kind": "crawlcheck-field-check", "v": 1, "domain": "victim.example", "field": "phone", "value": "555", "result": "match", "at": "2026-11-20T00:00:00Z"}, EVIL))
        cc = Offline()
        cc.field_check = lambda domain, field, value: doc
        tool = [t for t in agent_tools(cc) if t["name"] == "crawlcheck_verify_fact"][0]
        out = tool["execute"]({"site": "victim.example", "field": "phone", "value": "555"})
        self.assertIs(out["verified"], False, "a document signed by somebody else is not verified")
        good = dict(sign({"kind": "crawlcheck-field-check", "v": 1, "domain": "victim.example", "field": "phone", "value": "555", "result": "match", "at": "2026-11-20T00:00:00Z"}, REAL))
        cc.field_check = lambda domain, field, value: good
        self.assertIs(tool["execute"]({"site": "victim.example", "field": "phone", "value": "555"})["verified"], True, "control: CrawlCheck's own key")

    def test_command_line_refuses_a_forged_file(self):
        from crawlcheck import __main__ as M
        real_cls = M.CrawlCheck
        M.CrawlCheck = Offline
        try:
            for doc, want in ((sign(answer(), EVIL), 1), (sign(answer(), EVIL, kid=REAL["kid"], with_key=False), 1), (sign(answer(), REAL), 0)):
                with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
                    json.dump(doc, f)
                try:
                    with redirect_stdout(io.StringIO()):
                        self.assertEqual(M.main(["verify", f.name]), want)
                finally:
                    os.unlink(f.name)
        finally:
            M.CrawlCheck = real_cls

    def test_published_kid_but_no_key(self):
        r = every_path(sign(answer(), EVIL, kid=REAL["kid"], with_key=False))
        self.refused(r, "no key")
        for p in ("kids", "policy", "client"):
            self.assertIs(r[p]["integrity_valid"], False, p)
        self.assertIs(r["offline"]["verified"], False, "nothing was verified")

    def test_published_kid_no_key_no_signature(self):
        r = every_path(sign(answer(), EVIL, kid=REAL["kid"], with_key=False, sig=False))
        self.refused(r, "no key, no sig")
        self.assertIs(r["offline"]["verified"], False)
        self.assertIs(r["client"]["integrity_valid"], False)

    def test_real_public_key_but_missing_or_malformed_signature(self):
        for sig in (False, "", "!!!not-base64!!!", "AAAA", "A"):
            r = every_path(sign(answer(), EVIL, kid=REAL["kid"], with_key=REAL["jwk"], sig=sig))
            self.refused(r, "sig %r" % (sig,))
            for p in r:
                self.assertIs(r[p]["verified"], False, "%s verified, sig %r" % (p, sig))
                self.assertIs(r[p]["integrity_valid"], False, "%s integrity_valid, sig %r" % (p, sig))

    def test_malformed_key_or_signature_fields_never_raise_into_acceptance(self):
        base = sign(answer(), REAL)
        for mutate in (lambda s: s.update(sig=12345), lambda s: s.update(sig=None), lambda s: s.update(sig=["x"]), lambda s: s.update(key="x"), lambda s: s.update(key={"jwk": "x"}),
                       lambda s: s.update(key={"jwk": {"kty": "OKP", "crv": "Ed25519", "x": 5}}), lambda s: s.update(key={"jwk": {"x": REAL["jwk"]["x"]}}), lambda s: s.update(key={"jwk": {"kty": "OKP", "crv": "Ed25519", "x": "A"}})):
            doc = copy.deepcopy(base)
            mutate(doc["signature"])
            for kids in (None, KIDS):
                try:
                    v = verify_document(doc, kids)
                except ValueError:
                    continue   # refused outright
                self.assertIsNot(v["accepted"], True)
                self.assertIs(v["verified"], False)

    def test_wrong_key_under_published_kid(self):
        r = every_path(sign(answer(), EVIL, kid=REAL["kid"]))
        self.refused(r, "wrong key")
        self.assertIs(next(c["ok"] for c in r["offline"]["checks"] if c["id"] == "key_id"), False)

    def test_unknown_key_id(self):
        r = every_path(sign(answer(), EVIL))
        self.refused(r, "unknown kid")
        self.assertIs(next(c["ok"] for c in r["client"]["checks"] if c["id"] == "key_published"), False)

    def test_tampered_payload(self):
        doc = sign(answer(), REAL)
        doc["actions"]["transact"]["decision"] = "block"
        r = every_path(doc)
        self.refused(r, "tampered")
        self.assertIs(r["offline"]["verified"], False)

    def test_signature_replayed_on_another_domain(self):
        a = sign(answer("good.example"), REAL)
        b = dict(answer("victim.example"), sha256=a["sha256"], signature=a["signature"])
        self.refused(every_path(b), "replay, stated digest kept")
        c = dict(answer("victim.example"), signature=a["signature"])
        c["sha256"] = hashlib.sha256(canon(answer("victim.example")).encode()).hexdigest()
        r = every_path(c)
        self.refused(r, "replay, digest recomputed")
        self.assertIs(r["offline"]["verified"], False)

    def test_wrong_key_purpose(self):
        decision = {"kind": "crawlcheck-decision", "v": 1, "domain": "victim.example", "action": "read", "decision": "allow", "decided_at": "2026-11-20T00:00:00Z", "resolve": {"sha256": "b" * 64, "kid": REAL["kid"]}}
        for doc, label in ((sign(decision, LOGKEY), "log-head key on a decision"), (sign(decision, REAL), "document key on a decision"), (sign(answer(), DECISION), "decision key on an answer")):
            for v in (apply_key_policy(verify_document(doc, KP["kids"]), doc, KP), Offline().verify(doc)):
                self.assertIs(v["accepted"], False, label)
                self.assertIs(v["key_policy_valid"], False, label)
                self.assertEqual(v["key_policy_code"], "key_wrong_purpose", label)
        self.assertIs(Offline().verify(sign(decision, DECISION))["accepted"], True, "control: the decision key signs a decision")

    def test_retired_and_compromised_keys(self):
        late = Offline().verify(sign(answer(), RETIRED, signed_at="2026-11-20T00:00:00Z"))
        self.assertIs(late["accepted"], False)
        self.assertEqual(late["key_policy_code"], "key_retired")
        self.assertIs(Offline().verify(sign(dict(answer(), answered_at="2026-10-20T00:00:00Z"), RETIRED, signed_at="2026-10-20T00:00:00Z"))["accepted"], True, "control: inside the retired key's window (the time is inside the signed body)")
        for at in ("2026-11-20T00:00:00Z", "2026-11-01T00:00:00Z"):
            v = Offline().verify(sign(answer(), BURNT, signed_at=at))
            self.assertIs(v["accepted"], False, at)
            self.assertEqual(v["key_policy_code"], "key_compromised", at)

    def test_missing_transparency_lowers_assurance(self):
        v = Offline().verify(sign(answer(), REAL))
        self.assertIs(v["accepted"], True)
        self.assertIs(v["accepted_strict"], False, "no proof of the answer's place in the log")
        self.assertEqual(v["assurance"], "partial")
        c = [x for x in v["checks"] if x["id"] == "log_inclusion"]
        self.assertTrue(c and c[0]["ok"] is None, "log_inclusion is reported as not run")
        for t in (None, False, 0, "", {}):
            w = verify_document(sign(dict(answer(), transparency=t), REAL), KIDS)
            self.assertIsNot(w.get("accepted_strict"), True, "transparency %r" % (t,))

    def _with_head(self, sth):
        body = answer()
        return sign(dict(body, transparency={"log": "crawlcheck-resolve-log-v1", "state": "included", "leaf_hash": log_leaf(body), "index": 0, "batch": 0, "batch_size": 1, "path": [], "sth": sth}), REAL)

    def _head(self, key, root=None, **o):
        return sign({"kind": "crawlcheck-log-sth", "v": 1, "log_id": "crawlcheck-resolve-log-v1", "batch": 0, "first_index": 0, "batch_size": 1, "tree_size": 1,
                     "batch_root": root or log_leaf(answer()), "prev_sth_sha256": None, "created_at": "2026-11-20T00:00:00Z"}, key, **o)

    def test_transparency_log_head_never_signed(self):
        good = Offline().verify(self._with_head(self._head(LOGKEY)))
        self.assertIs(good["accepted"], True, good["checks"])
        self.assertIs(good["accepted_strict"], True, "control: a complete proof under the log key")
        for sth, label in ((self._head(EVIL, kid=LOGKEY["kid"], with_key=False), "head without a key"), (self._head(EVIL, kid=LOGKEY["kid"], with_key=False, sig=False), "head without key or signature"),
                           (self._head(EVIL), "head under a foreign key")):
            v = Offline().verify(self._with_head(sth))
            self.assertIs(v["accepted"], False, label)
            self.assertIs(v["verified"], False, label)

    def test_unsigned_log_head_cannot_plant_a_fork(self):
        store = new_log_store()
        for root in ("a" * 64, "b" * 64):
            self.assertEqual(log_observe(store, self._head(EVIL, root=root, kid=LOGKEY["kid"], with_key=False), KIDS)["state"], "invalid")
        self.assertEqual(len(store["forks"]), 0)
        self.assertEqual(log_observe(new_log_store(), self._head(EVIL, root="a" * 64, kid=LOGKEY["kid"], with_key=False))["state"], "invalid", "without a key list either")

    def test_guard_refuses_a_receipt_never_signed(self):
        c = [x for x in GUARD["cases"] if x["id"] == "block"][0]
        q = c["request"]

        def forge(with_key=True, sig=True):
            body = copy.deepcopy(c["crawlcheck"]["body"])
            sg = body.pop("signature")
            body.pop("sha256")
            body["decision"] = body["base_decision"] = "allow"
            sha = hashlib.sha256(canon(body).encode("utf-8")).hexdigest()
            s = dict(sg, message=PREFIX + sha)
            if with_key is False:
                s.pop("key", None)
            if sig is False:
                s.pop("sig", None)
            elif isinstance(sig, str):
                s["sig"] = sig
            return dict(body, sha256=sha, signature=s)
        from crawlcheck.verify import _kp_ms as ms
        for kw, label in ((dict(with_key=False), "key removed"), (dict(with_key=False, sig=False), "key and signature removed"), (dict(sig="!!!"), "signature not base64"), (dict(sig=False), "signature removed")):
            cc = Offline(extra={"/api/v1/preflight": forge(**kw)}, directory=GUARD["directory"], rotation=GUARD["rotation"])
            ok, rc = cc.guard(q["domain"], q["action"], allow_warn=True, nonce=q["nonce"], now=ms(q["now"]))
            self.assertIs(ok, False, "%s: %s" % (label, cc.last_guard.get("why")))
            self.assertIsNot((cc.last_guard.get("acceptance") or {}).get("accepted"), True, label)

    def test_pinned_key_ids_are_the_published_ones(self):
        d = json.load(open(os.path.join(HERE, "..", "..", "sdk", "test", "fixtures", "key-directory-20261107.json"))) if os.path.exists(os.path.join(HERE, "..", "..", "sdk", "test", "fixtures", "key-directory-20261107.json")) else None
        if d:
            self.assertEqual(sorted(crawlcheck.CRAWLCHECK_KEY_IDS), sorted(key_policy_from(d)["kids"]))
        for k in crawlcheck.CRAWLCHECK_LOCK_KIDS:
            self.assertIn(k, crawlcheck.CRAWLCHECK_KEY_IDS)
        doc = sign(answer(), EVIL, kid=crawlcheck.CRAWLCHECK_KEY_IDS[0])   # a pinned id, a foreign key
        v = verify_document(doc)
        self.assertIs(v["verified"], False)
        self.assertIs(v["accepted"], False)


if __name__ == "__main__":
    unittest.main()
