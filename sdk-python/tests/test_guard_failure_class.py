"""failure_class on guard() and guarded_fetch() results, and observe mode, over the acceptance suite's signed cases
(https://crawlcheck.io/spec/guard). Same table as the JS SDK's test/guard-failure-class.test.js."""
import copy, unittest
from urllib.parse import urlsplit

try:
    import test_guard_acceptance as A
except ImportError:  # run as tests.test_guard_failure_class
    from . import test_guard_acceptance as A
from crawlcheck import CrawlCheck, GUARD_FAILURE_CLASSES, CONTINUITY_FAILURE_CLASSES, guard_failure_class_of, new_revocation_store
from crawlcheck.continuity import continuity_class_of
from crawlcheck.tools import agent_tools

# The class every case in the suite gets. None: the case proceeds.
EXPECT = {
    "allow": None, "warn-default": "decision_refused", "warn-allowed": None, "confirm-missing": "server_identity_mismatch", "confirm-no": "decision_refused", "confirm-yes": None,
    "block": "decision_refused", "unsupported": "decision_refused", "decision-unknown": "signature_invalid", "other-domain": "server_identity_mismatch", "subdomain": "server_identity_mismatch",
    "www-same": None, "other-action": "server_identity_mismatch", "expired": "evidence_expired", "expired-in-skew": None, "skew-inflated": "evidence_expired", "future": "evidence_expired",
    "lifetime-transact": "evidence_expired", "lifetime-connect": "evidence_expired", "no-expiry": "evidence_expired", "nonce-other": "replay_mismatch", "nonce-missing": "replay_mismatch",
    "op-match": None, "op-other-url": "operation_mismatch", "op-other-method": "operation_mismatch", "op-missing": "operation_mismatch", "op-tool-schema": "operation_mismatch", "op-scopes": "operation_mismatch",
    "purpose-key-decision": None, "kp-decision-key-early": "key_retired", "kp-document-key-after-switch": "key_retired", "kp-request-key-unbound": "key_retired", "kp-request-key-bound": None,
    "kp-request-key-bound-after-switch": "key_retired", "kp-retired": "key_unknown", "kp-compromised-in-directory": "key_unknown", "kp-compromised-answer": "key_unknown", "kp-fallback": None,
    "kp-fallback-compromised-key": "key_unknown", "resolve-key-foreign": "key_unknown", "tampered": "signature_invalid", "tampered-unsigned-field": "signature_invalid", "unknown-signed-field": None,
    "foreign-key": "key_unknown", "kid-mismatch": "signature_invalid", "unsigned": "signature_invalid", "resolve-unbound": "signature_invalid", "wrong-kind": "response_malformed",
    "wrong-version": "response_malformed", "malformed-empty": "response_malformed", "malformed-array": "response_malformed", "malformed-text": "response_malformed", "http-500": "service_unavailable",
    "http-429": "service_unavailable", "unreachable": "service_unavailable", "fetch-ok": None, "fetch-blocked": "decision_refused", "redirect-to-blocked": "decision_refused", "redirect-to-allowed": None,
    "redirect-relative": None, "redirect-scheme": "fetch_refused", "redirect-loop": "fetch_refused", "redirect-ip": "service_unavailable", "fetch-receipt-reuse": None,
}
BY_ID = {c["id"]: c for c in A.SUITE["cases"]}


def run(c, client=None, **extra):
    """One case through guard() or guarded_fetch(). Returns (result, receipt, log, client): result is the guarded_fetch
    dict, or client.last_guard for a guard() case."""
    A.STATE["case"], A.STATE["asked"] = c, []
    q = c["request"]
    cc = client or CrawlCheck(base=A.DEAD if c["crawlcheck"].get("unreachable") else A.BASE, timeout=5)
    confirm = None if q.get("confirm") is None else (lambda rc, v=q["confirm"]: v)
    kw = dict(allow_warn=q["allow_warn"], confirm=confirm, nonce=q["nonce"], now=A.ms(q["now"]))
    kw.update(extra)
    log = {"fetched": [], "header_to": []}
    if q.get("url"):
        sites = c.get("sites") or {}

        def transport(method, url, headers, data):
            log["fetched"].append(url)
            if any(k.lower() == "crawlcheck-receipt" for k in headers):
                log["header_to"].append(urlsplit(url).hostname)
            s = sites.get(url)
            if not s:
                return 404, {}, b"not in fixture"
            return s["status"], ({"Location": s["location"]} if s.get("location") else {}), (s.get("body") or "").encode()
        r = cc.guarded_fetch(q["url"], action=q["action"], max_hops=q["max_hops"], transport=transport, **kw)
        return r, None, log, cc
    if q.get("operation"):
        kw["operation"] = q["operation"]
    p, rc = cc.guard(q["domain"], q["action"], **kw)
    g = cc.last_guard
    assert g["proceed"] == p
    return g, rc, log, cc


class Classes(unittest.TestCase):
    def test_table_names_every_case(self):
        self.assertEqual(sorted(EXPECT), sorted(BY_ID))

    def test_class_list(self):
        self.assertEqual(len(GUARD_FAILURE_CLASSES), 14)
        for k in ("service_unavailable", "check_timeout", "response_malformed", "signature_invalid", "key_unknown", "key_retired", "server_identity_mismatch", "evidence_expired",
                  "operation_mismatch", "replay_mismatch", "decision_refused", "revoked", "split_view", "fetch_refused"):
            self.assertIn(k, GUARD_FAILURE_CLASSES)
        for k in ("operation_mismatch", "replay_mismatch", "revoked", "split_view", "fetch_refused"):
            self.assertNotIn(k, CONTINUITY_FAILURE_CLASSES, "%s must not enter the continuity policy (its sha256 would change)" % k)

    def test_enforce_every_case(self):
        for c in A.SUITE["cases"]:
            with self.subTest(c["id"]):
                r, rc, _, _ = run(c)
                self.assertEqual(r["proceed"], c["expect"]["proceed"])
                self.assertEqual(r["failure_class"], EXPECT[c["id"]], "why: %s" % r["why"])
                self.assertEqual(r["failure_class"] is None, r["proceed"], "failure_class is None exactly when the result proceeds")
                self.assertEqual((r["mode"], r["enforced"], r["would_proceed"]), ("enforce", True, r["proceed"]))
                if not c["request"].get("url") and not r["proceed"] and isinstance(rc, dict):
                    self.assertEqual(guard_failure_class_of(rc, dict(r, failure_class=None)), r["failure_class"], "with a receipt, the class can be told from the rest of the result")

    def test_observe_every_case(self):
        for c in A.SUITE["cases"]:
            with self.subTest(c["id"]):
                seen = []
                r, rc, log, _ = run(c, mode="observe", on_record=lambda g, receipt: seen.append((g, receipt)))
                self.assertEqual((r["mode"], r["enforced"]), ("observe", False))
                self.assertEqual(r["would_proceed"], c["expect"]["proceed"], "would_proceed is what enforce returns")
                self.assertEqual(r["failure_class"], EXPECT[c["id"]])
                if EXPECT[c["id"]] == "fetch_refused":
                    self.assertFalse(r["proceed"], "a URL that cannot be checked is refused in observe too")
                    continue
                self.assertTrue(r["proceed"], "observe never refuses a decision")
                if c["request"].get("url"):
                    self.assertIsNotNone(r["status"], "the request went out")
                    self.assertEqual(len(seen), len(r["hops"]), "on_record saw every hop's check")
                    for h in r["hops"]:
                        if h["would_proceed"] is False:
                            self.assertNotIn(h["domain"], log["header_to"], "no receipt header goes to a hop the guard would refuse")
                else:
                    self.assertEqual(len(seen), 1)
                    self.assertIs(seen[0][0], r)
                    if not c["expect"]["proceed"]:
                        self.assertTrue(r["why"], "the reasons are kept")

    def test_operation_and_replay_split_out_continuity_unchanged(self):
        for cid, cls in (("op-other-url", "operation_mismatch"), ("nonce-other", "replay_mismatch")):
            r, rc, _, _ = run(BY_ID[cid])
            self.assertEqual(r["failure_class"], cls)
            self.assertEqual(continuity_class_of(False, rc, r["acceptance"], r["why"]), "server_identity_mismatch", "continuity records and policies keep their class")

    def test_confirmation_without_confirm(self):
        c = copy.deepcopy(BY_ID["confirm-no"]); c["request"]["confirm"] = None
        r, _, _, _ = run(c)
        self.assertFalse(r["proceed"]); self.assertEqual(r["failure_class"], "decision_refused"); self.assertIn("no confirm was given", " ".join(r["why"]))

    def test_timeout(self):
        cc = CrawlCheck(base=A.BASE, timeout=5)

        def slow(*a, **k):
            raise TimeoutError("timed out")
        cc._req = slow
        p, rc = cc.guard("good.example", "read")
        self.assertFalse(p); self.assertIsNone(rc); self.assertEqual(cc.last_guard["failure_class"], "check_timeout")

    def test_revoked(self):
        c, q = BY_ID["allow"], BY_ID["allow"]["request"]
        for mode in ("enforce", "observe"):
            st = new_revocation_store(); st["generated_at"] = "2026-10-10T00:00:00.000Z"
            st["revoked"][q["domain"]] = {"domain": q["domain"], "actions": ["transact"], "causes": ["test"], "state": "revoked", "since": "2026-10-09T00:00:00.000Z"}
            cc = CrawlCheck(base=A.BASE, timeout=5, revocation_store=st)
            A.STATE["case"], A.STATE["asked"] = c, []
            p, rc = cc.guard(q["domain"], "transact", nonce=q["nonce"], now=A.ms(q["now"]), mode=mode)
            g = cc.last_guard
            self.assertTrue(g.get("revoked"), "the fixture entry matched"); self.assertEqual(A.STATE["asked"], [], "no request")
            self.assertEqual((g["failure_class"], g["would_proceed"], p, rc), ("revoked", False, mode == "observe", None))

    def test_split_view(self):
        c, q = BY_ID["allow"], BY_ID["allow"]["request"]
        cc = CrawlCheck(base=A.BASE, timeout=5)
        cc.log["forks"].append({"kind": "two_heads_for_one_batch", "batch": 1, "why": "test"})
        A.STATE["case"], A.STATE["asked"] = c, []
        p, _ = cc.guard(q["domain"], "read", nonce=q["nonce"], now=A.ms(q["now"]))
        self.assertFalse(p); self.assertEqual(cc.last_guard["failure_class"], "split_view"); self.assertEqual(len(cc.last_guard["split_view"]), 1)

    def test_mode_is_enforce_or_observe(self):
        cc = CrawlCheck(base=A.BASE, timeout=5)
        A.STATE["case"], A.STATE["asked"] = BY_ID["allow"], []
        with self.assertRaises(ValueError):
            cc.guard("good.example", "read", mode="review")
        with self.assertRaises(ValueError):
            cc.guarded_fetch("https://good.example/", mode="off", transport=lambda *a: self.fail("requested"))
        self.assertEqual(A.STATE["asked"], [])

    def test_on_record_in_enforce_and_a_failing_recorder(self):
        seen = []

        def rec(g, rc):
            seen.append(g["failure_class"])
            raise RuntimeError("recorder down")
        r, _, _, _ = run(BY_ID["block"], on_record=rec)
        self.assertFalse(r["proceed"]); self.assertEqual(seen, ["decision_refused"])
        r, _, _, _ = run(BY_ID["allow"], on_record=rec)
        self.assertTrue(r["proceed"])

    def test_guarded_fetch_observe_follows_the_redirect_enforce_stops(self):
        c = BY_ID["redirect-to-blocked"]
        e, _, elog, _ = run(c)
        self.assertEqual((e["proceed"], e["failure_class"], e["would_proceed"]), (False, "decision_refused", False))
        self.assertEqual([h["failure_class"] for h in e["hops"]], [None, "decision_refused"]); self.assertEqual(elog["fetched"], ["https://good.example/go"])
        o, _, olog, _ = run(c, mode="observe")
        self.assertEqual((o["proceed"], o["would_proceed"], o["enforced"], o["failure_class"]), (True, False, False, "decision_refused"))
        self.assertEqual(olog["fetched"], ["https://good.example/go", "https://evil.example/x"])
        self.assertEqual([(h["proceed"], h["would_proceed"]) for h in o["hops"]], [(True, True), (True, False)])
        self.assertEqual(olog["header_to"], ["good.example"], "the receipt header went only where a receipt was accepted")

    def test_guarded_fetch_bad_url_in_both_modes(self):
        cc = CrawlCheck(base=A.BASE, timeout=5)
        for mode in ("enforce", "observe"):
            for u in ("not a url", "ftp://good.example/x"):
                r = cc.guarded_fetch(u, mode=mode, transport=lambda *a: self.fail("requested"))
                self.assertEqual((r["proceed"], r["failure_class"], r["would_proceed"]), (False, "fetch_refused", False))

    def test_a_replaced_guard_with_the_old_signature_still_works(self):
        cc = CrawlCheck(base=A.BASE, timeout=5)
        cc.last_guard = {"why": ["decision is block"]}
        cc.guard = lambda domain, action="read", agent=None, template=None, policy=None, confirm=None, allow_warn=False, nonce=None, now=None, operation=None: (False, {"kind": "crawlcheck-decision", "v": 1, "decision": "block"})
        r = cc.guarded_fetch("https://good.example/", transport=lambda *a: self.fail("requested"))
        self.assertFalse(r["proceed"]); self.assertFalse(r["would_proceed"]); self.assertIn(r["failure_class"], GUARD_FAILURE_CLASSES)

    def test_agent_tools_carry_the_class(self):
        A.STATE["case"], A.STATE["asked"] = BY_ID["block"], []
        tools = {t["name"]: t["execute"] for t in agent_tools(CrawlCheck(base=A.BASE, timeout=5))}
        out = tools["crawlcheck_check_site"]({"site": BY_ID["block"]["request"]["domain"]})
        self.assertFalse(out["proceed"]); self.assertIn(out["failure_class"], GUARD_FAILURE_CLASSES)
        A.STATE["case"] = BY_ID["malformed-array"]
        out = tools["crawlcheck_check_site"]({"site": "good.example"})   # a list where a receipt should be: refused, not a crash
        self.assertFalse(out["proceed"]); self.assertEqual(out["failure_class"], "response_malformed")


if __name__ == "__main__":
    unittest.main()
