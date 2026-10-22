"""The signing-policy suite (https://crawlcheck.io/keys#policy) against this package: same cases, same expected results
as the JavaScript verifiers (spec/key-policy/run.mjs). CC_SDK_PATH=<dir> runs it against another copy."""
import json, os, sys, unittest

if os.environ.get("CC_SDK_PATH"):
    sys.path.insert(0, os.environ["CC_SDK_PATH"])
from crawlcheck.verify import KEY_POLICY, key_policy_from, verify_document, apply_key_policy  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CANDIDATES = [os.path.join(HERE, "..", "..", "spec", "key-policy", "cases.json"), os.path.join(HERE, "fixtures", "key-policy.json")]
SUITE = json.load(open([p for p in CANDIDATES if os.path.exists(p)][0]))


class KeyPolicy(unittest.TestCase):
    def test_policy_matches_published(self):
        for k in ("object_purpose", "chains", "starts", "bound", "purpose_aliases"):
            self.assertEqual(KEY_POLICY[k], SUITE["policy"][k], "KEY_POLICY.%s differs from the published policy" % k)


def make(c):
    def t(self):
        kp = key_policy_from(SUITE["directory"], None if c["keys"] == "directory" else SUITE["rotation"])
        r = apply_key_policy(verify_document(c["doc"], kp["kids"]), c["doc"], kp)
        why = next((x["why"] for x in r["checks"] if x["id"] == "key_purpose"), "")
        for k, v in c["expect"].items():
            self.assertEqual(r[k], v, "%s: %s" % (k, why))
    return t


for _c in SUITE["cases"]:
    setattr(KeyPolicy, "test_" + _c["id"].replace("-", "_"), make(_c))

if __name__ == "__main__":
    unittest.main()
