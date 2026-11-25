"""Outside-witness verification: the same fixture and the same cases as the JavaScript SDK's checkpoint.test.js."""
import base64
import json
import os
import unittest

from crawlcheck.checkpoint import (LOG_VKEY, WITNESS_VKEYS, parse_vkey, parse_checkpoint, verify_checkpoint,
                                   verify_inclusion, verify_consistency, verify_answer_in_log)

F = json.load(open(os.path.join(os.path.dirname(__file__), "fixtures", "checkpoint.json"), encoding="utf-8"))
T = F["test"]


class Checkpoint(unittest.TestCase):
    def test_live_checkpoint_with_pinned_key(self):
        r = verify_checkpoint(F["live"]["note"])
        self.assertTrue(r["ok"] and r["log_signed"])
        self.assertEqual((r["origin"], r["size"]), ("crawlcheck.io/log", F["live"]["size"]))
        self.assertFalse(r["witnessed"])
        self.assertEqual(len(WITNESS_VKEYS), 0)
        q = verify_checkpoint(F["live"]["note"], quorum=1)
        self.assertTrue(q["log_signed"])
        self.assertFalse(q["ok"])

    def test_other_log_key_refused(self):
        self.assertFalse(verify_checkpoint(T["note"])["log_signed"])
        self.assertTrue(verify_checkpoint(T["note"], T["log_vkey"])["ok"])
        self.assertFalse(verify_checkpoint(F["live"]["note"], T["log_vkey"])["log_signed"])

    def test_quorum(self):
        k = T["log_vkey"]
        r = verify_checkpoint(T["note_w1"], k, [T["w1_vkey"]], 1)
        self.assertTrue(r["ok"] and r["witnessed"])
        self.assertEqual([x["name"] for x in r["cosigned_by"]], ["crawlcheck.io/witness"])
        r = verify_checkpoint(T["note_w1"], k, [T["w1_vkey"], T["w2_vkey"]], 2)
        self.assertFalse(r["ok"])
        self.assertEqual((len(r["cosigned_by"]), r["witnesses_pinned"]), (1, 2))
        self.assertTrue(verify_checkpoint(T["note_w1_w2"], k, [T["w1_vkey"], T["w2_vkey"]], 2)["ok"])
        self.assertFalse(verify_checkpoint(T["note_w1_w2"], k, [T["w1_vkey"], T["w1_vkey"]], 2)["ok"])
        self.assertEqual(verify_checkpoint(T["note_w1_w2"], k, [T["w1_vkey"], T["w1_vkey"]], 2)["witnesses_pinned"], 1)
        r = verify_checkpoint(T["note_w1_stranger"], k, [T["w1_vkey"]], 2)
        self.assertFalse(r["ok"])
        self.assertEqual(len(r["cosigned_by"]), 1)
        self.assertFalse(verify_checkpoint(T["note_w1"], k, [T["w2_vkey"]], 1)["ok"])
        r = verify_checkpoint(T["note"], k, [T["w1_vkey"]], 1)
        self.assertTrue(r["log_signed"])
        self.assertFalse(r["ok"])
        self.assertEqual(verify_checkpoint(T["note_w1"], k, [T["log_vkey"]], 1)["witnesses_pinned"], 0)

    def test_tamper(self):
        k, w = T["log_vkey"], [T["w1_vkey"]]
        size = str(parse_checkpoint(T["note_w1"])["size"])
        self.assertFalse(verify_checkpoint(T["note_w1"].replace(size, str(int(size) + 1)), k, w, 1)["log_signed"])
        w1line = T["note_w1"][len(T["note"]):]
        moved = verify_checkpoint(F["live"]["note"] + w1line, witnesses=w, quorum=1)
        self.assertTrue(moved["log_signed"])
        self.assertFalse(moved["witnessed"])
        for bad in ["", "x", T["note"].replace("\n\n", "\n"), T["note"][:-1], None, 7]:
            self.assertFalse(verify_checkpoint(bad, k, w, 1)["ok"])
        import re
        self.assertIsNone(parse_vkey(re.sub(r"\+[0-9a-f]{8}\+", "+00000000+", T["w1_vkey"])))
        self.assertEqual(parse_vkey(LOG_VKEY)["type"], 1)

    def test_inclusion(self):
        k, w = T["log_vkey"], [T["w1_vkey"]]
        for d in T["inclusion"]:
            r = verify_answer_in_log(d, d["leaf_hash"], k, w, 1)
            self.assertTrue(r["ok"] and r["included"] and r["checkpoint"]["witnessed"], r)
            self.assertTrue(verify_answer_in_log(dict(d, root="A" * 43 + "="), d["leaf_hash"], k, w, 1)["ok"])
            self.assertFalse(verify_answer_in_log(dict(d, index=d["index"] + 1), d["leaf_hash"], k, w, 1)["included"])
            self.assertFalse(verify_answer_in_log(dict(d, leaf_hash="00" * 32), None, k, w, 1)["included"])
            self.assertFalse(verify_answer_in_log(d, "11" * 32, k, w, 1)["ok"])
            self.assertFalse(verify_answer_in_log(dict(d, path=d["path"][1:]), d["leaf_hash"], k, w, 1)["included"])
            self.assertFalse(verify_answer_in_log(dict(d, tree_size=d["tree_size"] - 1), d["leaf_hash"], k, w, 1)["ok"])
            r2 = verify_answer_in_log(d, d["leaf_hash"], k, w, 2)
            self.assertTrue(r2["included"])
            self.assertFalse(r2["ok"])
            self.assertFalse(verify_answer_in_log(dict(d, checkpoint=F["live"]["note"]), d["leaf_hash"])["included"])
        lh = T["inclusion"][0]["leaf_hash"]
        self.assertTrue(verify_inclusion(lh, 0, 1, [], base64.b64encode(bytes.fromhex(lh)).decode()))

    def test_consistency(self):
        c = T["consistency"]
        self.assertTrue(verify_consistency(c["first"], c["second"], c["root1"], c["root2"], c["proof"]))
        self.assertFalse(verify_consistency(c["first"], c["second"], c["root2"], c["root1"], c["proof"]))
        self.assertFalse(verify_consistency(c["first"] + 1, c["second"], c["root1"], c["root2"], c["proof"]))
        self.assertFalse(verify_consistency(c["first"], c["second"], c["root1"], c["root2"], c["proof"][1:]))
        self.assertFalse(verify_consistency(c["first"], c["second"], c["root1"], c["root2"], []))
        self.assertTrue(verify_consistency(c["second"], c["second"], c["root2"], c["root2"], []))
        self.assertFalse(verify_consistency(c["second"], c["second"], c["root1"], c["root2"], []))
        self.assertFalse(verify_consistency(c["second"], c["first"], c["root2"], c["root1"], c["proof"]))


if __name__ == "__main__":
    unittest.main()
