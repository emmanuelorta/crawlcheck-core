"""Outside-witness verification for the CrawlCheck answer log (same rules as the JavaScript SDK's checkpoint.js).

The log publishes one tree over every signed answer and signs its head as a C2SP checkpoint: origin, tree size, base64
root, then an Ed25519 signature line from the log's key. A witness that has checked the log only ever grew adds its own
cosignature line. Here a client checks, offline: the checkpoint is signed by the log key it pinned; how many of the
witnesses IT pinned cosigned that exact checkpoint and whether that meets its quorum; that an answer's leaf is in the
tree the checkpoint commits to; and that a later checkpoint extends an earlier one. A cosignature from a key the caller
did not pin counts for nothing. The witness list ships EMPTY. Standard library only."""
import base64
import hashlib
import re

from ._ed25519 import verify as _ed_verify

LOG_ORIGIN = "crawlcheck.io/log"
LOG_VKEY = "crawlcheck.io/log+4b13e34e+AdysJh4Ix53TtkimkZ22ciVKyLSkE7Fe66ocUkTfWcpe"
WITNESS_VKEYS = ()   # cosignature/v1 verifier keys (type 0x04) trusted by default. None yet.

_B64 = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
_SIZE = re.compile(r"^(0|[1-9][0-9]{0,15})$")
_SIG = re.compile("^\u2014 ([^\\s+]+) ([A-Za-z0-9+/=]+)$")
_VKEY = re.compile(r"^([^+\s]+)\+([0-9a-f]{8})\+([A-Za-z0-9+/=]+)$")
_CTRL = re.compile("[\x00-\x09\x0b-\x1f]")


def _unb64(s):
    if not isinstance(s, str) or not _B64.match(s) or len(s) % 4:
        return None
    try:
        b = base64.b64decode(s, validate=True)
    except Exception:
        return None
    return b if base64.b64encode(b).decode() == s else None


def _as_hash(x):
    if isinstance(x, (bytes, bytearray)):
        u = bytes(x)
    elif isinstance(x, str):
        u = bytes.fromhex(x) if re.match(r"^[0-9a-f]{64}$", x) else _unb64(x)
    else:
        u = None
    return u if u is not None and len(u) == 32 else None


def _node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def parse_vkey(vkey):
    m = _VKEY.match(str(vkey or ""))
    if not m:
        return None
    k = _unb64(m.group(3))
    if not k or len(k) != 33:
        return None
    kid = hashlib.sha256(m.group(1).encode() + b"\n" + k[:1] + k[1:]).digest()[:4].hex()
    if kid != m.group(2):
        return None
    return {"name": m.group(1), "id": kid, "type": k[0], "pub": k[1:], "vkey": str(vkey)}


def parse_checkpoint(note):
    if not isinstance(note, str) or _CTRL.search(note):
        return {"error": "not a text note"}
    k = note.rfind("\n\n")
    if k < 0:
        return {"error": "no signature block"}
    text, sp = note[:k + 1], note[k + 2:]
    if not sp or not sp.endswith("\n"):
        return {"error": "signature lines must end in a newline"}
    sigs = []
    for line in sp[:-1].split("\n"):
        m = _SIG.match(line)
        if not m:
            return {"error": "malformed signature line"}
        b = _unb64(m.group(2))
        if not b or len(b) < 5:
            return {"error": "malformed signature"}
        sigs.append({"name": m.group(1), "id": b[:4].hex(), "sig": b[4:]})
    ls = text[:-1].split("\n")
    if len(ls) < 3 or any(x == "" for x in ls):
        return {"error": "a checkpoint is at least three non-empty lines"}
    if not _SIZE.match(ls[1]):
        return {"error": "bad tree size line"}
    root = _unb64(ls[2])
    if not root or len(root) != 32:
        return {"error": "bad root hash line"}
    return {"text": text, "origin": ls[0], "size": int(ls[1]), "root": root, "sigs": sigs}


def verify_checkpoint(note, log_vkey=LOG_VKEY, witnesses=WITNESS_VKEYS, quorum=0):
    """ok is True only when the pinned log key signed the checkpoint AND at least `quorum` distinct pinned witnesses cosigned it."""
    out = {"ok": False, "origin": None, "size": None, "root": None, "log_signed": False, "cosigned_by": [],
           "witnesses_pinned": 0, "quorum": 0, "quorum_met": False, "witnessed": False}
    if not isinstance(quorum, int) or isinstance(quorum, bool) or quorum < 0:
        return dict(out, why="quorum must be a whole number, zero or more")
    out["quorum"] = quorum
    cp = parse_checkpoint(note)
    if cp.get("error"):
        return dict(out, why=cp["error"])
    lk = parse_vkey(log_vkey)
    if not lk or lk["type"] != 1:
        return dict(out, why="the log key is not an Ed25519 verifier key")
    out.update(origin=cp["origin"], size=cp["size"], root=base64.b64encode(cp["root"]).decode())
    if cp["origin"] != lk["name"]:
        return dict(out, why="the checkpoint's origin is not the pinned log")
    msg = cp["text"].encode()
    for s in cp["sigs"]:
        if s["name"] == lk["name"] and s["id"] == lk["id"] and len(s["sig"]) == 64 and _ed_verify(lk["pub"], msg, s["sig"]):
            out["log_signed"] = True
    if not out["log_signed"]:
        return dict(out, why="no valid signature from the pinned log key")
    seen, pinned = set(), set()
    for v in witnesses or ():
        wk = parse_vkey(v)
        if not wk or wk["type"] != 4:
            continue
        if (wk["name"], wk["id"]) in pinned:
            continue   # a witness listed twice is one witness
        pinned.add((wk["name"], wk["id"]))
        out["witnesses_pinned"] += 1
        for s in cp["sigs"]:
            if s["name"] != wk["name"] or s["id"] != wk["id"] or len(s["sig"]) != 72:
                continue
            t = int.from_bytes(s["sig"][:8], "big")
            if _ed_verify(wk["pub"], ("cosignature/v1\ntime %d\n" % t).encode() + msg, s["sig"][8:]):
                seen.add((wk["name"], wk["id"]))
                out["cosigned_by"].append({"name": wk["name"], "time": t})
                break
    out["witnessed"] = len(out["cosigned_by"]) > 0
    out["quorum_met"] = len(out["cosigned_by"]) >= quorum
    out["ok"] = out["quorum_met"]
    if not out["ok"]:
        out["why"] = "cosigned by %d pinned witness(es), quorum is %d" % (len(out["cosigned_by"]), quorum)
    return out


def verify_inclusion(leaf, index, tree_size, path, root):
    lh, rt = _as_hash(leaf), _as_hash(root)
    if lh is None or rt is None or not isinstance(path, (list, tuple)):
        return False
    if not isinstance(index, int) or not isinstance(tree_size, int) or isinstance(index, bool) or index < 0 or index >= tree_size:
        return False
    fn, sn, r = index, tree_size - 1, lh
    for p0 in path:
        p = _as_hash(p0)
        if p is None or sn == 0:
            return False
        if (fn & 1) or fn == sn:
            r = _node(p, r)
            if not (fn & 1):
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == rt


def verify_consistency(first, second, root1, root2, proof):
    h1, h2 = _as_hash(root1), _as_hash(root2)
    if h1 is None or h2 is None or not isinstance(proof, (list, tuple)):
        return False
    if not isinstance(first, int) or not isinstance(second, int) or first < 1 or first > second:
        return False
    if first == second:
        return len(proof) == 0 and h1 == h2
    pr = [_as_hash(x) for x in proof]
    if not pr or any(x is None for x in pr):
        return False
    if first & (first - 1) == 0:
        pr = [h1] + pr
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = pr[0]
    for c in pr[1:]:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            fr = _node(c, fr)
            sr = _node(c, sr)
            if not (fn & 1):
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _node(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == h1 and sr == h2


def verify_answer_in_log(doc, leaf_hash=None, log_vkey=LOG_VKEY, witnesses=WITNESS_VKEYS, quorum=0):
    """`doc` is what GET https://crawlcheck.io/log/inclusion?leaf=<leaf hash> returns. The root comes from the VERIFIED
    checkpoint, never from the document's own "root" field."""
    cp = verify_checkpoint((doc or {}).get("checkpoint"), log_vkey, witnesses, quorum)
    out = {"ok": False, "included": False, "checkpoint": cp}
    if not cp["log_signed"]:
        return dict(out, why=cp.get("why"))
    if doc.get("tree_size") != cp["size"]:
        return dict(out, why="the proof is for another tree size than the checkpoint")
    if leaf_hash is not None and str(leaf_hash).lower() != str(doc.get("leaf_hash")).lower():
        return dict(out, why="the proof is for another leaf")
    out["included"] = verify_inclusion(doc.get("leaf_hash"), doc.get("index"), doc.get("tree_size"), doc.get("path"), cp["root"])
    if not out["included"]:
        return dict(out, why="the audit path does not lead to the checkpoint's root")
    out["ok"] = cp["ok"]
    if not out["ok"]:
        out["why"] = cp.get("why")
    return out
