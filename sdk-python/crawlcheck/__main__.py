"""python -m crawlcheck resolve <domain> | preflight <domain> <action> [agent] | verify <file.json>"""
import json
import sys

from . import CrawlCheck, verify_document


def main(argv=None):
    a = list(sys.argv[1:] if argv is None else argv)
    if not a or a[0] not in ("resolve", "preflight", "verify"):
        print(__doc__)
        return 2
    cc = CrawlCheck()
    if a[0] == "verify":
        with open(a[1], encoding="utf-8") as fh:
            doc = json.load(fh)
        r = cc.verify(doc)
        for c in r["checks"]:
            print({True: "PASS", False: "FAIL", None: " -- "}[c["ok"]], c["id"].ljust(16), c["why"])
        print("ACCEPTED" if r.get("accepted") else "NOT ACCEPTED")
        return 0 if r["verified"] and r.get("accepted") else 1   # never a passing status for a document that was not accepted
    if a[0] == "resolve":
        print(json.dumps(cc.resolve(a[1]), indent=1))
        return 0
    rc = cc.preflight(a[1], a[2] if len(a) > 2 else "read", a[3] if len(a) > 3 else None)
    v = cc.verify(rc)   # the receipt is checked before its decision is shown as CrawlCheck's
    print(rc.get("decision"), "-", rc.get("meaning"))
    for s in rc.get("steps", []):
        print("  ", s["rule"].ljust(26), s["effect"].ljust(20), s["why"])
    if not v.get("accepted"):
        print("NOT ACCEPTED: this receipt does not verify as CrawlCheck's (%s); do not act on it" % v.get("summary"))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
