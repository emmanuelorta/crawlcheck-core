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
        doc = json.load(open(a[1], encoding="utf-8"))
        r = cc.verify(doc)
        for c in r["checks"]:
            print({True: "PASS", False: "FAIL", None: " -- "}[c["ok"]], c["id"].ljust(16), c["why"])
        return 0 if r["verified"] else 1
    if a[0] == "resolve":
        print(json.dumps(cc.resolve(a[1]), indent=1))
        return 0
    rc = cc.preflight(a[1], a[2] if len(a) > 2 else "read", a[3] if len(a) > 3 else None)
    print(rc["decision"], "-", rc.get("meaning"))
    for s in rc.get("steps", []):
        print("  ", s["rule"].ljust(26), s["effect"].ljust(20), s["why"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
