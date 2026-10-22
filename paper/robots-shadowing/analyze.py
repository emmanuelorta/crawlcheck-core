"""Measure rule shadowing in robots.txt (RFC 9309). For each origin with a readable robots.txt:
  * groups: consecutive user-agent lines start a group; groups naming the same token merge (RFC 9309 2.2.1)
  * a crawler obeys only the group matching its product token; `*` applies only when nothing matches
  * a `*` Disallow rule is NOT INHERITED by crawler C when C has its own group and that group allows a URL the `*` group blocks
Writes results.json (aggregates) and sites.jsonl (per-origin facts, no bodies)."""
import json, re, sys, collections, random
from protego import Protego

SEARCH = ["googlebot", "bingbot", "slurp", "duckduckbot", "applebot", "yandexbot", "baiduspider"]
AI = ["gptbot", "oai-searchbot", "chatgpt-user", "claudebot", "claude-searchbot", "claude-user", "anthropic-ai",
      "perplexitybot", "perplexity-user", "google-extended", "applebot-extended", "ccbot", "bytespider", "amazonbot",
      "meta-externalagent", "cohere-ai", "diffbot", "youbot", "mistralai-user"]
CRAWLERS = SEARCH + AI

def groups_of(txt):
    groups, cur, ua_phase = [], None, False
    for raw in txt.splitlines():
        line = raw.split("#", 1)[0].strip()
        if ":" not in line: continue
        k, v = line.split(":", 1); k = k.strip().lower(); v = v.strip()
        if k == "user-agent":
            if not ua_phase or cur is None:
                cur = {"uas": [], "rules": []}; groups.append(cur); ua_phase = True
            cur["uas"].append(v.lower())
        elif k in ("allow", "disallow"):
            if cur is None: continue
            ua_phase = False
            cur["rules"].append((k == "allow", v))
        else:
            # sitemap, crawl-delay and other lines do not close a group (a later user-agent line after a rule starts a new one)
            if cur is not None and ua_phase is False: pass
    merged = collections.OrderedDict()
    for g in groups:
        for u in g["uas"]:
            merged.setdefault(u, []).extend(g["rules"])
    return merged

import functools
@functools.lru_cache(maxsize=200000)
def _parts(p):
    end = p.endswith("$")
    return tuple((p[:-1] if end else p).split("*")), end
def glob_match(p, path):
    """robots.txt pattern match ('*' any run, '$' end) without backtracking: greedy leftmost placement of each literal."""
    segs, end = _parts(p)
    if not path.startswith(segs[0]): return False
    if len(segs) == 1: return (path == segs[0]) if end else True
    pos = len(segs[0])
    mids, last = segs[1:-1], segs[-1]
    for m in mids:
        i = path.find(m, pos)
        if i < 0: return False
        pos = i + len(m)
    if end: return path.endswith(last) and len(path) - len(last) >= pos
    return path.find(last, pos) >= 0

def decide(rules, path):
    """RFC 9309: most specific (longest) matching rule wins; allow wins a tie; no match = allowed."""
    best, blen = True, -1
    for allow, p in rules:
        if p == "": continue
        if glob_match(p, path):
            L = len(p)
            if L > blen or (L == blen and allow): best, blen = allow, L
    return best

def test_url(p):
    u = p[:-1] if p.endswith("$") else p
    u = u.replace("*", "x")
    return u if u.startswith("/") else "/" + u

CAT = [("admin_login", r"wp-admin|/admin|administrator|wp-login|/login|/signin|/user/|/account|/my-account|/dashboard"),
       ("search", r"[?&]s=|/search|[?&]q=|[?&]query="),
       ("cart_checkout", r"cart|checkout|basket|/order"),
       ("api_json", r"/api|wp-json|graphql|\.json"),
       ("feeds", r"feed|rss|atom"),
       ("query_params", r"\?|&|="),
       ("private_staging", r"private|staging|test|dev|tmp|draft|preview|internal")]
def cat_of(p):
    pl = p.lower()
    for name, rx in CAT:
        if re.search(rx, pl): return name
    return "other"

def analyse(rec):
    o = {"origin": rec["origin"], "bucket": rec["bucket"]}
    if rec.get("error"): o["state"] = "error"; return o
    st = rec.get("status")
    if st != 200: o["state"] = "status_%s" % (st // 100 if st else "x"); o["status"] = st; return o
    body = rec.get("body") or ""
    if re.search(r"<html|<!doctype", body[:2000], re.I) or "html" in (rec.get("ctype") or "").lower():
        o["state"] = "html"; return o
    g = groups_of(body)
    o["state"] = "readable"; o["groups"] = len(g)
    star = g.get("*")
    o["has_star"] = star is not None
    named = [c for c in CRAWLERS if c in g]
    o["named"] = named
    if not star:
        o["star_dis"] = 0; return o
    star_dis = [p for a, p in star if not a and p != ""]
    o["star_dis"] = len(star_dis)
    o["star_blocks_root"] = not decide(star, "/")
    if not star_dis or o["star_blocks_root"] or not named:
        return o
    sh = {}
    for c in named:
        rules = g[c]
        lost = [p for p in star_dis if (not decide(star, test_url(p))) and decide(rules, test_url(p))]
        if lost:
            own_dis = [p for a, p in rules if not a and p != ""]
            sh[c] = {"lost": len(lost), "of": len(star_dis), "allow_only": len(own_dis) == 0,
                     "cats": sorted(set(cat_of(p) for p in lost)), "sample": lost[:5]}
    o["shadowed"] = sh
    # independent check with protego (Google-compatible parser) on the first lost rule of each shadowed crawler
    if sh:
        try:
            rp = Protego.parse(body)
            chk = []
            for c, v in sh.items():
                u = "https://x.example" + test_url(v["sample"][0])
                chk.append((rp.can_fetch(u, c), rp.can_fetch(u, "SomeOtherBot")))
            o["protego_agree"] = all(a is True and b is False for a, b in chk)
        except Exception as e:
            o["protego_agree"] = None
    return o

if __name__ == "__main__":
    import multiprocessing as mp
    recs = [json.loads(l) for l in open("robots.jsonl")]
    with mp.Pool(2) as pool:
        res = pool.map(analyse, recs, chunksize=50)
    with open("sites.jsonl", "w") as out:
        for r in res: out.write(json.dumps(r) + "\n")
