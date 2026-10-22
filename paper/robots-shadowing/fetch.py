"""Fetch robots.txt for a stratified sample of the CrUX top-1M origins. Output: robots.jsonl (one record per origin)."""
import asyncio, aiohttp, gzip, csv, json, random, sys, time, ssl
SEED = 20261022
PER_BUCKET_SAMPLE = 2500
UA = "CrawlCheck-research/1.0 (+https://crawlcheck.io; robots.txt study; contact@crawlcheck.io)"
MAXB = 512 * 1024
rows = list(csv.DictReader(gzip.open("crux.csv.gz", "rt")))
by = {}
for r in rows: by.setdefault(int(r["rank"]), []).append(r["origin"])
rng = random.Random(SEED)
sample = []
for b in sorted(by):
    lst = sorted(by[b])
    if b <= 10000: sample += [(o, b) for o in lst]
    else: sample += [(o, b) for o in rng.sample(lst, PER_BUCKET_SAMPLE)]
print("sample", len(sample), file=sys.stderr)
done = set()
try:
    for l in open("robots.jsonl"): done.add(json.loads(l)["origin"])
except FileNotFoundError: pass
todo = [s for s in sample if s[0] not in done]
out = open("robots.jsonl", "a")
sem = asyncio.Semaphore(120)
async def one(sess, origin, bucket):
    rec = {"origin": origin, "bucket": bucket, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    async with sem:
        try:
            async with sess.get(origin + "/robots.txt", allow_redirects=True, max_redirects=5) as r:
                rec["status"] = r.status; rec["final"] = str(r.url); rec["ctype"] = r.headers.get("content-type", "")
                rec["hops"] = len(r.history)
                body = await r.content.read(MAXB)
                rec["body"] = body.decode("utf-8", "replace") if r.status == 200 else ""
                rec["bytes"] = len(body)
        except Exception as e:
            rec["error"] = type(e).__name__ + ": " + str(e)[:120]
    out.write(json.dumps(rec) + "\n"); out.flush()
async def main():
    to = aiohttp.ClientTimeout(total=20, connect=10)
    sc = ssl.create_default_context(cafile="/root/.ccr/ca-bundle.crt")
    conn = aiohttp.TCPConnector(limit=120, ttl_dns_cache=300, ssl=sc)
    async with aiohttp.ClientSession(timeout=to, connector=conn, trust_env=True, headers={"user-agent": UA, "accept": "text/plain,*/*;q=0.5"}) as s:
        await asyncio.gather(*[one(s, o, b) for o, b in todo])
asyncio.run(main())
print("done", file=sys.stderr)
