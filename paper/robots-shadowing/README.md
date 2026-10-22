# Rule shadowing in robots.txt — measurement code

Code for *Naming a Crawler Unblocks It: Rule Shadowing in robots.txt Across 12,828 Popular Websites* (Emmanuel Orta, 2026). PDF: [`../robots-shadowing.pdf`](../robots-shadowing.pdf).

## Reproduce

1. Download the CrUX top-million global list (`data/global/current.csv.gz`) from https://github.com/zakird/crux-top-lists into this folder as `crux.csv.gz`. The run in the paper used the file published on 22 October 2026 (SHA-256 begins `be444a34`).
2. `pip install aiohttp protego`
3. `python3 fetch.py` — every origin in the top 10k plus 2,500 random origins from each lower rank bucket (seed 20261022); one request to `/robots.txt` each. Writes `robots.jsonl`.
4. `python3 analyze.py` — parses each file as RFC 9309 specifies and writes `sites.jsonl` (per-origin facts, no file bodies).

`results.json` holds every aggregate the paper reports. Per-site results are not published (the paper names no affected site); they are available to researchers on request at contact@crawlcheck.io.

MIT licence, as the rest of this repository.
