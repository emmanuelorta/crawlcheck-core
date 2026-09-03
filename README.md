# crawlcheck-core

The dependency-free modules of [CrawlCheck](https://crawlcheck.io), the AI-crawler visibility scanner, extracted from the production Worker. No build step, no dependencies, ESM, Node 20+.

The hosted service fetches a site as 15 crawler identities and grades 22 sections across three stages — **reach** (can the crawler get in), **read** (what it actually receives), **quote** (can an answer engine lift it). This repository is the open core: the readers and checks that need no network, no store and no key, published so the measurements can be reproduced.

**What is here today:** the robots.txt policy reader and the crawler identifier / log-line forgery verifier. **What stays in the service:** fetching as crawler identities, the record over time, monitoring, the dataset, billing.

## Install

```bash
npm install crawlcheck-core
```

## robots — which crawlers your robots.txt actually admits

```js
import { crawlerPolicy } from "crawlcheck-core/robots";

const policy = crawlerPolicy(robotsTxt, /* unreadable */ false, "/wp-admin/");
policy.agents.find(a => a.ua === "GPTBot");
// { ua:"GPTBot", label:"OpenAI training corpus", role:"train",
//   allowed:true, allowed_root:true, named:true, rules_shadowed:true }
policy.shadowed;
// [{ uas:["gptbot"], missing:["/wp-admin/","/feed/"], missing_count:2 }]
```

For each of 92 named agents (answer engines, search indexes, training crawlers, SEO tools, social unfurlers, regional engines) it reports: which user-agent group applies (`named`), whether the given path and the root are allowed under that group, and whether the group **shadows** the `*` rules.

### The shadowing defect

A crawler obeys only its most specific group. The moment you write

```
User-agent: *
Disallow: /wp-admin/

User-agent: GPTBot
Allow: /
```

GPTBot no longer sees `Disallow: /wp-admin/` — the `*` group stops applying to it entirely. Sites that add an allowlist for AI agents routinely void every rule they thought still held. `shadowedGroups()` lists each named group and the `*` disallows it lost. This was found on our own sites first: [how to block AI crawlers](https://crawlcheck.io/guides/how-to-block-ai-crawlers) and the glossary entry for [user-agent group](https://crawlcheck.io/glossary#user-agent-group).

### API

| Export | What it does |
|---|---|
| `crawlerPolicy(txt, unreadable, path)` | Full per-agent policy for one file. `measured:false` with a reason when the file is empty or unreadable — an absence is never reported as a policy |
| `parseGroups(txt)` | RFC 9309 groups: consecutive `User-agent` lines share one group; `Allow`/`Disallow` rules in order |
| `groupFor(groups, ua)` | The group that applies to an agent: longest-prefix match on the agent token, `*` as fallback |
| `pathAllowed(group, path)` / `rootAllowed(group)` | Longest rule wins; `Allow` beats `Disallow` at equal length |
| `shadowedGroups(groups)` | Named groups missing any `*` disallow |
| `AGENTS` | The 92-agent table: `[token, label, role]` |

### What it does not do

`*` inside a rule path is stripped and the remainder matched as a prefix; `$` end anchors are not honoured; `Crawl-delay`, `Sitemap` and unknown fields are ignored. These are the production scanner's readings too — the tests include byte-for-byte parity against the live `/api/tool/robots` endpoint on real files, so this module answers exactly what the service answers.

## agents — who fetched, and whether they are who they claim

```js
import { identifyBot, loadRanges, verifyLines } from "crawlcheck-core/agents";

identifyBot("Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"); // "GPTBot"

const ranges = await loadRanges(fetch);          // the operators' published IP feeds (cache this for a day)
const r = verifyLines(accessLogText, ranges);
r.tally;            // { verified, spoofed, unverifiable, no_bot }
r.forged_rate_pct;  // spoofed / (verified + spoofed), or null when nothing is checkable
r.rows[0];          // { line, bot, ip, verdict, why }
```

Three verdicts, never two. **Verified**: the address is inside a range the claimed operator publishes. **Spoofed**: it is outside every range that operator publishes. **Unverifiable**: the operator publishes no feed (Common Crawl, ByteDance, Meta, Amazon) or the feed could not be read — and that is reported as unverifiable, not as forgery. The forged rate divides by verified + spoofed only; counting unverifiable hits as forged would inflate it and counting them as genuine would understate it.

| Export | What it does |
|---|---|
| `identifyBot(ua)` | The named crawler token in a user-agent, longest match wins; `null` for browsers |
| `verifyLines(lines, ranges)` | The verifier behind `/api/tool/verify`: string or array of log lines → tally, rate, per-line verdicts |
| `verifyBotIP(bot, ip, ranges)` | `true` / `false` / `null` for one hit |
| `loadRanges(fetch)` | Fetches the 10 operator feeds (OpenAI ×3, Anthropic, Perplexity ×2, Google ×2, Bing, Apple) into the shape the verifier reads. The only network call in the package; absent feeds make their operator unverifiable |
| `ipInCidr(ip, cidr)`, `ip4ToInt`, `ip6ToBig` | Range matching, IPv4 and IPv6 (including IPv4-mapped) |
| `BOT_TOKENS`, `BOT_FEED_OF`, `BOT_IP_FEEDS`, `CRAWLERS` | The tables: tokens, token → feed family, feed URLs, and the 18-row operator/role/purpose table |

Why this exists: the scanner's own telemetry once counted 78 of 85 "GPTBot" hits as forged — they were our own test requests. Reverse DNS is the older check the feeds replace; a user-agent is a self-assertion and proves nothing on its own.

## Tests

```bash
npm test
```

Sixteen tests. robots: RFC group parsing, precedence, the shadowing case both ways, unmeasured inputs, table integrity, and parity with the production scanner on two real robots.txt files. agents: token matching, IPv4/IPv6 range logic, the three-state verdict, and parity with the production verifier on 11 real log lines against a stored snapshot of the five operator feeds those lines touch (`test/fixtures/ranges.json`, dated inside the file).

## Roadmap

Next modules, in order: the markdown negotiation reader, the quotable-content signals, the machine-file readers (llms.txt, entity map). Each ships only with a parity test against the live service.

## Licence

MIT. Built by [Emmanuel Orta](https://emmanuelorta.com/). The scanner itself is at [crawlcheck.io](https://crawlcheck.io) — free scan, no account.
