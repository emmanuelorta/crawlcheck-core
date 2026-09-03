# crawlcheck-core

The dependency-free modules of [CrawlCheck](https://crawlcheck.io), the AI-crawler visibility scanner, extracted from the production Worker. No build step, no dependencies, ESM, Node 20+.

The hosted service fetches a site as 15 crawler identities and grades 22 sections across three stages — **reach** (can the crawler get in), **read** (what it actually receives), **quote** (can an answer engine lift it). This repository is the open core: the readers and checks that need no network, no store and no key, published so the measurements can be reproduced.

**What is here today:** the robots.txt policy reader, the crawler identifier / log-line forgery verifier, the quotable-content reader, and the markdown-negotiation and agent-surface probes. **What stays in the service:** fetching as fifteen crawler identities, the record over time, monitoring, the dataset, billing.

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

## quotable — what an answer engine can lift from the page

```js
import { quotable } from "crawlcheck-core/quotable";

const { signals, rows, score } = quotable(html, "Acme Fencing LLC");

signals.lead_defines;    // does the first sentence say what this IS
signals.answer_units;    // paragraphs of 15-70 words that carry a fact
signals.quotable_share;  // % of sentences an engine could attribute unedited
signals.faq_questions;   // declared in FAQPage markup
signals.faq_visible;     // ...and actually readable on the page
score;                   // 0-100 over the scored rows, or null when not scorable
```

The question is not whether the copy is good. It is whether, when an answer engine wants to state a fact about this page, there is a sentence on it that can be lifted **as it stands** — or whether the engine has to assemble one, in which case the answer carries the engine's wording rather than yours.

Ten rows come back. Seven are scored against thresholds set from a 176-homepage corpus pass, and each row states the corpus figure it was measured against: a lead that defines the subject (30% of homepages do), at least 25% of paragraphs quotable whole (median 29%), question headings answered where they exist, FAQ markup matching the visible text, a median sentence of 22 words or fewer (median 15), at least 15% of sentences carrying a checkable fact (median 20%), and a third or fewer paragraphs opening in the first person (p90 24%).

Three rows are **measured and deliberately not scored** — heading ids, tables, a visible date. At 0-4% adoption, scoring them would dock almost every site for the same thing and say nothing about any of them. That is what `ok: null` means throughout this package, and `pctScore()` divides by the scored rows only, returning `null` rather than `0` for a section with none. A page with fewer than five body paragraphs is not scored at all: a JavaScript shell has no copy to judge, and the payload section already says so.

Two details that are easy to get wrong and are settled here. **FAQ parity is checked against the whole visible page**, not the stripped body — an FAQ accordion inside a `<footer>` is still text a reader can see. And **counts come from body paragraphs and list items with navigation, header, footer and forms removed**, because a nav menu is not prose and counting it inflates every ratio on the page.

| Export | What it does |
|---|---|
| `quotable(html, nameHint)` | The production call site in one call: signals, rows and section score |
| `quoteSignals(html, nodes, nameHint)` | The reader. `nodes` comes from `ldGraphNodes(html)`; `null` when the input has no `<body>` |
| `quoteRows({ quotable })` | The ten rows with their thresholds and the reason each one matters |
| `quoteBlock({ quotable })` | The prose block the report renders under the table |
| `SCORE_VERSION`, `QUOTABLE_WEIGHT` | 15, and the 0.8 this section carries in the overall grade |

## surfaces — markdown negotiation, and the Accept header that made a site an F

```js
import { agentSurfaces, grab } from "crawlcheck-core/surfaces";

const root = await grab("https://example.com/");
const out = await agentSurfaces("https://example.com", root);

out.found.markdown;    // Accept: text/markdown got a text/markdown answer
out.found.agents_md;   // an authored /agents.md, not a 200 of HTML
out.found.link_header; // read off the root response — no extra request
out.evidence.markdown; // { content_type: "text/markdown; charset=utf-8" }
```

A scanner's `Accept` header is part of its identity, and getting it wrong makes the whole grade a measurement of the wrong document. This fetcher sent `Accept: */*` until 2026-09-01. vercel.com answered that with 3,025 bytes of `text/markdown`, while every named-crawler row — which sends `text/html` — received the 521 KB page. The scan then scored mobile 0 (there is no viewport meta in a markdown file), entity-map parity 0, and graded the site **F**: a grade about a document no crawler is ever handed. Googlebot, GPTBot and ClaudeBot all send a browser-shaped Accept, so `CRAWLER_ACCEPT` does too.

Markdown negotiation is therefore measured **on purpose, once**, in its own request — never as a side effect of how the page was fetched. Conflating "this site offers markdown to agents" with "our scanner asked for the wrong thing" is the failure mode, and one test in this package exists solely to pin it: exactly one request carries `Accept: text/markdown`, and every other request carries `CRAWLER_ACCEPT`.

The other rule here is that **a 200 answering with HTML is a soft 404**. `/SKILL.md`, `/agents.md` and the three `.well-known` paths are absent on most sites, and a catch-all route returns the SPA shell at 200 for all of them; a naive check reports every one of those as present. Nine of the ten rows this module renders are informational and none is scored — adoption is early, absence is not a defect, and a row that says *NOT APPLICABLE: no Product, Offer or checkout found* is measuring the site rather than the checklist.

| Export | What it does |
|---|---|
| `agentSurfaces(base, root)` | The four `.well-known` probes fired together, the Link header off `root`, and the markdown negotiation request |
| `grab(url)` | The scanner's fetcher: crawler UA, browser-shaped Accept, 10s abort, body read to 60,000 chars |
| `skillMd(host)` / `agentsMd(host)` | `/SKILL.md` with its YAML frontmatter, `/agents.md` — both with the soft-404 rule |
| `agentSurfaceRows(result)` | The ten rows, including the applicability wording |
| `looksHtml(body, ctype)`, `UA`, `CRAWLER_ACCEPT`, `SURFACE_PATHS` | The pieces, exported so a caller can reproduce one probe |

## jsonld — the entities a page actually declares

```js
import { ldGraphNodes } from "crawlcheck-core/jsonld";
ldGraphNodes(html); // root nodes and @graph children, merged by @id
```

Two rules, both easy to get wrong. A node nested inside another node is a **value** — a PostalAddress, an Offer, a ListItem, an Answer — not a subject the page is asserting, and it is not held to the standards an entity is. And the **same `@id` twice is one subject**: RDF merges statements, so a reader that keeps the first node and drops the second reads a site declaring a typeless fingerprint stub before its full Organization as having an untyped business. That was measured on a live site, which is why the merge is here.

## Tests

```bash
npm test            # 33 tests, no network
CC_LIVE=1 npm test  # 36: adds the three live checks
```

**robots** — RFC group parsing, precedence, the shadowing case both ways, unmeasured inputs, table integrity, and parity with the production scanner on two real robots.txt files.

**agents** — token matching, IPv4/IPv6 range logic, the three-state verdict, and parity with the production verifier on 11 real log lines against a stored snapshot of the five operator feeds those lines touch (`test/fixtures/ranges.json`, dated inside the file).

**quotable** — the reader (what counts as a paragraph, the lead test, question headings, FAQ parity, what makes a sentence quotable), the rows (which are scored, which are deliberately not, what happens under five paragraphs), the JSON-LD graph rules, and parity with a live production scan.

**surfaces** — the Accept headers actually sent, one negotiation request and only one, soft-404 handling, and the row wording.

### How the parity fixtures work

Each `.quotable.json` holds the output of one real scan at crawlcheck.io — the service's own numbers, copied unaltered, with the scan id, score version and build sha they came from. The page itself is **not** committed. Instead the fixture stores `page_sha256`, the digest of the exact response body that scan read, and the live test re-fetches the page with the same user-agent and Accept, refuses to compare unless the bytes are identical, and only then checks that this module reproduces all 21 fields and the section score.

That makes drift loud instead of silent. A stored HTML blob would keep passing forever against a page that no longer exists; a digest mismatch says plainly that the site changed, not the reader, and the fixture needs recapturing.

One of the two fixtures is deliberately **not** a re-fetch target. `emmanuelorta.com` renders live figures on an hourly refresh — measured on 2026-09-03, an identical-length response returned a different digest three hours after capture — so its fixture carries `reproducible: false` and the reason. It stays because the two recorded readings disagree (100 against 67; nine FAQ questions against none; markdown negotiated against not), which is what proves the reader does not flatten one site into another.

## Roadmap

Next: the machine-file readers (llms.txt, entity map, the soft-404 and challenge verdicts behind them). Each ships only with a parity test against the live service.

## Licence

MIT. Built by [Emmanuel Orta](https://emmanuelorta.com/). The scanner itself is at [crawlcheck.io](https://crawlcheck.io) — free scan, no account.
