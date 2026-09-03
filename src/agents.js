// crawlcheck-core / agents.js
// The crawler identifier and log-line verifier from CrawlCheck (crawlcheck.io),
// extracted verbatim from the production scanner. ESM. The only network call is
// loadRanges(), which is optional and takes the fetch function you give it.
//
// Three verdicts, never two: a hit is VERIFIED when its address sits inside the
// range the claimed operator publishes, SPOOFED when it sits outside every range
// that operator publishes, and UNVERIFIABLE when the operator publishes no feed
// (or the feed could not be read). Counting unverifiable as forged inflates the
// rate; counting it as genuine understates it — so the forged rate divides by
// verified + spoofed only. That rule is unchanged from production.

export const BOT_TOKENS = [
  "OAI-SearchBot", "ChatGPT-User", "GPTBot", "Claude-SearchBot", "Claude-User",
  "ClaudeBot", "anthropic-ai", "PerplexityBot", "Perplexity-User",
  "Google-Extended", "Googlebot", "Bingbot", "Applebot-Extended", "Applebot",
  "Amazonbot", "Bytespider", "Meta-ExternalAgent", "meta-externalagent",
  "FacebookBot", "YandexBot", "Baiduspider", "DuckDuckBot", "CCBot",
  "Diffbot", "omgili", "cohere-ai", "MistralAI-User", "YouBot",
  "Timpibot", "Scrapy", "SemrushBot", "AhrefsBot", "DataForSeoBot",
];

export function identifyBot(ua) {
  if (!ua) return null;
  const low = ua.toLowerCase();
  let best = null;
  for (const t of BOT_TOKENS) {
    if (low.includes(t.toLowerCase()) && (!best || t.length > best.length)) best = t;
  }
  return best;
}

export const BOT_FEED_OF = {
  "GPTBot": "openai", "OAI-SearchBot": "openai_search", "ChatGPT-User": "openai_user",
  "ClaudeBot": "anthropic", "Claude-User": "anthropic", "Claude-SearchBot": "anthropic",
  "anthropic-ai": "anthropic",
  "PerplexityBot": "perplexity", "Perplexity-User": "perplexity_user",
  "Googlebot": "google", "Google-Extended": "google",
  "Bingbot": "bing", "Applebot": "apple", "Applebot-Extended": "apple",
};

export const BOT_IP_FEEDS = {
  openai:          "https://openai.com/gptbot.json",
  openai_search:   "https://openai.com/searchbot.json",
  openai_user:     "https://openai.com/chatgpt-user.json",
  anthropic:       "https://claude.com/crawling/bots.json",
  perplexity:      "https://www.perplexity.ai/perplexitybot.json",
  perplexity_user: "https://www.perplexity.ai/perplexity-user.json",
  google:          "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
  google_user:     "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json",
  bing:            "https://www.bing.com/toolbox/bingbot.json",
  apple:           "https://search.developer.apple.com/applebot.json",
};

export const CRAWLERS = [
  ["GPTBot", "OpenAI", "training", "Collects pages to train models. Blocking it does not remove you from ChatGPT answers.", "openai.com/gptbot.json"],
  ["OAI-SearchBot", "OpenAI", "indexing", "Builds the index ChatGPT search draws on. This is the one that decides whether you can be surfaced.", "openai.com/searchbot.json"],
  ["ChatGPT-User", "OpenAI", "live fetch", "Fetches a page mid-conversation because a user asked. Blocking it means ChatGPT cannot open your page on request.", "openai.com/chatgpt-user.json"],
  ["ClaudeBot", "Anthropic", "training", "Collects pages for model training.", "published IP ranges"],
  ["Claude-User", "Anthropic", "live fetch", "Fetches a page during a conversation at a user\u2019s request.", "published IP ranges"],
  ["Claude-SearchBot", "Anthropic", "indexing", "Indexes pages so Claude can find them.", "published IP ranges"],
  ["PerplexityBot", "Perplexity", "indexing", "Builds Perplexity\u2019s index.", "published IP ranges"],
  ["Perplexity-User", "Perplexity", "live fetch", "Opens a page because a user followed a citation.", "published IP ranges"],
  ["Google-Extended", "Google", "training", "Controls Gemini training use ONLY. It does not affect Google Search or AI Overviews.", "Googlebot verification"],
  ["Googlebot", "Google", "indexing", "Search indexing, and the source most AI Overviews draw on.", "reverse DNS to googlebot.com"],
  ["Bingbot", "Microsoft", "indexing", "Search indexing; feeds Copilot.", "reverse DNS to search.msn.com"],
  ["Applebot", "Apple", "indexing", "Siri and Spotlight.", "reverse DNS to applebot.apple.com"],
  ["Applebot-Extended", "Apple", "training", "Controls Apple Intelligence training use only.", "reverse DNS to applebot.apple.com"],
  ["CCBot", "Common Crawl", "training", "An open archive many models are trained from. Blocking it removes you from a corpus, not from answers.", "no published ranges"],
  ["Bytespider", "ByteDance", "training", "High-volume and frequently unexpected \u2014 it is the crawler most operators have never considered.", "no published ranges"],
  ["Amazonbot", "Amazon", "indexing", "Alexa and Amazon search.", "published IP ranges"],
  ["meta-externalagent", "Meta", "training", "Collects pages for Meta AI.", "published IP ranges"],
  ["DuckAssistBot", "DuckDuckGo", "live fetch", "Fetches for DuckAssist answers.", "published IP ranges"]
];

export function ip4ToInt(s) {
  const p = String(s).split(".");
  if (p.length !== 4) return null;
  let n = 0;
  for (const q of p) {
    if (!/^\d{1,3}$/.test(q)) return null;
    const v = Number(q);
    if (v < 0 || v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

export function ip6ToBig(s) {
  let head = String(s);
  const z = head.indexOf("%");
  if (z > -1) head = head.slice(0, z);
  if (head.indexOf(":") === -1) return null;
  const m = head.match(/:((?:\d{1,3}\.){3}\d{1,3})$/);
  if (m) {
    const n = ip4ToInt(m[1]);
    if (n === null) return null;
    head = head.slice(0, m.index + 1)
         + ((n >>> 16) & 0xffff).toString(16) + ":" + (n & 0xffff).toString(16);
  }
  const parts = head.split("::");
  if (parts.length > 2) return null;
  const left = parts[0] ? parts[0].split(":") : [];
  const right = parts.length === 2 ? (parts[1] ? parts[1].split(":") : []) : [];
  let groups;
  if (parts.length === 1) {
    if (left.length !== 8) return null;
    groups = left;
  } else {
    const fill = 8 - left.length - right.length;
    if (fill < 0) return null;
    groups = left.concat(new Array(fill).fill("0"), right);
  }
  if (groups.length !== 8) return null;
  let big = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    big = (big << 16n) | BigInt(parseInt(g, 16));
  }
  return big;
}

export function ipInCidr(ip, cidr) {
  const bits4 = String(cidr).split("/");
  const net = bits4[0], bits = Number(bits4[1]);
  if (!net || !Number.isInteger(bits) || bits < 0) return false;
  if (net.indexOf(":") === -1) {
    if (String(ip).indexOf(":") !== -1 || bits > 32) return false;
    const a = ip4ToInt(ip), b = ip4ToInt(net);
    if (a === null || b === null) return false;
    if (bits === 0) return true;
    const mask = bits === 32 ? 0xFFFFFFFF : (0xFFFFFFFF - (Math.pow(2, 32 - bits) - 1));
    return ((a & mask) >>> 0) === ((b & mask) >>> 0);
  }
  if (String(ip).indexOf(":") === -1 || bits > 128) return false;
  const a = ip6ToBig(ip), b = ip6ToBig(net);
  if (a === null || b === null) return false;
  if (bits === 0) return true;
  const shift = BigInt(128 - bits);
  return (a >> shift) === (b >> shift);
}

export function verifyBotIP(bot, ip, ranges) {
  if (!ip) return null;
  const fam = BOT_FEED_OF[bot];
  if (!fam) return null;                  // operator publishes no feed
  const list = ranges && ranges.feeds && ranges.feeds[fam];
  if (!list || !list.length) return null; // feed unreadable — not forgery
  for (const c of list) if (ipInCidr(ip, c)) return true;
  return false;
}

// Load every operator feed with the fetch you pass in. Returns the same shape
// verifyBotIP() expects: { at, feeds: { openai: ["cidr", ...], ... } }.
// A feed that fails to load is simply absent, which makes its operator's hits
// UNVERIFIABLE — never spoofed. Production caches this for a day; you should too.
export async function loadRanges(fetchFn, userAgent) {
  const f = fetchFn || globalThis.fetch;
  const feeds = {};
  await Promise.all(Object.keys(BOT_IP_FEEDS).map(async (name) => {
    try {
      const r = await f(BOT_IP_FEEDS[name], { headers: { "user-agent": userAgent || "crawlcheck-core (+https://crawlcheck.io/bot)", accept: "application/json" }, redirect: "follow" });
      if (!r || !r.ok) return;
      const j = await r.json();
      const list = ((j && j.prefixes) || []).map((p) => p && (p.ipv4Prefix || p.ipv6Prefix)).filter(Boolean);
      if (list.length) feeds[name] = list;
    } catch { /* absent feed = unverifiable, not forged */ }
  }));
  return { at: new Date().toISOString(), feeds };
}

const IPRE = /\b((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})\b/i;

// The log-line verifier behind /api/tool/verify. `lines` is a string or an
// array; `ranges` comes from loadRanges() (or your own cache of it).
export function verifyLines(lines, ranges) {
  const raw = (Array.isArray(lines) ? lines.map((x) => String(x || "")).join("\n") : String(lines || "")).slice(0, 20000);
  const list = raw.split(/\r?\n/).map((x) => x.trim()).filter(Boolean).slice(0, 200);
  const out = [], tally = { verified: 0, spoofed: 0, unverifiable: 0, no_bot: 0 };
  for (const ln of list) {
    const ipm = ln.match(IPRE);
    const ip = ipm ? ipm[1] : "";
    const bot = identifyBot(ln);
    if (!bot) { tally.no_bot++; out.push({ line: ln.slice(0, 160), bot: null, ip, verdict: "no named crawler" }); continue; }
    if (!ip) { tally.unverifiable++; out.push({ line: ln.slice(0, 160), bot, ip: "", verdict: "unverifiable", why: "no IP address found on this line" }); continue; }
    const v = verifyBotIP(bot, ip, ranges);
    if (v === true) { tally.verified++; out.push({ line: ln.slice(0, 160), bot, ip, verdict: "verified", why: "inside " + bot + "'s published range" }); }
    else if (v === false) { tally.spoofed++; out.push({ line: ln.slice(0, 160), bot, ip, verdict: "spoofed", why: "claims " + bot + " from an address outside every range " + bot + "'s operator publishes" }); }
    else { tally.unverifiable++; out.push({ line: ln.slice(0, 160), bot, ip, verdict: "unverifiable", why: "this operator publishes no address feed, so the claim can be neither confirmed nor accused" }); }
  }
  const checkable = tally.verified + tally.spoofed;
  return { counted: list.length, tally, forged_rate_pct: checkable ? Math.round((tally.spoofed / checkable) * 1000) / 10 : null, rows: out };
}
