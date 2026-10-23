// crawlcheck-core / robots.js
// The robots.txt policy reader from CrawlCheck (crawlcheck.io), extracted verbatim
// from the production scanner. No dependencies. ESM.
//
// What it answers: for each named crawler agent, which user-agent group of a
// robots.txt file applies to it, whether a given path (and the root) is allowed
// under that group, and whether naming the agent in its own group has SHADOWED
// every rule in the `*` group — the defect this module was written to find.
//
// Path matching follows RFC 9309, as production has since 2026-09-30:
//   - `*` matches any run of characters anywhere in a rule; a trailing `$`
//     anchors the end of the path. (Before 0.6.0 this module stripped `*` and
//     ignored `$`, so `Disallow: /` + `Allow: /$` read as the whole site closed.)
//   - Longest-rule-wins, Allow beats Disallow on equal length (RFC 9309 §2.2.2).
//   - Crawl-delay, Sitemap and unknown fields are ignored.
//   - Percent-encoding is not normalised: rules and paths are compared as written.

export const AGENTS = [
// The production agent table, copied from the service unaltered. Every string was
// taken from real robots.txt files or the operator's own documentation. Roles:
// answer, search, train, tool, regional; only answer engines and search indexes
// are scored by the service.
["Googlebot-Image","Google image crawler","search"],["Googlebot-News","Google News","search"],["Googlebot-Video","Google video crawler","search"],
["Storebot-Google","Google Shopping","search"],["Mediapartners-Google","Google AdSense","search"],["APIs-Google","Google push delivery","search"],
["BingPreview","Bing page preview","search"],["msnbot","Microsoft legacy crawler","search"],["Slurp","Yahoo Slurp","search"],
["Yandex","Yandex (umbrella token)","search"],["coccocbot-web","Coc Coc","search"],["Facebot","Meta link crawler","social"],
["Magpie-crawler","Magpie AI","train"],["img2dataset","img2dataset image corpus","train"],["AwarioRssBot","Awario RSS","train"],
["AwarioSmartBot","Awario smart","train"],["TurnitinBot","Turnitin","train"],["archive.org_bot","Internet Archive","train"],
["ia_archiver","Internet Archive (legacy)","train"],["AhrefsBot","Ahrefs link index","tool"],["SemrushBot","Semrush crawler","tool"],
["MJ12bot","Majestic link index","tool"],["DotBot","Moz link index","tool"],["rogerbot","Moz site crawler","tool"],
["DataForSeoBot","DataForSEO","tool"],["BLEXBot","WebMeUp link index","tool"],["Yeti","Naver","regional"],
["YoudaoBot","Youdao","regional"],["Exabot","Exalead","regional"],["Sogou web spider","Sogou","regional"],
["YisouSpider","Yisou","regional"],["360Spider","360 Search","regional"],["Sosospider","Soso","regional"],
["meta-webindexer","Meta web index","train"],["omgili","Webz.io omgili","train"],["cohere-training-data-crawler","Cohere training corpus","train"],
["PanguBot","Huawei PanGu","train"],["Ai2Bot-Dolma","Allen Institute Dolma","train"],["FriendlyCrawler","FriendlyCrawler ML","train"],
["VelenPublicWebCrawler","Velen","train"],["MyCentralAIScraperBot","MyCentral AI","train"],["DeepSeekBot","DeepSeek","train"],
["ICC-Crawler","NICT ICC","train"],["GoogleOther","Google non-search fetch","train"],["Google-CloudVertexBot","Vertex AI agent build","train"],
["CloudflareBrowserRenderingCrawler","Cloudflare Browser Run /crawl","tool"],["Cloudflare-AutoRAG","Cloudflare AutoRAG","tool"],["Peer39_Crawler","Peer39 ad context","tool"],
["AdsBot-Google","Google Ads quality","tool"],["AmazonAdBot","Amazon Ads","tool"],["AdIdxBot","Microsoft Ads","tool"],
["Twitterbot","X link preview","social"],["LinkedInBot","LinkedIn link preview","social"],["facebookexternalhit","Facebook link preview","social"],
["Pinterestbot","Pinterest","social"],["Slackbot-LinkExpanding","Slack unfurl","social"],["OAI-SearchBot","ChatGPT search index","answer"],
["ChatGPT-User","ChatGPT live fetch","answer"],["Claude-SearchBot","Claude search index","answer"],["Claude-User","Claude live fetch","answer"],
["PerplexityBot","Perplexity index","answer"],["Perplexity-User","Perplexity live fetch","answer"],["Gemini-Deep-Research","Gemini research agent","answer"],
["MistralAI-User","Le Chat live fetch","answer"],["DuckAssistBot","DuckDuckGo AI assist","answer"],["YouBot","You.com","answer"],
["PhindBot","Phind","answer"],["Kagibot","Kagi","answer"],["Copilot-User","Microsoft Copilot fetch","answer"],
["Meta-ExternalFetcher","Meta AI live fetch","answer"],["Googlebot","Google Search and AI Overviews","search"],["bingbot","Bing and Copilot index","search"],
["Applebot","Apple and Siri","search"],["Amazonbot","Amazon","search"],["DuckDuckBot","DuckDuckGo","search"],
["YandexBot","Yandex","search"],["Baiduspider","Baidu","search"],["Seznambot","Seznam","search"],
["Neevabot","Neeva","search"],["PetalBot","Huawei Petal","search"],["GPTBot","OpenAI training and index","train"],
["ClaudeBot","Anthropic training","train"],["anthropic-ai","Anthropic legacy agent","train"],["Claude-Web","Anthropic legacy agent","train"],
["Google-Extended","Gemini training","train"],["Applebot-Extended","Apple training","train"],["CCBot","Common Crawl","train"],
["Bytespider","ByteDance","train"],["meta-externalagent","Meta AI training","train"],["FacebookBot","Meta legacy","train"],
["cohere-ai","Cohere","train"],["Diffbot","Diffbot knowledge graph","train"],["Omgilibot","Webz.io","train"],
["ImagesiftBot","Imagesift","train"],["Timpibot","Timpi","train"],["AI2Bot","Allen Institute","train"],
["Scrapy","Generic scraper framework","train"],["SemrushBot-OCOB","Semrush AI corpus","train"],["Applebot-Extended-Ads","Apple ads corpus","train"],
["TikTokSpider","TikTok","train"],["QuillBot","QuillBot","train"],["Webzio-Extended","Webz.io extended","train"],
["ProRataInc","ProRata","train"],["AwarioBot","Awario","train"],["Amzn-SearchBot","Amazon search eligibility, separate from Amazonbot","search"],
["Amzn-User","Amazon live fetch for Alexa questions","answer"],["MistralAI-Index","Mistral search index for Vibe","search"],["MistralAI-Training","Mistral training crawl","train"],
["OAI-AdsBot","OpenAI ChatGPT ads page validation","tool"],["Google-Agent","Google user-triggered agent, acts on the web","answer"],["Google-GeminiNotebook","Gemini Notebook user-supplied URL fetch","answer"],
["GoogleOther-Image","Google common crawler, public image URLs","train"],["GoogleOther-Video","Google common crawler, public video URLs","train"],["ExaSearchBot","Exa AI search index, Web Bot Auth signed","search"]
];

export function parseGroups(txt) {
  const groups = []; let cur = null; let expectUA = true;
  for (const raw of String(txt || "").split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim(); if (!line) continue;
    const i = line.indexOf(":"); if (i < 0) continue;
    const f = line.slice(0, i).trim().toLowerCase(); const v = line.slice(i + 1).trim();
    if (f === "user-agent") {
      if (!expectUA || !cur) { cur = { uas: [], rules: [] }; groups.push(cur); expectUA = true; }
      cur.uas.push(v.toLowerCase());
    } else if (f === "allow" || f === "disallow") {
      if (!cur) continue; expectUA = false; cur.rules.push({ allow: f === "allow", path: v });
    }
  }
  return groups;
}

export function starGroup(groups) {
  let found = null;
  for (const g of groups || []) {
    if ((g.uas || []).indexOf("*") < 0) continue;
    if (!found) found = { uas: ["*"], rules: [] };
    (g.rules || []).forEach(function (r) { found.rules.push(r); });
  }
  return found;
}

export function groupFor(groups, ua) {
  const u = String(ua).toLowerCase(); let best = null; let bestLen = -1;
  for (const g of groups) for (const a of g.uas) {
    if (a === "*") { if (bestLen < 0) { best = g; bestLen = 0; } continue; }
    if (u === a || u.startsWith(a) || a.startsWith(u)) { if (a.length > bestLen) { best = g; bestLen = a.length; } }
  }
  return { group: best, named: bestLen > 0 };
}

// groupFor() returns an envelope ({ group, named }) so callers can tell a
// named match from the * fallback. pathAllowed() and rootAllowed() accept
// either the envelope or the bare group, so the documented call
// pathAllowed(groupFor(groups, ua), path) works as well as the internal one.
function unwrapGroup(g) {
  if (!g) return null;
  if (Object.prototype.hasOwnProperty.call(g, "group") && !Array.isArray(g.rules)) return g.group || null;
  return g;
}

// RFC 9309 rule matching: `*` matches any run of characters, a trailing `$`
// anchors the end, and the rule must match from the start of the path.
const RULE_RE = new Map();
export function ruleMatches(rule, path) {
  const s0 = String(rule || "");
  if (!s0) return false;
  let re = RULE_RE.get(s0);
  if (!re) {
    let s = s0; const end = s.length > 1 && s.charAt(s.length - 1) === "$"; if (end) s = s.slice(0, -1);
    re = new RegExp("^" + s.split("*").map(function (x) { return x.replace(/[.+?^${}()|[\]\\]/g, "\\$&"); }).join("[\\s\\S]*") + (end ? "$" : ""));
    if (RULE_RE.size < 2000) RULE_RE.set(s0, re);
  }
  return re.test(String(path || "/"));
}

// rules: [{path, allow}] -> { allowed, rule }: the rule that decided, or null.
export function decide(rules, path) {
  let best = null;
  (rules || []).forEach(function (r) {
    if (!r || !r.path || !ruleMatches(r.path, path)) return;
    const L = r.path.length;
    if (!best || L > best.len || (L === best.len && r.allow)) best = { len: L, allow: !!r.allow, rule: r.path };
  });
  return best ? { allowed: best.allow, rule: best.rule } : { allowed: true, rule: null };
}

export function pathAllowed(g, path) {
  g = unwrapGroup(g);
  if (!g) return true;
  return decide(g.rules, path || "/").allowed;
}

export function rootAllowed(g) {
  g = unwrapGroup(g);
  if (!g) return true;
  return decide(g.rules, "/").allowed;
}

// A `*` Disallow is shadowed for a named group only when none of that group's own Disallow rules
// covers it (production shadow2, 2026-10-06: `Disallow: /` already covers every path). Groups that
// name no agent in AGENTS are counted in `unrecognised_groups`, not reported.
export function shadowedGroups(groups) {
  const star = starGroup(groups);
  if (!star) return [];
  const starDis = (star.rules || []).filter(function (r) { return !r.allow && r.path !== ""; }).map(function (r) { return r.path; });
  if (!starDis.length) return [];
  const known = {};
  AGENTS.forEach(function (a) { known[String(a[0]).toLowerCase()] = true; });
  const out = []; let unknownGroups = 0;
  for (const g of groups || []) {
    if ((g.uas || []).indexOf("*") > -1) continue;
    const own = (g.rules || []).filter(function (r) { return !r.allow && r.path !== ""; }).map(function (r) { return r.path; });
    // shadow2 (SCORE_VERSION 28): a `*` Disallow is only missing if none of the group's OWN Disallow rules covers it the way
    // robots.txt matching works (longest-prefix, `*` wildcard, `$` end). Exact string comparison reported every site that
    // blocks an AI crawler with `Disallow: /` as shadowing its `*` rules - `/` already covers every path. Measured
    // 2026-10-06 on 139,788 homepages: 83% of sites blocking an AI crawler carried the finding, almost all for this reason.
    const covers = function (o, p) { if (o === p) return true; if (o.indexOf("*") < 0 && o.indexOf("$") < 0) return p.indexOf(o) === 0;
      try { const re = new RegExp("^" + o.replace(/[.+?^{}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\\?\$$/, "$")); return re.test(p.replace(/\*/g, "").replace(/\$$/, "")); } catch (e) { return own.indexOf(p) > -1; } };
    const missing = starDis.filter(function (p) { return !own.some(function (o) { return covers(o, p); }); });
    if (!missing.length) continue;
    const hits = (g.uas || []).filter(function (u) { return known[String(u).toLowerCase()]; });
    if (!hits.length) { unknownGroups++; continue; }
    out.push({ uas: hits.slice(0, 6), missing: missing.slice(0, 20), missing_count: missing.length,
      declares_own_rules: own.length > 0 });
  }
  out.unrecognised_groups = unknownGroups;
  return out;
}

export function crawlerPolicy(txt, unreadable, path) {
  if (unreadable || !String(txt || "").trim()) {
    return { measured: false, reason: unreadable ? "robots.txt did not return readable directives" : "no robots.txt served — every agent is allowed by default", agents: [] };
  }
  const groups = parseGroups(txt);
  const agents = AGENTS.map(function (a) {
    const m = groupFor(groups, a[0]);
    return { ua: a[0], label: a[1], role: a[2], allowed: pathAllowed(m.group, path || "/"), allowed_root: rootAllowed(m.group), named: m.named };
  });
  const shadowed = shadowedGroups(groups);
  const shUas = [];
  shadowed.forEach(function (s2) { s2.uas.forEach(function (u) { if (shUas.indexOf(u) < 0) shUas.push(u); }); });
  return { measured: true, groups: groups.length, path: path || "/", agents: agents.map(function (x) {
    return Object.assign({}, x, { rules_shadowed: !!x.named && shUas.indexOf(String(x.ua).toLowerCase()) > -1 });
  }), shadowed: shadowed, shadowed_groups: shadowed.length };
}
