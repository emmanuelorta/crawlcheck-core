// crawlcheck-core / robots.js
// The robots.txt policy reader from CrawlCheck (crawlcheck.io), extracted verbatim
// from the production scanner. No dependencies. ESM.
//
// What it answers: for each named crawler agent, which user-agent group of a
// robots.txt file applies to it, whether a given path (and the root) is allowed
// under that group, and whether naming the agent in its own group has SHADOWED
// every rule in the `*` group — the defect this module was written to find.
//
// Known simplifications (deliberate, documented, unchanged from production):
//   - `*` inside a rule path is stripped and the remainder matched as a prefix;
//     `$` end anchors are not honoured. This is the same reading Google's parser
//     gives for the common cases and differs only on exotic patterns.
//   - Crawl-delay, Sitemap and unknown fields are ignored.
//   - Longest-rule-wins, Allow beats Disallow on equal length (RFC 9309 §2.2.2).

export const AGENTS = [
// Added from the live robots.txt adoption distribution: these are the agents
// operators actually write rules for. Every one below is either a corpus
// crawler or an SEO/market-research tool, so NOTHING here is scored - the
// scored rows stay answer engines and search indexes only.
["Magpie-crawler","Magpie AI","train"],["img2dataset","img2dataset image corpus","train"],
["AwarioRssBot","Awario RSS","train"],["AwarioSmartBot","Awario smart","train"],
["TurnitinBot","Turnitin","train"],["archive.org_bot","Internet Archive","train"],
["ia_archiver","Internet Archive (legacy)","train"],
["AhrefsBot","Ahrefs link index","tool"],["SemrushBot","Semrush crawler","tool"],
["MJ12bot","Majestic link index","tool"],["DotBot","Moz link index","tool"],
["rogerbot","Moz site crawler","tool"],["DataForSeoBot","DataForSEO","tool"],
["BLEXBot","WebMeUp link index","tool"],
// Reclassified: a Denver contractor is not worse off for Naver not indexing it.
// Regional engines are REPORTED, never scored - same trade as the train row.
["Yeti","Naver","regional"],["YoudaoBot","Youdao","regional"],["Exabot","Exalead","regional"],
// Every string below was taken from REAL robots.txt files (91 sites swept) or
// from the operator's own documentation. Nothing here is a guessed user-agent.
["Sogou web spider","Sogou","regional"],["YisouSpider","Yisou","regional"],
["360Spider","360 Search","regional"],["Sosospider","Soso","regional"],
["meta-webindexer","Meta web index","train"],["omgili","Webz.io omgili","train"],
["cohere-training-data-crawler","Cohere training corpus","train"],["PanguBot","Huawei PanGu","train"],
["Ai2Bot-Dolma","Allen Institute Dolma","train"],["FriendlyCrawler","FriendlyCrawler ML","train"],
["VelenPublicWebCrawler","Velen","train"],["MyCentralAIScraperBot","MyCentral AI","train"],
["DeepSeekBot","DeepSeek","train"],["ICC-Crawler","NICT ICC","train"],
["GoogleOther","Google non-search fetch","train"],["Google-CloudVertexBot","Vertex AI agent build","train"],
["CloudflareBrowserRenderingCrawler","Cloudflare Browser Run /crawl","tool"],["Cloudflare-AutoRAG","Cloudflare AutoRAG","tool"],
["Peer39_Crawler","Peer39 ad context","tool"],["AdsBot-Google","Google Ads quality","tool"],
["AmazonAdBot","Amazon Ads","tool"],["AdIdxBot","Microsoft Ads","tool"],
["Twitterbot","X link preview","social"],["LinkedInBot","LinkedIn link preview","social"],
["facebookexternalhit","Facebook link preview","social"],["Pinterestbot","Pinterest","social"],
["Slackbot-LinkExpanding","Slack unfurl","social"],
["OAI-SearchBot","ChatGPT search index","answer"],["ChatGPT-User","ChatGPT live fetch","answer"],
["Claude-SearchBot","Claude search index","answer"],["Claude-User","Claude live fetch","answer"],
["PerplexityBot","Perplexity index","answer"],["Perplexity-User","Perplexity live fetch","answer"],
["Gemini-Deep-Research","Gemini research agent","answer"],["MistralAI-User","Le Chat live fetch","answer"],
["DuckAssistBot","DuckDuckGo AI assist","answer"],["YouBot","You.com","answer"],
["PhindBot","Phind","answer"],["Kagibot","Kagi","answer"],
["Copilot-User","Microsoft Copilot fetch","answer"],["Meta-ExternalFetcher","Meta AI live fetch","answer"],
["Googlebot","Google Search and AI Overviews","search"],["bingbot","Bing and Copilot index","search"],
["Applebot","Apple and Siri","search"],["Amazonbot","Amazon","search"],
["DuckDuckBot","DuckDuckGo","search"],["YandexBot","Yandex","search"],
["Baiduspider","Baidu","search"],["Seznambot","Seznam","search"],
["Neevabot","Neeva","search"],["PetalBot","Huawei Petal","search"],
["GPTBot","OpenAI training and index","train"],["ClaudeBot","Anthropic training","train"],
["anthropic-ai","Anthropic legacy agent","train"],["Claude-Web","Anthropic legacy agent","train"],
["Google-Extended","Gemini training","train"],["Applebot-Extended","Apple training","train"],
["CCBot","Common Crawl","train"],["Bytespider","ByteDance","train"],
["meta-externalagent","Meta AI training","train"],["FacebookBot","Meta legacy","train"],
["cohere-ai","Cohere","train"],["Diffbot","Diffbot knowledge graph","train"],
["Omgilibot","Webz.io","train"],["ImagesiftBot","Imagesift","train"],
["Timpibot","Timpi","train"],["AI2Bot","Allen Institute","train"],
["Scrapy","Generic scraper framework","train"],["SemrushBot-OCOB","Semrush AI corpus","train"],
["Applebot-Extended-Ads","Apple ads corpus","train"],["TikTokSpider","TikTok","train"],
["QuillBot","QuillBot","train"],["Webzio-Extended","Webz.io extended","train"],
["ProRataInc","ProRata","train"],["AwarioBot","Awario","train"]
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

export function pathAllowed(g, path) {
  if (!g) return true;
  const p = path || "/";
  let best = null;
  for (const r of g.rules) {
    const rp = r.path;
    if (rp === "") continue;
    const pat = rp.replace(/\*+/g, "");
    if (pat === "" || p.indexOf(pat) === 0) {
      const L = rp.length;
      if (!best || L > best.len || (L === best.len && r.allow)) best = { len: L, allow: r.allow };
    }
  }
  return best ? best.allow : true;
}

export function rootAllowed(g) {
  if (!g) return true;
  let best = null;
  for (const r of g.rules) {
    const p = r.path;
    if (p === "") continue;
    const pat = p.replace(/\*+/g, "");
    if (pat === "" || pat === "/" || "/".startsWith(pat)) {
      const L = p.length;
      if (!best || L > best.len || (L === best.len && r.allow)) best = { len: L, allow: r.allow, path: p };
    }
  }
  return best ? best.allow : true;
}

export function shadowedGroups(groups) {
  const star = starGroup(groups);
  if (!star) return [];
  const starDis = (star.rules || []).filter(function (r) { return !r.allow && r.path !== ""; }).map(function (r) { return r.path; });
  if (!starDis.length) return [];
  const out = [];
  for (const g of groups || []) {
    if ((g.uas || []).indexOf("*") > -1) continue;
    const own = (g.rules || []).filter(function (r) { return !r.allow && r.path !== ""; }).map(function (r) { return r.path; });
    const missing = starDis.filter(function (p) { return own.indexOf(p) < 0; });
    if (missing.length) out.push({ uas: (g.uas || []).slice(0, 6), missing: missing.slice(0, 20), missing_count: missing.length });
  }
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
