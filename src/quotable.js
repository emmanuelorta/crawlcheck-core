// crawlcheck-core / quotable.js
// The quotable-content signals from CrawlCheck (crawlcheck.io), extracted
// verbatim from the production scanner. ESM, no dependencies.
//
// The question this answers is not "is the copy good". It is: when an answer
// engine wants to state a fact about this page, is there a sentence on it that
// can be lifted AS IT STANDS, or must the engine assemble one? A page that only
// yields assembled answers gets quoted in the engine's wording, not the site's.
//
// What it reads, all from the delivered HTML: the lead paragraph (does it name
// the subject and say what it is), paragraphs short enough to quote whole that
// carry a checkable fact, question headings with an answer under them, FAQPage
// markup checked against the visible text, headings with an id (a citable
// fragment), sentence length, and how much of the copy opens in the first
// person. Navigation, header, footer, forms, script and style are removed first.
//
// WHAT THIS MODULE IS AND IS NOT. It publishes the MEASUREMENT: every count and
// share the production scanner reads from a page, reproducible byte-for-byte
// against a live scan (see test/quotable.test.js, CC_LIVE=1). It does not
// publish the SCORING. The thresholds each signal is judged against, the weight
// the section carries in the overall grade, and the corpus calibration those
// numbers were set from stay in the service at crawlcheck.io. That split is
// deliberate and it is the honest one: the reading is a fact about your page and
// you are entitled to check it, while the calibration took a multi-hundred-site
// corpus to earn and is the product.

import { ldGraphNodes } from "./jsonld.js";

const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );

// ── QUOTABLE CONTENT (build 194) — measured, not yet scored ─────────────────
// What an answer engine can lift from the page as a self-contained statement:
// a lead sentence that says what the thing IS, paragraphs short enough to
// quote whole that carry a fact (a number, a date, a proper noun), question
// headings with an answer under them, FAQ markup that matches visible text,
// headings with an id (a citable fragment), and how much of the copy is
// third-person. None of this decides quality; it measures whether the
// sentences an engine would need are on the page in a form it can take.
export function quoteSignals(html, nodes, nameHint) {
  const h = String(html || "");
  if (!/<body\b/i.test(h)) return null;
  const strip = function (s) { return String(s || "").replace(/<[^>]+>/g, " ").replace(/&nbsp;/gi, " ").replace(/&amp;/gi, "&").replace(/&#0?39;|&rsquo;|&#8217;/gi, "'").replace(/&quot;/gi, '"').replace(/\s+/g, " ").trim(); };
  const body = (h.match(/<body\b[^>]*>([\s\S]*)<\/body>/i) || [null, h])[1]
    .replace(/<(script|style|noscript|template|svg|nav|header|footer|form)\b[^>]*>[\s\S]*?<\/\1>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ");
  const wc = function (s) { return s ? s.split(/\s+/).filter(Boolean).length : 0; };
  const factRe = /\b\d[\d,.]*\s?(%|percent|years?|hours?|days?|minutes?|miles?|km|ft|feet|inch(?:es)?|lb|kg|mm|cm|m|\$|usd)?\b|\b(19|20)\d{2}\b|\b[A-Z][a-z]+(?:\s[A-Z][a-z]+){1,3}\b/;
  const paras = [];
  for (const m of body.matchAll(/<(p|li|dd|blockquote)\b[^>]*>([\s\S]*?)<\/\1>/gi)) {
    const t = strip(m[2]); const n = wc(t);
    if (n >= 6) paras.push({ t: t, n: n });
  }
  const heads = [];
  for (const m of body.matchAll(/<h([1-3])\b([^>]*)>([\s\S]*?)<\/h\1>/gi)) {
    const t = strip(m[3]); if (!t) continue;
    heads.push({ level: Number(m[1]), t: t, id: /\bid\s*=\s*["'][^"']+["']/i.test(m[2]), q: /\?\s*$/.test(t) || /^(how|what|why|when|where|who|which|can|do|does|is|are|should)\b/i.test(t), pos: m.index });
  }
  // an answer under a question heading: the first paragraph after it, within 1500 chars
  let qa = 0;
  heads.filter(function (x) { return x.q; }).forEach(function (x) {
    const after = body.slice(x.pos, x.pos + 2500);
    const pm = after.match(/<(p|li|dd)\b[^>]*>([\s\S]*?)<\/\1>/i);
    if (pm) { const n = wc(strip(pm[2])); if (n >= 8 && n <= 90) qa++; }
  });
  const qHeads = heads.filter(function (x) { return x.q; }).length;
  // lead definition: the first real paragraph, does it name the subject and say what it is
  const lead = paras[0] ? paras[0].t : "";
  const nm = String(nameHint || "").toLowerCase().replace(/\s+(llc|inc|ltd|co)\.?$/, "").trim();
  const leadNames = !!(nm && lead.toLowerCase().indexOf(nm.split(" ")[0]) > -1);
  const leadDefines = /\b(is|are|provides?|offers?|specialis(?:e|z)es?|serves?|builds?|installs?|repairs?|sells?|makes?|helps?)\b/i.test(lead.split(/[.!?]/)[0] || "");
  // answer units
  const units = paras.filter(function (p) { return p.n >= 15 && p.n <= 70 && factRe.test(p.t); });
  const firstPerson = paras.filter(function (p) { return /^(we|our|i|us|my)\b/i.test(p.t); }).length;
  // sentences
  const text = paras.map(function (p) { return p.t; }).join(" ");
  const sents = text.split(/(?<=[.!?])\s+(?=[A-Z0-9"'])/).map(function (s) { return s.trim(); }).filter(function (s) { return wc(s) >= 4; });
  const lens = sents.map(wc).sort(function (a, b) { return a - b; });
  const median = lens.length ? lens[Math.floor(lens.length / 2)] : 0;
  const quotable = sents.filter(function (s) { const n = wc(s); return n >= 8 && n <= 30 && factRe.test(s) && !/^(we|our|i|us|my)\b/i.test(s); });
  // FAQ parity: every FAQPage question appears in the visible text
  let faqQ = 0, faqVisible = 0;
  // parity is checked against the WHOLE visible page, not the stripped body: an
  // FAQ accordion inside a <footer> or a <form> wrapper is still visible text
  const whole = strip(h.replace(/<(script|style|noscript|template|svg)\b[^>]*>[\s\S]*?<\/\1>/gi, " ")).toLowerCase().replace(/[^a-z0-9 ]/g, "");
  try {
    (nodes || []).forEach(function (n) {
      const t = [].concat(n["@type"] || []);
      if (t.indexOf("FAQPage") === -1) return;
      [].concat(n.mainEntity || []).forEach(function (q) {
        const qt = strip(q && q.name || ""); if (!qt) return; faqQ++;
        const probe = qt.toLowerCase().replace(/[^a-z0-9 ]/g, "").split(" ").filter(Boolean).slice(0, 6).join(" ");
        if (probe && whole.indexOf(probe) > -1) faqVisible++;
      });
    });
  } catch (e) { }
  const dated = /\b(last\s+)?(updated|reviewed|revised|published)\b[^.<]{0,40}\b(19|20)\d{2}\b/i.test(strip(body));
  const tables = (body.match(/<table\b[\s\S]*?<\/table>/gi) || []).filter(function (t) { return (t.match(/<tr\b/gi) || []).length >= 3 && /<th\b/i.test(t); }).length;
  return { paragraphs: paras.length, words: wc(text), lead: lead.slice(0, 220), lead_names_subject: leadNames, lead_defines: leadDefines,
    answer_units: units.length, first_person: firstPerson,
    headings: heads.length, question_headings: qHeads, question_headings_answered: qa, headings_with_id: heads.filter(function (x) { return x.id; }).length,
    sentences: sents.length, median_sentence_words: median, short_share: sents.length ? Math.round(100 * sents.filter(function (s) { return wc(s) <= 25; }).length / sents.length) : 0,
    quotable: quotable.length, quotable_share: sents.length ? Math.round(100 * quotable.length / sents.length) : 0, samples: quotable.slice(0, 3).map(function (s) { return s.slice(0, 200); }),
    faq_questions: faqQ, faq_visible: faqVisible, dated: dated, tables: tables };
}

// Convenience: the production call site, in one call. scan() runs
//   result.quotable = quoteSignals(html, ldGraphNodes(html), nameHint)
// and this does the same, parsing the JSON-LD graph for you. The rows, the
// thresholds and the section score are the service's; this hands back the
// reading they are computed from.
export function quotable(html, nameHint) {
  return { signals: quoteSignals(html, ldGraphNodes(html), nameHint || "") };
}
