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
// Thresholds come from a 176-homepage corpus pass (2026-09-02) and are pinned to
// SCORE_VERSION 15; each row states the corpus figure it was set against. Three
// rows — heading ids, tables, visible dates — are measured and deliberately NOT
// scored: at 0-4% adoption they would punish almost every site for the same
// thing. A page with fewer than five body paragraphs is not scored at all.

import { tgt, pctScore } from "./rows.js";
import { ldGraphNodes } from "./jsonld.js";

export { pctScore };

// The score version these thresholds belong to, and the weight the quotable
// section carries in the production overall grade.
export const SCORE_VERSION = 15;
export const QUOTABLE_WEIGHT = 0.8;

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

export function quoteRows(r) {
  const q = r.quotable; if (!q) return [];
  // SCORE_VERSION 15: thresholds from a 176-homepage corpus pass (2026-09-02).
  // Fewer than five body paragraphs -> every content row n/a: a JS shell or a
  // wall has no copy to judge, and payload already scores that case.
  const enough = (q.paragraphs || 0) >= 5;
  const na = null;
  const unitShare = q.paragraphs ? Math.round(100 * q.answer_units / q.paragraphs) : 0;
  const fpShare = q.paragraphs ? Math.round(100 * q.first_person / q.paragraphs) : 0;
  return [
    tgt("Lead paragraph defines the subject", q.lead ? ((q.lead_names_subject ? "names it" : "does not name it") + ", " + (q.lead_defines ? "defines it" : "no defining verb")) : "no lead paragraph", "a first sentence that says what this is (corpus: 30% of homepages do)", (enough && q.lead) ? !!q.lead_defines : na,
      "the first paragraph is the one most often lifted whole; if it is a slogan, the engine has to assemble the answer from fragments. Naming the subject is shown, not scored"),
    tgt("Paragraphs an engine can quote whole", q.paragraphs ? q.answer_units + " of " + q.paragraphs + " (" + unitShare + "%)" : "none", "at least 25% (corpus median 29%)", enough ? unitShare >= 25 : na,
      "a self-contained paragraph of 15-70 words with a fact in it is the unit answer engines extract; a 200-word paragraph gets summarised instead, and the summary is theirs"),
    tgt("Question headings with an answer under them", q.question_headings ? q.question_headings_answered + " of " + q.question_headings : "no question headings", "at least half, where question headings exist", (enough && q.question_headings) ? q.question_headings_answered * 2 >= q.question_headings : na,
      "the shape a query has when it arrives; a page that already carries the question and a short answer is quoted in that order. Having none is not scored"),
    tgt("FAQ markup matches the visible text", q.faq_questions ? q.faq_visible + " of " + q.faq_questions + " questions visible" : "no FAQPage", "every declared question readable on the page", q.faq_questions ? q.faq_visible === q.faq_questions : na,
      "FAQ markup for text a visitor cannot see is a claim with nothing behind it; engines that compare the two drop the markup"),
    tgt("Headings carry an id", q.headings ? q.headings_with_id + " of " + q.headings : "no headings", "an id on each, so a passage can be cited by fragment (not scored: corpus median 0%)", na,
      "a heading with an id is a stable address for one passage; without it a citation can only point at the whole page"),
    tgt("Sentence length", q.sentences ? "median " + q.median_sentence_words + " words, " + q.short_share + "% under 26" : "no sentences", "a median of 22 words or fewer (corpus median 15)", (enough && q.sentences >= 10) ? q.median_sentence_words <= 22 : na,
      "quotes are short; a 40-word sentence is paraphrased, and the paraphrase carries the engine's wording, not yours"),
    tgt("Sentences with a checkable fact", q.sentences ? q.quotable + " of " + q.sentences + " (" + q.quotable_share + "%)" : "no sentences", "at least 15% (corpus median 20%)", (enough && q.sentences >= 10) ? q.quotable_share >= 15 : na,
      "8-30 words with a number, date or name, in the third person: the sentence an engine can attribute to you without editing it"),
    tgt("Paragraphs that open in the first person", q.paragraphs ? q.first_person + " of " + q.paragraphs + " (" + fpShare + "%)" : "none", "a third or fewer (corpus p90 24%)", enough ? fpShare <= 33 : na,
      "\"We offer\" needs rewriting before it can be quoted about you; \"Acme offers\" does not"),
    tgt("Tables with a header row and at least two data rows", String(q.tables || 0), "one per set of comparable facts (not scored: rare on homepages)", na,
      "a table is the one structure every extractor reads the same way; the same facts in prose are re-assembled differently by each engine"),
    tgt("A visible updated or published date", q.dated ? "yes" : "none found", "a dated line in the copy (not scored: 4% of homepages carry one)", na,
      "engines weigh freshness from the text as well as from schema; a date the reader can see is the one they trust")
  ];
}

export function quoteBlock(r) {
  const q = r.quotable; if (!q) return "";
  let h = "";
  if (q.samples && q.samples.length) h += '<p class="none"><strong>Sentences an engine could lift as they stand:</strong></p><ul class="cmp__fl">' + q.samples.map(function (s) { return "<li>\u201c" + esc(s) + "\u201d</li>"; }).join("") + "</ul>";
  if (q.lead) h += '<p class="none"><strong>The lead, as delivered:</strong> \u201c' + esc(q.lead) + '\u201d</p>';
  return h + '<p class="none"><strong>What this scores, and what it is not.</strong> These rows read the delivered HTML for the shape of quotable text: nothing here judges whether the copy is good, true or wanted. ' +
    'Counts come from body paragraphs and list items with the navigation, header, footer and forms removed; a page with fewer than five is not scored here. Thresholds were set from a 176-homepage corpus pass and each row states the corpus figure it was set against. Weight 0.8 in the overall and part of the Quote stage, from score version 15.</p>';
}

// Convenience: the production call site, in one call. scan() runs
//   result.quotable = quoteSignals(html, ldGraphNodes(html), nameHint)
// and then quoteRows({ quotable: result.quotable }); this does both and hands
// back the signals, the rows and the section score together.
export function quotable(html, nameHint) {
  const signals = quoteSignals(html, ldGraphNodes(html), nameHint || "");
  const rows = signals ? quoteRows({ quotable: signals }) : [];
  return { signals: signals, rows: rows, score: pctScore(rows) };
}
