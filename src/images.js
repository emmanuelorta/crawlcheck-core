// crawlcheck-core / images.js
// What an engine can learn from the pictures, read from the delivered HTML and
// extracted verbatim from the production scanner. ESM, no dependencies.
//
// imageSignals(html) counts; imageRows(record) turns the counts into the row
// contract in rows.js. Five rows are scored - missing alt, declared dimensions,
// nothing lazy-loaded above the fold, an entity image in JSON-LD, an og:image.
//
// Three things are reported and deliberately NEVER scored, and the distinction
// is the point of the module:
//
//   * alt="" is not a missing alt. It is the correct markup for a decorative
//     image, and most real sites are nearly all decorative alt. Scoring it
//     fails almost every site on a signal that is usually right.
//   * File format and hero priority are preferences, not defects.
//   * A page with no images at all returns a single unscored row, never a zero.
//
// `ok === null` means measured but not scored; pctScore() in rows.js divides by
// the scored rows only, so an unscored row can never drag a section to zero.

import { tgt } from "./rows.js";

export function imageSignals(html) {
  var h = String(html || ""); var out = { measured: h.length > 0 };
  var body = h.replace(/<script(?![^>]*ld\+json)[\s\S]*?<\/script>/gi, "").replace(/<noscript[\s\S]*?<\/noscript>/gi, "");
  var imgs = body.match(/<img\b[^>]*>/gi) || [];
  out.total = imgs.length;
  // The value pattern excluded whitespace, so ANY quoted attribute holding a
  // space read back as an empty string: alt="a cedar fence" was indistinguishable
  // from alt="". Measured across six live homepages, that reported 15 of 15, 9 of
  // 9 and 10 of 11 images as decorative when almost all carried real alt text.
  // no_alt was never affected - a match still occurred - so no score ever moved,
  // but the published count was wrong. Quoted values now run to their closing
  // quote; unquoted values still stop at whitespace.
  var attr = function (t, a) { var m = t.match(new RegExp("\\s" + a + "\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s\"'>]+))", "i")); return m ? (m[1] !== undefined ? m[1] : (m[2] !== undefined ? m[2] : m[3])) : null; };
  var noAlt = 0, emptyAlt = 0, noDims = 0, lazy = 0, modern = 0, svg = 0, dataUri = 0;
  var bi = body.search(/<body/i); var head = body.slice(bi < 0 ? 0 : bi, (bi < 0 ? 0 : bi) + Math.max(6000, Math.round((body.length - (bi < 0 ? 0 : bi)) * 0.25)));
  var lazyAbove = (head.match(/<img\b[^>]*loading\s*=\s*["']?lazy/gi) || []).length;
  imgs.forEach(function (t) {
    var alt = attr(t, "alt"); if (alt === null) noAlt++; else if (!alt.trim()) emptyAlt++;
    var src = (attr(t, "src") || attr(t, "data-src") || "").toLowerCase();
    if (/^data:/.test(src)) dataUri++;
    if (/\.(webp|avif)(\?|$)/.test(src) || /<source[^>]+type=["']image\/(webp|avif)/i.test(t)) modern++;
    if (/\.svg(\?|$)/.test(src)) svg++;
    if (!attr(t, "width") || !attr(t, "height")) noDims++;
    if (/loading\s*=\s*["']?lazy/i.test(t)) lazy++;
  });
  var pictureModern = (body.match(/<source[^>]+type=["']image\/(webp|avif)/gi) || []).length;
  out.no_alt = noAlt; out.empty_alt = emptyAlt; out.no_dimensions = noDims; out.lazy = lazy; out.lazy_above_fold = lazyAbove;
  out.modern_format = modern + pictureModern; out.svg = svg; out.data_uri = dataUri;
  out.og_image = /<meta[^>]+property=["']og:image["'][^>]*content=["'][^"']+/i.test(h) || /<meta[^>]+content=["'][^"']+["'][^>]*property=["']og:image["']/i.test(h);
  var ld = (h.match(/<script[^>]+application\/ld\+json[^>]*>([\s\S]*?)<\/script>/gi) || []).join("\n");
  out.ld_image = /"(image|logo)"\s*:\s*(\{|"|\[)/.test(ld);
  out.ld_imageobject = /"@type"\s*:\s*"ImageObject"/.test(ld);
  var pre = (h.match(/<link[^>]+rel=["']preload["'][^>]+as=["']image["']/gi) || []).length; out.preloaded = pre;
  out.fetchpriority_high = (body.match(/<img\b[^>]*fetchpriority\s*=\s*["']?high/gi) || []).length;
  return out;
}

export function imageRows(r) {
  var m = r && r.images; if (!m || !m.measured) return [];
  var na = null; var t = m.total || 0;
  if (!t) return [tgt("Images on the page", "none", "", na, "a page with no images gives an engine nothing to show beside the name; not a defect on its own")];
  var pct = function (n) { return t ? Math.round(100 * n / t) + "%" : "-"; };
  return [
    tgt("Images on the page", String(t) + (m.svg ? " (" + m.svg + " SVG)" : ""), "", na, "counted from <img> tags in the delivered HTML"),
    tgt("Missing alt text", (m.no_alt || 0) + " missing, " + (m.empty_alt || 0) + " empty (" + pct((m.no_alt || 0)) + " missing)", "0 missing; empty only on decorative images", (m.no_alt || 0) === 0, "alt is the only text an engine gets from a picture; empty alt is correct for decoration, missing alt is a hole"),
    tgt("Width and height declared", (t - (m.no_dimensions || 0)) + " of " + t, "all", ((t - (m.no_dimensions || 0)) / t) >= 0.9, "without both, the browser cannot reserve space and the page shifts as pictures load (the CLS score)"),
    tgt("Lazy-loaded", (m.lazy || 0) + " of " + t + (m.lazy_above_fold ? " \u2014 " + m.lazy_above_fold + " in the first quarter of the page" : ""), "below the fold only", (m.lazy_above_fold || 0) === 0, "lazy-loading the hero image delays the largest paint; lazy-loading the rest speeds everything else"),
    tgt("Modern formats (WebP/AVIF)", (m.modern_format || 0) + " of " + t, "most", na, "smaller files, same picture"),
    tgt("Hero image prioritised", (m.fetchpriority_high || m.preloaded) ? ((m.fetchpriority_high || 0) + " fetchpriority=high, " + (m.preloaded || 0) + " preloaded") : "no", "one, when the largest paint is an image", na, "the one image the browser should fetch first"),
    tgt("Entity image in JSON-LD", m.ld_image ? (m.ld_imageobject ? "yes (ImageObject)" : "yes") : "no", "an image or logo on the organisation node", !!m.ld_image, "what an engine shows next to the name; a URL in image or logo, ideally an ImageObject with dimensions"),
    tgt("og:image", m.og_image ? "yes" : "no", "present", !!m.og_image, "the picture a link preview uses when the page is shared")
  ];
}
