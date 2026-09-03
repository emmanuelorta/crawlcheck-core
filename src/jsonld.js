// crawlcheck-core / jsonld.js
// The JSON-LD graph reader from CrawlCheck, extracted verbatim from the
// production scanner. ESM, no dependencies.
//
// ldGraphNodes(html) returns the ENTITIES a page declares: every root node and
// every @graph child, with two rules that matter and are easy to get wrong.
//
//   1. Depth. A node nested inside another node is a VALUE (a PostalAddress, an
//      Offer, a ListItem, an Answer), not a subject the page is asserting, and
//      it is not held to the standards an entity is. Only depth 0 counts.
//   2. Same @id twice is ONE subject. RDF merges statements about a subject;
//      a reader that keeps the first node and drops the second reads a site
//      that declares a typeless fingerprint stub before its full Organization
//      as having an untyped business. Statements are merged, @type is unioned.
//
// Nodes carry a non-enumerable `__top` marker so a caller can tell a root node
// from a @graph child without changing what JSON.stringify emits.

export function ldGraphNodes(html) {
  const out = [], seen = new Set(), byId = new Map();
  for (const m of String(html || "").matchAll(/<script\b[^>]*application\/ld\+json[^>]*>([\s\S]*?)<\/script>/gi)) {
    let data; try { data = JSON.parse(m[1]); } catch (e) { continue; }
    // depth 0 = a root node or a @graph child: the entities the page declares.
    // Anything deeper is a value (PostalAddress, Offer, ListItem, Answer) and is
    // not held to the standards an entity is. Same @id twice = one subject.
    const stack = [{ n: data, top: true }];
    while (stack.length) {
      const it = stack.pop(); const n = it.n;
      if (Array.isArray(n)) { n.forEach(function (x) { stack.push({ n: x, top: it.top }); }); continue; }
      if (!n || typeof n !== "object" || seen.has(n)) continue;
      seen.add(n);
      const keys = Object.keys(n);
      const isStub = keys.length === 1 && keys[0] === "@id";
      const isWrapper = keys.every(function (k) { return k === "@context" || k === "@graph"; });
      if (!isStub && !isWrapper) {
        const id = typeof n["@id"] === "string" ? n["@id"] : null;
        if (id && byId.has(id)) {
          // RDF merges statements about one subject. terrariumstation.com
          // (measured 2026-09-01) declares #organization twice: a typeless
          // fingerprint stub first, the full Organization second - keeping the
          // first and dropping the second read the business as untyped.
          const ex = byId.get(id);
          keys.forEach(function (k) {
            if (k === "@context" || k === "@id") return;
            if (k === "@type") { ex["@type"] = [].concat(ex["@type"] || []).concat([].concat(n[k] || [])).filter(function (t, i, a) { return a.indexOf(t) === i; }); if (ex["@type"].length === 1) ex["@type"] = ex["@type"][0]; return; }
            if (ex[k] === undefined) ex[k] = n[k];
          });
          if (it.top) { try { Object.defineProperty(ex, "__top", { value: true, enumerable: false }); } catch (e) { } }
        } else {
          if (id) byId.set(id, n);
          try { Object.defineProperty(n, "__top", { value: !!it.top, enumerable: false }); } catch (e) { }
          out.push(n);
        }
      }
      keys.forEach(function (k) { if (k === "@context") return; const v = n[k]; if (v && typeof v === "object") stack.push({ n: v, top: isWrapper && k === "@graph" ? it.top : false }); });
    }
  }
  return out;
}
