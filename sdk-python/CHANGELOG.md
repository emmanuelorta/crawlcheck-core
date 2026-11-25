# Changelog

## 1.17.0 (2026-11-25)

- Security: verification now fails closed, so forged signed answers that earlier releases could report as accepted are rejected; upgrading is advised.
- The signing policy is read at the latest time a document states inside its signed body; `signature.signed_at` can move that time later, never earlier. `created_at` and `approved_at` count as body times.
- The client keeps a log head only when a key CrawlCheck publishes for log heads signed it (`resolve`, `resolve_batch`, `log_gossip`, `log_check`). Other heads are ignored and listed in `client.log_ignored`. New: `log_prune`, the `key_policy` argument of `log_observe` / `log_gossip` / `log_check`, and `issuer_checked` on stored heads and forks. `guard()` re-checks forks a saved store holds before it refuses on them.
- A document whose signed body states no time is refused when the signing policy does not accept its key for that object now (a retired key, a key of another purpose): `signature.signed_at` alone never places a document at an earlier time, whether it is present or left out.
- With key ids alone, a listed id this release does not ship gives `key_policy_code: "purpose_unknown"`: accepted, partial, never `accepted_strict`. `log_observe` does not keep a head under such a key; pass `key_policy`.
- `canon` orders member names by UTF-16 code unit, as the service does (it differed only for names mixing U+E000..U+FFFF with characters above U+FFFF).
- `issuer_pinned` is true only when the signature verifies under a key id this release ships. New: `pinned_key_policy()`; with key ids alone, the purposes of the ids this release knows still apply.
- `python -m crawlcheck preflight` verifies the receipt and exits 1 when it is not accepted, as `verify` does.
- The source distribution ships the package, README and changelog only; tests and examples stay in the source repository.
