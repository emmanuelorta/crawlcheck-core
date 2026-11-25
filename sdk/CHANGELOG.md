# Changelog

## 1.16.0 (2026-11-25)

- Security: verification now fails closed, so forged signed answers that earlier releases could report as accepted are rejected; upgrading is advised.
- The signing policy is read at the latest time a document states inside its signed body; `signature.signed_at` can move that time later, never earlier. `created_at` and `approved_at` count as body times.
- The client keeps a log head only when a key CrawlCheck publishes for log heads signed it (`resolve`, `resolveBatch`, `logGossip`, `logCheck`). Other heads are ignored and listed in `client.logIgnored`. New: `logPrune`, the `keyPolicy` option of `logObserve` / `logGossip`, and `issuer_checked` on stored heads and forks. `guard()` re-checks forks a saved store holds before it refuses on them.
- A document whose signed body states no time is refused when the signing policy does not accept its key for that object now (a retired key, a key of another purpose): `signature.signed_at` alone never places a document at an earlier time, whether it is present or left out.
- With key ids alone (`publishedKids`), a listed id this release does not ship gives `key_policy_code: "purpose_unknown"`: accepted, partial, never `accepted_strict`. `logObserve` does not keep a head under such a key and `guard()` does not act on a decision under one; pass `keyPolicy`.
- `issuer_pinned` is true only when the signature verifies under a key id this release ships. New: `pinnedKeyPolicy()`; with `publishedKids` alone, the purposes of the ids this release knows still apply.
- The command-line verifier exits 0 only when it prints ACCEPTED (1: a check failed or the key is unknown to this release; 3: intact, issuer not checked).
- Every own member of a signed document, lockfile or tool definition is hashed, whatever its name; tools named like built-in object members are compared like any other tool.
- API types regenerated from the current API description.
- The package ships the built code, README and changelog only; tests, fixtures and examples stay in the source repository.
