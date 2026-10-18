#!/usr/bin/env bash
# CrawlCheck fixes: fetch the corrected files for the live site, write the ones
# that changed into the repository, and open (or update) one pull request.
set -euo pipefail
API="${CC_API:-https://crawlcheck.io}"
DOMAIN="$(printf '%s' "${CC_DOMAIN:?domain is required}" | sed -E 's#^https?://##; s#/.*$##' | tr 'A-Z' 'a-z')"
OUT="${GITHUB_OUTPUT:-/dev/null}"
NOTES="$(mktemp)"; WROTE=0
ua="crawlcheck-action/1 (+https://github.com/emmanuelorta/crawlcheck-core/tree/main/action)"

fetch() { curl -fsS --retry 2 --max-time 120 -A "$ua" "$1"; }
field() { python3 -c 'import json,sys; d=json.load(sys.stdin); v=d.get(sys.argv[1]); print("" if v is None else (json.dumps(v) if isinstance(v,(bool,list,dict)) else v), end="")' "$1"; }

if [ -n "${CC_ROBOTS:-}" ]; then
  j="$(fetch "$API/api/fix/robots?domain=$DOMAIN&format=json")"
  if [ "$(printf '%s' "$j" | field changed)" = "true" ]; then
    mkdir -p "$(dirname "$CC_ROBOTS")"
    printf '%s' "$j" | field text > "$CC_ROBOTS"
    { echo "### robots.txt ($CC_ROBOTS)"; printf '%s' "$j" | python3 -c 'import json,sys; [print("- "+n) for n in json.load(sys.stdin).get("notes") or ["Corrected; every change is listed in the comments at the top of the file."]]'; echo; } >> "$NOTES"
    WROTE=1
  else echo "robots.txt: no change needed"; fi
fi

if [ -n "${CC_SITEMAP:-}" ]; then
  j="$(fetch "$API/api/fix/sitemap?domain=$DOMAIN" || true)"
  if [ -n "$j" ] && [ "$(printf '%s' "$j" | field changed)" = "true" ] && [ -n "$(printf '%s' "$j" | field text)" ]; then
    mkdir -p "$(dirname "$CC_SITEMAP")"
    printf '%s' "$j" | field text > "$CC_SITEMAP"
    { echo "### sitemap ($CC_SITEMAP)"; echo "- $(printf '%s' "$j" | field note)"; echo; } >> "$NOTES"
    WROTE=1
  else echo "sitemap: no change needed (or not available: $(printf '%s' "$j" | field note)$(printf '%s' "$j" | field error))"; fi
fi

if [ "$WROTE" = 0 ] || [ -z "$(git status --porcelain -- ${CC_ROBOTS:+"$CC_ROBOTS"} ${CC_SITEMAP:+"$CC_SITEMAP"})" ]; then echo "changed=false" >> "$OUT"; echo "Nothing to fix."; exit 0; fi
[ "${CC_DRY_RUN:-}" = 1 ] && { git status --short; cat "$NOTES"; echo "changed=true" >> "$OUT"; exit 0; }

BASE="$(git rev-parse --abbrev-ref HEAD)"
git config user.name "crawlcheck-fixes[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git checkout -B "$CC_BRANCH"
git add -A -- ${CC_ROBOTS:+"$CC_ROBOTS"} ${CC_SITEMAP:+"$CC_SITEMAP"}
git commit -q -m "CrawlCheck: fix machine files for $DOMAIN"
git push -q -f origin "$CC_BRANCH"

BODY="$(mktemp)"
{ echo "CrawlCheck read the files **$DOMAIN** serves and found defects it can repair. The corrected files are below; each was derived from the live file, so review the diff before merging."; echo; cat "$NOTES"
  echo "After merging and deploying, re-check at https://crawlcheck.io/?url=$DOMAIN"; } > "$BODY"
PR="$(gh pr list --head "$CC_BRANCH" --state open --json url -q '.[0].url' 2>/dev/null || true)"
if [ -n "$PR" ]; then gh pr edit "$PR" --body-file "$BODY" >/dev/null
else PR="$(gh pr create --base "$BASE" --head "$CC_BRANCH" --title "CrawlCheck: fix machine files for $DOMAIN" --body-file "$BODY" 2>&1)" || {
  echo "::warning::Could not open the pull request ($PR). Turn on Settings > Actions > General > 'Allow GitHub Actions to create and approve pull requests', or open it yourself: $GITHUB_SERVER_URL/$GITHUB_REPOSITORY/compare/$BASE...$CC_BRANCH"
  PR="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/compare/$BASE...$CC_BRANCH"; }; fi
echo "changed=true" >> "$OUT"; echo "pr_url=$PR" >> "$OUT"; echo "Pull request: $PR"
