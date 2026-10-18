# CrawlCheck fixes (GitHub Action)

Checks the robots.txt (and, for static sites, the sitemap) that your live site serves. When CrawlCheck finds a defect it can repair, the action writes the corrected file into your repository and opens one pull request. Nothing is merged for you.

```yaml
# .github/workflows/crawlcheck.yml
name: CrawlCheck fixes
on:
  schedule: [{ cron: "17 13 * * 1" }]   # weekly
  workflow_dispatch:
permissions:
  contents: write
  pull-requests: write
jobs:
  fix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: emmanuelorta/crawlcheck-core/action@main
        with:
          domain: example.com
          robots-path: public/robots.txt     # where robots.txt lives in this repo
          # sitemap-path: public/sitemap.xml # only for a hand-maintained sitemap
```

Turn on **Settings › Actions › General › Allow GitHub Actions to create and approve pull requests**. Without it the action still pushes the `crawlcheck/fixes` branch and prints the link to open the pull request yourself.

| Input | Default | |
|---|---|---|
| `domain` | (required) | The site to check |
| `robots-path` | `robots.txt` | Empty skips robots.txt |
| `sitemap-path` | empty | Leave empty when a CMS or plugin generates the sitemap |
| `branch` | `crawlcheck/fixes` | Re-runs update the same branch and pull request |
| `token` | `github.token` | Needs contents and pull-requests write |

Outputs: `changed` (`true`/`false`) and `pr-url`.

The corrected files come from the live site, not from the file in your repository, so review the diff: if your repository holds changes that are not deployed yet, the pull request will not include them. Every change is listed in comments at the top of the corrected robots.txt and in the pull request body.

Docs: https://github.com/emmanuelorta/crawlcheck-core/tree/main/action
