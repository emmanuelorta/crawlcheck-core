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

| `fix` | `true` | `false` skips the fix step (observe only) |
| `observe` | `false` | `true` also reads the site from this runner as a CrawlCheck observer |

Outputs: `changed` (`true`/`false`) and `pr-url`.

The corrected files come from the live site, not from the file in your repository, so review the diff: if your repository holds changes that are not deployed yet, the pull request will not include them. Every change is listed in comments at the top of the corrected robots.txt and in the pull request body.

## Observe from your own runner

With `observe: "true"` the action also reads your site from the machine the job runs on, under the same request profiles CrawlCheck's scanner uses, and posts one signed reading. CrawlCheck then has a reading of your site taken from your runner's network, not only its own; on a self-hosted runner that is your own network.

```yaml
permissions:
  contents: write
  pull-requests: write
  id-token: write          # proves which repository is observing; no secret to store
jobs:
  fix:
    runs-on: ubuntu-latest  # or self-hosted
    steps:
      - uses: actions/checkout@v5
      - uses: emmanuelorta/crawlcheck-core/action@main
        with:
          domain: example.com
          observe: "true"
```

Each run makes a fresh key and asks GitHub for a token bound to it; GitHub's token names your repository and workflow, so there is nothing to enrol and no secret to keep. The observer id is `gha:<owner>/<repo>`. The first run registers the repository; readings are stored and listed at once, and they count toward CrawlCheck's verdicts after 7 days and 20 accepted readings, like every new observer. Each reading carries what the requests got back: status, a few response headers and the page bytes (CrawlCheck stores them by their hash); no cookies or credentials are sent. A failed observation never fails the job. Protocol: https://crawlcheck.io/docs/observer-protocol#ci

Docs: https://github.com/emmanuelorta/crawlcheck-core/tree/main/action
