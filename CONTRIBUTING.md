# How this repo works

## Daily flow

1. **Collect** (`collect.yml`, every 4 hours): polls the feeds in `pipeline/feeds.yml` and stores
   new items on the `intel` branch. No AI, no cost.
2. **Draft** (`daily.yml`, 10:00 UTC): scores the recent items, asks Claude to pick the most
   huntable threat, researches it with web search and fetch, writes the hunt and a LinkedIn
   draft, runs the validator, and opens a pull request labelled `daily-hunt`.
3. **Review** (Jose): read the PR, run the query in a real tenant if possible, edit, merge.
   Unmerged drafts close after 3 days.
4. **Publish** (`publish.yml`, on merge): regenerates READMEs, indexes and `feed/hunts.json`,
   and shows the LinkedIn draft in the run summary. Posting to LinkedIn is manual.

## One-time setup

- **Secret:** Settings → Secrets and variables → Actions → New repository secret
  `ANTHROPIC_API_KEY`.
- **Let Actions open PRs:** Settings → Actions → General → Workflow permissions → select
  "Read and write permissions" and tick "Allow GitHub Actions to create and approve pull requests".
- **Optional model override:** repository variable `THREATHUNTER_MODEL` (default `claude-opus-5-5`).

Note: PRs opened by the workflow's built-in token don't trigger other workflows, so the daily
job runs the validator itself and puts the results in the PR body. Pushing your own edits to the
PR branch runs `validate.yml` as normal.

## Local commands

```bash
pip install -r requirements.txt
python -m pipeline.validate            # check every hunt
python -m pipeline.validate --check-links hunts/2026/<folder>
python -m pipeline.render              # rebuild READMEs, indexes, feed
python -m pipeline.collect --store intel/intel.json
ANTHROPIC_API_KEY=... python -m pipeline.triage --store intel/intel.json
ANTHROPIC_API_KEY=... python -m pipeline.draft --pick pick.json
```

## Writing a hunt by hand

Copy an existing folder under `hunts/<year>/`, rename it `YYYY-MM-DD-short-name`, edit
`hunt.yml` (see `schema/hunt.schema.json`), `query.kql` and optionally `query.sigma.yml`,
then run `python -m pipeline.validate` and `python -m pipeline.render`.

## Website

`site/hunts-section.html` is a block for 144company.com/cyber that lists the latest hunts from
`feed/hunts.json`. It needs the repo to be public.
