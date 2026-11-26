# How this repo works

## Daily flow

1. **Collect** (`collect.yml`, GitHub Actions, every 4 hours): polls the feeds in
   `pipeline/feeds.yml` and stores new items on the `intel` branch. Free, no AI.
2. **Draft** (a Claude scheduled task on Jose's Claude plan, about 4:45 AM Eastern): a Claude
   session follows [PLAYBOOK.md](PLAYBOOK.md): lists candidates with `pipeline.triage`, picks
   one, researches it, writes the hunt and LinkedIn draft with `pipeline.new_hunt`, and opens a
   pull request labelled `daily-hunt`. No API key is needed.
3. **Review** (Jose): read the PR, run the query in a real tenant if possible, edit, merge.
   `housekeeping.yml` closes drafts nobody merged within 3 days.
4. **Publish** (`publish.yml`, on merge): regenerates READMEs, indexes and `feed/hunts.json`,
   and shows the LinkedIn draft in the run summary. Posting to LinkedIn is manual.

`validate.yml` checks every PR. All GitHub Actions here are free on public repos.

## Local commands

```bash
pip install -r requirements.txt
python -m pipeline.validate            # check every hunt
python -m pipeline.validate --check-links hunts/2026/<folder>
python -m pipeline.render              # rebuild READMEs, indexes, feed
python -m pipeline.collect --store intel/intel.json
python -m pipeline.triage --store intel/intel.json
python -m pipeline.new_hunt spec.json  # create a hunt from a JSON spec
```

## Writing a hunt by hand

Copy an existing folder under `hunts/<year>/`, rename it `YYYY-MM-DD-short-name`, edit
`hunt.yml` (see `schema/hunt.schema.json`), `query.kql` and optionally `query.sigma.yml`,
then run `python -m pipeline.validate` and `python -m pipeline.render`.

## Source policy

Every hunt links its sources. Personal-use or non-redistributable sources (for example
Ransomware.live) are listed under `research_only` in `pipeline/source_policy.yml`: agents may
use them as leads, but the checker fails any hunt, README or LinkedIn draft that mentions them.
Open data such as CISA KEV and abuse.ch Feodo Tracker (CC0) is fine to cite.

## Website

`site/hunts-section.html` is a block for 144company.com/cyber that lists the latest hunts from
`feed/hunts.json`. It needs the repo to be public.
