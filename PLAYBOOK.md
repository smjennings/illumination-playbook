# Illumination playbook

Illumination asks one question every week: **which vulnerabilities attackers are actively exploiting right now are present in our environment, and what patterns in our Tenable data make them worse?** It answers that with four agents and two scripts, and every claim in the brief traces back to a record count.

Run it with `/illumination-run` (optionally `/illumination-run 30 days, focus identity`).

## Pipeline

```
            ┌────────────────────┐     ┌──────────────────────┐
 Tenable ──▶│ 1 Collector        │     │ 2 Threat Scout       │◀── Tenable VI + web
            │ baseline pull      │     │ watchlist.json       │
            └─────────┬──────────┘     └──────────┬───────────┘
                      └──────────┬────────────────┘   (1 and 2 run in parallel)
                                 ▼
                      ┌────────────────────┐
                      │ 3 Correlator       │──▶ product-specific Tenable pulls
                      │ correlations.json  │
                      │ insights.json      │
                      └─────────┬──────────┘
                                ▼
                      ┌────────────────────┐
                      │ 4 Briefer          │──▶ brief.html, brief.md ──▶ published artifact
                      └────────────────────┘
```

| Stage | Agent file | Reads | Writes |
|---|---|---|---|
| 1 Collect | `.claude/agents/illumination-collector.md` | Tenable VM + Tenable One | `raw/*.txt`, `data/*.json`, `collector_manifest.json` |
| 2 Scout | `.claude/agents/illumination-threat-scout.md` | Tenable VI, web | `data/tvi_trending.json`, `watchlist.json` |
| 3 Correlate | `.claude/agents/illumination-correlator.md` | stages 1–2, more Tenable pulls | `correlations.json`, `insights.json`, `software_presence.json` |
| 4 Brief | `.claude/agents/illumination-briefer.md` | stage 3 | `brief.html`, `brief.md` |

Each run lives in `runs/YYYY-MM-DD/`. Keep old runs: the Correlator diffs against the previous one.

## Scripts

- `scripts/parse_tenable.py <kind> <in> <out> [--label]` turns Tenable MCP text into JSON. The kinds are `t1_findings`, `t1_assets`, `vm_assets`, `vm_plugins` and `tvi`. It exits non-zero when it parses 0 records.
- `scripts/correlate.py runs/<date>` is the deterministic pattern miner (described below).

## What the miner looks for

| Pattern | Why a human misses it | Rule |
|---|---|---|
| Collision map | Threat intel and asset data live in different tools | watchlist `finding_regex` × open, non-info findings |
| Multi-threat hosts | A host can rank low on finding count and still sit under several live campaigns | hosts matched by ≥ 2 watchlist threats |
| Trending regressions | A fix and its rollback happen weeks apart | collision hosts with RESURFACED findings |
| Identity vs software resurfacing | Each dashboard shows one domain | % of open findings in RESURFACED, identity keywords vs the rest |
| Identity flappers | Fix counts look like progress | identity findings with ≥ 3 RESURFACED |
| Risk concentration | Totals hide the shape | share of crit+high held by the top 1/5/10/20% of hosts |
| Coverage gap | Zero findings looks like "clean" | hosts with 0 findings, hosts with unknown OS |
| Control plane in the top 25 | Patch and identity infrastructure is assumed to be managed | hostname regex (wsus, bigfix, dc, exchange, vcenter, relay…) |
| Golden-image suspects | A rebuild reopens years of findings in one scan | ≥ 10 software findings on a host, all RESURFACED, none ACTIVE |
| Legacy criticals | Old bulletins drop out of view | open crit/high with MS0x/MS1x or a pre-2021 year in the name |
| Tool accounts in the top 40 | Scanner and management accounts are trusted by default | identity name regex (nessus, tenable, sccm, msol_, svc…) ranked by AES |
| Unscored AI agents | New asset class, outside the scoring model | AI_AGENT assets with no AES |

The Correlator agent then adds judgment-based findings on top of these: cross-domain attack chains, partial upgrades, role-implied criticality (OT, prod, AI), internet exposure, and the week-over-week diff.

## Ranking

Insights are ranked by **active exploitation × reachability × blast radius**:
1. A KEV item with a near due date on a reachable host
2. A host under several trending threats, or a trending threat that regressed
3. A chain to domain or fleet control (DCs, WSUS/BigFix, scanner credentials)
4. Process failures (identity drift, golden images)
5. Visibility gaps (coverage, unscored assets)

## Known tool quirks

- **Tenable One `filters` argument gets rejected.** The MCP client passes the JSON string as a list, and the server rejects it. Use the convenience parameters and product-name matching, not `finding_cves`.
- **Export chunks are previews.** `tenable_one_download_export_chunk` returns 5 records. Page the search tools at limit 1000 instead.
- **Spilled results.** Large results are written to a tool-results file. Agents `cp` them into `raw/` rather than reading them into context.
- **Search caps.** A findings search that returns exactly 1000 records was truncated. Page with `offset`.

## Extending it

- **New pattern:** add a block to `correlate.py`, add a row to the table above, and re-run it against an old run to check the output.
- **New data source** (EDR, CMDB, ticketing): add a Collector pull plus a `parse_tenable.py` kind, or write a new parser that emits the same `{kind,label,count,records}` envelope.
- **Schedule:** use `/schedule` to run `/illumination-run` weekly. Publishing to the same artifact URL keeps one living brief.

## First run

`runs/2026-11-20/` holds the data behind the first published brief (a partial set: only the pulls that were saved to files), plus a hand-built 4-threat `watchlist.json` used to test the scripts.
