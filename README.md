# Illumination playbook

Illumination answers one question each week: **which vulnerabilities attackers are actively exploiting right now are present in our environment, and what patterns in our Tenable data make them worse?**

It is a [Claude Code](https://claude.com/claude-code) playbook: four project agents, one orchestration skill and two Python scripts. They join Tenable VM and Tenable One exposure data with trending exploited vulnerabilities from Tenable Vulnerability Intelligence and the web, then produce an evidence-backed HTML brief.

## What's here

| Path | What it is |
|---|---|
| `PLAYBOOK.md` | Pipeline, pattern rules, ranking and known tool quirks. Start here. |
| `.claude/skills/illumination-run/SKILL.md` | The `/illumination-run` orchestration skill |
| `.claude/agents/illumination-collector.md` | Stage 1: baseline Tenable VM + Tenable One pull |
| `.claude/agents/illumination-threat-scout.md` | Stage 2: trending / KEV watchlist from Tenable VI + web |
| `.claude/agents/illumination-correlator.md` | Stage 3: joins, product pulls, insights |
| `.claude/agents/illumination-briefer.md` | Stage 4: HTML brief + 72-hour action list |
| `scripts/parse_tenable.py` | Turns Tenable MCP text (or compact TSV) into JSON records |
| `scripts/correlate.py` | Deterministic pattern miner (collisions, resurfacing, concentration, …) |
| `illumination-brief.html` | House template for the brief (placeholders only) |

## Requirements

- Claude Code, with this folder as the project
- The Tenable MCP server connected (Tenable VM, Tenable One / Exposure Management, Vulnerability Intelligence)
- Web search enabled for the Threat Scout
- Python 3.8+ (standard library only)

## Usage

```
/illumination-run
/illumination-run 30 days, focus identity
```

Each run writes to `runs/YYYY-MM-DD/` (git-ignored, because it holds real asset, account and finding data). The Correlator diffs against the previous run folder, so keep old runs locally.

## Known limitations

See "Known tool quirks" in `PLAYBOOK.md`. In short: the Tenable One `filters` argument is rejected by the MCP client (product-name matching is used instead), export chunks return 5-record previews, findings searches cap at 1000 per page, and small results come back inline instead of spilling to a file. The Collector saves those as compact TSV, but Claude Code permission settings may need to allow those writes.

## Data handling

Never commit `runs/`. Briefs and raw pulls contain hostnames, IPs, account names and exposure details.

## License

[MIT](LICENSE)
