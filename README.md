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
- The [Tenable Hexa MCP](https://github.com/tenable/hexa-mcp) server connected (Tenable VM, Tenable One / Exposure Management, Vulnerability Intelligence)
- Web search enabled for the Threat Scout
- Python 3.8+ (standard library only)

## Installation

1. Clone the repo and open Claude Code in it. The agents and the skill are project-scoped, so they load automatically from `.claude/`:

   ```bash
   git clone https://github.com/smjennings/illumination-playbook.git
   cd illumination-playbook
   claude
   ```

2. Connect the [Tenable Hexa MCP](https://github.com/tenable/hexa-mcp) server to Claude Code, with access to Tenable VM, Tenable One and Vulnerability Intelligence. The agents call it as `mcp__tenable__*`, so register the server under the name `tenable`.
3. Check that `python3 --version` reports 3.8 or later. The scripts use only the standard library.

## Usage

```
/illumination-run
/illumination-run 30 days, focus identity
```

The optional arguments are a lookback window (default 60 days) and a focus area. Each run writes to `runs/YYYY-MM-DD/` (git-ignored, because it holds real asset, account and finding data). The Correlator diffs against the previous run folder, so keep old runs locally.

## Outputs

Each run folder contains:

| File | Contents |
|---|---|
| `raw/`, `data/` | Raw Tenable tool output and the normalized JSON parsed from it |
| `collector_manifest.json` | Record counts per pull, plus any capped or failed pulls |
| `watchlist.json` | Trending exploited threats with CVEs, KEV dates, sources and a `finding_regex` |
| `correlations.json` | The pattern miner's output: collisions, multi-threat hosts, resurfacing, concentration, coverage gaps and more |
| `insights.json` | 8–12 ranked insights, each with narrative, evidence counts, hosts and actions |
| `brief.html` | The exposure brief: collision map, ranked patterns, 72-hour actions, structural fixes, method and limits, sources |
| `brief.md` | A short plain-text 72-hour list for pasting into a channel |

## Data flows

Illumination reads data. It never changes Tenable configuration, scans or assets. Data moves only through these paths:

- **Tenable (read-only):** the Collector and Correlator use read-only search and list tools from your Tenable Hexa MCP server (assets, findings, software, plugin summaries, tags). The Threat Scout queries Tenable Vulnerability Intelligence and the plugin catalogue.
- **Web (Threat Scout only):** the Threat Scout runs web searches and fetches public pages (CISA KEV, vendor advisories, security news) to build the watchlist. Its queries contain CVE IDs, product names and campaign names, never your asset or account data. No other stage has web tools.
- **Anthropic:** all stages run in Claude Code, so the data they read is processed by Claude under your Claude Code / Anthropic account terms.
- **Local disk:** everything is written to `runs/<date>/` on your machine.
- **Optional publish:** the last step of `/illumination-run` publishes `brief.html` as a claude.ai Artifact, which is private to your account by default. Remove step 6 from `.claude/skills/illumination-run/SKILL.md` if you don't want this.

The Python scripts make no network calls.

## Known limitations

See "Known tool quirks" in `PLAYBOOK.md`. In short:

- The Tenable One `filters` argument is rejected by the MCP client, so threats are matched by product name and plugin-title regex, not CVE ID. Matching can miss plugins whose titles lack the product name, and a broad regex can over-count. The Correlator checks counts by severity to catch this.
- Export chunks return only 5-record previews, so the Collector pages the search tools instead. Findings searches cap at 1000 per page, and very broad keywords (for example `Windows`) can't be fully paged.
- Small results come back inline instead of spilling to a file. The agents save those as compact TSV, but your Claude Code permission settings may need to allow those file writes. A blocked write is recorded as a gap in the manifest and in the brief.
- Threats with no Tenable plugin (shown as `plugin_missing` in the watchlist) can only be detected as installed software, not as vulnerable versions.

## Data handling

Never commit `runs/`. Briefs and raw pulls contain hostnames, IPs, account names and exposure details.

## License

[MIT](LICENSE)
