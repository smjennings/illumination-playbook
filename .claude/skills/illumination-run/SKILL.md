---
name: illumination-run
description: Run the full Illumination exposure-intelligence playbook. Collect Tenable data, scout trending vulnerabilities, correlate them, and publish the brief. Use when the user asks to run Illumination, refresh the exposure brief, or check which trending vulnerabilities affect the environment.
---

# Illumination run

Follow `PLAYBOOK.md` at the project root. This skill is the orchestration script.

1. Set `RUN_DIR=runs/<today YYYY-MM-DD>` (add `-2`, `-3` if that folder already exists). Create `RUN_DIR/raw` and `RUN_DIR/data`.
2. **In parallel**, spawn the `illumination-collector` and `illumination-threat-scout` agents, passing each the RUN_DIR. They don't depend on each other.
3. When both have reported, check that `RUN_DIR/data/vm_assets.json` and `RUN_DIR/watchlist.json` exist and aren't empty. If either is missing, tell the user which stage failed and stop.
4. Spawn `illumination-correlator` with RUN_DIR.
5. Spawn `illumination-briefer` with RUN_DIR.
6. Publish `RUN_DIR/brief.html` with the Artifact tool. If an earlier brief was published at the URL in memory (`illumination-project`), read that artifact first and then publish to the same URL, so the link stays stable. Each run's `brief.html` stays in its own run folder as the history.
7. Reply with the link, the top five insights in one line each, and any stage failures or data caps.

Arguments: an optional lookback window (default 60 days) and an optional focus (e.g. "identity only", "AI stack"). Pass both to the Threat Scout and the Correlator.
