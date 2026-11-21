#!/usr/bin/env python3
"""Correlate a run's Tenable data with the threat watchlist and mine patterns.

Usage: correlate.py runs/<date>

Expects in the run dir (written by the Collector and Threat Scout):
  data/vm_assets.json            parse_tenable vm_assets
  data/findings_*.json           parse_tenable t1_findings (label = search keyword)
  data/assets_*.json             parse_tenable t1_assets (ACCOUNT, IDENTITY, AI_AGENT, DEVICE ...)
  watchlist.json                 Threat Scout output (see PLAYBOOK.md for schema)
Writes:
  correlations.json              every metric below, with evidence
"""
import json, re, sys, glob, os, collections

IDENTITY_RX = re.compile(r"account|password|privileg|delegation|group|dormant|identity|krbtgt|kerberos pre-auth", re.I)
IDENTITY_EXCLUDE_RX = re.compile(r"libcurl|IAM |Client Data Leakage|Linux virtual machine|Virtual machine", re.I)
CONTROL_PLANE_RX = re.compile(r"wsus|sccm|mecm|bigfix|mgengine|manageengine|tanium|intune|\bdc\b|-dc|dc-|\bdc\d|domain|tad-|relay|exchange|vcenter|esxi|jump|bastion|ansible|puppet|chef|salt|backup|veeam|pki|adcs|\bca\b|siem|splunk|nessus|tenable", re.I)
TOOL_ACCOUNT_RX = re.compile(r"admin|svc|service|sccm|nessus|tenable|scan|armis|msol_|sync|okta|crowdstrike|qualys|rapid7|backup|sql", re.I)
LEGACY_RX = re.compile(r"\bMS0\d-|\bMS1[0-7]-|\((19|20[01]\d|2020)\)|20(0\d|1[0-8])\b")
OPEN = ("ACTIVE", "RESURFACED")


def load(p):
    return json.load(open(p))


def main(run):
    d = os.path.join(run, "data")
    vm = load(os.path.join(d, "vm_assets.json"))["records"] if os.path.exists(os.path.join(d, "vm_assets.json")) else []
    host = {a["id"]: (a["hostname"].split(",")[0] or a["ipv4"]) for a in vm}
    vm_by_id = {a["id"]: a for a in vm}

    findings, by_label = {}, {}
    for f in glob.glob(os.path.join(d, "findings_*.json")):
        j = load(f)
        by_label[j["label"] or os.path.basename(f)] = j["records"]
        for r in j["records"]:
            findings[r["id"]] = r
    F = list(findings.values())

    assets = {}
    for f in glob.glob(os.path.join(d, "assets_*.json")):
        for r in load(f)["records"]:
            assets[r["id"]] = r
            host.setdefault(r["id"], r["name"])
    name = lambda aid: host.get(aid, aid[:8])

    watch = load(os.path.join(run, "watchlist.json")) if os.path.exists(os.path.join(run, "watchlist.json")) else []
    out = dict(run=os.path.basename(run.rstrip("/")), totals=dict(vm_hosts=len(vm), findings=len(F), assets=len(assets), watchlist=len(watch)))

    # 1. Collision map: watchlist threat -> affected hosts
    coll, host_threats = [], collections.defaultdict(set)
    for w in watch:
        rx = re.compile(w.get("finding_regex") or "|".join(map(re.escape, w.get("product_keywords", []))) or r"^\b$", re.I)
        hits = [r for r in F if r["state"] in OPEN and r["severity"] != "INFO" and rx.search(r["name"])]
        hosts = collections.defaultdict(lambda: dict(states=set(), findings=set()))
        for r in hits:
            hosts[r["asset_id"]]["states"].add(r["state"]); hosts[r["asset_id"]]["findings"].add(r["name"])
        for aid in hosts:
            host_threats[aid].add(w["threat"])
        coll.append(dict(threat=w["threat"], cves=w.get("cves", []), kev=w.get("kev"), kev_due=w.get("kev_due"),
                         status=w.get("status"), host_count=len(hosts),
                         hosts=[dict(asset_id=a, host=name(a), resurfaced="RESURFACED" in v["states"],
                                     findings=sorted(v["findings"])[:5]) for a, v in sorted(hosts.items(), key=lambda kv: name(kv[0]))]))
    out["collisions"] = sorted(coll, key=lambda c: (-bool(c["kev"]), -c["host_count"]))

    # 2. Hosts under multiple trending threats
    out["multi_threat_hosts"] = sorted([dict(asset_id=a, host=name(a), threats=sorted(t)) for a, t in host_threats.items() if len(t) > 1],
                                       key=lambda x: -len(x["threats"]))

    # 3. Resurfacing rate: identity vs software
    def rate(rs):
        c = collections.Counter(r["state"] for r in rs)
        o = c["ACTIVE"] + c["RESURFACED"]
        return dict(n=len(rs), open=o, resurfaced=c["RESURFACED"], fixed=c["FIXED"], pct=round(100 * c["RESURFACED"] / o, 1) if o else None)
    ident = [r for r in F if IDENTITY_RX.search(r["name"]) and not IDENTITY_EXCLUDE_RX.search(r["name"])]
    soft = [r for r in F if r not in ident and r["severity"] != "INFO"]
    out["resurfacing"] = dict(identity=rate(ident), software=rate(soft))
    top_flap = collections.Counter()
    for r in ident:
        top_flap[(r["name"], r["state"])] += 1
    flappers = collections.defaultdict(dict)
    for (n, s), k in top_flap.items():
        flappers[n][s] = k
    out["identity_flappers"] = sorted([dict(name=n, **v) for n, v in flappers.items() if v.get("RESURFACED", 0) >= 3],
                                      key=lambda x: -x.get("RESURFACED", 0))[:12]

    # 4. Risk concentration + coverage gap (VM)
    if vm:
        ch = sorted((a["critical"] + a["high"] for a in vm), reverse=True); tot = sum(ch) or 1
        out["concentration"] = {f"top_{p}pct": dict(hosts=max(1, len(vm) * p // 100), share=round(100 * sum(ch[:max(1, len(vm) * p // 100)]) / tot, 1)) for p in (1, 5, 10, 20)}
        out["coverage_gap"] = dict(zero_finding_hosts=sum(1 for a in vm if a["critical"] + a["high"] + a["medium"] + a["low"] == 0),
                                   unknown_os_hosts=sum(1 for a in vm if not a["os"] or a["os"] == "N/A"), total=len(vm))
        top = sorted(vm, key=lambda a: -(a["critical"] + a["high"]))[:25]
        out["top_hosts"] = [dict(host=host[a["id"]], ip=a["ipv4"], os=a["os"][:60], critical=a["critical"], high=a["high"],
                                 control_plane=bool(CONTROL_PLANE_RX.search(a["hostname"]))) for a in top]
        out["control_plane_in_top25"] = [h for h in out["top_hosts"] if h["control_plane"]]

    # 5. Golden-image signature: scanned hosts where >=10 software findings are all RESURFACED (none ACTIVE)
    #    -> host was rebuilt from a stale template; identity objects excluded (they flap for other reasons)
    ident_ids = {r["id"] for r in ident}
    per = collections.defaultdict(list)
    for r in F:
        if r["id"] not in ident_ids and r["asset_id"] in vm_by_id:
            per[r["asset_id"]].append(r["state"])
    out["golden_image_suspects"] = [dict(asset_id=a, host=name(a), findings=len(s), resurfaced=s.count("RESURFACED"))
                                    for a, s in per.items() if len(s) >= 10 and s.count("RESURFACED") >= 10 and s.count("ACTIVE") == 0]

    # 6. Patch regressions on trending threats (fixed once, back again)
    out["trending_regressions"] = [dict(threat=c["threat"], host=h["host"]) for c in out["collisions"] for h in c["hosts"] if h["resurfaced"]]

    # 7. Legacy criticals still open (old bulletins / years)
    leg = collections.defaultdict(set)
    for r in F:
        if r["state"] in OPEN and r["severity"] in ("CRITICAL", "HIGH") and LEGACY_RX.search(r["name"]):
            leg[r["name"]].add(name(r["asset_id"]))
    out["legacy_criticals"] = sorted([dict(name=n, hosts=sorted(h)) for n, h in leg.items()], key=lambda x: -len(x["hosts"]))[:15]

    # 8. Identity: tool / service accounts among highest exposure
    ids = [a for a in assets.values() if a["asset_class"] in ("ACCOUNT", "IDENTITY")]
    ranked = sorted([a for a in ids if a["aes"] is not None], key=lambda a: -a["aes"])
    top40 = ranked[:40]
    out["tool_accounts_top40"] = [dict(name=a["name"], aes=a["aes"], acr=a["acr"], cls=a["asset_class"]) for a in top40 if TOOL_ACCOUNT_RX.search(a["name"])]
    dup = collections.Counter(a["name"].lower() for a in ids)
    out["duplicate_identity_names"] = [dict(name=n, count=c) for n, c in dup.most_common(15) if c > 1]
    sev_id = collections.Counter(r["name"] for r in ident if r["state"] in OPEN and r["severity"] in ("CRITICAL", "HIGH"))
    out["identity_top_issues"] = [dict(name=n, open=c) for n, c in sev_id.most_common(12)]

    # 9. Unscored AI agents
    ai = [a for a in assets.values() if a["asset_class"] == "AI_AGENT"]
    out["ai_agents"] = dict(total=len(ai), unscored=sum(1 for a in ai if a["aes"] is None), names=sorted(a["name"] for a in ai)[:40])

    json.dump(out, open(os.path.join(run, "correlations.json"), "w"), indent=1, default=list)
    # concise console summary for the calling agent
    print(json.dumps(dict(totals=out["totals"], collisions=[(c["threat"], c["host_count"]) for c in out["collisions"]],
                          multi_threat=[(m["host"], m["threats"]) for m in out["multi_threat_hosts"][:8]],
                          resurfacing=out["resurfacing"], concentration=out.get("concentration"), coverage=out.get("coverage_gap"),
                          control_plane=[h["host"] for h in out.get("control_plane_in_top25", [])],
                          golden=[g["host"] for g in out["golden_image_suspects"]], regressions=out["trending_regressions"][:10],
                          tool_accounts=[(t["name"], t["aes"]) for t in out["tool_accounts_top40"]], ai=out["ai_agents"]["total"]), indent=1))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else sys.exit(__doc__))
