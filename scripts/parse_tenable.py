#!/usr/bin/env python3
"""Normalize Tenable MCP tool output into JSON records.

The Tenable MCP returns human-readable text (sometimes wrapped as {"result": "..."}
when a large result is spilled to a tool-results file). This turns that text into
structured records the correlator can join.

Usage:
  parse_tenable.py <kind> <input_file> <output_json> [--label LABEL]

kinds:
  t1_findings   Tenable One search_findings output
  t1_assets     Tenable One search_assets output
  vm_assets     VM workbenches_list_assets output
  vm_plugins    VM workbenches_list_vulnerabilities output
  tvi           vulnerability_intelligence_search output (JSON)
"""
import json, re, sys, argparse


def read_text(path):
    raw = open(path, encoding="utf-8").read()
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict) and "result" in obj:
            return obj["result"]
        return raw
    except json.JSONDecodeError:
        return raw


def t1_findings(t):
    pat = re.compile(r"- ID: (\S+)\n\s+Name: (.*)\n\s+Asset ID: (\S+) \| State: (\w+) \| Severity: (\w+)")
    return [dict(id=a, name=b.strip(), asset_id=c, state=d, severity=e) for a, b, c, d, e in pat.findall(t)]


def t1_assets(t):
    pat = re.compile(r"- ID: (\S+)\n\s+Name: (.*)\n\s+Class: (\w+) \| AES: (\S+) \| ACR: (\S+)")
    num = lambda v: None if v in ("N/A", "None") else float(v)
    return [dict(id=a, name=b.strip(), asset_class=c, aes=num(d), acr=num(e)) for a, b, c, d, e in pat.findall(t)]


def vm_assets(t):
    out = []
    for b in t.split("\n- Asset ID: ")[1:]:
        g = lambda rx: (m.group(1).strip() if (m := re.search(rx, b)) else "")
        v = re.search(r"Critical: (\d+), High: (\d+), Medium: (\d+), Low: (\d+)", b)
        c, h, m, l = (int(x) for x in v.groups()) if v else (0, 0, 0, 0)
        out.append(dict(id=b.split("\n")[0].strip(), hostname=g(r"Hostnames: (.*)"), ipv4=g(r"IPv4: (.*)"),
                        os=g(r"OS: (.*)"), critical=c, high=h, medium=m, low=l))
    return out


def vm_plugins(t):
    pat = re.compile(r"- Plugin (\d+): (.*)\n\s+Severity: (\w+) \| Count: (\d+) \| VPR Score: (\S+)\n\s+Family: (.*)")
    return [dict(plugin_id=int(a), name=b.strip(), severity=c, count=int(d),
                 vpr=None if e == "N/A" else float(e), family=f.strip()) for a, b, c, d, e, f in pat.findall(t)]


def tvi(t):
    d = json.loads(t) if isinstance(t, str) else t
    out = []
    for c in d.get("cves", []):
        v = c.get("vpr_v2") or {}
        out.append(dict(cve=c["id"], names=c.get("vulnerability_names") or [], vpr=v.get("score"),
                        kev=bool(v.get("on_cisa_kev")), kev_added=(c.get("cisa_kev") or {}).get("date_added"),
                        epss=(c.get("epss") or {}).get("score"), maturity=c.get("exploit_maturity"),
                        zero_day=c.get("zero_day"), weaponization=c.get("weaponization") or [],
                        summary=v.get("threat_summary") or c.get("description", "")[:400]))
    return out


KINDS = dict(t1_findings=t1_findings, t1_assets=t1_assets, vm_assets=vm_assets, vm_plugins=vm_plugins, tvi=tvi)

# Compact TSV input (for results the MCP returned inline instead of spilling to a file).
# First line is a header of the record fields for the kind; one record per line after it.
TSV_FIELDS = dict(
    t1_findings=["id", "name", "asset_id", "state", "severity"],
    t1_assets=["id", "name", "asset_class", "aes", "acr"],
    vm_assets=["id", "hostname", "ipv4", "os", "critical", "high", "medium", "low"],
    vm_plugins=["plugin_id", "name", "severity", "count", "vpr", "family"],
)
NUMERIC = {"aes": float, "acr": float, "vpr": float, "plugin_id": int, "count": int,
           "critical": int, "high": int, "medium": int, "low": int}


def from_tsv(kind, path):
    import csv
    rows = list(csv.DictReader(open(path, encoding="utf-8"), delimiter="\t"))
    want = TSV_FIELDS[kind]
    if rows and set(want) - set(rows[0]):
        sys.exit(f"TSV header missing fields for {kind}: {sorted(set(want) - set(rows[0]))}")
    out = []
    for r in rows:
        rec = {}
        for k in want:
            v = (r.get(k) or "").strip()
            rec[k] = (None if v in ("", "N/A", "None") else NUMERIC[k](v)) if k in NUMERIC else v
        out.append(rec)
    return out

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("kind", choices=KINDS)
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--label", default="", help="search keyword or asset class this file came from")
    a = ap.parse_args()
    if a.input.endswith(".tsv"):
        if a.kind not in TSV_FIELDS:
            sys.exit(f"TSV input not supported for kind {a.kind}")
        recs = from_tsv(a.kind, a.input)
    else:
        recs = KINDS[a.kind](read_text(a.input))
    json.dump(dict(kind=a.kind, label=a.label, count=len(recs), records=recs), open(a.output, "w"), indent=1)
    print(f"{a.kind}: {len(recs)} records -> {a.output}")
    if not recs:
        sys.exit("WARNING: zero records parsed — check the input format")
