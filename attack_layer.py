#!/usr/bin/env python3
"""attack_layer.py (P13, 2026-11-24): ATT&CK coverage of the lab's custom Wazuh rules.

Run as root on the Wazuh manager (CT 100). Reads the custom rule files' <mitre><id> tags and Wazuh's own ATT&CK database
(/var/ossec/var/db/mitre.db) for names and tactics, and writes two files to the directory given (default /tmp):
  attack-layer.json     ATT&CK Navigator layer (v4.5): score = number of rules per technique, comment = the rules.
                        Open it at https://mitre-attack.github.io/attack-navigator/ -> Open Existing Layer -> Upload.
  attack-coverage.json  the same coverage grouped by tactic, for the dashboard page (attack.html).
  attack-techniques.json  every ATT&CK technique's name and tactics, for the page's story chain diagrams.
Re-run after adding or regenerating rules (e.g. a new sigma_rules.xml), then copy the three files to the Homepage
container's /srv/digest/www/ (see the runbook).
"""
import collections, datetime as dt, json, os, re, sqlite3, sys
import xml.etree.ElementTree as ET

RULE_DIR = "/var/ossec/etc/rules"
FILES = {  # file -> short source label used on the page
    "local_rules.xml": "local", "config_change_rules.xml": "config-change (P4)",
    "mikrotik_npm_rules.xml": "mikrotik/npm", "sigma_rules.xml": "sigma (P6)",
    "anomaly_engine_rules.xml": "anomaly engine (P7-P9)",
}
TACTICS = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence",
           "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement",
           "collection", "command-and-control", "exfiltration", "impact"]
out_dir = sys.argv[1] if len(sys.argv) > 1 else "/tmp"

# ---- rules
rules = []
for fn, label in FILES.items():
    p = os.path.join(RULE_DIR, fn)
    if not os.path.exists(p):
        continue
    text = re.sub(r"<\?xml[^>]*\?>", "", open(p, encoding="utf-8", errors="replace").read())
    root = ET.fromstring("<root>" + text + "</root>")
    for r in root.iter("rule"):
        ids = [i.text.strip() for i in r.findall("./mitre/id") if i.text]
        if ids:
            rules.append({"id": r.get("id"), "level": int(r.get("level", 0)), "file": fn, "source": label,
                          "desc": (r.findtext("description") or "").strip(), "techniques": ids})

# ---- ATT&CK names and tactics from Wazuh's database
db = sqlite3.connect("file:/var/ossec/var/db/mitre.db?mode=ro", uri=True)
ext = {sid: eid for sid, eid in db.execute("select id, external_id from reference where source='mitre-attack' "
                                            "and external_id is not null")}
tech = {}
for sid, name in db.execute("select id, name from technique"):
    if sid in ext:
        tech[ext[sid]] = {"name": name, "sid": sid}
tac_short = {sid: short for sid, short in db.execute("select id, short_name from tactic")}
tech_tactics = collections.defaultdict(set)
for tac_id, tech_id in db.execute("select tactic_id, tech_id from phase"):
    if tech_id in ext and tac_id in tac_short:
        tech_tactics[ext[tech_id]].add(tac_short[tac_id])

by_tech = collections.defaultdict(list)
for r in rules:
    for t in r["techniques"]:
        by_tech[t].append(r)

# ---- Navigator layer
now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
maxscore = max((len(v) for v in by_tech.values()), default=1)
layer = {
    "name": "homelab custom detection coverage",
    "versions": {"layer": "4.5", "navigator": "5.1.0"},
    "domain": "enterprise-attack",
    "description": f"Custom Wazuh rules with ATT&CK tags ({len(rules)} rules, {len(by_tech)} techniques), generated {now} "
                   "by attack_layer.py. Score = number of rules.",
    "sorting": 3, "hideDisabled": False,
    "layout": {"layout": "side", "showName": True, "showID": True, "expandedSubtechniques": "annotated"},
    "gradient": {"colors": ["#9ec5f4", "#2a78d6", "#104281"], "minValue": 1, "maxValue": min(maxscore, 20)},
    "techniques": [],
    "legendItems": [{"label": "1 rule", "color": "#9ec5f4"}, {"label": f"{min(maxscore, 20)}+ rules", "color": "#104281"}],
    "metadata": [{"name": "generated", "value": now}, {"name": "source", "value": "Wazuh CT 100 custom rule files"}],
}
for t, rs in sorted(by_tech.items()):
    comment = "; ".join(f'{r["id"]} (L{r["level"]}) {r["desc"][:80]}' for r in sorted(rs, key=lambda r: -r["level"])[:12])
    if len(rs) > 12:
        comment += f"; ... {len(rs) - 12} more"
    entry = {"techniqueID": t, "score": len(rs), "comment": comment, "enabled": True,
             "metadata": [{"name": "sources", "value": ", ".join(sorted({r["source"] for r in rs}))}]}
    if "." not in t:
        entry["showSubtechniques"] = True
    for tac in sorted(tech_tactics.get(t, [])):
        layer["techniques"].append(dict(entry, tactic=tac))
    if not tech_tactics.get(t):
        layer["techniques"].append(entry)

# ---- page coverage
cov = {"generated": now, "rules": len(rules), "techniques": len(by_tech),
       "sources": dict(collections.Counter(r["source"] for r in rules)), "tactics": []}
unmapped = sorted(t for t in by_tech if not tech_tactics.get(t))
for tac in TACTICS:
    items = []
    for t, rs in by_tech.items():
        if tac in tech_tactics.get(t, ()):
            items.append({"id": t, "name": tech.get(t, {}).get("name", "?"), "rules": len(rs),
                          "max_level": max(r["level"] for r in rs),
                          "sources": sorted({r["source"] for r in rs}),
                          "top": [f'{r["id"]} L{r["level"]} {r["desc"][:90]}' for r in sorted(rs, key=lambda r: -r["level"])[:6]]})
    items.sort(key=lambda x: (-x["rules"], x["id"]))
    cov["tactics"].append({"tactic": tac, "techniques": items})
cov["unmapped"] = unmapped
# every technique's name and tactics (display names), for the dashboard's chain diagram
tac_name = {short: name for short, name in db.execute("select short_name, name from tactic")}
names = {}
for t, v in tech.items():
    if t.startswith("T"):
        names[t] = {"n": v["name"], "t": [tac_name.get(x, x) for x in TACTICS if x in tech_tactics.get(t, ())]}
for name, obj in (("attack-layer.json", layer), ("attack-coverage.json", cov), ("attack-techniques.json", names)):
    with open(os.path.join(out_dir, name), "w") as f:
        json.dump(obj, f, indent=1)
print(f"{len(rules)} rules, {len(by_tech)} techniques, {sum(len(x['techniques']) for x in cov['tactics'])} tactic cells, "
      f"unmapped {unmapped}")
