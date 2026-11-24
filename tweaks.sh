#!/bin/bash
# P13 tweaks (2026-11-24): Homepage service entry, hub entities, CLAUDE.md switch-admin note. Idempotent.
set -e
pct exec 111 -- python3 - <<'PY'
p = "/opt/homepage/app/config/services.yaml"
s = open(p).read()
if "attack.html" not in s:
    open(p + ".bak-20261124", "w").write(s)
    entry = """    - Attack stories:
        href: https://digest.example.com/attack.html
        description: attack-stories agent, hourly at :17 (timeline, stories, ATT&CK coverage)
        widget:
          type: iframe
          name: attackstories
          src: https://digest.example.com/attack.html?embed=1
          classes: h-80
"""
    assert s.count("\n- Storage:\n") == 1
    s = s.replace("\n- Storage:\n", "\n" + entry + "- Storage:\n")
    open(p, "w").write(s)
    print("services.yaml: Attack stories added")
PY
pct exec 107 -- su agent -c 'python3 - <<"PY"
import json, collections
p = "/home/agent/agents/attack-stories/config.json"
c = json.load(open(p), object_pairs_hook=collections.OrderedDict)
for x in ("0.0.0.0", "::"):
    if x not in c["hub_entities"]:
        c["hub_entities"].append(x)
json.dump(c, open(p, "w"), indent=2)
print("hub_entities:", len(c["hub_entities"]))
PY'
pct exec 107 -- su agent -c 'f=/home/agent/agents/attack-stories/CLAUDE.md; grep -q "AG01" $f || printf "\n- The CRS305 switches AG01-AG03 (192.168.99.4-.6) are administered by the admin with the switch account \`admin\` from winbox, so \`admin\` there is a real login, not only the RouterOS default name. Changes by it are still worth a one-line confirm request.\n" >> $f; tail -2 $f'
