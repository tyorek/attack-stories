#!/usr/bin/env python3
"""Give the supervisor chat the attack-stories agent (2026-11-24): describe it and the anomaly engine in CLAUDE.md,
and let run_agent start attack-stories. Idempotent; backups *.pre-attack-stories."""
import py_compile, shutil, sys
W = "/home/agent/agents/supervisor/"
def edit(path, pairs):
    s = open(path).read()
    if "attack-stories" in s:
        print(path, "already has attack-stories"); return
    shutil.copy2(path, path + ".pre-attack-stories")
    for old, new in pairs:
        if s.count(old) != 1:
            sys.exit(f"{path}: anchor not found once: {old[:60]!r}")
        s = s.replace(old, new)
    open(path, "w").write(s)
    print(path, "patched")

edit(W + "server.py", [
    ('    "Bash(/home/agent/agents/supervisor/bin/run-agent daily-digest)",\n',
     '    "Bash(/home/agent/agents/supervisor/bin/run-agent daily-digest)",\n'
     '    "Bash(/home/agent/agents/supervisor/bin/run-agent attack-stories)",\n'),
    ("- `run_agent(name)`: start wazuh-triage, mikrotik-audit or daily-digest.",
     "- `run_agent(name)`: start wazuh-triage, mikrotik-audit, daily-digest or attack-stories."),
    ('"enum": ["wazuh-triage", "mikrotik-audit", "daily-digest"]',
     '"enum": ["wazuh-triage", "mikrotik-audit", "daily-digest", "attack-stories"]'),
    ('               "daily-digest": r"digest"}',
     '               "daily-digest": r"digest",\n'
     '               "attack-stories": r"attack|stor(y|ies)|mitre|att&?ck|chain"}'),
    ('raise ValueError("name must be wazuh-triage, mikrotik-audit or daily-digest")',
     'raise ValueError("name must be wazuh-triage, mikrotik-audit, daily-digest or attack-stories")'),
])
py_compile.compile(W + "server.py", doraise=True)

edit(W + "bin/run-agent", [
    ("    wazuh-triage|mikrotik-audit|daily-digest) ;;",
     "    wazuh-triage|mikrotik-audit|daily-digest|attack-stories) ;;"),
    ('echo "usage: run-agent wazuh-triage|mikrotik-audit|daily-digest"',
     'echo "usage: run-agent wazuh-triage|mikrotik-audit|daily-digest|attack-stories"'),
])

edit(W + "CLAUDE.md", [
    ("three monitoring agents and a news digest.",
     "three monitoring agents, the anomaly engine, the attack-stories agent (MITRE ATT&CK) and a news digest."),
    ("All under /home/agent/agents/:\n",
     "All under /home/agent/agents/:\n"
     "- `attack-stories/` -- the MITRE ATT&CK agent (P11-P13), hourly at :17. Joins the last 24 h of Wazuh\n"
     "  alerts that carry ATT&CK IDs with the anomaly engine's findings into attacker stories (events that\n"
     "  share an IP, user or host), with tactics in kill-chain order and a rule-based severity. Files:\n"
     "  `stories.jsonl` (every current story, worst first: id, severity, tactics, techniques, entities,\n"
     "  timeline), `reports/stories-*.md` (written only when a story is new or grew; high and critical ones\n"
     "  are explained by Claude), `last_status.json`, `logs/cron.log`, `config.json` (suppressions, hubs),\n"
     "  `README.md`. Dashboard: https://digest.example.com/attack.html (timeline, stories, coverage).\n"
     "  ATT&CK coverage of the custom Wazuh rules is in that dashboard's attack-coverage.json, not on this box.\n"
     "- `anomaly-engine/` -- statistical detectors over the syslog collector's data, every 5 min. In burn-in\n"
     "  (learn-only) until 2026-12-07: would-be findings go to `learn.jsonl`, real ones to `findings.jsonl`;\n"
     "  `logs/cron.log`, `README.md` (detector table with rule IDs and ATT&CK techniques),\n"
     "  `reports/investigations/` (automatic DNS-share investigations). Treat burn-in findings as context.\n"),
    ("  `/home/agent/agents/supervisor/bin/run-agent daily-digest`\n",
     "  `/home/agent/agents/supervisor/bin/run-agent daily-digest`\n"
     "  `/home/agent/agents/supervisor/bin/run-agent attack-stories`\n"),
])
