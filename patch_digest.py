#!/usr/bin/env python3
"""P12: add attack-stories to the daily digest (run.sh collector + CLAUDE.md). Idempotent."""
import shutil, sys
D = "/home/agent/agents/daily-digest/"
run, cmd = D + "run.sh", D + "CLAUDE.md"
s = open(run).read()
if "attack-stories" not in s:
    block = r'''
# ---------------------------------------------------------------- attack-stories (P11/P12, 2026-11-24)
echo "## attack-stories (hourly at :17; writes a report only when a story is new or grew)"
echo "### Run log (last 6 lines of logs/cron.log)"
echo '```'
tail -n 6 "$AGENTS_DIR/attack-stories/logs/cron.log" 2>&1
echo '```'
echo "### Current stories (stories.jsonl, worst first: id severity events tactics entities)"
echo '```'
python3 - "$AGENTS_DIR/attack-stories/stories.jsonl" <<'PY' 2>&1
import json, sys
for l in list(open(sys.argv[1]))[:15]:
    s = json.loads(l)
    print(s["id"], s["severity"], s["events"], "/".join(s["tactics"]) or "-", " ".join(s["entities"][:4]),
          "(engine burn-in only)" if s.get("sources") == ["engine-learn"] else "")
PY
echo '```'
n=$(find "$AGENTS_DIR/attack-stories/reports" -maxdepth 1 -name '*.md' -mmin -1440 2>/dev/null | wc -l)
f=$(find "$AGENTS_DIR/attack-stories/reports" -maxdepth 1 -name '*.md' -mmin -1440 2>/dev/null | sort | tail -n 1)
if [ -n "$f" ]; then
    echo "### Latest story report: $(basename "$f") (${n} written in the last 24 hours)"
    echo '````'
    head -c 8000 "$f"
    echo
    echo '````'
else
    echo "No story reports in the last 24 hours (nothing new or grown)."
fi
echo
'''
    marker = "\n    echo\ndone\n}\n"
    if s.count(marker) != 1:
        sys.exit("run.sh: agents-loop marker not found exactly once; not patched")
    shutil.copy2(run, run + ".bak-20261124")
    s = s.replace(marker, "\n    echo\ndone\n" + block + "}\n")
    open(run, "w").write(s)
    print("run.sh patched")
c = open(cmd).read()
if "attack-stories" not in c:
    shutil.copy2(cmd, cmd + ".bak-20261124")
    c = c.rstrip("\n") + '''

## attack-stories (added 2026-11-24)

attack-stories runs hourly at :17. It joins the last 24 hours of Wazuh alerts that carry ATT&CK IDs with the anomaly
engine's findings into attacker stories (events sharing an IP, user or host), and writes a report only when a story is
new or has grown; high and critical stories get Claude's explanation. In the digest, give each high or critical story
one line with its id, what it is and the verdict from the latest report, and fold low and medium stories into a single
count. Stories marked "(engine burn-in only)" come from the engine's learn-only period (until 2026-12-07): context,
not alerts. If the run log's last line is more than two hours old, say the agent has stalled.
'''
    open(cmd, "w").write(c)
    print("CLAUDE.md patched")
