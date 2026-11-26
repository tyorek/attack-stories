#!/bin/bash
# attack-stories/run.sh (P11/P12, 2026-11-24). Hourly from the agent crontab:
#   17 * * * * /home/agent/agents/attack-stories/run.sh
# Builds attacker stories (stories.py), and pushes the Kuma monitor named after this folder
# (KUMA_PUSH_ATTACK_STORIES in agent.env): down with the verdict when a high or critical story was flagged, so Kuma's
# Discord notification fires; up otherwise. No push URL set = no push (the run still happens).
set -uo pipefail
source /home/agent/.config/agent.env
cd "$(dirname "$0")"
mkdir -p logs reports
exec 9>.lock
flock -n 9 || { echo "$(date -Is) previous run still going, skipping" >> logs/cron.log; exit 0; }
rm -f last_status.json
/usr/bin/python3 stories.py >> logs/cron.log 2>&1
rc=$?
# P13: publish the dashboard data to the Homepage container's viewer (same write-only rrsync account as the digest)
if [ -n "${DIGEST_PUSH_TARGET:-}" ] && [ -f attack.json ]; then
    rsync -t --chmod=F644 -e "ssh -i /home/agent/.ssh/id_ed25519 -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new" \
        attack.json "${DIGEST_PUSH_TARGET}:attack.json" 2>>logs/cron.log \
        || echo "$(date -Is) WARNING: could not publish attack.json to ${DIGEST_PUSH_TARGET}" >> logs/cron.log
fi
url="${KUMA_PUSH_ATTACK_STORIES:-}"
if [ -n "$url" ]; then
    status=up; msg="ok"
    if [ "$rc" -ne 0 ]; then status=down; msg="stories.py exit $rc"; fi
    if [ -f last_status.json ] && [ "$(python3 -c 'import json;print(json.load(open("last_status.json"))["alert"])')" = "True" ]; then
        status=down
        msg=$(python3 -c 'import json,urllib.parse;d=json.load(open("last_status.json"));sp=d.get("events_span","");ids=",".join(d.get("ids",[]));print(urllib.parse.quote(("["+d["worst"]+"] "+(sp+" " if sp else "")+(ids+": " if ids else "")+d["verdict"])[:220]))')
    fi
    curl -fsS -m 10 -o /dev/null "${url}?status=${status}&msg=${msg}" || true
fi
if [ "$(wc -l < logs/cron.log)" -gt 20000 ]; then tail -n 10000 logs/cron.log > logs/cron.log.tmp && mv logs/cron.log.tmp logs/cron.log; fi
exit $rc
