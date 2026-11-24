#!/bin/bash
# Wire the three new Uptime Kuma push monitors (2026-11-24) without printing their tokens.
set -euo pipefail
tok() { pct exec 110 -- python3 -c "import sqlite3,sys;c=sqlite3.connect('file:/opt/uptime-kuma/app/data/kuma.db?mode=ro',uri=True);print(c.execute('select push_token from monitor where name=?',(sys.argv[1],)).fetchone()[0])" "$1"; }
BASE="http://192.168.99.7:3001/api/push"
AS="$BASE/$(tok attack-stories)"; AE="$BASE/$(tok anomaly-engine)"; SF="$BASE/$(tok 'syslog freshness')"
ENV=/home/agent/.config/agent.env
for kv in "KUMA_PUSH_ATTACK_STORIES=$AS" "KUMA_PUSH_ANOMALY_ENGINE=$AE"; do
  k=${kv%%=*}
  pct exec 107 -- bash -c "grep -q '^$k=' $ENV || echo '$kv' >> $ENV"
done
echo "agent.env: $(pct exec 107 -- grep -c '^KUMA_PUSH_' $ENV) push URLs"
# anomaly-engine run.sh: push after each run
pct exec 107 -- python3 - <<'PY'
p = "/home/agent/agents/anomaly-engine/run.sh"
s = open(p).read()
if "KUMA_PUSH_ANOMALY_ENGINE" not in s:
    old = "/usr/bin/python3 engine.py >> logs/cron.log 2>&1\n"
    assert s.count(old) == 1, "engine line not found"
    new = old + '''rc=$?
# Uptime Kuma push monitor "anomaly-engine" (2026-11-24): up after a clean run, down with the exit code otherwise
url=$(grep -oP '^KUMA_PUSH_ANOMALY_ENGINE=\\K.*' /home/agent/.config/agent.env 2>/dev/null || true)
if [ -n "$url" ]; then
    if [ "$rc" -eq 0 ]; then q="status=up&msg=ok"; else q="status=down&msg=engine.py%20exit%20$rc"; fi
    curl -fsS -m 10 -o /dev/null "${url}?${q}" || true
fi
'''
    s = s.replace(old, new)
    if not s.rstrip().endswith("exit $rc"):
        s = s.rstrip("\n") + "\nexit $rc\n"
    open(p + ".bak-20261124", "w").write(open(p).read())
    open(p, "w").write(s)
    print("anomaly-engine run.sh patched")
PY
pct exec 107 -- bash -n /home/agent/agents/anomaly-engine/run.sh && echo "run.sh syntax ok"
# syslog-freshness on CT 112
pct exec 112 -- bash -c "cp -n /usr/local/bin/syslog-freshness /usr/local/bin/syslog-freshness.bak-20261124; sed -i 's#^KUMA=\"REPLACE_WITH_KUMA_PUSH_URL\"#KUMA=\"$SF\"#' /usr/local/bin/syslog-freshness; grep -c REPLACE_WITH /usr/local/bin/syslog-freshness || true"
pct exec 112 -- /usr/local/bin/syslog-freshness && echo "freshness push sent: rc 0"
pct exec 112 -- sed -i 's|^#\*/5 \* \* \* \* root /usr/local/bin/syslog-freshness|*/5 * * * * root /usr/local/bin/syslog-freshness|' /etc/cron.d/syslog-freshness
pct exec 112 -- grep -c '^\*/5' /etc/cron.d/syslog-freshness
pct exec 107 -- bash -c "curl -fsS -m 10 -o /dev/null '$AS?status=up&msg=wired' && echo attack-stories push ok"
