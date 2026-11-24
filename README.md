# attack-stories (P11 / P12 / P13)

Deployed 2026-11-24 on CT 107 (`agents`, 192.168.99.14) as `/home/agent/agents/attack-stories/`, owned by `agent`.
Board items: P11 (triage agent that chains findings into attacker stories), P12 (Claude audit of high/critical
stories, digest and Discord), P13 (dashboard with an anomaly timeline and an ATT&CK coverage layer).

## What it does

Hourly (`17 * * * *` in the agent crontab) `run.sh` runs `stories.py`, which:

1. Pulls the last 24 h of Wazuh alerts with `rule.level >= 5` that carry ATT&CK IDs (indexer, read-only user from
   `agent.env`), plus the anomaly engine's `findings.jsonl` and, during burn-in, `learn.jsonl`.
2. Drops test events (`P6-TEST`, `p4test`, `p6test`) and known false positives (`suppress` in config.json: the Sigma
   public-IP logon rules that fired on the LAN's own GUAs before the sigma2wazuh local filter went in).
3. Joins events that share an IP, user or host (union-find; `hub_entities` such as the DCs, siem, fw-edge and the
   router never join anything), maps techniques to tactics and orders them along the kill chain.
4. Scores each story by rules, not by a model: critical if a level 12+ event or 3+ tactics including a key tactic;
   high if level 10+ or 2+ tactics including a key tactic; medium if 2+ tactics or level 8+; else low. Burn-in
   (`engine-learn`) findings link events and show their tactics but cannot raise severity; a story made only of them
   is capped at medium. `rule_overrides` re-scores Wazuh 87702 (pfSense block burst, tagged T1110 upstream) as T1046
   at level 6.
5. Writes `stories.jsonl` (all current stories) and `attack.json` (stories plus a 7-day hourly series, for the
   dashboard). When a story is new or has grown, writes an evidence file and calls `llm-report`: low/medium stories
   use the local model only (`LLM_MODE=local`); a high or critical story goes through the normal local-then-Claude
   path (P12 Claude audit). The report lands in `reports/stories-YYYYMMDD-HHMM.md`; `state.json` remembers each story's
   event count, max level and tactics: a story is re-reported only when it gets worse (higher max level or a new
   tactic), not when more events of the same kind join it (since 2026-11-24).
6. `last_status.json`: `alert` is true when the worst new story is high/critical and the verdict is not
   "Nothing actionable".

`run.sh` then rsyncs `attack.json` to the Homepage container's viewer (`DIGEST_PUSH_TARGET`, the same write-only
rrsync account the digest uses) and pushes the Uptime Kuma monitor `attack-stories` (`KUMA_PUSH_ATTACK_STORIES` in
agent.env): down with "[severity] verdict" when `alert` is true, so Kuma's Discord notification fires; up otherwise.

## P12 wiring

- Daily digest: `daily-digest/run.sh` collects the run log, the current stories and the latest story report
  (block added by `patch_digest.py`, backups `*.bak-20261124`); `daily-digest/CLAUDE.md` says how to summarise them.
- Kuma push monitors created 2026-11-24: `attack-stories` (75 min heartbeat), `anomaly-engine` (15 min, pushed from
  anomaly-engine/run.sh after each run), `syslog freshness` (15 min, CT 112 `/usr/local/bin/syslog-freshness`, cron
  enabled). Wired by `wire_kuma.sh`, which reads the push tokens from Kuma's database without printing them.

## P13 dashboard

- `attack.html` is served by digest-viewer on CT 111 (`/srv/digest/www/attack.html`, reachable as
  https://digest.example.com/attack.html). `?embed=1` shows only the summary tiles and the timeline, for a Homepage
  iframe. It reads `attack.json` (symlink to `/srv/digest/incoming/attack.json`, refreshed hourly) and
  `attack-coverage.json`.
- `attack_layer.py` runs as root on the Wazuh manager (CT 100). It reads the custom rule files' `<mitre><id>` tags and
  Wazuh's ATT&CK database and writes `attack-layer.json` (ATT&CK Navigator layer v4.5, score = number of rules) and
  `attack-coverage.json`, plus `attack-techniques.json` (technique id -> name and official tactics, used by the
  drill-down). Re-run it after rules change and copy all three to CT 111:

      pct push 100 attack_layer.py /root/attack_layer.py && pct exec 100 -- python3 /root/attack_layer.py /tmp
      for f in attack-layer.json attack-coverage.json attack-techniques.json; do
        pct pull 100 /tmp/$f /root/$f && pct push 111 /root/$f /srv/digest/www/$f --perms 644; done

  First run: 286 custom rules map to 86 techniques (T1219.002 has no tactic in Wazuh's ATT&CK DB yet).
- To view the layer in Navigator: download it from the page, then mitre-attack.github.io/attack-navigator → Open
  Existing Layer → Upload from local (the public Navigator cannot fetch an internal http URL).

## Drill-down (2026-11-24)

The five tiles (critical, high, medium, low stories, ATT&CK alerts 24 h) are buttons. Clicking one opens a panel under
the tiles; with more than one item it shows a drop-down, with exactly one it opens it directly. Picking an item draws
its ATT&CK chain: tactic boxes in kill-chain order with the techniques seen under each (events, max level, rules),
its position in the 14-column Enterprise matrix, an events-over-time strip and the event list, plus a per-story
Navigator layer download. A technique Wazuh maps to several tactics is drawn under its earliest tactic that the alert
itself carried; the others are listed as "also ...". Deep links: `attack.html?cat=medium&story=a35f9145d7`
(stories) or `?cat=alerts&story=<rule id>`. In the embed view an "open full view" link opens the same item full size.
`stories.py` writes the extra fields this needs into `attack.json`: per story `rules`, `tech_detail`, `all_blocked`
and `outcome` per timeline event, and a top-level `alert_groups` (Wazuh alerts grouped by rule, 60 max).

## Blocked attempts

An event counts as blocked when it shows the attempt failed: an NPM access-log event whose status (`data.id`) is in
`blocked_status` (400/401/403/404/405/444/499), a rule in `blocked_rules` (87701/87702 firewall blocks), or an engine
finding from a detector in `blocked_detectors`. A story whose core events are all blocked is capped at medium and
marked "all attempts blocked"; a single non-blocked event (a 200 from the same scanner, say) lifts the cap. First run
moved three internet scanners from high/critical to medium (a35f9145d7 8.234.35.234, 0f51aea086 103.59.161.68,
d91ce1cad9 139.59.244.94). `data.id` had to be added to the indexer `_source` list for this to work.

## Files

| File | Where it runs |
|---|---|
| stories.py, config.json, run.sh, CLAUDE.md | CT 107 `/home/agent/agents/attack-stories/` |
| attack.html | CT 111 `/srv/digest/www/` |
| attack_layer.py | CT 100 `/root/` (by hand) |
| patch_supervisor.py, patch_mermaid.py | one-off, CT 107 supervisor folder (idempotent; backups `*.pre-attack-stories`, `*.pre-mermaid`) |
| patch_digest.py | one-off, CT 107 (daily-digest integration; idempotent) |
| wire_kuma.sh | one-off, pve root (Kuma push wiring; idempotent) |

## Manual checks

    pct exec 107 -- su agent -c "cd /home/agent/agents/attack-stories && python3 stories.py --dry-run"
    pct exec 107 -- tail -5 /home/agent/agents/attack-stories/logs/cron.log

## Supervisor chat

Since 2026-11-24 the supervisor chat (`supervisor/`, sup.example.com) knows this agent and the anomaly engine:
its CLAUDE.md lists their files, and `run_agent` / `bin/run-agent` accept `attack-stories` (same 15-minute limit
and "only when the admin asks" guard as the other agents). Applied by `patch_supervisor.py` (backups
`*.pre-attack-stories` in the supervisor folder).

Since 2026-11-24 it also renders Mermaid. `patch_mermaid.py` vendors `mermaid.min.js` (v11, served from
`/static/mermaid.min.js` so the CSP needs no CDN), turns ```` ```mermaid ```` fences in replies into rendered SVG
(securityLevel strict, dark theme; a parse error shows the error and the source), and adds a "Diagrams" section to the
supervisor CLAUDE.md telling Gemma to answer diagram requests with a Mermaid flowchart (tactics left to right,
techniques inside) and to link the matching drill-down, e.g. `attack.html?cat=critical&story=<id>`. Gemma cannot
produce an ATT&CK Navigator layer image itself; the Navigator layer stays a download on the dashboard.

---

*Published from a home lab. Site identifiers are sanitized: public IPv4 uses the documentation ranges (203.0.113.0/24, 198.51.100.0/24), the delegated IPv6 prefix is `2001:db8::/32`, the ULA prefix is `fd12:3456:789a::/48`, domains are `example.com` / `home.arpa`, MAC addresses, Wi-Fi SSIDs, serials, keys and names are replaced. RFC 1918 addresses are left as they are so the layouts still read. Credentials are never in these files; scripts read them from `agent.env` or similar files that are not published.*

## Disclaimer

This repository is shared **as is**, for reference and learning. It is a personal home-lab project, not a product, and it comes with no support.

- **No warranty.** Everything here (code, configurations, scripts, rules and documentation) is provided without warranty of any kind, express or implied, including fitness for a particular purpose. It may contain bugs, errors or omissions.
- **No commitment to maintain.** The author makes no commitment to fix bugs, answer questions, upgrade or update this repository beyond what is provided here. Any future updates are made purely on a voluntary basis, at the author's sole discretion, and may stop at any time.
- **You are solely responsible.** Any review, adaptation, configuration, testing, deployment or operation of this material is solely the responsibility of the person using it. Bugs, fixes and updates in your environment are yours to handle.
- **No liability.** To the fullest extent permitted by law, the author is not liable for any damages or losses of any kind arising from the use or misuse of this material, including but not limited to outages, data loss, security incidents, lost revenue, damage to hardware or other property, and any physical or digital harm.
- **Test before you trust.** Several scripts change firewalls, routers, DNS, authentication or system services. Read them, adapt them to your network, test them in a lab, and keep backups and a rollback path before running anything in production.

## License

The code and documentation in this repository are released under the [MIT License](LICENSE), an open-source license, unless a file or folder states otherwise.
