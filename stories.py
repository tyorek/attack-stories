#!/usr/bin/env python3
"""attack-stories (P11/P12, 2026-11-24): bundle ATT&CK-tagged Wazuh alerts and anomaly-engine findings into
per-entity attacker stories, have the local model explain them, and send high-severity stories to Claude.

Flow (hourly, run.sh):
  1. Collect the last WINDOW_HOURS of
       - Wazuh alerts with an ATT&CK technique and level >= MIN_LEVEL (read-only indexer user), and
       - anomaly-engine findings (findings.jsonl; learn.jsonl too while the engine is in burn-in, marked as such).
  2. Pull entities out of each event: source IP, user, host. Hub entities that every event shares (the DCs, the
     siem, the admin desktop's MAC, machine accounts, SYSTEM...) are listed in config.json and never link events.
  3. Events that share an entity are joined (union-find); each group is a story. Techniques map to tactics, and the
     tactics are put in kill-chain order.
  4. Severity is rule-based, not model-based: tactic breadth, highest level and a few "this matters" tactics.
  5. Stories that are new or grew since the last run go into an evidence file; llm-report writes the report with
     stories/CLAUDE.md. Only when a high or critical story is present may it escalate to Claude (P12);
     otherwise it runs local-only.
  6. stories.jsonl keeps every current story for the dashboard (P13) and the digest.

Stdlib only. Usage: stories.py [--dry-run] [--hours N]
"""
import argparse, base64, collections, datetime as dt, hashlib, ipaddress, json, os, re, ssl, subprocess, sys, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CFG = json.load(open(os.path.join(HERE, "config.json")))
TZ = dt.timezone(dt.timedelta(hours=-6))  # America/Chicago (CST); only used for display

TACTIC_ORDER = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
                "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
                "Collection", "Command and Control", "Exfiltration", "Impact"]
# Techniques the anomaly engine emits (its findings carry IDs only). Wazuh alerts bring their own tactics.
TECH_TACTICS = {
    "T1021": ["Lateral Movement"], "T1210": ["Lateral Movement"], "T1046": ["Discovery"],
    "T1071": ["Command and Control"], "T1071.001": ["Command and Control"], "T1071.004": ["Command and Control"],
    "T1571": ["Command and Control"], "T1573": ["Command and Control"], "T1190": ["Initial Access"],
    "T1200": ["Initial Access"], "T1078": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
    "T1110": ["Credential Access"], "T1098": ["Persistence", "Privilege Escalation"], "T1041": ["Exfiltration"],
    "T1048": ["Exfiltration"], "T1562": ["Defense Evasion"],
}
SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


# ---------------------------------------------------------------- input

def env():
    e = dict(os.environ)
    p = "/home/agent/.config/agent.env"
    if os.path.exists(p):
        for line in open(p):
            m = re.match(r"\s*(?:export\s+)?([A-Z_][A-Z0-9_]*)=(.*)", line)
            if m and m.group(1) not in e:
                e[m.group(1)] = m.group(2).strip().strip('"').strip("'")
    return e


def indexer_search(e, q):
    req = urllib.request.Request(e["WAZUH_INDEXER_URL"].rstrip("/") + "/wazuh-alerts-*/_search",
                                 data=json.dumps(q).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": "Basic " +
                                          base64.b64encode(f'{e["WAZUH_INDEXER_USER"]}:{e["WAZUH_INDEXER_PASS"]}'.encode()).decode()})
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE  # self-signed, VLAN 99
    return json.load(urllib.request.urlopen(req, timeout=60, context=ctx))


def indexer_alerts(e, hours):
    q = {"size": 3000, "sort": [{"@timestamp": "asc"}],
         "_source": ["@timestamp", "rule.id", "rule.level", "rule.description", "rule.mitre", "rule.groups",
                     "agent.name", "location", "data.srcip", "data.src_ip", "data.dstuser", "data.srcuser",
                     "data.win.system.computer", "data.win.system.eventID", "data.win.eventdata.ipAddress",
                     "data.win.eventdata.targetUserName", "data.win.eventdata.subjectUserName",
                     "data.win.eventdata.workstationName", "data.mikrotik.object", "data.url", "data.id", "data.npm.host"],
         "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                                       {"range": {"rule.level": {"gte": CFG["min_level"]}}},
                                       {"exists": {"field": "rule.mitre.id"}}]}}}
    hits = indexer_search(e, q)["hits"]["hits"]
    out = []
    for h in hits:
        s = h["_source"]; r = s.get("rule", {}); d = s.get("data", {}) or {}
        w = d.get("win", {}) or {}; ws, wd = w.get("system", {}) or {}, w.get("eventdata", {}) or {}
        if ws.get("computer") in CFG["ignore_test_hosts"] or d.get("dstuser") in CFG["ignore_test_users"]:
            continue
        m = r.get("mitre", {}) or {}
        ips = [x for x in [d.get("srcip"), d.get("src_ip"), wd.get("ipAddress")] if x]
        if suppressed(r, ips):
            continue
        ov = CFG.get("rule_overrides", {}).get(str(r.get("id")), {})
        out.append({
            "ts": s["@timestamp"], "src": "wazuh", "id": f'wazuh:{h["_id"]}', "rule": r.get("id"), "level": int(ov.get("level", r.get("level", 0))),
            "desc": r.get("description", ""), "techniques": ov.get("techniques", m.get("id", []) or []),
            "tactics": [] if "techniques" in ov else (m.get("tactic", []) or []),
            "tnames": {} if "techniques" in ov else dict(zip(m.get("id", []) or [], m.get("technique", []) or [])),
            "agent": (s.get("agent") or {}).get("name"),
            "ips": ips,
            "outcome": outcome_of(r, d),
            "users": [x for x in [d.get("dstuser"), d.get("srcuser"), wd.get("targetUserName"), wd.get("subjectUserName")] if x],
            "hosts": [x for x in [ws.get("computer"), wd.get("workstationName"), (s.get("agent") or {}).get("name")] if x],
        })
    return out


def outcome_of(rule, data):
    """"blocked" when the event itself shows the attempt failed: the proxy refused or errored it (NPM status in
    blocked_status, e.g. 444 drop, 401, 403, 404) or the rule is a firewall block (blocked_rules). Otherwise ""."""
    status = str(data.get("id", "")) if isinstance(data.get("id"), (str, int)) else ""
    if str(rule.get("id")) in CFG.get("blocked_rules", []):
        return "blocked"
    if data.get("url") and status in CFG.get("blocked_status", []):  # NPM access log (url + status in "id")
        return "blocked"
    return ""


def suppressed(rule, ips):
    """Config "suppress": drop alerts already known to be false positives (e.g. Sigma alerts that fired before a
    local filter went in). Every key given in an entry must match: rule (exact id), desc_regex, ip_regex (any IP)."""
    for s in CFG.get("suppress", []):
        if "rule" in s and str(rule.get("id")) != str(s["rule"]):
            continue
        if "desc_regex" in s and not re.search(s["desc_regex"], rule.get("description", "")):
            continue
        if "ip_regex" in s and not any(re.search(s["ip_regex"], str(i)) for i in ips):
            continue
        return True
    return False


def engine_findings(hours):
    out, since = [], dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours)
    base = CFG["engine_dir"]
    files = [("findings.jsonl", "active")]
    if CFG.get("include_learn_findings"):
        files.append(("learn.jsonl", "learn"))
    for fn, mode in files:
        p = os.path.join(base, fn)
        if not os.path.exists(p):
            continue
        for line in open(p, errors="replace"):
            try:
                f = json.loads(line)["anomaly_engine"]
            except Exception:
                continue
            if f.get("detector") in ("engine_status",):
                continue
            try:
                t = dt.datetime.fromisoformat(f["event_time"])
            except Exception:
                continue
            if t < since:
                continue
            ev, ent = f.get("evidence", {}) or {}, str(f.get("entity", ""))
            ips = [x for x in [ent, ev.get("src"), ev.get("dst"), ev.get("client"), ev.get("srcip")] if x and is_ip(x)]
            users = [x for x in [ev.get("user")] if x]
            sev = f.get("severity", "medium")
            out.append({
                "ts": t.astimezone(dt.timezone.utc).isoformat(), "src": f"engine-{mode}", "rule": f.get("detector"),
                "outcome": "blocked" if f.get("detector") in CFG.get("blocked_detectors", ["dmz_firewall_block"]) else "",
                "id": "engine:" + hashlib.sha1(line.encode()).hexdigest()[:16],
                "level": {"low": 5, "medium": 8, "high": 10, "critical": 12}.get(sev, 8), "desc": f.get("summary", ""),
                "techniques": f.get("attack", []) or [], "tactics": [], "agent": "anomaly-engine",
                "ips": ips, "users": users, "hosts": [],
            })
    return out


# ---------------------------------------------------------------- entities and grouping

def is_ip(x):
    try:
        ipaddress.ip_address(str(x).split("%")[0].replace("::ffff:", ""))
        return True
    except ValueError:
        return False


def norm_entities(e):
    ents = set()
    for ip in e["ips"]:
        ip = str(ip).replace("::ffff:", "")
        if ip in ("-", "::1", "127.0.0.1") or ip in CFG["hub_entities"]:
            continue
        ents.add("ip:" + ip)
    for u in e["users"]:
        u = str(u).split("@")[0].split("\\")[-1].lower()
        if not u or u in ("-",) or u.endswith("$") or u in [x.lower() for x in CFG["hub_entities"]]:
            continue
        ents.add("user:" + u)
    for h in e["hosts"]:
        h = str(h).split(".")[0].lower()
        if h in [x.lower() for x in CFG["hub_entities"]]:
            continue
        ents.add("host:" + h)
    return ents


def tactics_for(e):
    t = set(e["tactics"])
    for tech in e["techniques"]:
        t.update(TECH_TACTICS.get(tech, TECH_TACTICS.get(tech.split(".")[0], [])))
    return t


def group(events):
    parent = list(range(len(events)))
    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]; i = parent[i]
        return i
    by_ent = collections.defaultdict(list)
    for i, e in enumerate(events):
        e["entities"] = sorted(norm_entities(e))
        for x in e["entities"]:
            by_ent[x].append(i)
    for idx in by_ent.values():
        for j in idx[1:]:
            parent[find(j)] = find(idx[0])
    comps = collections.defaultdict(list)
    for i in range(len(events)):
        comps[find(i)].append(events[i])
    return list(comps.values())


def score(evs):
    """Severity comes from Wazuh alerts and active engine findings. Burn-in (engine-learn) findings still join
    events into stories and show their tactics, but on their own a story of them is capped at medium."""
    core = [e for e in evs if e["src"] != "engine-learn"] or evs
    tactics, shown = set(), set()
    for e in evs:
        shown |= tactics_for(e)
    for e in core:
        tactics |= tactics_for(e)
    ordered = [t for t in TACTIC_ORDER if t in tactics]
    max_level = max(e["level"] for e in core)
    key = tactics & set(CFG["key_tactics"])
    # A tactic chain only escalates when it rests on enough evidence: several events, at least one of them
    # noteworthy on its own. Two routine level-5 events on one host (a game's anti-cheat driver install, then a
    # backup's shadow-copy mount 15 h later) span three tactics but are not a critical story.
    n = len(core)
    if max_level >= 12 or (len(ordered) >= 3 and key and n >= 3 and max_level >= 8):
        sev = "critical"
    elif max_level >= 10 or (len(ordered) >= 2 and key and n >= 2 and max_level >= 7):
        sev = "high"
    elif len(ordered) >= 2 or max_level >= 8:
        sev = "medium"
    else:
        sev = "low"
    if all(e["src"] == "engine-learn" for e in evs) and sev in ("high", "critical"):
        sev = "medium"
    # Every event shows a failed attempt (all dropped, refused or blocked): noisy but not a compromise. A single
    # success (a 200 among the probes, an allowed connection, a config change) keeps the full severity.
    if core and all(e.get("outcome") == "blocked" for e in core) and sev in ("high", "critical"):
        sev = "medium"
    return sev, [t for t in TACTIC_ORDER if t in shown], max_level


def tech_detail(evs):
    """Per technique in a story: name, tactics, events, max level, first/last, rules. Feeds the dashboard's chain
    diagram (P13); the page re-places techniques with the official ATT&CK mapping when it has it."""
    d = {}
    for ev in evs:
        techs = ev["techniques"] or ["-"]
        for t in techs:
            x = d.setdefault(t, {"id": t, "name": "", "events": 0, "max_level": 0, "first": ev["ts"], "last": ev["ts"],
                                 "rules": [], "tactics": set(), "sources": set()})
            x["events"] += 1
            x["max_level"] = max(x["max_level"], ev["level"])
            x["first"], x["last"] = min(x["first"], ev["ts"]), max(x["last"], ev["ts"])
            x["name"] = x["name"] or ev.get("tnames", {}).get(t, "")
            if ev["rule"] not in x["rules"]:
                x["rules"].append(ev["rule"])
            mapped = TECH_TACTICS.get(t) or TECH_TACTICS.get(t.split(".")[0])
            x["tactics"].update(mapped or (ev["tactics"] if len(techs) == 1 else ev["tactics"][:1]) or [])
            x["sources"].add(ev["src"])
    out = []
    for x in d.values():
        x["tactics"] = [t for t in TACTIC_ORDER if t in x["tactics"]]
        x["sources"] = sorted(x["sources"])
        x["rules"] = x["rules"][:8]
        out.append(x)
    return sorted(out, key=lambda x: x["first"])


def alert_groups(events, stories, limit=60):
    """The 24 h of ATT&CK-tagged Wazuh alerts grouped by rule, for the dashboard's "ATT&CK alerts" drill-down."""
    by_rule = {}
    story_of = {}
    for s in stories:
        for r in s.get("rules", []):
            story_of.setdefault(r, []).append(s["id"])
    for ev in events:
        if ev["src"] != "wazuh":
            continue
        g = by_rule.setdefault(ev["rule"], {"rule": ev["rule"], "desc": ev["desc"][:160], "level": ev["level"], "count": 0,
                                            "first": ev["ts"], "last": ev["ts"], "techniques": [], "tnames": {},
                                            "tactics": set(), "entities": collections.Counter(), "sample": []})
        g["count"] += 1
        g["first"], g["last"] = min(g["first"], ev["ts"]), max(g["last"], ev["ts"])
        for t in ev["techniques"]:
            if t not in g["techniques"]:
                g["techniques"].append(t)
        g["tnames"].update(ev.get("tnames", {}))
        g["tactics"].update(tactics_for(ev))
        g["entities"].update(ev["entities"])
        if len(g["sample"]) < 10:
            g["sample"].append({"ts": ev["ts"], "entities": ev["entities"][:4]})
    out = []
    for g in by_rule.values():
        g["tactics"] = [t for t in TACTIC_ORDER if t in g["tactics"]]
        g["entities"] = [x for x, _ in g["entities"].most_common(6)]
        g["stories"] = story_of.get(g["rule"], [])[:5]
        out.append(g)
    out.sort(key=lambda g: (-g["level"], -g["count"]))
    return out[:limit]


def parse_ts(ts):
    try:
        return dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return None


def span_text(tss):
    """'Nov 24 04:25-11:58 CST' for a set of event timestamps (display only)."""
    ts = sorted(t.astimezone(TZ) for t in map(parse_ts, tss) if t)
    if not ts:
        return ""
    a, b = ts[0], ts[-1]
    if a.date() == b.date():
        return f"{a:%b %d %H:%M}-{b:%H:%M} CST" if a != b else f"{a:%b %d %H:%M} CST"
    return f"{a:%b %d %H:%M} - {b:%b %d %H:%M} CST"


def story_id(evs):
    first = min(evs, key=lambda e: e["ts"])
    ents = sorted({x for e in evs for x in e["entities"]})
    return hashlib.sha1((first["id"] + "|" + (ents[0] if ents else "")).encode()).hexdigest()[:10]


# ---------------------------------------------------------------- dashboard data (P13)

def hourly_series(e, events_week, days=7):
    """Hourly counts for the dashboard timeline: Wazuh alerts with ATT&CK IDs (indexer date_histogram) and the
    anomaly engine's findings, active and burn-in, over the last `days` days."""
    now = dt.datetime.now(dt.timezone.utc).replace(minute=0, second=0, microsecond=0)
    hours = [now - dt.timedelta(hours=h) for h in range(days * 24 - 1, -1, -1)]
    idx = {h.strftime("%Y-%m-%dT%H"): i for i, h in enumerate(hours)}
    out = {"wazuh": [0] * len(hours), "engine-active": [0] * len(hours), "engine-learn": [0] * len(hours)}
    q = {"size": 0, "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": f"now-{days * 24}h"}}},
                                                  {"range": {"rule.level": {"gte": CFG["min_level"]}}},
                                                  {"exists": {"field": "rule.mitre.id"}}],
                                       "must_not": [{"terms": {"data.win.system.computer": CFG["ignore_test_hosts"]}},
                                                    {"terms": {"data.dstuser": CFG["ignore_test_users"]}}]}},
         "aggs": {"h": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "time_zone": "UTC"}}}}
    for b in indexer_search(e, q)["aggregations"]["h"]["buckets"]:
        k = b["key_as_string"][:13]
        if k in idx:
            out["wazuh"][idx[k]] += b["doc_count"]
    for ev in events_week:
        if ev["src"].startswith("engine-"):
            k = ev["ts"][:13]
            if k in idx:
                out[ev["src"]][idx[k]] += 1
    return [h.strftime("%Y-%m-%dT%H:00Z") for h in hours], out


def write_dashboard(e, stories, now, events=()):
    try:
        hours, series = hourly_series(e, engine_findings(7 * 24))
    except Exception as ex:  # the timeline is a nice-to-have; never fail the run over it
        print(f"{now.isoformat(timespec='seconds')} dashboard series failed: {ex}")
        hours, series = [], {}
    slim = [dict(s, timeline=s["timeline"][-15:]) for s in stories[:25]]
    with open(os.path.join(HERE, "attack.json"), "w") as f:
        json.dump({"updated": now.isoformat(timespec="seconds"), "window_hours": CFG["window_hours"],
                   "hours": hours, "series": series, "stories": slim,
                   "alert_groups": alert_groups(list(events), stories)}, f, separators=(",", ":"))


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="build stories and print them; no LLM, no state change")
    ap.add_argument("--hours", type=int, default=CFG["window_hours"])
    a = ap.parse_args()
    e = env()
    events = indexer_alerts(e, a.hours) + engine_findings(a.hours)
    state_p = os.path.join(HERE, "state.json")
    state = json.load(open(state_p)) if os.path.exists(state_p) else {}
    # Event fingerprints (wazuh:<doc id>, engine:<line hash>) already judged in an earlier run, with the event time and
    # the story id they were judged under. Escalation is decided on these, not on story ids: a story's id changes when
    # older events join its group, and on 2026-11-25 that re-paged an already-alerted set of config changes (b3f705dcee).
    first_run = "_seen" not in state
    seen = state.get("_seen", {})
    stories, groups, used = [], {}, set()
    for evs in group(events):
        evs.sort(key=lambda x: x["ts"])
        sev, tactics, max_level = score(evs)
        if len(evs) < CFG["min_events"] and max_level < CFG["single_event_level"]:
            continue
        ents = collections.Counter(x for ev in evs for x in ev["entities"])
        # stable id: keep the id these events were judged under before, if any
        prior = collections.Counter(seen[ev["id"]][1] for ev in evs if ev["id"] in seen)
        sid = next((i for i, _ in prior.most_common() if i not in used), None) or story_id(evs)
        used.add(sid)
        groups[sid] = evs
        fresh = [ev for ev in evs if ev["id"] not in seen]
        stories.append({
            "id": sid, "severity": sev, "tactics": tactics, "max_level": max_level,
            "first": evs[0]["ts"], "last": evs[-1]["ts"], "events": len(evs),
            "new_events": len(fresh), "new_span": span_text(ev["ts"] for ev in fresh), "span": span_text(ev["ts"] for ev in evs),
            "entities": [x for x, _ in ents.most_common(8)],
            "techniques": sorted({t for ev in evs for t in ev["techniques"]}),
            "sources": sorted({ev["src"] for ev in evs}),
            "rules": sorted({str(ev["rule"]) for ev in evs}),
            "all_blocked": all(ev.get("outcome") == "blocked" for ev in evs),
            "tech_detail": tech_detail(evs),
            "timeline": [{"ts": ev["ts"], "src": ev["src"], "rule": ev["rule"], "level": ev["level"],
                          "desc": ev["desc"][:200], "techniques": ev["techniques"], "entities": ev["entities"][:4],
                          "outcome": ev.get("outcome", ""), "new": ev["id"] not in seen}
                         for ev in evs[-CFG["max_timeline"]:]],
        })
    stories.sort(key=lambda s: (-SEV_RANK[s["severity"]], -s["max_level"], s["first"]))
    def escalated(s):
        """Report a story only when it holds events never judged before AND it is new or got worse because of them:
        a higher max level or a tactic the already-judged events didn't have. A regrouping of old events (new story
        id, nothing new) never reports; more events of the same kind (e.g. more of the admin's own config changes) only
        update the state."""
        if first_run:  # migration from the per-story state (before 2026-11-26)
            old = state.get(s["id"])
            if old is None:
                return True
            if isinstance(old, int):
                return old < s["events"]
            return s["max_level"] > old.get("max_level", 0) or not set(s["tactics"]) <= set(old.get("tactics", []))
        evs = groups[s["id"]]
        if not any(ev["id"] not in seen for ev in evs):
            return False
        known = [ev for ev in evs if ev["id"] in seen]
        if not known:
            return True
        _, k_tactics, k_level = score(known)
        return s["max_level"] > k_level or not set(s["tactics"]) <= set(k_tactics)

    def save_state():
        cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=CFG.get("seen_days", 8))
        for sid, evs in groups.items():
            for ev in evs:
                seen[ev["id"]] = [ev["ts"], sid]
        kept = {k: v for k, v in seen.items() if (parse_ts(v[0]) or cutoff) >= cutoff}
        out = {s["id"]: {"events": s["events"], "max_level": s["max_level"], "tactics": s["tactics"]} for s in stories}
        out["_seen"] = kept
        tmp = state_p + ".tmp"
        json.dump(out, open(tmp, "w"), separators=(",", ":"))
        os.replace(tmp, state_p)
    new = [s for s in stories if escalated(s)]
    new_span = (span_text(ev["ts"] for s in new for ev in groups[s["id"]] if ev["id"] not in seen)
                or span_text(ev["ts"] for s in new for ev in groups[s["id"]]))
    now = dt.datetime.now(TZ)
    if a.dry_run:
        print(json.dumps({"events": len(events), "stories": len(stories), "new_or_grown": len(new), "seen_fingerprints": len(seen),
                          "first_run": first_run, "would_report": [s["id"] for s in new],
                          "top": [{k: s[k] for k in ("id", "severity", "tactics", "events", "new_events", "span", "entities", "max_level")} for s in stories[:10]]},
                         indent=1))
        return
    # every current story, for the dashboard and the digest
    with open(os.path.join(HERE, "stories.jsonl"), "w") as f:
        for s in stories:
            f.write(json.dumps(dict(s, updated=now.isoformat(timespec="seconds"), new=(s in new)), separators=(",", ":")) + "\n")
    write_dashboard(e, stories, now, events)
    os.makedirs(os.path.join(HERE, "reports"), exist_ok=True)
    if not new:
        print(f"{now.isoformat(timespec='seconds')} events={len(events)} stories={len(stories)} new=0 (no report)")
        save_state()
        return
    worst = max(SEV_RANK[s["severity"]] for s in new)
    evidence = {"generated": now.isoformat(timespec="seconds"), "window_hours": a.hours,
                "engine_mode_note": "Findings marked engine-learn come from the anomaly engine's burn-in (learn-only until 2026-12-07); weigh them lightly.",
                "new_or_grown_stories": new[:CFG["max_stories_in_report"]],
                "other_current_stories": [{k: s[k] for k in ("id", "severity", "tactics", "events", "entities")} for s in stories if s not in new][:20]}
    ev_p = f"/tmp/attack-stories-evidence-{now:%Y%m%d%H%M}.json"
    json.dump(evidence, open(ev_p, "w"), indent=1)
    report = os.path.join(HERE, "reports", f"stories-{now:%Y%m%d-%H%M}.md")
    sys.stdout.flush()
    run_env = dict(os.environ)
    if worst < SEV_RANK["high"]:
        run_env["LLM_MODE"] = "local"        # P12: Claude only audits high and critical stories
    task = "Explain these attacker stories per CLAUDE.md."
    rc = subprocess.run([CFG["llm_report"], "--input", ev_p, "--report", report, "--task", task,
                         "--ok-verdict", "Nothing actionable"], cwd=HERE, env=run_env, timeout=1500).returncode
    if rc != 0 or not os.path.exists(report):
        with open(report, "w") as f:
            f.write("# Attacker stories: raw evidence (no model report)\n\nNeeds attention: the report model failed; raw evidence below.\n\n```json\n"
                    + json.dumps(evidence, indent=1)[:60000] + "\n```\n")
    verdict = next((l.strip() for l in open(report, errors="replace") if l.strip() and not l.startswith("#")), "")
    save_state()
    # P12: high/critical + flagged -> Discord through the Kuma push monitor (run.sh reads this file)
    alert = worst >= SEV_RANK["high"] and not verdict.lower().startswith("nothing actionable")
    with open(os.path.join(HERE, "last_status.json"), "w") as f:
        json.dump({"time": now.isoformat(timespec="seconds"), "alert": alert, "verdict": verdict[:300], "report": report,
                   "worst": [k for k, v in SEV_RANK.items() if v == worst][0], "new": len(new), "stories": len(stories),
                   "ids": [s["id"] for s in new][:3],
                   "events_span": new_span}, f)
    print(f"{now.isoformat(timespec='seconds')} events={len(events)} stories={len(stories)} new={len(new)} worst={[k for k, v in SEV_RANK.items() if v == worst][0]} alert={alert} report={report}", flush=True)


if __name__ == "__main__":
    main()
