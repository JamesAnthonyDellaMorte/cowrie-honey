#!/usr/bin/env python3
"""Quick 24h stats from Cowrie JSON logs."""

import json
import glob
import sys
from datetime import datetime, timedelta
from collections import Counter

import pytz

md = "--markdown" in sys.argv or "-m" in sys.argv
cutoff = datetime.now() - timedelta(hours=24)

def format_timestamp(ts_str):
    try:
        # The logs are already in local time but incorrectly labeled or processed as UTC.
        # Removing the offset adjustment and just formatting the string.
        dt = datetime.fromisoformat(ts_str.replace("Z", ""))
        return dt.strftime("%b %d, %Y at %I:%M:%S %p EST")
    except Exception:
        return ts_str

connections = 0
logins_ok = 0
logins_fail = 0
commands = []
passwords = Counter()
usernames = Counter()
ips = Counter()
files = 0

for logfile in sorted(glob.glob("/root/cowrie/log/cowrie.json*")):
    for line in open(logfile):
        try:
            j = json.loads(line)
        except:
            continue

        ts = j.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00").replace("+00:00", ""))
        except:
            continue

        if dt < cutoff:
            continue

        eid = j.get("eventid", "")

        if eid == "cowrie.session.connect":
            connections += 1
            ips[j.get("src_ip", "?")] += 1

        elif eid == "cowrie.login.success":
            logins_ok += 1
            passwords[j.get("password", "")] += 1
            usernames[j.get("username", "")] += 1

        elif eid == "cowrie.login.failed":
            logins_fail += 1
            passwords[j.get("password", "")] += 1
            usernames[j.get("username", "")] += 1

        elif eid == "cowrie.command.input":
            commands.append(j.get("input", ""))

        elif eid == "cowrie.session.file_upload":
            files += 1

last_conn = None
last_conn_ip = None
for logfile in sorted(glob.glob("/root/cowrie/log/cowrie.json*")):
    for line in open(logfile):
        try:
            j = json.loads(line)
            if j.get("eventid") == "cowrie.session.connect":
                last_conn = j.get("timestamp", "")
                last_conn_ip = j.get("src_ip", "?")
        except:
            continue

now = datetime.now()
if last_conn:
    try:
        last_dt = datetime.fromisoformat(last_conn.replace("Z", ""))
        ago = now - last_dt
        mins = int(ago.total_seconds() // 60)
        if mins < 60:
            ago_str = f"{mins}m ago"
        else:
            ago_str = f"{mins // 60}h {mins % 60}m ago"
    except:
        ago_str = ""
    last_str = f"{format_timestamp(last_conn)}  ({last_conn_ip}, {ago_str})"
else:
    last_str = "none"

if md:
    print("## Honeypot Report (Last 24h)\n")
    print(f"```")
    print(f"  Last seen    {last_str}")
    print(f"  Connections  {connections:,}")
    print(f"  Logins OK    {logins_ok:,}")
    print(f"  Logins Fail  {logins_fail:,}")
    print(f"  Commands     {len(commands):,}")
    print(f"  Uploads      {files:,}")
    print(f"  Unique IPs   {len(ips):,}")
    print(f"```")
else:
    print(f"Honeypot Report (Last 24h)\n")
    print(f"  Last seen    {last_str}")
    print(f"  Connections  {connections:,}")
    print(f"  Logins OK    {logins_ok:,}")
    print(f"  Logins Fail  {logins_fail:,}")
    print(f"  Commands     {len(commands):,}")
    print(f"  Uploads      {files:,}")
    print(f"  Unique IPs   {len(ips):,}")
