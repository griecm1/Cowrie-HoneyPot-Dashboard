from flask import Flask, jsonify, render_template
import json
import os
import glob
from datetime import datetime, timezone, timedelta
from collections import defaultdict
import requests
import geoip2.database

app = Flask(__name__)

LOG_FILE = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
GEOIP_DB = "/home/cowrie/geoip/GeoLite2-City.mmdb"

_geo_cache = {}
_asn_cache = {}
_file_cache = {}

KEEP_FIELDS = {"eventid", "src_ip", "timestamp", "username", "password", "input"}

def get_location(ip):
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        with geoip2.database.Reader(GEOIP_DB) as reader:
            r = reader.city(ip)
            result = {
                "country": r.country.name,
                "country_code": r.country.iso_code,
                "city": r.city.name,
                "lat": float(r.location.latitude),
                "lon": float(r.location.longitude)
            }
    except Exception:
        result = {"country": "Unknown", "country_code": "", "city": "Unknown", "lat": 0, "lon": 0}
    _geo_cache[ip] = result
    return result

def read_file_events(path):
    try:
        cur_size = os.path.getsize(path)
    except OSError:
        return []

    cached = _file_cache.get(path)
    if cached and cached["size"] == cur_size:
        return cached["events"]

    if cached and cur_size > cached["size"]:
        events = list(cached["events"])
        start_offset = cached["byte_offset"]
    else:
        events = []
        start_offset = 0

    byte_offset = start_offset
    try:
        with open(path, "r", errors="replace") as f:
            f.seek(start_offset)
            while True:
                line = f.readline()
                if not line:
                    break
                stripped = line.strip()
                if stripped:
                    try:
                        raw = json.loads(stripped)
                        events.append({k: raw[k] for k in KEEP_FIELDS if k in raw})
                        byte_offset = f.tell()
                    except json.JSONDecodeError:
                        pass
    except OSError:
        pass

    _file_cache[path] = {"size": cur_size, "events": events, "byte_offset": byte_offset}
    return events

def parse_logs():
    log_dir = os.path.dirname(LOG_FILE)
    log_base = os.path.basename(LOG_FILE)
    files = sorted(glob.glob(os.path.join(log_dir, log_base + '*')))
    events = []
    for path in files:
        events.extend(read_file_events(path))
    return events

def fetch_asns(ips):
    uncached = [ip for ip in ips if ip not in _asn_cache]
    if not uncached:
        return
    for i in range(0, len(uncached), 100):
        batch = uncached[i:i+100]
        try:
            resp = requests.post(
                "http://ip-api.com/batch?fields=query,org",
                json=[{"query": ip} for ip in batch],
                timeout=5
            )
            for item in resp.json():
                _asn_cache[item["query"]] = item.get("org") or "Unknown"
        except Exception:
            for ip in batch:
                _asn_cache.setdefault(ip, "Unknown")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def stats():
    events = parse_logs()

    connections = [e for e in events if e.get("eventid") == "cowrie.session.connect"]
    logins     = [e for e in events if e.get("eventid") == "cowrie.login.success"]
    failed     = [e for e in events if e.get("eventid") == "cowrie.login.failed"]
    commands   = [e for e in events if e.get("eventid") == "cowrie.command.input"]

    unique_ips = list(set(e.get("src_ip") for e in connections if e.get("src_ip")))
    ip_locations = {ip: get_location(ip) for ip in unique_ips}

    usernames = {}
    for e in logins + failed:
        u = e.get("username", "")
        usernames[u] = usernames.get(u, 0) + 1
    top_usernames = sorted(usernames.items(), key=lambda x: x[1], reverse=True)

    passwords = {}
    for e in logins + failed:
        p = e.get("password", "")
        passwords[p] = passwords.get(p, 0) + 1
    top_passwords = sorted(passwords.items(), key=lambda x: x[1], reverse=True)

    attack_map = []
    for ip, loc in ip_locations.items():
        entry = dict(loc)
        entry["ip"] = ip
        attack_map.append(entry)

    recent = sorted(connections, key=lambda x: x.get("timestamp", ""), reverse=True)[:20]
    feed = []
    for e in recent:
        loc = ip_locations.get(e.get("src_ip", ""), {})
        feed.append({
            "ip": e.get("src_ip"),
            "timestamp": e.get("timestamp"),
            "country": loc.get("country", "Unknown"),
            "country_code": loc.get("country_code", "")
        })

    recent_commands = sorted(commands, key=lambda x: x.get("timestamp", ""), reverse=True)[:20]
    cmd_list = []
    for e in recent_commands:
        loc = ip_locations.get(e.get("src_ip", ""), {})
        cmd_list.append({
            "ip": e.get("src_ip"),
            "command": e.get("input"),
            "timestamp": e.get("timestamp"),
            "country_code": loc.get("country_code", "")
        })

    country_counts = {}
    for e in connections:
        country = ip_locations.get(e.get("src_ip", ""), {}).get("country", "Unknown")
        country_counts[country] = country_counts.get(country, 0) + 1

    command_counts = {}
    for e in commands:
        cmd = e.get("input", "").strip()
        if cmd:
            command_counts[cmd] = command_counts.get(cmd, 0) + 1
    top_commands = sorted(command_counts.items(), key=lambda x: x[1], reverse=True)

    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    time_buckets = defaultdict(int)
    for e in connections:
        ts = e.get("timestamp", "")
        if ts and len(ts) >= 13:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt >= cutoff:
                    time_buckets[ts[:13].replace("T", " ")] += 1
            except ValueError:
                pass
    connections_over_time = sorted(time_buckets.items())

    fetch_asns(unique_ips)
    asn_counts = {}
    for ip in unique_ips:
        asn = _asn_cache.get(ip, "Unknown")
        if asn != "Unknown":
            asn_counts[asn] = asn_counts.get(asn, 0) + 1
    top_asns = sorted(asn_counts.items(), key=lambda x: x[1], reverse=True)

    return jsonify({
        "total_connections": len(connections),
        "unique_ips": len(unique_ips),
        "total_commands": len(commands),
        "top_usernames": top_usernames,
        "top_passwords": top_passwords,
        "attack_map": attack_map,
        "recent_feed": feed,
        "recent_commands": cmd_list,
        "country_counts": sorted(country_counts.items(), key=lambda x: x[1], reverse=True),
        "top_commands": top_commands,
        "connections_over_time": connections_over_time,
        "top_asns": top_asns
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
