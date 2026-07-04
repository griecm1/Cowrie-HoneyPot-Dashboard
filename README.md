# Cowrie-HoneyPot-Dashboard

A real-time web dashboard for monitoring SSH honeypot activity captured by [Cowrie](https://github.com/cowrie/cowrie). Displays live attack data including geographic origins, login attempts, commands executed, and network infrastructure.

## Features

- **Live attack map** — world map with markers for each unique attacker IP
- **Top usernames & passwords** — ranked lists with pie charts
- **Attacks by country** — geographic breakdown with pie chart
- **Top commands** — most common commands executed by attackers
- **Connections over time** — hourly line graph for the last 24 hours
- **Top ASNs / ISPs** — which networks attackers are coming from
- **Recent attacks & commands** — live scrolling feeds
- **Hover tooltips** — on all charts for counts and percentages

## Requirements

- Python 3
- Cowrie SSH honeypot (logs to `cowrie.json`)
- [MaxMind GeoLite2-City](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) database (`.mmdb`)

```bash
pip install flask geoip2 requests
