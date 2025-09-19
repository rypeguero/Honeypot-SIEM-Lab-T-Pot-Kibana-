# Honeypot SIEM Lab (T‑Pot + Kibana)

A single‑VPS honeypot lab for practicing log correlation, detections, and weekly reporting. Uses **T‑Pot Standard (HIVE)** on Ubuntu 24.04 and keeps all admin UIs private via an **SSH tunnel**.

> ⚠️ Ethics & Safety: Honeypots must be passive. Do not pivot or retaliate. Confirm your VPS provider allows honeypots. Expose only decoy ports.

---

## Table of contents

* [Architecture](#architecture)
* [Prereqs](#prereqs)
* [Deploy (quick)](#deploy-quick)
* [Secure access (SSH tunnel)](#secure-access-ssh-tunnel)
* [Open decoy ports](#open-decoy-ports)
* [Verify T‑Pot](#verify-t-pot)
* [Kibana data view & starter KQL](#kibana-data-view--starter-kql)
* [Screenshots to capture](#screenshots-to-capture)
* [Future work](#future-work)
* [Attribution](#attribution)

---

## Architecture

* **VPS (Ubuntu 24.04 LTS):** runs **T‑Pot Standard (HIVE)** (multi‑honeypot + Suricata + ELK).
* **Admin access:** via **SSH on 64295** and **local port‑forward** to portal `64297` (no public access).
* **Public exposure:** only decoy ports (e.g., 22/23/80/443).

```
Internet ──> [VPS/T‑Pot] ──(ssh -L 64297:127.0.0.1:64297)──> Admin’s browser (https://localhost:64297)
```

---

## Prereqs

* A fresh **Ubuntu 24.04 LTS** VPS.
* SSH key for login.
* Local machine (Linux/macOS/Windows) with OpenSSH.

---

## Deploy (quick)

Run these on the **VPS** (user `ops`, via normal SSH):

```bash
# 1) Baseline
sudo apt update && sudo apt -y install curl ufw

# 2) Avoid lockout when T‑Pot moves SSH to 64295
sudo ufw allow OpenSSH
sudo ufw allow 64295/tcp
sudo ufw --force enable

# 3) Install T‑Pot (run as NON‑ROOT from $HOME)
cd ~
env bash -c "$(curl -sL https://github.com/telekom-security/tpotce/raw/master/install.sh)"
# choose: H  (Standard/HIVE)
# set WEB_USER + strong WEB_PASSWORD

# 4) Reboot when the installer prompts
sudo reboot
```

After reboot, T‑Pot’s real SSH is on **64295**.

---

## Secure access (SSH tunnel)

Create a shortcut on your **local machine**:

```ssh-config
# ~/.ssh/config
Host tpot
  HostName YOUR_VPS_IP
  User ops
  Port 64295
  LocalForward 64297 127.0.0.1:64297
  ServerAliveInterval 30
  ServerAliveCountMax 3
```

Use it:

```bash
ssh tpot
# Then browse: https://localhost:64297 (login with WEB_USER/WEB_PASSWORD)
```

Block public access to the portal (on the **VPS**):

```bash
sudo ufw delete allow 64297/tcp 2>/dev/null || true
sudo ufw deny 64297/tcp
```

---

## Open decoy ports

Pick a minimal, safe set (you can expand later):

```bash
# VPS
sudo ufw allow 22,23,80,443/tcp
sudo ufw status verbose
```

![UFW Status (pre-lockdown)](docs/images/ufw_status.png)

---

## Verify T‑Pot

On the **VPS**:

```bash
sudo docker ps --format "table {{.Names}}\t{{.Ports}}"
sudo ss -tulnp | grep -E ':(22|23|80|443|64297)\b'
```

![Docker Containers](docs/images/docker_ps.png)
![Listeners & Ports](docs/images/docker_and_ss.png)

Open the portal via your tunnel:

* `https://localhost:64297` → click **Kibana** → **Discover**.

![T‑Pot Portal](docs/images/portal_landing.png)
![Attack Map](docs/images/attack_map.png)
![Kibana Dashboard](docs/images/kibana_dashboard.png)

---

## Kibana data view & starter KQL

Set **Data view** to `logstash-*` (create if needed). Time: **Last 7 days**.

Paste into the **KQL query bar** in Discover:

**A) All Suricata**

```kql
path:"/data/suricata/log/eve.json"
```

**B) Alerts only**

```kql
path:"/data/suricata/log/eve.json" and event_type:alert
```

**C) High/Med alerts**

```kql
path:"/data/suricata/log/eve.json" and event_type:alert and (alert.severity:1 or alert.severity:2)
```

**D) Cowrie successes**

```kql
message:*cowrie* and (event.id:"cowrie.login.success" or cowrie.eventid:"cowrie.login.success")
```

**E) Cowrie downloads (curl/wget)**

```kql
message:*cowrie* and (message:*wget* or message:*curl* or event.id:*file_download* or cowrie.eventid:*file_download*)
```

*Add useful columns from the left panel (click **+**):*

* Suricata: `src_ip`, `dest_ip`, `dest_port` (or `DestPort`), `app_proto`, `alert.signature`.
* Cowrie: `source.ip` (or `src_ip`), `user.name`, `cowrie.password`, `url.full`.

*Save each search* (floppy icon) and add to a new dashboard (e.g., **Honeypot — Dashboard**).

> **Screenshots**

![Kibana Discover — Suricata (broad)](docs/images/kibana_discover_suricata.png)
![Kibana Discover — Suricata High/Med Alerts](docs/images/kibana_suricata_alerts.png)

---

## Executive Summary

* One paragraph on activity volume & notable findings.

## Notable Events

* 2025‑09‑18 21:57Z — Suricata alert `ALERT_SIGNATURE` — src\_ip → dest\_port (screenshot link)
* … 3–5 bullets

## TTPs (MITRE ATT\&CK)

* T1059 Command and Scripting Interpreter (Cowrie commands)
* T1105 Ingress Tool Transfer (downloads)
* T1190 Exploit Public‑Facing Application (web hits)

## IOCs

* IPs: x.x.x.x, …
* URLs/domains: http\[:]//example\[.]com/payload
* Hashes: sha256: …

## Detections / Queries Used

* Suricata — High/Med Alerts (24h) — saved search link
* Cowrie — Login Success — saved search link
* Cowrie — Downloads — saved search link

## Screenshots

* ![Dashboard Overview](docs/images/YYYY‑WW_dashboard.png)
* ![Discover — Suricata High/Med](docs/images/YYYY‑WW_suricata.png)
* ![Discover — Cowrie Downloads](docs/images/YYYY‑WW_cowrie.png)

## Next Actions

* Expand decoy ports (e.g., 445/3389) cautiously
* Tune KQL / add visualizations (top signatures, top src IPs)
* Consider adding Wazuh or WireGuard in Phase 2

```

> **Screenshot prompts** are embedded; place images under `docs/images/` and link them in reports.

---

## Future work
- Add **RDP/SMB** decoys (445/3389) after monitoring current noise.
- Optional **WireGuard** for portal access instead of SSH tunneling.
- Add malware sample capture (quarantined), separate egress‑blocked sandbox.

---

## Attribution
This lab is powered by **T‑Pot Community Edition** by Deutsche Telekom Security:  
**https://github.com/telekom-security/tpotce**

If you publish this project, please credit T‑Pot in your README.

```
