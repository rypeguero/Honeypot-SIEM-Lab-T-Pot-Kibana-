# T-Pot Honeypot Deployment Guide

This repository documents how I deployed a T-Pot honeypot lab on a public VPS for blue-team learning and SIEM practice. It focuses on installation, secure administrative access, exposed decoy ports, service verification, and basic Kibana access.

This repository is for the **deployment and setup process only**. SOC-style analysis reports, screenshots, KQL findings, and honeypot telemetry writeups are documented separately in my [Honeypot SIEM Lab](https://github.com/rypeguero/honeypot-siem-lab) repository.

> ⚠️ Ethics & Safety: Honeypots must be passive. Do not pivot, retaliate, or interact with systems that connect to the honeypot. Confirm your VPS provider allows honeypot activity and expose only intentional decoy services.

---

## Table of Contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Deploy T-Pot](#deploy-t-pot)
- [Secure Access](#secure-access)
- [Open Decoy Ports](#open-decoy-ports)
- [Verify T-Pot](#verify-t-pot)
- [Kibana Access and Starter Queries](#kibana-access-and-starter-queries)
- [Maintenance](#maintenance)
- [Troubleshooting](#troubleshooting)
- [Related Repository](#related-repository)
- [Attribution](#attribution)

---

## Architecture

- **VPS:** Ubuntu 24.04 LTS running T-Pot Community Edition.
- **Admin SSH:** T-Pot moves administrative SSH to port `64295`.
- **Web Portal:** T-Pot web portal is available on port `64297`.
- **Public Exposure:** Honeypot/decoy services listen on selected public ports such as `22`, `23`, `80`, `443`, and others depending on the T-Pot profile.
- **Analysis Stack:** T-Pot includes Elastic, Kibana, Logstash, Suricata, and multiple honeypots.

```text
Internet traffic -> VPS / T-Pot honeypot services -> Elastic / Kibana dashboards
Admin access -> SSH on port 64295 -> T-Pot portal on port 64297
```

---

## Prerequisites

- Fresh Ubuntu 24.04 LTS VPS
- SSH access to the VPS
- Non-root user account for installation
- Strong password for T-Pot web access
- Basic familiarity with Linux commands, SSH, and firewall rules

---

## Deploy T-Pot

Run the installer from a non-root user account on the VPS.

```bash
# Update the server
sudo apt update && sudo apt upgrade -y

# Install curl if needed
sudo apt install curl -y

# Run the T-Pot installer from the user's home directory
cd ~
env bash -c "$(curl -sL https://github.com/telekom-security/tpotce/raw/master/install.sh)"
```

During installation:

- Select the desired T-Pot edition/profile.
- Create the T-Pot web username and password.
- Reboot when prompted.

```bash
sudo reboot
```

After reboot, reconnect using the T-Pot SSH port:

```bash
ssh -p 64295 <username>@<VPS_PUBLIC_IP>
```

---

## Secure Access

T-Pot uses port `64295` for SSH after installation.

Example SSH command:

```bash
ssh -p 64295 <username>@<VPS_PUBLIC_IP>
```

The T-Pot web portal is available at:

```text
https://<VPS_PUBLIC_IP>:64297
```

For a safer setup, restrict administrative access to trusted IP addresses where possible. Do not expose management services more than necessary.

If using a host firewall, make sure you do not accidentally block honeypot collection traffic unless that is intentional.

---

## Open Decoy Ports

T-Pot exposes multiple honeypot services so internet scanners and automated probes can interact with decoy services.

Common ports observed or used in this lab include:

| Port | Purpose |
|---:|---|
| 22 | SSH honeypot activity |
| 23 | Telnet honeypot activity |
| 80 | HTTP/web honeypot activity |
| 443 | HTTPS/web honeypot activity |
| 445 | SMB-related probing |
| 9200 | Elasticsearch-related probing |
| 5432 | PostgreSQL-related probing |
| 8728 | MikroTik/RouterOS-related probing |

> Note: The exact exposed ports depend on the T-Pot configuration and active containers.

### Firewall / Port Screenshot

![UFW Status](docs/images/UFW%20Status.png)

---

## Verify T-Pot

Check the T-Pot service:

```bash
sudo systemctl status tpot --no-pager
```

Start T-Pot manually if needed:

```bash
sudo systemctl start tpot
```

Enable T-Pot to start automatically after reboot:

```bash
sudo systemctl enable tpot
```

Confirm it is enabled:

```bash
sudo systemctl is-enabled tpot
```

Check running T-Pot containers:

```bash
sudo dps
```

If `dps` is unavailable, use Docker directly:

```bash
sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

Check listening ports:

```bash
sudo ss -tulnp
```

### Service Verification Screenshots

![Docker Containers](docs/images/Docker%20Containers.png)

![Listeners and Ports](docs/images/Listeners%20%26%20Ports.png)

---

## Kibana Access and Starter Queries

Open the T-Pot portal and launch Kibana:

```text
https://<VPS_PUBLIC_IP>:64297
```

In Kibana Discover, use the `logstash-*` data view.

### T-Pot Portal and Dashboard Screenshots

![T-Pot Portal](docs/images/T-pot%20Portal.png)

![Attack Map](docs/images/Attack%20Map.png)

![Kibana Dashboard](docs/images/Kibana%20Dashboard.png)

### Starter KQL Queries

#### Suricata events

```kql
path:"/data/suricata/log/eve.json"
```

#### Suricata alerts only

```kql
path:"/data/suricata/log/eve.json" and event_type:alert
```

#### Cowrie activity

```kql
type.keyword: "Cowrie"
```

#### Honeytrap activity

```kql
type.keyword: "Honeytrap"
```

#### Filter out VPS source IP and dashboard traffic

```kql
src_ip: * and not src_ip: "<VPS_PUBLIC_IP>" and not DestPort: 64297
```

Helpful fields to review in Kibana:

- `src_ip`
- `DestPort` or `dest_port`
- `geoip.country_name`
- `type.keyword`
- `event_type`
- `alert.signature`
- `username`
- `password`
- `input`

---

## Maintenance

Useful commands:

```bash
# Check service status
sudo systemctl status tpot --no-pager

# Start T-Pot
sudo systemctl start tpot

# Stop T-Pot
sudo systemctl stop tpot

# Enable auto-start after reboot
sudo systemctl enable tpot

# View recent service logs
sudo journalctl -u tpot -n 100 --no-pager

# Check containers
sudo dps
```

If the VPS reboots and T-Pot does not come back online, confirm the service is enabled:

```bash
sudo systemctl is-enabled tpot
```

---

## Troubleshooting

### Cannot SSH after installation

T-Pot moves SSH to port `64295`.

```bash
ssh -p 64295 <username>@<VPS_PUBLIC_IP>
```

### Web portal does not load

Check whether Nginx is listening on port `64297`:

```bash
sudo ss -lntp | grep 64297
```

Test locally from the VPS:

```bash
curl -k -I https://127.0.0.1:64297
```

A `401 Unauthorized` response means the portal is running and asking for authentication.

### T-Pot is inactive after reboot

Enable automatic startup:

```bash
sudo systemctl enable tpot
sudo systemctl start tpot
```

### Containers are still starting

Some services, especially Kibana, Logstash, and Elasticsearch, may take a few minutes to become healthy after startup.

```bash
sudo dps
```

---

## Related Repository

SOC analysis reports and honeypot findings are documented separately here:

[Honeypot SIEM Lab](https://github.com/rypeguero/honeypot-siem-lab)

This keeps the deployment guide separate from the investigation reports.

---

## Future Work

- Add tighter management access controls.
- Document firewall rules for different deployment models.
- Add optional VPN or SSH tunnel workflow for portal access.
- Add a separate troubleshooting guide for common T-Pot startup issues.

---

## Attribution

This lab is powered by **T-Pot Community Edition** by Deutsche Telekom Security:

https://github.com/telekom-security/tpotce

If you publish a T-Pot-based project, credit the T-Pot project in your README.
