# KnitSentinel: complete feature guide

**Centralized Infrastructure Monitoring & Log Intelligence**, by InfraKnit.

This guide lists every feature built so far (up to plan item 35, 2026-10-28). For each feature it gives:

- **Where:** where to find it in the web UI, on the server, or in the configuration.
- **How it works:** what happens behind the screen.
- **How to test:** commands and clicks that prove it works, and what you should see.

The examples use the production server **10.10.10.216**, with the UI at **https://10.10.10.216:8443**.
Commands marked *(on the server)* run there over SSH (`ssh support@10.10.10.216`). Commands marked
*(from a test host)* run on any Linux machine that can reach the server.

Each feature has its own detailed document in `docs/`; the link is given in each section.

---

## Contents

1. [Platform and architecture](#1-platform-and-architecture)
2. [Installation, upgrade, offline install](#2-installation-upgrade-offline-install)
3. [HTTPS and certificates](#3-https-and-certificates)
4. [Sign-in, users, roles and audit](#4-sign-in-users-roles-and-audit)
5. [The web interface (layout, menu, themes)](#5-the-web-interface)
6. [Dashboard](#6-dashboard)
7. [Collecting logs and events](#7-collecting-logs-and-events)
8. [Processing: parsers, categories, patterns, GeoIP, threat intelligence](#8-processing-what-happens-to-every-log)
9. [Search and analysis](#9-search-and-analysis)
10. [Metrics: SNMP devices, discovery, traps, containers](#10-metrics-snmp-devices-discovery-traps-containers)
11. [Traffic: NetFlow, IPFIX, sFlow](#11-traffic-netflow-ipfix-sflow)
12. [Agents page](#12-agents-page)
13. [Alerts](#13-alerts)
14. [Incidents](#14-incidents)
15. [Settings page](#15-settings-page)
16. [Configuration database and secrets](#16-configuration-database-and-secrets)
17. [Operating and monitoring KnitSentinel itself](#17-operating-and-monitoring-knitsentinel-itself)
18. [Complete test plan (checklist)](#18-complete-test-plan-checklist)
19. [Automated tests (for developers)](#19-automated-tests-for-developers)
20. [Not built yet](#20-not-built-yet)

### Quick map: where each feature lives

| Feature | In the UI | Detailed doc |
|---|---|---|
| Overview, security tiles, top hosts | **Dashboard** | — |
| Log search, saved searches, export, live tail | **Search** | saved-searches-export.md, live-tail.md |
| Statistics, patterns, map, context | **Search** → tabs *Events / Statistics / Patterns / Map*, event details | statistics.md, log-patterns.md, geoip.md, context-view.md |
| Log categories, custom rules, re-categorize | **Categories** | log-categories.md |
| SNMP devices, discovery, profiles, traps, containers | **Metrics** → tabs | discovery.md, snmp-device-logs.md, containers.md |
| NetFlow / IPFIX / sFlow | **Traffic** | flows.md |
| Agents, agentless sources, cloud, WEF, Kubernetes | **Agents** → tabs | agents.md, agentless-windows.md, agentless-pull.md, cloud-logs.md, wef.md |
| Alert rules, library, maintenance, channels, history | **Alerts** → tabs | correlation-rules.md, detection-library.md, anomaly-detection.md, alert-handling.md, notification-channels.md |
| Incidents (cases) | **Incidents** | incidents.md |
| Users | **Users** (administrators) | — |
| GeoIP, threat feeds, HTTPS certificate | **Settings** (administrators) | geoip.md, threat-intel.md, https.md |
| Ingest queue, inputs | `/etc/knitsentinel/knitsentinel.env` | ingest-queue.md, gelf-beats-kafka.md, fluent-forward.md |

---

## 1. Platform and architecture

**What it is:** a self-hosted log management and monitoring product, like Graylog, written from
scratch (no Graylog or Grafana code).

| Layer | Technology |
|---|---|
| Web UI | React 18.3.1 + TypeScript 5.6.3 (Vite build), served by the API |
| API and services | Python 3.11+, FastAPI 0.139.0 on Uvicorn 0.50.2 |
| Log store | OpenSearch 3.8.0 (daily indices `knitsentinel-logs-*`, flows in `knitsentinel-flows-*`) |
| Metrics store | VictoriaMetrics v1.102.1 |
| Configuration and inventory | MySQL 8 (production, on 10.10.10.216) or SQLite (trials) |
| Agent | KnitSentinel Agent = OpenTelemetry Collector Contrib 0.161.0 with a generated configuration |
| Deployment | Native Linux with systemd. No Docker. |

### The services (all systemd units on the server)

| Service | Job | Ports |
|---|---|---|
| `knitsentinel-ingest` | Receives everything (syslog, traps, agents, HTTP, GELF, Beats, Kafka, Fluentd, WEF, flows), parses, categorizes, enriches, queues on disk and writes to OpenSearch. Also runs the agentless collectors (WinRM, cloud, SFTP, REST). | 514 UDP/TCP, 6514 TLS, 162/udp, 8082 HTTPS (8081 HTTP), 12201, 5044, 24224, 5986 (WEF), 2055/4739/6343 (flows) |
| `knitsentinel-api` | Web UI and REST API, agent installers (`/agent/`), threat-feed and GeoIP updates | 8443 HTTPS (8080 redirects) |
| `knitsentinel-poller` | SNMP polling of devices into VictoriaMetrics, network discovery scans | outbound 161/udp |
| `knitsentinel-alerter` | Evaluates alert rules on their interval, sends notifications, groups alerts into incidents | outbound to mail, chat and ticket services |
| `knitsentinel-victoriametrics` | Metrics database | 127.0.0.1:8428 |
| `opensearch` | Log database | 127.0.0.1:9200 |

### How data flows

```
devices / hosts / cloud / apps
        │  syslog, traps, agents (OTLP), HTTP, GELF, Beats, Kafka, Fluentd, WEF, NetFlow, WinRM/API pulls
        ▼
knitsentinel-ingest ── parse (vendor parsers) ── categorize ── GeoIP ── threat intel ── pattern
        │                                                                   │
        ▼                                                                   ▼
disk queue (/var/lib/knitsentinel/queue)  ───────────────►  OpenSearch (logs, flows)
SNMP poller, agents' metrics, flow rates  ───────────────►  VictoriaMetrics (metrics)
users, devices, rules, alerts, incidents  ───────────────►  MySQL (configuration)
        ▲
knitsentinel-api (UI + REST)        knitsentinel-alerter (rules → alerts → notifications → incidents)
```

**Where:** program in `/opt/knitsentinel/app`, UI in `/opt/knitsentinel/web`, settings in
`/etc/knitsentinel/knitsentinel.env`, data in `/var/lib/knitsentinel` and `/var/lib/opensearch`.

**How to test** *(on the server)*:
```sh
systemctl status knitsentinel-ingest knitsentinel-api knitsentinel-poller knitsentinel-alerter \
                 knitsentinel-victoriametrics opensearch --no-pager | grep -E "●|Active"
curl -sk https://localhost:8443/api/v1/health          # {"status":"ok", ...}
```
All six must be `active (running)`. In the UI, the bottom of the side menu shows a green dot and
**All systems operational**.

---

## 2. Installation, upgrade, offline install

### Online install and upgrade

**Where:** `server-files/install.sh`, `server-files/build-release.sh`, and for 10.10.10.216
`server-files/releases/10.10.10.216/deploy.sh`.

**How it works:**
- `build-release.sh` builds the UI and packs `knitsentinel-0.1.0.tar.gz`.
- `install.sh` does the following:
  1. installs OpenSearch, VictoriaMetrics and Python packages;
  2. creates the `knitsentinel` user, the systemd units and the env file with random secrets
     (`KS_SECRET_KEY`, `KS_INGEST_TOKEN`);
  3. opens the firewall ports;
  4. applies the database migrations;
  5. on a fresh install, creates the first `admin` with a temporary password.
- Re-running it upgrades and keeps settings and data.
- New settings are added to the env file on upgrade.
- `deploy.sh` (216) unpacks the bundle, runs the installer with the stored settings, and reinstalls
  the server's own agent over HTTPS.

**Deploy to 216** *(from the Windows PC)*:
```
cd C:\Users\Madhurima\Desktop\KnitSentinel\server-files\releases
scp -r 10.10.10.216 support@10.10.10.216:/tmp/
ssh support@10.10.10.216
sudo cp -r /tmp/10.10.10.216/. /opt/knitsentinel/ && rm -rf /tmp/10.10.10.216
cd /opt/knitsentinel && sudo bash deploy.sh
```
Then reload the browser with **Ctrl+F5**.

**How to test:** after `deploy.sh`, all services are running (section 1).
`sudo knitsentinel-db status` shows the latest schema version (MySQL **17** as of 2026-10-28).

### Offline install

**Where:** `server-files/build-offline.sh` → `server-files/releases/knitsentinel-offline/`. See docs/offline-install.md.

**How it works:**
- The bundle (about 1.4 GB) contains everything needed:
  - the release;
  - Python wheels for Python 3.11–3.14;
  - the OpenSearch package with its checksum;
  - VictoriaMetrics;
  - the agent packages.
- `install-offline.sh` runs `install.sh --offline DIR`. Nothing is downloaded from apt, PyPI or GitHub.

**How to test:** on a VM without Internet, run `sudo bash install-offline.sh`. It must finish and print the
UI address. **Note:** the offline bundle is older than the latest features (rebuild it before use).

---

## 3. HTTPS and certificates

**Where:**
- UI at **https://10.10.10.216:8443**; port 8080 redirects there.
- Agents and HTTP ingest on 8082; plain 8081 is kept for agents installed before HTTPS.
- **Settings → HTTPS** card. See docs/https.md.

**How it works:**
- On first start, KnitSentinel creates its **own CA**, valid 10 years, and from it a **server
  certificate** for all the server's names and addresses.
- The certificate is renewed automatically 30 days before expiry, or when a name is added.
- Changes are loaded without a restart (hot reload).
- You can **upload a company certificate** (key, certificate, chain) instead, and switch back to the
  own CA at any time.
- Agent installers carry the CA, so agents check the server certificate.
- The Agents page marks agents still on plain HTTP with a *plain HTTP* badge.
- Session cookies get the `Secure` flag over HTTPS.

**How to test:**
1. Open https://10.10.10.216:8443. The browser warns until you trust the CA. Download it from
   **Settings → HTTPS → Download the CA certificate** and import it into "Trusted Root Certification
   Authorities" (the card shows the steps for Windows, macOS and Linux). After a browser restart, the
   lock icon shows no warning.
2. `curl -sI http://10.10.10.216:8080/` → `308` with `Location: https://…:8443/`.
3. `curl -s --cacert ca.crt https://10.10.10.216:8443/api/v1/health` works without `-k`.
4. **Settings → HTTPS**: add a name (e.g. `knitsentinel.infraknit.local`) and **Save names**. Within 30 seconds
   the certificate includes it: `openssl s_client -connect 10.10.10.216:8443 </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName`.

---

## 4. Sign-in, users, roles and audit

**Where:**
- the sign-in page;
- the user menu in the top bar (Change password, Sign out);
- **Users** in the side menu, under Administration;
- on the server, `sudo knitsentinel-users`.

**How it works:**
- **Roles:**
  - **Administrator:** everything.
  - **Viewer:** reads everything. A viewer can also handle alerts and incidents but can't change
    configuration.
- **Sign-in:** by username or email. Passwords are hashed with scrypt. Sessions are stored in the database.
- **Lockout:** 5 failed attempts lock an account for 15 minutes; 20 failed attempts from one address lock that address.
- **Forgot password?:** emails a one-time link, valid 30 minutes. This needs `KS_SMTP_*` and the user's
  email. The link uses `KS_PUBLIC_URL` or the server's address, never the browser's Host header.
- **Temporary passwords** (new user, admin reset) must be changed at the next sign-in.
- **Audit log:** every change (sign-ins, users, rules, devices, channels, incidents, CLI actions with
  `by=cli`) goes to the audit table and to the log `knitsentinel.audit`.

**How to test:**
1. **Users → Add user** creates a viewer `test1`. Sign in as `test1` in a private window: it asks for a new
   password. The menu has no *Users* or *Settings*.
2. Enter a wrong password 5 times: *Account locked for 15 minutes*. Wait 15 minutes, or have an
   administrator reset the password (**Users → Reset password**, or *(on the server)*
   `sudo knitsentinel-users reset-password test1`).
3. **Forgot password?** with SMTP configured: the email arrives and the link opens a set-password form.
4. *(on the server)* `sudo knitsentinel-users list`, `sudo knitsentinel-users reset-password test1`.
5. *(on the server)* `sudo journalctl -u knitsentinel-api | grep knitsentinel.audit | tail`: each step appears with the user.

---

## 5. The web interface

**Where:** every page.

**How it works:**
- **Top bar (navy):** the KnitSentinel logo with "powered by InfraKnit", a theme button (light/dark),
  and a user pill with name, role and initials. Sign-out is the arrow icon.
- **Side menu:** Dashboard, Search, Categories, Metrics, Traffic, Agents, Alerts, Incidents. Under
  *Administration* come Users and Settings.
  - Badges: a red badge on Alerts shows the number firing; an indigo badge on Incidents shows the
    number active.
  - The footer shows the health dot and **Collapse**. The collapsed menu shows icons only and is
    remembered in the browser.
  - Below 900px wide, the menu becomes a drawer opened with the ☰ button.
- **Themes:** light and dark, remembered per browser.
- **Layout:** works from phone width (390px) to wide screens. Tables hide less important columns when
  space runs short.

**How to test:**
- Click **Collapse** and reload: it stays collapsed.
- Switch the theme.
- Narrow the window below 900px: the ☰ drawer appears.
- With an alert firing, the Alerts badge shows the count, red if one is critical.

---

## 6. Dashboard

**Where:** **Dashboard**, the home page `/`.

**How it works:** every number is a live query to OpenSearch, VictoriaMetrics or MySQL for the chosen range
(1 hour, 24 hours or 7 days):
- **Overview (navy panel):**
  - events and errors, with the change against the previous period;
  - the ingest rate;
  - firing alerts;
  - hosts online.
- **Security events tiles:** failed logins, denied traffic, threats, config changes, account changes,
  links down. Built on log categories. Click one to open Search with that query.
- **Log volume** chart.
- **Severity tiles:** with an "error or worse" share.
- **Top hosts and Top applications:** a ranked leaderboard and radial rings.
- **Log categories, event sources.**
- **Failed logins:** top source IPs and users, plus a **map** of where failed logins come from (needs GeoIP).
- **Active alerts.**
- **Hosts table:** devices and agents with status. Click a row to open that device or agent.

**How to test:**
1. Send a few failed logins (section 7.1) and open the Dashboard (24 hours). *Failed logins* increases.
2. Click the tile: Search opens with `category:authentication outcome:failure`.
3. Click a host in the hosts table: the right device (Metrics) or agent (Agents) opens.

---

## 7. Collecting logs and events

Every input below ends in the same pipeline (section 8), so logs from all sources are searched,
categorized and alerted on the same way. Check any input with **Search** → `source_type:<type>`.

### 7.1 Syslog (UDP, TCP, TLS)

**Where:**
- ports 514 UDP/TCP;
- 6514 TLS, when `KS_SYSLOG_TLS_CERT`/`_KEY` are set;
- device setup guides in docs/sending-logs.md, and **Metrics → a device → Set up logging**.

**How it works:**
- Accepts RFC 3164 and RFC 5424, with octet-counted or newline framing on TCP.
- The device's time zone is applied when its timestamp carries none (`KS_SYSLOG_TIMEZONE`, e.g. Asia/Kolkata).
- Vendor parsers (section 8.1) extract fields.

**How to test** *(from a test host)*:
```sh
logger -n 10.10.10.216 -P 514 -d -t sshd "Failed password for invalid user test from 203.0.113.9 port 4242 ssh2"
logger -n 10.10.10.216 -P 514 -T "hello over TCP from $(hostname)"
```
**Search** (last 15 minutes):
- `"hello over TCP"` finds the second line.
- `action:login_failed src_ip:203.0.113.9` finds the first, with fields `user=test`, `category=authentication`, `outcome=failure`.

### 7.2 SNMP traps and informs (v1, v2c, v3)

**Where:**
- UDP 162;
- **Metrics → SNMP traps** for v3 users, rejected traps and examples;
- docs/snmp-device-logs.md.

**How it works:**
- **Decoding:** traps are decoded (link down/up, cold/warm start, authentication failure, config
  change, vendor alarms) and linked to the device by address.
- **v2c informs:** acknowledged.
- **SNMPv3:** users are configured in the UI, or taken from devices and SNMP profiles.
  - The engine ID is learned and each message is authenticated and decrypted (MD5/SHA, DES/AES).
  - Failures are counted with reasons.
- **Community check:** `KS_SNMP_TRAP_COMMUNITIES` limits the accepted v1/v2c communities.

**How to test** *(from a test host with net-snmp)*:
```sh
snmptrap -v 2c -c public 10.10.10.216 '' 1.3.6.1.6.3.1.1.5.3 ifIndex i 2 ifDescr s "Gi0/2"     # linkDown
snmptrap -v 3 -u ksuser -l authPriv -a SHA -A authpass123 -x AES -X privpass123 \
         10.10.10.216 '' 1.3.6.1.6.3.1.1.5.1                                                   # coldStart (add user ksuser first)
```
- **Search:** `source_type:snmp_trap` shows both. The linkDown has `category:interface subcategory:link_down`.
- **Wrong v3 password:** the trap appears under **Metrics → SNMP traps → Rejected** with the reason.

### 7.3 HTTP JSON and GELF over HTTP (applications)

**Where:**
- `POST https://10.10.10.216:8082/api/v1/ingest` and `POST …:8082/gelf`;
- plain HTTP on 8081 still works;
- the header `Authorization: Bearer <KS_INGEST_TOKEN>`. The token is in the env file.

**How it works:**
- The body can be one object, an array, or NDJSON; gzip is allowed.
- `message`, `timestamp`, `host`, `app` and `level` are mapped. **Every other key becomes a searchable field.**

**How to test:**
```sh
TOKEN=$(sudo grep ^KS_INGEST_TOKEN= /etc/knitsentinel/knitsentinel.env | cut -d= -f2)    # on the server
curl -sk -X POST https://10.10.10.216:8082/api/v1/ingest -H "Authorization: Bearer $TOKEN" \
  -d '{"host":"shop01","app":"checkout","level":"error","message":"payment gateway timeout","order_id":991}'
```
- **Search:** `order_id:991` finds it, with severity error.
- **Without the token:** the request gets `401`.

### 7.4 KnitSentinel Agent (Linux, Windows, macOS)

**Where:**
- **Agents → Add agent**, with tabs Linux / Windows / macOS / Kubernetes;
- **Install agent** on a server's device page;
- docs/agents.md.

**How it works:**
- **What the agent is:** the OpenTelemetry Collector with a configuration written by the installer.
- **Logs:**
  - Linux: journald or /var/log files;
  - Windows: the Application, System and Security Event Logs, plus Sysmon, PowerShell and Defender
    when present;
  - macOS: the unified log, filtered to security processes and errors;
  - extra log files with `--logs`.
- **Metrics every 30 seconds:** CPU, memory, disks, network.
- **Transport:** OTLP over HTTPS to 8082, checked against the KnitSentinel CA.
  - Data waits in a disk queue while the server is unreachable.
  - Each agent has a fixed identity; reinstalling keeps it.
- **Ways to install:**
  - a one-line command;
  - a downloadable installer (a Windows **KnitSentinel-Agent-Setup.exe** with an uninstall entry in
    Settings → Apps; a Linux `.sh`; a macOS `.sh`);
  - **Install over SSH** (Linux): you confirm the host key fingerprint first;
  - **Install over WinRM** (Windows).
  - Credentials are used once, never stored, and audited.
- **Options:**
  - `--containers docker`: container logs and stats;
  - `--database mysql|postgresql|oracle`: database logs parsed;
  - `-SecurityChannels` (Windows).

**How to test:**
1. **Agents → Add agent → Linux**, copy the command and run it on a test Linux host. Within a minute the
   agent shows **online** on the Agents page with CPU and memory charts.
2. On that host: `logger "agent test 123"`. **Search** `"agent test 123" source_type:agent` finds it.
3. Windows: run the setup .exe as administrator. The agent appears; a failed Windows login (wrong
   password at the lock screen) appears as `msg_id:4625 action:login_failed`.
4. **Queue:** stop the server's ingest for 2 minutes (`sudo systemctl stop knitsentinel-ingest`),
   run `logger "while down"` on the agent host, then start ingest again. The line arrives afterwards.
5. **Uninstall:** Windows *Settings → Apps → KnitSentinel Agent → Uninstall*; Linux
   `curl -fsSL http://10.10.10.216:8080/agent/uninstall-agent.sh | sudo bash`.

### 7.5 Containers: Docker and Kubernetes

**Where:**
- **Agents → Add agent → Linux** with *Docker containers on this host* ticked;
- **Agents → Add agent → Kubernetes**, which gives a manifest;
- **Metrics → Containers**;
- docs/containers.md.

**How it works:**
- **Docker:** the agent reads the json-file logs of every container (with the container name and
  image) and Docker stats.
- **Kubernetes:** the manifest deploys a DaemonSet that collects pod logs and kubelet stats, and a
  cluster collector for events and object state, all with read-only RBAC. Pod, namespace and node
  become `k8s_*` fields.

**How to test:**
- **Docker:**
  1. `docker run -d --name kstest alpine sh -c 'while true; do echo hello-kstest; sleep 5; done'`.
  2. **Search** `hello-kstest` shows `container_name:kstest`.
  3. Metrics → Containers lists `kstest` with CPU and memory.
- **Kubernetes:** `kubectl apply -f knitsentinel-k8s.yaml`; after a minute, the pods appear under Metrics → Containers.

### 7.6 Agentless Windows (WinRM pull)

**Where:** **Agents → Agentless → Windows** and *Collect without an agent* on a Windows device page. See docs/agentless-windows.md.

**How it works:**
- The ingest service logs in over WinRM (5985 or 5986) with a stored, encrypted account.
- It runs a read-only `Get-WinEvent` for the chosen channels and remembers the last record ID per channel.
- The first poll takes the last 10 minutes.
- Events become the same fields as agent events.

**How to test:**
1. On a Windows server: `Enable-PSRemoting -Force`.
2. Add the source with an administrator account and click **Test**: it shows the channels found.
3. After **Poll now**, **Search** `source_type:winrm` (or the host name) shows the events.

### 7.7 Windows Event Forwarding (WEF, push)

**Where:**
- **Agents → Agentless → Windows Event Forwarding**;
- HTTPS 5986 on the server;
- enabled when `KS_WEF_HOSTNAME` is set;
- docs/wef.md.

**How it works:**
- KnitSentinel acts as a WEC (Windows Event Collector) over HTTPS with client certificates.
- It issues each computer a `.pfx` from its own CA, provides `setup.ps1` and the subscription, and
  acknowledges events only after queueing them.

**How to test:**
1. Set `KS_WEF_HOSTNAME`, then restart ingest.
2. On the Windows computer, download the client certificate and `setup.ps1`, run it as administrator,
   then `wecutil`/`gpupdate` as the page shows.
3. **Search** for the computer's events. *(Not yet verified with a real forwarder.)*

### 7.8 Cloud and SaaS

**Where:** **Agents → Agentless → Cloud and SaaS → Add**. See docs/cloud-logs.md.

**How it works:** the ingest service pulls from each provider's API with read-only credentials, with
overlap and de-duplication so nothing is missed or doubled. Supported providers:
- **AWS:** CloudTrail and CloudWatch Logs;
- **Microsoft:** Azure Activity, Azure Monitor Log Analytics (KQL), Entra ID sign-ins and audit, Microsoft 365 audit;
- **Google:** Google Workspace;
- **Cloudflare:** audit log and firewall events.

Cloud sign-ins are categorized like other logins.

**How to test:**
1. Add a source with a real read-only key and click **Test** (it checks credentials).
2. After the next poll (or **Poll now**), **Search** `source_type:cloud cloud_provider:aws` (or the provider) shows events.
3. A failed console login shows up as `category:authentication outcome:failure`.

### 7.9 Agentless pull: SSH/SFTP files and REST APIs

**Where:** **Agents → Agentless → Add source** (types *SSH/SFTP files*, *REST API*). See docs/agentless-pull.md.

**How it works:**
- **SFTP:** reads only the appended part of each file, remembering an offset per file. The host key
  is pinned.
- **REST:** follows paging, uses a "since" filter, supports token, basic or header authentication,
  and de-duplicates by an ID field.

**How to test:**
1. Add an SFTP source for `/var/log/syslog` on a Linux host, then **Test** and **Poll now**.
2. Append to the file with `logger sftp-test-1`; after the next poll, `sftp-test-1 source_type:ssh_pull` is found in Search (REST sources: `source_type:rest_pull`).

### 7.10 GELF, Beats and Kafka

**Where:** GELF on UDP/TCP 12201, Beats on 5044, Kafka through `KS_KAFKA_*` settings. See docs/gelf-beats-kafka.md.

**How it works:**
- **GELF:** chunked and compressed UDP is reassembled.
- **Beats:** the Lumberjack v2 protocol, acknowledged only after queueing; optional TLS and client
  certificates. Winlogbeat events map like agent Windows events.
- **Kafka:** a consumer group that commits offsets only after queueing.

**How to test:**
```sh
docker run --rm --log-driver gelf --log-opt gelf-address=udp://10.10.10.216:12201 --log-opt tag=gelftest alpine echo gelf-hello
```
- **GELF:** **Search** `gelf-hello source_type:gelf`.
- **Filebeat:** set `output.logstash.hosts: ["10.10.10.216:5044"]`, then search `source_type:beats`.

### 7.11 Fluentd and Fluent Bit (forward protocol)

**Where:** TCP 24224 (`KS_FLUENT_FORWARD`); optional shared key and TLS. See docs/fluent-forward.md.

**How it works:**
- Supports all forward-protocol modes, including gzip, acknowledgements, and the shared-key handshake.
- JSON log lines are unpacked into fields.

**How to test:**
1. Configure a Fluent Bit `[OUTPUT] Name forward, Host 10.10.10.216, Port 24224` and send a test line.
2. **Search** `source_type:fluent`.
3. A wrong shared key is refused and logged by the ingest service.

### 7.12 Durable ingest queue (no loss on restarts or outages)

**Where:** `KS_QUEUE=disk` (the default), files in `/var/lib/knitsentinel/queue`. See docs/ingest-queue.md.

**How it works:**
- Every accepted event is written to a segment file, synced every 0.2 seconds, before inputs
  acknowledge it (agents, HTTP, Beats, Fluentd, WEF, Kafka).
- A writer sends segments to OpenSearch with fixed IDs, so a resend after a crash overwrites
  instead of duplicating.
- Read segments are deleted.
- Limits: `KS_QUEUE_MAX_BYTES` (default 4g) and `KS_QUEUE_MIN_FREE` (default 2g).
- Inputs stay open while OpenSearch is down.

**How to test** *(on the server)*:
1. `sudo systemctl stop opensearch`.
2. Send 100 syslog lines: `for i in $(seq 100); do logger -n 10.10.10.216 -T "queue-test $i"; done`.
3. `ls -la /var/lib/knitsentinel/queue` shows the data.
4. `sudo systemctl start opensearch` and wait about 1 minute.
5. **Search** `queue-test` shows **100** events.

### 7.13 Databases

**Where:**
- agent option `--database mysql|postgresql|oracle`;
- SQL Server through the Windows event log;
- docs/database-logs.md.

**How it works:** parsers recognize logins, failed logins, errors and start/stop in MySQL/MariaDB,
PostgreSQL, SQL Server and Oracle logs.

**How to test:**
1. On a MySQL host with the agent installed using `--database mysql`, try a wrong password:
   `mysql -u root -pwrong`.
2. **Search** `action:login_failed app:mysql*`.

---

## 8. Processing: what happens to every log

### 8.1 Vendor parsers

**Where:** automatic. Fields appear in Search event details. See docs/sending-logs.md.

**How it works:**
- **Devices with their own format:** Cisco IOS/ASA/NX-OS, FortiGate, Palo Alto, Juniper, MikroTik,
  Sophos, Linux sshd/sudo, and databases have parsers.
- **Windows:** logon events get `user`, `src_ip`, `action`, `msg_id`.
- **Common field names:** all of them extract `src_ip`, `dst_ip`, `user`, `action` and `vendor`, so
  one query works across vendors.

**How to test:**
1. Send a FortiGate-style line:
   ```sh
   logger -n 10.10.10.216 -d 'date=2026-10-28 time=10:00:00 devname="FGT1" type="traffic" subtype="forward" srcip=10.0.0.5 dstip=8.8.8.8 action="deny"'
   ```
2. **Search** `vendor:fortinet action:deny` shows `src_ip`/`dst_ip` fields.

### 8.2 Log categories, custom rules, re-categorize

**Where:**
- **Categories** page;
- the category bar and Category column in **Search**;
- docs/log-categories.md.

**How it works:**
- **Fields set on every log:** `category`, `subcategory`, `outcome` and `device_class`.
  - `category` is one of authentication, account_management, network_traffic, threat, vpn, configuration,
    interface, routing, hardware, system, web, dns_dhcp, application, other.
  - `outcome` is one of success, failure, allowed, denied, unknown.
- **How a category is chosen:** the first source that recognizes the event wins: the vendor's own
  classification, then Windows event IDs, Sysmon and cloud hints, then message rules.
- **Custom rules** on the Categories page (a query → category/subcategory/outcome) run first.
- **Re-categorize stored logs** applies the current rules to logs already stored. It also fills in
  GeoIP, threat and pattern fields.

**How to test:**
1. **Categories → Add rule**: query `app:backupd "job failed"` → category `application`, outcome `failure`.
2. Send `logger -t backupd "job failed: disk full"`. **Search** `category:application outcome:failure` finds it.
3. **Re-categorize** last 24 hours: older matching lines are updated too.

### 8.3 Log patterns

**Where:** **Search → Patterns** tab. See docs/log-patterns.md.

**How it works:**
- Each message is turned into a pattern when stored:
  - IPs, numbers, times, emails, URLs and other variable parts become placeholders, e.g.
    `Failed password for <*> from <IP> port <NUM>`;
  - the pattern is saved with a stable `pattern_id`.
- The tab counts patterns and compares with the period before and the past 7 days, which marks
  **New** and **change**.
- Similar patterns can be merged.

**How to test:**
1. Send 20 failed logins with different IPs.
2. Patterns shows **one** pattern with count 20.
3. **Show events** filters Search to `pattern:<id>`; **Exclude** hides it.

### 8.4 GeoIP

**Where:**
- **Settings → GeoIP** (download DB-IP Lite or MaxMind GeoLite2, or upload `.mmdb`);
- **Search → Map**, the **Traffic** Countries card, and the **Dashboard** failed-login map;
- docs/geoip.md.

**How it works:**
- Public source and destination addresses get country, city, location, ASN and organization on arrival
  (`src_country`, `src_city`, `src_asn`, …).
- Private addresses are skipped.
- The databases are re-read when replaced; an optional daily update is set with `KS_GEOIP_AUTO_UPDATE`.

**How to test:**
1. Settings → GeoIP → **Download DB-IP Lite**.
2. Send `logger -t sshd "Failed password for root from 8.8.8.8 port 22 ssh2"`.
3. **Search** shows `src_country:US`. **Lookup** in Settings resolves any IP.

### 8.5 Threat intelligence

**Where:**
- **Settings → Threat intelligence** (turn on the free feeds, add MISP/URL/manual lists, look up an address);
- the ⚠ **Threat** badge in Search;
- docs/threat-intel.md.

**How it works:**
- **Feeds:** Spamhaus DROP, FireHOL level 1, Feodo, URLhaus, ThreatFox, Emerging Threats, AlienVault OTX,
  AbuseIPDB, MISP, your own URL lists and manual lists.
- **Updates:** feeds are downloaded on their schedule. Private addresses are always dropped. A failed
  download keeps the old list.
- **Matching:** every log is checked for listed IPs or networks, domains (including parent domains),
  URLs and file hashes. A match adds `threat_match:true`, `threat_indicator`, `threat_feeds`.
- **Alerts:** the recommended alert *Known malicious address or domain* uses this.

**How to test:**
1. **Turn on the free feeds** and wait a few minutes.
2. Add a manual list with `198.51.100.66`.
3. Send `logger -t sshd "Accepted password for bob from 198.51.100.66 port 22 ssh2"`.
4. **Search** `threat_match:true` finds it with the ⚠ badge. The Dashboard *Threats* tile counts it.

---

## 9. Search and analysis

### 9.1 Search page and query language

**Where:** **Search** (`/search`).

**How it works:**
- **What the page has:** a time range, a query box, a histogram (events and errors over time), a
  field list on the left (top values, click to filter), a category bar, results and event details.
- **Results columns:** time, severity, host, app, category, message. Columns drop on narrow screens.
  **Hide fields** gives more room.
- **The URL holds the query and range**, so links can be shared.
- **Query language:**

```
timeout                         word anywhere in the message
"link down"                     phrase
host:sw-core-01   host:sw-*     exact field / prefix
severity:<=3                    error or worse (0 emergency … 7 debug)
action:login_failed             any extracted field
_exists_:src_ip                 field present
-app:cron   NOT app:cron        exclude
(deny OR drop) host:fw-*        grouping; terms side by side are ANDed
category:authentication outcome:failure
```

**How to test:**
1. Search `severity:<=3` for 24 hours. The histogram and results agree with the error count on the Dashboard.
2. Click a host in the field list: `host:…` is added.
3. Open an event and use the **+ / −** buttons to filter by a field value.

### 9.2 Saved searches and export

**Where:** Search toolbar → **Saved searches**, **Save**, **Export**. See docs/saved-searches-export.md.

**How it works:**
- **Saved searches:** private or shared, opened by link `/search?saved=<id>`. A saved search keeps the
  tab and its Statistics/Patterns settings, and *(modified)* shows unsaved changes. The owner or an
  administrator can edit it.
- **Export:** CSV (Excel-safe) or JSON of the shown time range, up to `KS_EXPORT_MAX_ROWS` (100,000).
  Exports are audited.

**How to test:**
1. Save `action:login_failed` as *Failed logins*, shared, then open it as another user.
2. **Export CSV**: the file opens in Excel with the same row count as the results.

### 9.3 Live tail

**Where:** Search toolbar → **Live tail** (URL `tail=1`). See docs/live-tail.md.

**How it works:**
- The server polls OpenSearch every second and streams new matching logs to the browser (Server-Sent
  Events). The delay is about 2 seconds.
- Pause/resume keeps a buffer, and the newest 1000 lines stay on screen.
- Limits: `KS_TAIL_PER_USER` (3) and `KS_TAIL_MAX` (20).

**How to test:**
1. Start a live tail with `"tail-test"`.
2. From a test host: `for i in $(seq 10); do logger -n 10.10.10.216 -T "tail-test $i"; sleep 1; done`.
3. The lines appear one by one.

### 9.4 Statistics and the filter builder

**Where:** **Search → Statistics** tab, and the **Filter** button. See docs/statistics.md.

**How it works:**
- **Measures:** count, distinct count, sum/avg/min/max, percentiles (p50–p99).
- **Split:** by up to two fields (top or bottom N, 1–50), optionally over time.
- **Views:** bar, donut, line chart and table, with CSV download. Clicking a value drills down into the events.
- **Filter builder:** builds queries from picked fields and conditions (is, is not, starts with,
  exists, missing, message contains).

**How to test:**
1. Statistics: *count* by `src_ip`, top 10, last 24 hours.
2. Compare the top value with Search `src_ip:<that IP>` for the same range: the counts match.

### 9.5 Context view

**Where:** open an event (in Search or live tail) → **View in context**. See docs/context-view.md.

**How it works:**
- Shows the 50 lines before and after the event, from the same host, source IP or app, or all logs.
- **Load 50 earlier/later** keeps the view in place.
- **Open in Search** jumps to that time window.

**How to test:**
1. Send `logger "ctx A"; logger "ctx B"; logger "ctx C"` from one host.
2. Open "ctx B" → View in context: A is above it and C below, with B highlighted.

### 9.6 Map

**Where:** **Search → Map** tab (also on Traffic and the Dashboard).

**How it works:** counts events per source or destination location from the GeoIP fields, drawn on
a world map, with a table of countries and cities.

**How to test:** after section 8.4, the Map tab shows a dot in the US for the 8.8.8.8 event.

---

## 10. Metrics: SNMP devices, discovery, traps, containers

### 10.1 Devices and SNMP polling

**Where:** **Metrics** → device list → a device page. **Add device** is for administrators.

**How it works:**
- The poller service polls each device with SNMP v2c or v3: availability, uptime, CPU, memory, disks,
  and per-interface traffic, errors and status.
- Samples go to VictoriaMetrics.
- Vendor fallbacks are included (Cisco SB/CBS CPU and memory).
- Credentials are encrypted.
- **Device page:** charts, interfaces, *View logs*, *Traffic*, *Set up logging* and, for servers, *Install agent*.

**How to test:**
1. Add the CBS350 switch (10.10.10.252) with its community and click **Test** (it shows sysName).
2. Within 1–2 minutes: status *Up*, CPU and interface charts filled.
3. *(on the server)* `curl -s 'localhost:8428/api/v1/query?query=ks_device_up'` shows value 1 for the device.

### 10.2 Auto-discovery and SNMP profiles

**Where:** **Metrics → Discovery** and **Metrics → SNMP profiles** (administrators). See docs/discovery.md.

**How it works:**
- **Profiles** are credential sets (v2c communities and v3 users).
- A **discovery job** scans address ranges with the profiles, on demand or on a schedule.
- Found hosts get their vendor, model, type and serial identified.
- Duplicates are removed by SNMP engine ID.
- Hosts are added automatically, or listed for review (**Add** / **Add all**).

**How to test:**
1. Create a profile with your community.
2. Create a job for `10.10.10.0/24` and click **Run**.
3. The switch and pfSense appear with vendor and model; **Add** puts them in the device list.

### 10.3 Device log status, "Set up logging", configure over SSH

**Where:**
- the Metrics device list (*✓ Logs / No logs* and a coverage count);
- the device page → **Set up logging**;
- docs/snmp-device-logs.md.

**How it works:**
- **Log status:** KnitSentinel checks whether logs arrived from the device's address or name.
- **Set up logging:**
  - shows vendor-specific steps (Cisco IOS/CBS/ASA/NX-OS, Junos, FortiGate, MikroTik, pfSense/OPNsense,
    Sophos, Palo Alto);
  - for supported devices, **Configure over SSH** runs the commands itself, after you confirm the host
    key fingerprint, and stops at the first rejected command;
  - "Allow older SSH algorithms" is an opt-in for old devices;
  - it then waits for the first log.

**How to test:**
1. On the switch page, **Set up logging → Configure over SSH** with an admin login. The page shows each command.
2. Then *First log received ✓* appears, and the list shows *✓ Logs*.
3. *(SSH configure has been tested against simulated devices, not yet on a real one; try it on a lab device first.)*

### 10.4 SNMP traps tab

See 7.2 (v3 users, rejected traps with reasons and an *Add user* shortcut, sender examples).

### 10.5 Containers tab

See 7.5. CPU, memory and network per container (Docker) and per pod/node (Kubernetes). Viewers can see it.

---

## 11. Traffic: NetFlow, IPFIX, sFlow

**Where:**
- **Traffic** page, with the *Traffic* button on a device page;
- UDP 2055 (NetFlow), 4739 (IPFIX) and 6343 (sFlow); each port accepts any of the formats;
- docs/flows.md.

**How it works:**
- **Decoding:** NetFlow v5/v9, IPFIX (including sampling) and sFlow v5.
- **Storage:** records are aggregated per minute (exporter, source, destination, protocol, service
  port, interfaces) into OpenSearch `knitsentinel-flows-*`, kept `KS_FLOW_RETENTION_DAYS` (7).
- **Alerting metrics:** `ks_flow_bits_per_second` and per-host rates go to VictoriaMetrics for alert rules.
- **The page shows:**
  - bandwidth over time;
  - top talkers and destinations;
  - applications (ports);
  - conversations;
  - protocols;
  - exporters and interfaces;
  - largest flows;
  - countries.
- **Filters:** exporter, IP or subnet, and port. They are kept in the URL.
- **Setup guides** are on the page for Cisco, FortiGate, pfSense, MikroTik, sFlow switches and Linux.

**How to test:**
1. **pfSense:** install the *softflowd* package; set host 10.10.10.216, port 2055, version 9.
2. **Or a Linux host:**
   ```sh
   sudo apt install softflowd
   sudo softflowd -i eth0 -n 10.10.10.216:2055 -v 9 -t maxlife=60
   ```
3. Generate traffic (e.g. download a file). After 1–2 minutes, Traffic shows the host in top talkers.
4. *(on the server)* `curl -s localhost:8081/metrics | grep ^ks_flow` shows packet and flow counters increasing.

---

## 12. Agents page

**Where:** **Agents**, with tabs *Agents*, *Agentless*, and *Add agent* (dialog).

**How it works:**
- Each agent shows its host, OS, version, address and first/last seen.
- An agent is **online** if it sent data in the last 2 minutes.
- Agents still sending over plain HTTP have a *plain HTTP* badge.
- Charts show CPU, memory, disk and network.
- **View logs** opens Search with `agent_id:<id>`.
- Deleting an agent removes its metrics; its logs stay until retention removes them.

**How to test:**
1. Stop the agent on a host (`sudo systemctl stop knitsentinel-agent`). After 2 minutes it shows **offline**.
2. Start it again: it goes back to **online**.

---

## 13. Alerts

**Where:** **Alerts**, with tabs *Active*, *Rules*, *Library*, *Maintenance*, *Channels*, *History*.
Rules and channels can be changed by administrators only.

### 13.1 Rule types

**How it works:** the alerter service evaluates each enabled rule every *Evaluate every* seconds. An
alert is per rule and per group (e.g. per `src_ip`).
- **States:** *pending*, until the "for" time passes; then *firing*; then *resolved* when the
  condition clears.
- **Notifications:**
  - sent on firing and on resolved;
  - *Re-notify every N minutes* while firing.

| Type | What it checks | Example |
|---|---|---|
| **Logs** | count of events matching a query in a window, above/below a threshold, optionally per field | `action:login_failed` > 10 in 5 min per `src_ip` |
| **Metrics** | a PromQL expression over VictoriaMetrics with a threshold and duration | `ks_device_up < 1` for 2 min |
| **Sequence** (correlation) | 1–5 steps in order for the same field value within a window; each step "at least N events" or "N different values of a field" | 10 failed logins then a success from the same IP within 15 min. See docs/correlation-rules.md |
| **Baseline** (anomaly) | the count now vs the same time on past days/weeks (or the periods before): fires above mean + k × spread (or below) | failed logins per user 3× above usual. See docs/anomaly-detection.md |
| **First seen** (anomaly) | a value never seen for that user/host in the learning period | a user logs in from a new country |

- **Preview** shows which groups would fire now. Sequence and First-seen rules can preview the last
  hour, 24 hours or 7 days ("would it have fired?").
- Anomaly rules show **⏳ Learning** until they have enough history.

**How to test (Logs rule):**
1. **New rule** → Logs, query `action:login_failed`, group by `src_ip`, above 5 in 5 minutes,
   evaluate every 30 s, and notify a channel.
2. From a test host:
   ```sh
   for i in $(seq 8); do logger -n 10.10.10.216 -t sshd "Failed password for root from 203.0.113.50 port 22 ssh2"; done
   ```
3. Within about a minute, **Active** shows the alert *Firing* for `src_ip=203.0.113.50`, and the channel receives it.
4. After 5 minutes without new failures it resolves and moves to **History** (with a *resolved* notification).

**How to test (Sequence):**
1. Add the recommended *Brute force followed by a successful login*.
2. Send 10 failed logins from one IP, then
   `logger -n 10.10.10.216 -t sshd "Accepted password for root from 203.0.113.50 port 22 ssh2"`.
3. The alert shows a step timeline (failures → success).

**How to test (Metrics):**
1. Rule `ks_device_up < 1` for 1 minute.
2. Unplug or block SNMP for a test device. It fires per device and resolves when the device answers again.

### 13.2 Detection library (MITRE ATT&CK) and recommended alerts

**Where:** **Alerts → Library**, and the *Recommended alerts* card on the Rules tab. See docs/detection-library.md.

**How it works:**
- **69 ready-made rules** (log, sequence and anomaly), each tagged with ATT&CK techniques (51
  techniques), a platform, and the data it needs.
  - Windows: accounts, Kerberos, services, tasks, process creation, Sysmon, PowerShell.
  - Linux: sudo, root SSH, crontab.
  - Network: scans, sweeps, spraying, VPN brute force.
  - Threat-feed hits and web attacks.
- **Data-source chips** show whether the needed logs arrived in the last 7 days, with how-to steps.
- **Bulk add.**
- The **ATT&CK coverage matrix** shows techniques as covered / available / no data.
- Any rule can be tagged with ATT&CK IDs; the tags appear on alerts and in notifications.

**How to test:**
1. Library → filter *Linux* → tick *SSH login as root* → **Add selected**.
2. From a host: `ssh root@<linux-host>` (where root SSH login is allowed). The alert fires with the
   tags *T1078.003* and *T1021.004*.
3. The coverage matrix shows that technique as covered.

### 13.3 Alert handling: acknowledge, assign, snooze, mute, maintenance

**Where:** row buttons on **Active**, **Details** (timeline + notes), the **Maintenance** tab, and **Mute…**. See docs/alert-handling.md.

**How it works:**
- **Acknowledge:** stops repeat notifications.
- **Assign:** viewers can assign only themselves.
- **Snooze:** 1 hour to 7 days.
- **Notes**, and a **timeline** per alert.
- **Mute:** a rule, optionally only for alerts with some labels (e.g. `host=backup01`), for a time or
  until removed.
- **Maintenance windows:**
  - one-off, daily, weekly, or monthly (e.g. *second Tuesday*);
  - in a time zone;
  - for all or some rules and labels.
- **Held notifications:** a firing notification held back by a window, mute or snooze is **sent
  when the hold ends** if the alert is still firing. If it resolves while held, nobody is told.
- Filters: *Not acknowledged*, *Assigned to me*, *Unassigned*, *Held back*.
- A banner shows active maintenance.
- Every notification links to the alert (`/alerts?alert=<id>`).

**How to test:**
1. While an alert fires, click **Acknowledge**. No repeat notifications arrive (with *re-notify* set
   to 5 minutes).
2. **Maintenance → Add window** *once, now to +30 min, host=web01*. A new alert for web01 shows
   🔕 *maintenance* and is not notified.
3. Delete the window: the notification goes out and the timeline shows *held → released*.

### 13.4 Notification channels

**Where:** **Alerts → Channels → Add channel**. Each channel has a **Send test** button. See docs/notification-channels.md.

| Group | Channels | Behaviour |
|---|---|---|
| Messages | Email (SMTP), Slack, Microsoft Teams, Google Chat (thread per alert), Telegram | a message per firing / repeat / resolved |
| On-call | PagerDuty, Opsgenie | one incident per alert, resolved/closed when the alert clears |
| Tickets | Jira (Cloud or Server/DC), ServiceNow | one ticket per alert; repeats add comments/work notes; resolved or transitioned when the alert clears; ticket links on the alert |
| Phone | SMS and WhatsApp through Twilio (WhatsApp templates) | title and link |
| Other | Webhook | the alert as JSON (with `alert_id`, `url`, `mitre`, `incident`, …) |

**How it works:**
- Tokens, keys, passwords and webhook URLs are **encrypted** and never sent back to the browser.
  Leaving a secret blank when editing keeps the stored one.
- **Send test:**
  - Jira and ServiceNow only check access (no ticket is created).
  - PagerDuty and Opsgenie raise a test incident and close it.

**How to test:**
1. Add an **Email** channel to your address, then **Send test**: the mail arrives.
2. Add a **Webhook** to `https://webhook.site/<your-id>` and attach it to a rule. Firing and resolved
   JSON appear there.
3. For Jira, **Send test** reports "project OK". After a real alert, the issue key shows on the
   alert's details (*Jira OPS-12 ↗*).

---

## 14. Incidents

**Where:**
- **Incidents** in the side menu (the badge counts active incidents);
- tick boxes on **Alerts → Active/History**;
- the rule option *Group alerts into incidents*;
- docs/incidents.md.

**How it works:**
- **What an incident is:** a case with a title, description, severity, owner, the alerts in it (one
  incident per alert), a timeline with notes, and a resolution.
- **Status:** Open → Investigating → Contained → Resolved → Closed.
  - Leaving *Open* **acknowledges** its open alerts, so repeat notifications stop.
  - Resolving asks for a resolution text.
  - Choosing an earlier step **reopens** the incident.
- **Creating incidents:**
  - **From alerts:** tick them, then **Create incident**, or **Add to incident…**.
  - **Empty:** **New incident**, then **Add alerts**.
  - **Automatically:** with a rule's *Group alerts into incidents*:
    - **per rule:** all the rule's alerts join one incident;
    - **per label value across rules:** e.g. all alerts for `device=sw1` from any rule grouping by `device`;
    - within a time window (default 30 minutes).
- **Severity:** rises when a more severe alert joins.
- **Notifications:** they name the incident (`Incident: #12 …`).
- **History:** alerts in an incident are kept beyond the normal 90-day cleanup.
- **The Incidents list:** coloured counts per status, status and owner filters (*Mine*, *No owner*),
  alerts firing/total, last activity.
- **Rights:**
  - Everyone can work on incidents.
  - Viewers can only make themselves the owner.
  - Only administrators can delete.

**How to test:**
1. Make two log alerts fire (13.1), tick both on **Active**, then **Create incident**. The incident
   page opens with both alerts.
2. Click **Investigating**: both alerts show *✓ Ack: <you>*.
3. Add a note: it appears at the top of the timeline. **Include alert activity** shows the alerts' own events.
4. Click **Resolved**: it asks for a resolution. Fill it in; the status turns green and *to resolve* shows the time taken.
5. **Automatic grouping:**
   1. Edit two metric rules (e.g. device down and high CPU) and set *Group alerts into incidents →
      one incident per label value*, label `device`.
   2. When both fire for the same device, **one** incident *device X: …* (chip *auto · device=X*)
      contains both alerts.

---

## 15. Settings page

**Where:** **Settings** (administrators).

| Card | Purpose | Section |
|---|---|---|
| GeoIP | download/upload the location databases, lookup | 8.4 |
| Threat intelligence | feeds on/off, your lists, MISP/OTX/AbuseIPDB keys, lookup | 8.5 |
| HTTPS | certificate in use, extra names (**Save names**), **Upload a certificate**, **Download the CA certificate**, **Use KnitSentinel's CA again** | 3 |

---

## 16. Configuration database and secrets

**Where:**
- MySQL 8.4 on 10.10.10.216, database `knitsentinel`, user `sentinel`;
- migrations in `backend/knitsentinel/core/sql/mysql/` (001–017);
- the CLI `knitsentinel-db`.

**How it works:**
- **What it holds:** users, sessions, audit log, devices, profiles, discovery, agents, sources, rules,
  channels, alerts, alert timelines, mutes, maintenance windows, tickets, incidents and saved searches.
- **What it doesn't hold:** logs (OpenSearch) and metrics (VictoriaMetrics).
- **Migrations:** applied automatically when the services start.
- **Secrets:** SNMP credentials, WinRM/cloud keys and channel tokens are encrypted with `KS_SECRET_KEY`
  (Fernet). **Back up `/etc/knitsentinel/knitsentinel.env`**: without the key, the stored secrets can't
  be read.

**How to test** *(on the server)*:
```sh
sudo knitsentinel-db status     # engine, schema version (17), rows per table
mysql -h 10.10.10.216 -u sentinel -p knitsentinel -e "SELECT config FROM alert_channels LIMIT 1"   # secrets start with enc:v1:
```

---

## 17. Operating and monitoring KnitSentinel itself

**Where:** systemd, journald, the ingest metrics endpoint.

```sh
systemctl status knitsentinel-ingest knitsentinel-api knitsentinel-poller knitsentinel-alerter
journalctl -u knitsentinel-ingest -u knitsentinel-api -u knitsentinel-alerter -f     # live service logs
curl -s localhost:8081/metrics | grep -E '^ks_(ingest|queue|flow)'                  # counters
sudo nano /etc/knitsentinel/knitsentinel.env && sudo systemctl restart knitsentinel-ingest knitsentinel-api
```

Useful counters:
- `ks_ingest_received_total` per input;
- `ks_ingest_written_total`;
- `ks_ingest_dropped_total` and `ks_ingest_write_failures_total`;
- `ks_ingest_queue_bytes`;
- `ks_flow_*`;
- `ks_alerts_open{state=…}` (in VictoriaMetrics).

Retention: logs `KS_RETENTION_DAYS` (30, daily indices dropped), metrics `KS_METRICS_RETENTION`
(90d), flows `KS_FLOW_RETENTION_DAYS` (7), resolved alerts 90 days (except alerts in incidents).

---

## 18. Complete test plan (checklist)

Run this after each deployment to 216. Each line takes a minute or two; together they cover every part of the product.

| # | Test | Expected |
|---|---|---|
| 1 | `systemctl status` of all services | all *active (running)*; green dot in the menu |
| 2 | Open https://10.10.10.216:8443 with the CA trusted | no browser warning; http://…:8080 redirects |
| 3 | Sign in; wrong password 5× with a test user | lockout message; after 15 minutes (or a password reset) sign-in works |
| 4 | `logger -n 10.10.10.216 -T "deploy-check $(date +%s)"` | found in Search within seconds |
| 5 | Failed-login line (7.1) | `action:login_failed`, `category:authentication outcome:failure` |
| 6 | `snmptrap` linkDown (7.2) | `source_type:snmp_trap`, `subcategory:link_down` |
| 7 | HTTP ingest with token (7.3), and without | found; 401 without token |
| 8 | Agents page | all agents online; the 216 agent over HTTPS (no *plain HTTP* badge) |
| 9 | Metrics → a device | Up, CPU and interface charts current |
| 10 | Traffic (if a flow exporter is set up) | talkers in the last 15 min; `ks_flow` counters rising |
| 11 | Dashboard 24 h | tiles and charts filled; clicking a tile opens Search |
| 12 | Search: Statistics count by host, Patterns, Map, live tail, context view | each shows data; the live tail shows new lines |
| 13 | Save a search, export CSV | link reopens it; CSV row count = results |
| 14 | Logs alert rule (13.1) with an email/webhook channel | fires, notifies, resolves, notifies resolved |
| 15 | Acknowledge, snooze, maintenance window (13.3) | repeats stop; held then released |
| 16 | Channel **Send test** for each configured channel | ✓ result under the channel name |
| 17 | Create an incident from 2 alerts, move to Investigating, note, resolve (14) | alerts acknowledged; timeline complete; counts update |
| 18 | Settings: GeoIP lookup 8.8.8.8, threat lookup of a listed IP | country shown; feed match shown |
| 19 | `sudo knitsentinel-db status` | schema version 17, no errors |
| 20 | Queue test with OpenSearch stopped (7.12), only in a maintenance window | no events lost |

---

## 19. Automated tests (for developers)

**Backend** (on the development PC, Windows PowerShell):
```powershell
cd C:\Users\Madhurima\Desktop\KnitSentinel\backend
$env:KS_TEST_MYSQL_HOST = (wsl hostname -I).Trim().Split(' ')[0]   # optional: run the MySQL tests (WSL mysql running)
.\.venv\Scripts\python.exe -m pytest -q
```
576 tests as of 2026-10-28, covering:
- parsers, categories and storage;
- every ingest protocol, against real clients where possible;
- SNMP, flows and the agent installers;
- alerts of every kind, handling, channels and incidents;
- HTTPS and the database on both SQLite and MySQL.

**Frontend:**
```powershell
cd C:\Users\Madhurima\Desktop\KnitSentinel\frontend
npx tsc --noEmit -p .        # type check
npm run build                # production build (also done by build-release.sh)
```

**Browser end-to-end tests:**
- **What they are:** Playwright scripts run against a throwaway KnitSentinel stack in WSL
  (http://localhost:8091).
- **Where they are:** in the development scratchpads (e.g. `incidents-flow.js` 32 checks,
  `channels-flow.js` 29, `handling-flow.js` 24, `sidenav-flow.js` 56).
- **What each one does:** signs in, clicks through a feature and checks both the screen and the API.
- **How they run:** on demand during development; they aren't part of the release.

---

## 20. Not built yet

From plan.txt, still open (most important first):
- **Access:** LDAP/Active Directory and SSO (SAML/OIDC) login (item 2), two-factor login, finer roles
  and per-team access, API keys, masking of sensitive data, an audit-log viewer page.
- **Monitoring:**
  - uptime checks: ping, HTTP, TCP, certificate expiry (item 41);
  - per-interface thresholds on SNMP data (item 42);
  - MAC/ARP tables, topology map;
  - APM traces.
- **Parsing:** a dedicated pfSense/OPNsense parser and more vendors (item 14), a grok/regex field
  editor in the UI.
- **Dashboards and reports:** custom dashboards, scheduled PDF/email reports, compliance report packs
  (item 27), NOC wall mode.
- **Response and endpoint:**
  - automatic response (SOAR);
  - file integrity monitoring;
  - vulnerability and CIS checks;
  - software inventory.
- **Operations:** high availability/clustering, per-type retention and archiving, backup/restore from
  the UI, central agent management, a code-signed Windows agent, multi-tenancy, a self-monitoring page.
- **Gaps inside built features:**
  - **Incidents:** a ticket for the whole incident, owner emails, merging, evidence and a report export.
  - **Alerts:** two-way sync with PagerDuty/Jira/ServiceNow, voice calls, assignment emails.
  - **Untested setups:** WEF with a real Windows forwarder, SSH device configuration and the cloud
    collectors with real accounts.
