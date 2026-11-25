# Greenbone Vulnerabilities for Home Assistant

A Home Assistant custom integration that gives you visibility into
[Greenbone Community Edition](https://www.greenbone.net/en/community-edition/)
(OpenVAS) vulnerability scan results, right inside Home Assistant. It talks
directly to `gvmd` over the real **GMP (Greenbone Management Protocol)**, the
same protocol `gvm-tools`/`gvm-cli` and Greenbone's own web UI use internally.

## Features

- Global vulnerability counts by severity: **Critical / High / Medium / Low / Total**
- Vulnerability counts **per scanned host**, created automatically as hosts
  show up in scan results — no manual configuration needed
- Hosts are labeled by their resolved **hostname** when GVM's reverse-DNS
  lookup succeeded during the scan, falling back to the IP otherwise
- Per-host **open ports**, **operating system**, and **applications**
  detected, as sensor attributes (from GVM's service detection and CPE
  inventory results)
- A **Top Critical Vulnerabilities** sensor listing the highest-severity
  findings (name, CVE, CVSS score, host) across every scanned host
- A **Scan Progress** sensor per task (0–100%, with status as an attribute)
- A **Start Scan** button per task, to kick off (or resume) a scan from
  Home Assistant
- A **Refresh Now** button entity to force an immediate update on demand,
  independent of the scan interval
- Scan interval is adjustable from the UI after setup (no YAML editing)

## Why this needs a relay

Greenbone's official Docker Compose deployment only exposes two things to
the network: the web UI (port 443) and gsad's internal HTTP bridge, which is
**not** a general-purpose GMP-over-HTTP API in current GSA versions (it's an
internal, undocumented contract the web frontend itself uses, not meant for
external API clients). The actual GMP protocol `gvmd` speaks is only
reachable via a **unix socket** inside the `gvmd` container, which isn't
reachable from another machine like Home Assistant.

So this integration talks to a small [`socat`](http://www.dest-unreach.org/socat/)
TCP relay running on the Greenbone host, which forwards a plain TCP port
straight to that unix socket. GMP's own username/password authentication
still fully applies — the relay doesn't add or remove any authentication,
it's purely a transport bridge — but the relay itself has **no TLS and no
additional auth layer of its own**, so it must be restricted to trusted
source IPs (the setup script below does this for you, restricting it to your
Home Assistant server's IP specifically).

## Requirements

- A running Greenbone Community Edition deployment via the
  [official Docker Compose setup](https://greenbone.github.io/docs/latest/22.4/container_installation/compose.html)
- Root or sudo access on the Greenbone host, to install the relay (one-time
  setup, see below)
- Network access from your Home Assistant instance to the relay port on the
  Greenbone host (default `9391`)
- A GVM user with read access (the built-in `admin` account works)

## Setup

### 1. Install the relay (on the Greenbone host)

```bash
curl -O https://raw.githubusercontent.com/taikowolfsbane/ha-greenbone/main/scripts/setup-relay.sh
chmod +x setup-relay.sh
sudo ./setup-relay.sh <your-home-assistant-ip>
```

This installs `socat` if needed, auto-detects your `gvmd` container's socket
volume, and sets up a systemd service (`gvmd-gmp-relay.service`) that
survives reboots and restarts automatically if it ever stops. The script
prints the host/port to use in the next step.

Prefer to do it by hand, or need a non-default port? See
[`scripts/setup-relay.sh`](scripts/setup-relay.sh) — it's short and
documents exactly what it does; you can copy the systemd unit it generates
and adjust as needed.

### 2. Install the integration in Home Assistant

#### Via HACS (recommended)

1. In HACS, go to **Integrations → ⋮ → Custom repositories**.
2. Add this repository's URL, category **Integration**.
3. Search for "Greenbone Vulnerabilities" in HACS and install it.
4. Restart Home Assistant.

#### Manual install

1. Copy the `custom_components/greenbone_vulnerabilities` folder from this
   repository into your Home Assistant `config/custom_components/`
   directory, so you end up with
   `config/custom_components/greenbone_vulnerabilities/`.
2. Restart Home Assistant.

### 3. Configure

All configuration happens through the UI — no YAML required.

1. Go to **Settings → Devices & Services → Add Integration**.
2. Search for **Greenbone Vulnerabilities**.
3. Enter:
   - **Host** — the Greenbone host's IP or hostname (e.g. `192.168.1.50`)
   - **Relay port** — whatever you used in step 1 (default `9391`)
   - **Username** / **Password** — your GVM credentials
4. Submit. The integration will test the connection before completing setup,
   and will show an error if it can't reach or authenticate through the
   relay.

### Options (adjustable any time after setup)

From **Settings → Devices & Services → Greenbone Vulnerabilities → Configure**:

| Option | Default | Description |
|---|---|---|
| Scan interval (minutes) | 60 | How often to poll Greenbone. This data doesn't change continuously — hourly is reasonable for most setups; lower it if you want fresher data, at the cost of more frequent queries. |

## Entities created

- `sensor.vulnerabilities_total`
- `sensor.vulnerabilities_critical`
- `sensor.vulnerabilities_high`
- `sensor.vulnerabilities_medium`
- `sensor.vulnerabilities_low`
- `sensor.<host>_total` — one per scanned host, with a critical/high/medium/low
  breakdown, open ports, operating system, and applications all available as
  entity attributes, plus the severity breakdown again as four separate
  per-host sensors (below). These all live on the integration's single
  **Greenbone** device, not a device of their own per host — a home-LAN scan
  can turn up dozens of hosts, and a device-per-host design would mean Home
  Assistant prompting you to name/assign an area for every single one,
  forever, as DHCP leases change. Dashboard tooling (e.g. HACS's
  `auto-entities`) can still target a single host's sensors by their entity
  IDs.
- `sensor.<host>_critical` / `_high` / `_medium` / `_low` — the per-host
  severity breakdown as individual entities
- `sensor.top_critical_vulnerabilities` — count of the highest-severity
  critical/high findings across all scanned hosts; the findings themselves
  (name, CVE, CVSS score, host) are in the `vulnerabilities` attribute as a
  list, since there's no single native entity type for structured records
- `sensor.<task name>_scan_progress` — one per GVM task, 0–100%, with the
  task's status (`Running`/`Done`/`Stopped`/etc.) as an attribute. This is
  still polling-based (GMP has no push/event stream) — set a shorter scan
  interval, or press Refresh Now a few times, for a tighter-grained view
  while a scan is actively running
- `button.<task name>_start_scan` — one per GVM task, starts (or resumes) that
  task's scan; pressing it while already running surfaces GVM's own error as
  a Home Assistant notification
- `button.refresh_now` — forces an immediate refresh of all the above

## On severity buckets

GVM natively only reports High/Medium/Low/Log (no separate "Critical"
bucket — its own web UI doesn't have one either). To keep this integration's
dashboard visually consistent with other severity-bucketed security
integrations, Critical is carved out of the top of GVM's High range
(CVSS ≥ 9.0), with High then covering 7.0–8.9. See
`custom_components/greenbone_vulnerabilities/const.py` if you'd rather use
different cut points.

## License

MIT — see [LICENSE](LICENSE).
