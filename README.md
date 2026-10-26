# pan-ngfw-load – PAN-OS load analysis

`pan-ngfw-load` shows how busy a Palo Alto Networks firewall's **dataplane** (DP) and **management plane** are, and **which traffic causes the load**. Reports come out as PDF (with charts), CSV tables and a findings summary (`findings.txt` / `findings.json`).

It works with two data sources:

| Source | How | What you get |
|---|---|---|
| **Tech support file** (offline) | `pan-ngfw-load tsf <file.tgz>` | Up to ~4 weeks of DP load history (since the last reboot), DP CPU time per processing stage and function, 30 days of management-plane CPU, application totals |
| **Live, via XML API** | `pan-ngfw-load init`, then cron | Samples every 5 min (configurable), traffic/threat logs for attribution by app, rule, zone and host, plus daily reports |

On the firewall, pan-ngfw-load only *reads*. It sends `show …` commands, `debug dataplane pow performance` and log queries, and nothing else. A built-in allow-list blocks everything else before it leaves the host.

## Requirements (short)

- Linux or another Unix (tested on Ubuntu 22.04). Python **3.10 or newer** with the `venv` module, plus `cron` (or systemd timers).
- HTTPS (443) from this host to the firewall's management IP.
- Internet access to PyPI during installation, or an offline wheel bundle.
- For live mode: one admin account on the firewall with a restricted role. `pan-ngfw-load init` explains how to set it up.
- Disk space: about 4 MB/day of samples and about 3 MB/day of traffic logs per firewall (PA-440 at ~6,000 logs/h).

Package-manager commands for each OS are in **[docs/SETUP.md](docs/SETUP.md#1-system-requirements)**. `install.sh` detects the OS and prints the right command if something is missing.

## Quick start

```sh
# 1. install (per user: ~/.local/share/pan-ngfw-load + ~/.local/bin/pan-ngfw-load; it asks before installing Python packages)
./install.sh
#    only the tech support file analyser (no live collector, no firewall access, no cron):
#    ./install.sh --tsf-only      -> then only step 2 applies

# 2. offline: analyse a tech support file right away
pan-ngfw-load tsf ~/Downloads/20250424_1219_techsupport.tgz
#    -> ~/pan-ngfw-load/reports/<hostname>/tsf_<file>/  (PDF, charts/, data/, findings.txt)

# 3. live: guided setup (paths, firewall, admin role + admin, API key, permission test, cron)
pan-ngfw-load init

# 4. check
pan-ngfw-load status
pan-ngfw-load test
```

`pan-ngfw-load init` can install the cron jobs. After that everything runs unattended:

| When | Command | Does |
|---|---|---|
| every minute | `pan-ngfw-load tick` | takes a sample for each firewall whose interval has passed (default **5 min**, `sample_interval` in the config) |
| hourly | `pan-ngfw-load logs` | exports new traffic logs (incremental) |
| daily 06:15 | `pan-ngfw-load report && pan-ngfw-load prune` | report for the last 7 days into `report_dir/<device>/latest/`, then retention clean-up |

`pan-ngfw-load cron` prints the block and `pan-ngfw-load cron --install` installs it. For systemd timers see `contrib/systemd/`.

## Everyday commands

```sh
pan-ngfw-load report                    # report now (last report_days, default 7)
pan-ngfw-load report --days 30          # longer window
pan-ngfw-load logs --since "2026/10/01 00:00:00"   # back-fill older logs
pan-ngfw-load info                      # firewall version, how far back logs reach
pan-ngfw-load sample                    # one sample now
pan-ngfw-load prune -n                  # show what retention would delete
pan-ngfw-load tsf -a file.tgz           # anonymized report (to share with others, see below)
pan-ngfw-load -h                        # all commands
pan-ngfw-load -h report                 # options of one command
```

## Anonymized reports

`-a` / `--anonymize` (for `tsf` and `report`) replaces the device identity in everything the report writes: PDF, CSV tables, findings, file and directory names.

| Replaced | By |
|---|---|
| hostname | `firewall`, or `--alias NAME` |
| serial number | `SERIAL-REDACTED` |
| management IP | `MGMT-IP` |
| the firewall's own interface IPs (from the TSF) | `DEVICE-IP-1`, `DEVICE-IP-2`, … |
| TSF file name, unless it's already in the standard form `YYYYMMDD_HHMM_techsupport` | `YYYYMMDD_HHMM_techsupport`: date from the name if it contains one, else the TSF's own time |
| IPsec tunnel names and VPN peer addresses (core-spike section) | removed - only `tunnel.N` is shown |

**Not** replaced: the model (needed to judge the load), other IP addresses (clients, servers), zone, rule and application names. The input data (TSF, collected data) stays untouched. Reports go to `<report_dir>/<alias>/…_anon/`.

```sh
pan-ngfw-load tsf -a --alias customer-a ts.tgz -o /tmp/share
```

## Where things are

| What | Default | Config key |
|---|---|---|
| Configuration | `~/.config/pan-ngfw-load/pan-ngfw-load.ini` (or `$PAN_NGFW_LOAD_CONFIG`) | – |
| Reports | `~/pan-ngfw-load/reports/<device>/<timestamp>/`, `latest` → newest | `report_dir` |
| Raw data, logs, state, `pan-ngfw-load.log` | `~/pan-ngfw-load/data/` | `data_dir` |
| API keys, pinned TLS fingerprints | `~/.config/pan-ngfw-load/keys/` (700/600) | `secrets_dir` |

## More

- **[docs/SETUP.md](docs/SETUP.md)**: requirements per OS, installation (also offline and system-wide), admin role design, security notes, cron/systemd, troubleshooting, uninstall.
- **[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)**: code layout, data sources, how to add a report section.

## License and disclaimer

MIT - see [LICENSE](LICENSE).

pan-ngfw-load is an independent project. It is not affiliated with, endorsed by or supported by Palo Alto Networks. "Palo Alto Networks" and "PAN-OS" are trademarks of Palo Alto Networks, Inc. The meaning of internal counters and dataplane functions is inferred from their names and observed behaviour, not from vendor documentation.
