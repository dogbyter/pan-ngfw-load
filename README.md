# pan-ngfw-load – PAN-OS load analysis

`pan-ngfw-load` turns a Palo Alto Networks **tech support file (TSF)** into a PDF report: how busy the **dataplane** (DP) and **management plane** (MP) are, **which traffic causes the load**, and whether **single DP cores spike** above the rest. It works completely **offline**: no access to the firewall, no API key, no cron job.

Everything is read from the TSF itself, so you can analyse a file a customer or colleague sent you, on any Linux/macOS host. Reports come out as PDF (with charts), CSV tables and a findings summary (`findings.txt` / `findings.json`).

For long-term monitoring there is also a **live mode**: it samples the firewall over the read-only XML API and exports traffic logs, see [Live mode](#live-mode-optional).

## Analyse a tech support file

### 1. Get the TSF

- GUI: **Device → Support → Generate Tech Support File**, then download it.
- CLI: `scp export tech-support to user@host:/path/`

The file is called like `20250424_1219_techsupport.tgz`. Take it while (or shortly after) the load you want to understand happens - the detailed DP history in a TSF only reaches back about two days.

### 2. Install the TSF analyser

**Download:** the current archive `pan-ngfw-load-<version>.tar.gz` is in [`dist/`](https://github.com/dogbyter/pan-ngfw-load/tree/main/dist), and every version is under [Releases](https://github.com/dogbyter/pan-ngfw-load/releases) (with its SHA-256 in the release notes). The [latest release](https://github.com/dogbyter/pan-ngfw-load/releases/latest) is the same file as `dist/`.

```sh
tar xzf pan-ngfw-load-<version>.tar.gz && cd pan-ngfw-load-<version>
./install.sh --tsf-only
```

This installs only the offline analyser (no live collector, no setup wizard) into `~/.local/share/pan-ngfw-load` with the command `~/.local/bin/pan-ngfw-load`. It needs Python **3.10 or newer** with the `venv` module and asks before installing the Python packages (pandas, matplotlib, reportlab). Package-manager commands per OS: [docs/SETUP.md](docs/SETUP.md#1-system-requirements).

### 3. Run it

```sh
pan-ngfw-load tsf ~/Downloads/20250424_1219_techsupport.tgz
```

The report goes to `~/pan-ngfw-load/reports/<hostname>/tsf_<file>/`:

| File | Content |
|---|---|
| `<hostname>_tsf_<file>.pdf` | the report |
| `findings.txt`, `findings.json` | the summary of findings (info / notice / warning) |
| `charts/*.png` | every chart of the report |
| `data/*.csv` | every table behind the report, for your own analysis |

The findings are also printed in the terminal. The TSF is unpacked once into `~/pan-ngfw-load/data/bundles/` (about 1–1.5 GB per file; delete it when you're done).

### What the report shows

| Section | Answers |
|---|---|
| Summary of findings | the key results on one page, e.g. peak DP load, spiking cores, busiest applications |
| Data coverage | which data the TSF holds and how far back each source reaches |
| Dataplane CPU load | load per DP core: per week, per day, per hour (24 h) and per minute (~2 days), daily profile |
| Core spikes | *only when a core spikes*: which cores run above the others, when, and what changes meanwhile (traffic profile, counters, IPsec, per-core work since boot, busiest tunnels) |
| What consumes dataplane CPU | DP CPU time by processing stage, work group, feature and function - since boot and over time |
| Traffic that drives the load | packets, new sessions and sessions over time, how closely the load follows them, top applications since boot |
| Management plane CPU | MP CPU over 30 days, CPU split, load average |
| Appendix | method and caveats |

### How far back a TSF reaches

| Data in the TSF | Time frame | Detail |
|---|---|---|
| resource monitor | 60 s, 60 min, 24 h, 7 days, 13 weeks | DP load per core (average and max); nothing before the last reboot |
| dp-monitor logs | about 2 days | 10-minute blocks: DP load per minute, packet/session rates, counters, DP CPU per function |
| pow performance | since the last boot | DP CPU time per work group and function, total and per core |
| application statistics | since the last boot | sessions, packets, bytes per application |
| mp-monitor logs | about 2 days | MP load, processes, memory |
| sar | 30 days | MP CPU per core |

So the **longest DP history** is the weekly resource-monitor data (up to 13 weeks, but never before the last reboot), and the **finest** is the per-minute data of the last ~2 days. The *Data coverage* section shows the exact ranges for each file.

### Options

```sh
pan-ngfw-load tsf -a file.tgz                       # anonymized (see below)
pan-ngfw-load tsf file.tgz -o /tmp/reports          # other output directory
pan-ngfw-load tsf file.tgz -p dp                    # DP-only profile (no MP section)
pan-ngfw-load tsf file.tgz -s dp_load,core_spikes   # only these sections
pan-ngfw-load tsf file.tgz --spike-threshold 15 --spike-min-duration 30m
pan-ngfw-load tsf extracted_dir/                    # an already unpacked TSF works too
pan-ngfw-load -h tsf                                # all options
```

**Core spikes:** a core *spikes* while its per-minute load is at least **10 points** above the median of the other DP cores for at least **15 minutes**. Comparing with the other cores, not with a fixed level, separates a real imbalance from a busy but evenly loaded firewall. Both values can be changed per run (above) or in the config file (`spike_threshold`, `spike_min_duration`).

### Anonymized reports (to share)

`-a` / `--anonymize` replaces the device identity in everything the report writes: PDF, CSV tables, findings, file and directory names.

| Replaced | By |
|---|---|
| hostname | `firewall`, or `--alias NAME` |
| serial number | `SERIAL-REDACTED` |
| management IP | `MGMT-IP` |
| the firewall's own interface IPs | `DEVICE-IP-1`, `DEVICE-IP-2`, … |
| TSF file name, unless it's already in the standard form `YYYYMMDD_HHMM_techsupport` | `YYYYMMDD_HHMM_techsupport`: date from the name if it contains one, else the TSF's own time |
| IPsec tunnel names and VPN peer addresses (core-spike section) | removed - only `tunnel.N` is shown |

**Not** replaced: the model (needed to judge the load), other IP addresses (clients, servers), zone, rule and application names. The TSF itself stays untouched. Reports go to `<report_dir>/<alias>/tsf_<date>_techsupport_anon/`.

```sh
pan-ngfw-load tsf -a --alias customer-a 20250424_1219_techsupport.tgz -o /tmp/share
```

## Live mode (optional)

A TSF is a snapshot. For weeks of per-minute history and for traffic logs that name the sessions behind the load, run pan-ngfw-load as a collector:

| | Tech support file | Live mode |
|---|---|---|
| Firewall access | none | read-only XML API (HTTPS 443) |
| Per-minute DP history | ~2 days | as long as you collect (retention configurable) |
| Traffic logs (who causes the load) | no | yes, by app, rule, zone, host; largest sessions during core spikes |
| Setup | `install.sh --tsf-only` | `install.sh`, `pan-ngfw-load init`, cron |

On the firewall, pan-ngfw-load only *reads*. It sends `show …` commands, `debug dataplane pow performance` and log queries, and nothing else. A built-in allow-list blocks everything else before it leaves the host.

```sh
# 1. full install (TSF analyser + live collector); it asks before installing Python packages
./install.sh

# 2. guided setup: paths, firewall, admin role + admin, API key, TLS pinning, permission test, cron
pan-ngfw-load init

# 3. check
pan-ngfw-load status
pan-ngfw-load test
```

`pan-ngfw-load init` can install the cron jobs. After that everything runs unattended:

| When | Command | Does |
|---|---|---|
| every minute | `pan-ngfw-load tick` | takes a sample for each firewall whose interval has passed (default **5 min**, `sample_interval` in the config) |
| hourly | `pan-ngfw-load logs` | exports new traffic logs (incremental) |
| daily 06:15 | `pan-ngfw-load report && pan-ngfw-load prune` | report for the last 7 days into `report_dir/<device>/latest/`, then retention clean-up |

`pan-ngfw-load cron` prints the block and `pan-ngfw-load cron --install` installs it. For systemd timers see `contrib/systemd/`. Live reports have the same sections as TSF reports plus *Traffic logs - who generates the load*, and `-a` works the same way.

Live-mode requirements: cron (or systemd timers), HTTPS from this host to the firewall's management IP, one admin account with a restricted role (`pan-ngfw-load init` explains it), and about 4 MB/day of samples plus ~3 MB/day of traffic logs per firewall (at ~6,000 logs/h).

```sh
pan-ngfw-load report                    # report now (last report_days, default 7)
pan-ngfw-load report --days 30          # longer window
pan-ngfw-load logs --since "2026/10/01 00:00:00"   # back-fill older logs
pan-ngfw-load info                      # firewall version, how far back logs reach
pan-ngfw-load sample                    # one sample now
pan-ngfw-load prune -n                  # show what retention would delete
```

## Where things are

| What | Default | Config key |
|---|---|---|
| Configuration (optional for TSF analysis) | `~/.config/pan-ngfw-load/pan-ngfw-load.ini` (or `$PAN_NGFW_LOAD_CONFIG`) | – |
| Reports | `~/pan-ngfw-load/reports/<device>/…`, live: `latest` → newest | `report_dir` |
| Unpacked TSFs, samples, logs, state, `pan-ngfw-load.log` | `~/pan-ngfw-load/data/` | `data_dir` |
| API keys, pinned TLS fingerprints (live only) | `~/.config/pan-ngfw-load/keys/` (700/600) | `secrets_dir` |

## More

- **[docs/SETUP.md](docs/SETUP.md)**: requirements per OS, installation (also offline and system-wide), admin role design, security notes, cron/systemd, configuration reference, troubleshooting, uninstall.
- **[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)**: code layout, data sources, how to add a report section.

## License and disclaimer

MIT - see [LICENSE](LICENSE).

pan-ngfw-load is an independent project. It is not affiliated with, endorsed by or supported by Palo Alto Networks. "Palo Alto Networks" and "PAN-OS" are trademarks of Palo Alto Networks, Inc. The meaning of internal counters and dataplane functions is inferred from their names and observed behaviour, not from vendor documentation.
