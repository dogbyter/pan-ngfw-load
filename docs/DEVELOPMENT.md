# pan-ngfw-load – development notes

## Code layout

| Path | Purpose |
|---|---|
| `bin/pan-ngfw-load` | launcher; runs `python -m pan_ngfw_load` with the venv next to it |
| `install.sh` | installer (copies files, creates the venv, asks before pip install, OS hints) |
| `pan_ngfw_load/cli.py` | all commands (`init`, `tick`, `logs`, `report`, `tsf`, `prune`, `cron`, ...), locking, logging |
| `pan_ngfw_load/config.py` | INI config: paths, intervals, retention, devices |
| `pan_ngfw_load/wizard.py` | `pan-ngfw-load init` – guided setup |
| `pan_ngfw_load/collect/api.py` | XML API client: key files, TLS fingerprint pinning, **allow-list**, keygen |
| `pan_ngfw_load/collect/core.py` | samples, incremental log export, device info, permission test |
| `pan_ngfw_load/bundle.py` | finds files in a tech support file (safe tgz extraction) |
| `pan_ngfw_load/parsers/` | `cli.py` (CLI dump), `resmon.py` (resource monitor), `powperf.py` (pow performance), `simple.py` (session info, counters, app stats, session list), `monitor.py` (dp-/mp-monitor logs, top), `sar.py`, `live.py` (collector data → same tables as a TSF) |
| `pan_ngfw_load/dataset.py` | builds all tables plus derived ones (interval deltas, rates, coverage); `build()` for TSF, `build_live()` for collector data |
| `pan_ngfw_load/knowledge.py` | **domain mapping**: pow groups to stages, functions to features. Edit when we learn more. |
| `pan_ngfw_load/charts.py` | shared chart style (validated colour palette) and helpers |
| `pan_ngfw_load/report.py` | PDF assembly (reportlab) and the `Ctx` helper used by sections |
| `pan_ngfw_load/sections/` | one module per report chapter, plus `PROFILES` |
| `contrib/` | example config, crontab, systemd units |

A report always uses **one** source: a TSF or the live data of one device. Counters reset at reboot, so mixing sources across a reboot would make the deltas meaningless.

## Adding a focus area

1. Create `pan_ngfw_load/sections/sNN_<name>.py` with `TITLE` (without a number - sections are numbered in the order they appear) and `build(ctx) -> list` (return `[]` if the data is missing or there is nothing to show; the section is then left out).
   - Thresholds: `ctx.settings` (from the config file / command line, see `cli._settings`)
   - Tables: `ctx.ds["table"]`, `ctx.ds.has("table")`, `ctx.ds.meta`, `ctx.ds.source` (`"tsf"`/`"live"`)
   - Output: `ctx.h1/h2/p/small`, `ctx.figure(fig, name, caption)`, `ctx.table(df, widths_cm, fmt=...)`
   - Summary line: `ctx.find("info|notice|warning", "Area", "text")` → also lands in `findings.json`
2. Register it in `pan_ngfw_load/sections/__init__.py` (`SECTIONS` and a profile). Select it with `pan-ngfw-load report -p <profile>` or `-s a,b`.
3. If it needs new raw data:
   - TSF: add a parser in `pan_ngfw_load/parsers/` and wire it up in `dataset.py`.
   - Live: add the **read-only** command to `SAMPLE_CMDS` in `collect/core.py` (it must start with `show`, otherwise the allow-list blocks it) and parse it in `parsers/live.py`.

## Data sources

| Source | Time frame | Notes |
|---|---|---|
| `show running resource-monitor` (TSF and API) | second, minute, hour, day, week (13 weeks max, never before the last boot) | per DP core avg and max. The API reports `0` instead of `*` for pre-boot periods; `dataset._rm_tables` discards those. |
| `debug dataplane pow performance` | accumulated since boot | DP CPU time per group and function; per core in the TSF. Needs a role with Operational Requests (not superreader). |
| `show running application statistics` | since boot | sessions, packets, bytes per app |
| `var/log/pan/dp-monitor.log*` (TSF) | ~2-3 days, every 10 min | resource monitor (15 min), session info, global counters, pow perf |
| `var/log/pan/mp-monitor.log*` (TSF) | ~2-3 days | top, load average, memory |
| `var/log/sa/sarDD` (TSF) | ~30 days, 10 min | Linux CPU. On shared-CPU models (PA-400) the DP cores always show 100% (busy-poll). |
| Traffic / threat logs (API) | as far back as the firewall keeps them | per session: app, rule, zones, hosts, packets, bytes, decrypt/offload flags |

## Testing against a device

```sh
pan-ngfw-load -c /path/test.ini test          # permission matrix
pan-ngfw-load -v sample                       # one sample, verbose
pan-ngfw-load -v logs --since "YYYY/MM/DD HH:MM:SS" --until "..."   # small window
pan-ngfw-load report --days 1
```

## Planned

- Comparing several TSFs or collections of the same device over time.
