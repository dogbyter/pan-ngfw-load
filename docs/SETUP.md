# pan-ngfw-load – setup guide for administrators

1. [System requirements](#1-system-requirements)
2. [Installation](#2-installation)
3. [Firewall preparation: role and admin](#3-firewall-preparation-role-and-admin)
4. [pan-ngfw-load init, step by step](#4-pan-ngfw-load-init-step-by-step)
5. [Unattended operation: cron or systemd](#5-unattended-operation-cron-or-systemd)
6. [Configuration reference](#6-configuration-reference)
7. [Security notes](#7-security-notes)
8. [Troubleshooting](#8-troubleshooting)
9. [Uninstall](#9-uninstall)

---

## 1. System requirements

| Component | Needed | Why |
|---|---|---|
| OS | Linux or another Unix. Tested on Ubuntu 22.04; the others below are expected to work. | – |
| Python | **3.10 or newer**, with the `venv` module | runtime |
| Python packages | `pandas`, `matplotlib`, `reportlab` (and their dependencies, e.g. numpy) | analysis, charts, PDF. Installed by `install.sh` into a private venv, not system-wide. |
| cron *or* systemd | `cron`/`cronie`, or systemd user timers | unattended sampling, log export, reports (not needed for `--tsf-only`) |
| Network | HTTPS 443 → firewall management IP. During install: `pypi.org`, `files.pythonhosted.org` (or offline wheels). | – |
| Disk | ~4 MB/day of samples + ~3 MB/day of traffic logs per firewall (PA-440, ~6,000 logs/h; scales with log rate), plus ~1 MB per report | retention defaults: 35 / 90 / 180 days |
| Fonts | none extra (matplotlib ships DejaVu Sans) | – |

Check what you have: `python3 -V` (must be ≥ 3.10), `python3 -m venv --help`, `command -v crontab`.

### Packages per OS

| OS | Install | Then |
|---|---|---|
| **Ubuntu 22.04 / 24.04**, Debian 12, Raspberry Pi OS 12 | `sudo apt install python3 python3-venv cron` | `./install.sh` |
| **Ubuntu 20.04** | `sudo add-apt-repository ppa:deadsnakes/ppa && sudo apt update`<br>`sudo apt install python3.11 python3.11-venv cron` | `PYTHON=python3.11 ./install.sh` |
| **Debian 10 / 11** | Python < 3.10 in the base system: upgrade to Debian 12, or build Python with [pyenv](https://github.com/pyenv/pyenv) | `PYTHON=~/.pyenv/shims/python3.11 ./install.sh` |
| **RHEL / Rocky / Alma 9**, RHEL 8.8+ | `sudo dnf install python3.11 cronie`<br>`sudo systemctl enable --now crond` | `PYTHON=python3.11 ./install.sh` |
| **Fedora** | `sudo dnf install python3 cronie`<br>`sudo systemctl enable --now crond` | `./install.sh` |
| **openSUSE Leap 15.x / SLES 15** | `sudo zypper install python311 cron` | `PYTHON=python3.11 ./install.sh` |
| **openSUSE Tumbleweed** | `sudo zypper install python3 cron` | `./install.sh` |
| **Arch / Manjaro** | `sudo pacman -S python cronie`<br>`sudo systemctl enable --now cronie` | `./install.sh` |
| **Alpine** | `sudo apk add python3 py3-pip cronie build-base`<br>`sudo rc-update add cronie && sudo rc-service cronie start` | `./install.sh` (build-base in case a wheel has to compile on musl) |
| **Gentoo** | `sudo emerge dev-lang/python sys-process/cronie` | `./install.sh` |
| **macOS** (Homebrew) | `brew install python@3.12` (cron is built in; launchd works too) | `PYTHON=python3.12 ./install.sh` |
| **FreeBSD** | `sudo pkg install python311 py311-sqlite3` (cron is built in) | `PYTHON=python3.11 ./install.sh` |

If something is missing, `install.sh` detects the OS from `/etc/os-release` and prints the matching line.

**No root rights?** If only `python3-venv` is missing, `install.sh` can create the venv without pip and bootstrap pip from `https://bootstrap.pypa.io/get-pip.py`. It downloads with Python itself (no curl needed) and asks first. A broken or half-finished venv from an earlier run is detected and repaired automatically.

## 2. Installation

```sh
tar xzf pan-ngfw-load-<version>.tar.gz && cd pan-ngfw-load-<version>
./install.sh                 # per user: ~/.local/share/pan-ngfw-load, command ~/.local/bin/pan-ngfw-load
```

`install.sh` copies the files, creates `<prefix>/.venv`, **shows the Python packages and asks** before installing them (`--yes` skips the question), and links `pan-ngfw-load` into the bin directory. Nothing else on the system is changed.

**TSF analyser only:** `./install.sh --tsf-only` installs just the offline analysis of tech support files. The live collector, setup wizard and cron/systemd examples are left out, and only the `tsf` command is offered. It needs no firewall admin, API key, cron or network access to firewalls, and no config file (defaults: reports in `~/pan-ngfw-load/reports`, or `-o DIR`). The Python requirements are the same. Running `./install.sh` again without the option upgrades to the full installation; with it, it goes back to TSF-only. Config and reports are kept either way.

**System-wide, with a dedicated user** (recommended for servers):
```sh
sudo useradd --system --create-home --home-dir /var/lib/pan-ngfw-load --shell /usr/sbin/nologin pan-ngfw-load
sudo ./install.sh --prefix /opt/pan-ngfw-load --bindir /usr/local/bin
sudo -u pan-ngfw-load -H pan-ngfw-load init        # config, keys and data end up under /var/lib/pan-ngfw-load (the user's HOME)
sudo -u pan-ngfw-load -H pan-ngfw-load cron --install
```

**Offline / air-gapped host:** on a machine with internet access and the *same* OS and Python version:
```sh
python3 -m pip download -r requirements.txt -d wheels/
```
Copy `wheels/` along, then on the target:
```sh
./install.sh            # answer "n" when asked to install the packages
~/.local/share/pan-ngfw-load/.venv/bin/python -m pip install --no-index --find-links wheels/ -r ~/.local/share/pan-ngfw-load/requirements.txt
```

**Update:** unpack the new version and run `./install.sh` again. Config, keys and data are kept, because they don't live in the prefix.

## 3. Firewall preparation: role and admin

`pan-ngfw-load init` prints these instructions when they're needed. They're here for review in advance.

PAN-OS can't restrict API access to individual commands. The useful XML API permissions are:

| XML API permission | Needed for | Also allows (and why that matters) |
|---|---|---|
| **Operational Requests** | `show …` commands, `debug dataplane pow performance` | all op commands, including `request restart`, `clear session`. pan-ngfw-load never sends those (allow-list), so **protect the key file**. |
| **Log** | traffic/threat log export | reading logs |
| Configuration, Commit, Import, Export, Report, User-ID, IoT | **not needed** – keep disabled | – |

### Layout A (recommended): one admin with a custom role

*Device → Admin Roles → Add* (on a Panorama-managed firewall: locally on the firewall, or in the template plus a push)

| Field | Value |
|---|---|
| Name | `pan-ngfw-load-collector` |
| Role | Device |
| Web UI | disable everything |
| XML API | **only** Operational Requests + Log |
| REST API | disable everything |
| Command Line | None |

*Device → Administrators → Add*: name `pan-ngfw-load-collector`, Authentication Profile **None**, password (used once), Administrator Type **Role Based** → profile `pan-ngfw-load-collector`. Commit.

Result: live samples **with** the DP breakdown by stage and function. The admin can't read or change the configuration and can't commit (`pan-ngfw-load test` verifies the first part).

### Layout B: strictly read-only admin, optionally plus a "diag" admin

- `pan-ngfw-load-readonly`: Administrator Type **Dynamic → Superuser (read-only)**. The device itself enforces read-only, but this admin **can read the whole configuration**, including password hashes. Without debug rights there's no live DP breakdown; tech support files still have it.
- Optional `pan-ngfw-load-diag` with the custom role from layout A. pan-ngfw-load uses it only for `pow performance`.

### Recommended for both

- Restrict management access to the pan-ngfw-load host: *Device → Setup → Interfaces → Management → Permitted IP Addresses* (or the interface management profile).
- Use a long random password. It's needed only once, to generate the API key.

**Known issue:** on **PAN-OS 11.2.6** no newly created admin could log in ("Authentication profile not found for the user" in the system log); only the pre-existing `admin` worked. Upgrading (here to 11.2.13-h3) fixed it.

## 4. pan-ngfw-load init, step by step

| Step | What happens | Changes |
|---|---|---|
| 1 Paths | asks for data/report/secrets directories, sample interval (default 5m, minimum 60s), report window, log types, retention | writes the config at the end of step 3 |
| 2 Firewall | asks for name and management IP, reads the TLS certificate fingerprint and shows it with an `openssl` command for independent verification. You confirm it. | pins the fingerprint in `secrets_dir` |
| 3 Role/admin | explains layouts A/B and shows the exact settings. You create role and admin, then press Enter. pan-ngfw-load asks for the password **once** (not echoed), requests an API key over the pinned connection and stores **only the key** (mode 600). | key file, config file |
| 4 Test | checks: show and logs must work, config reads must be **denied** by the firewall itself (layout A). The config probes deliberately bypass the allow-list; their content is discarded. | – |
| 5 First sample | `show system info`, how far back logs reach, one sample | data directory |
| 6 Cron | shows the crontab block and installs it on request | your crontab (marked block) |

Re-run it at any time: `pan-ngfw-load init --device <name>` keeps existing values as defaults. Use it to renew a key, for example after a password change.

## 5. Unattended operation: cron or systemd

```cron
# >>> pan-ngfw-load >>>
* * * * *   PAN_NGFW_LOAD_CONFIG=... pan-ngfw-load tick   >/dev/null 2>&1   # samples devices that are due (interval in config)
7 * * * *   PAN_NGFW_LOAD_CONFIG=... pan-ngfw-load logs   >/dev/null 2>&1   # incremental log export
15 6 * * *  PAN_NGFW_LOAD_CONFIG=... pan-ngfw-load report >/dev/null 2>&1 && PAN_NGFW_LOAD_CONFIG=... pan-ngfw-load prune >/dev/null 2>&1
# <<< pan-ngfw-load <<<
```

- `pan-ngfw-load cron` prints the block with real paths, `pan-ngfw-load cron --install` adds or replaces it, and `pan-ngfw-load cron --remove` removes it. Other crontab lines are left alone.
- The **sample interval is not set in cron.** `tick` runs every minute and samples a device only when its `sample_interval` has passed, so each device can have its own interval.
- Overlapping runs are skipped through per-device lock files, so a slow log export never piles up.
- All output goes to `<data_dir>/pan-ngfw-load.log` (rotated, 3 × 5 MB).
- **systemd** instead of cron: see `contrib/systemd/README` (user timers, `loginctl enable-linger`).

## 6. Configuration reference

`~/.config/pan-ngfw-load/pan-ngfw-load.ini` (or `$PAN_NGFW_LOAD_CONFIG`, or `pan-ngfw-load -c FILE`). Durations: `300`, `300s`, `5m`, `24h`, `7d`. Full example: `contrib/pan-ngfw-load.ini.example`.

| Key | Default | Meaning |
|---|---|---|
| `data_dir` | `~/pan-ngfw-load/data` | samples, logs, extracted TSFs, state, `pan-ngfw-load.log` |
| `report_dir` | `~/pan-ngfw-load/reports` | `<device>/<YYYYMMDD_HHMM>_live_<N>d/` and `<host>/tsf_<bundle>/`; `latest` link |
| `secrets_dir` | `~/.config/pan-ngfw-load/keys` | `<key>.key`, `<key>.fingerprint` |
| `sample_interval` | `5m` | default for all devices; per device `[device X] sample_interval` |
| `report_days` | `7` | window of `pan-ngfw-load report` |
| `log_types` | `traffic` | `traffic`, `threat` |
| `log_initial` | `1d` | how far the first incremental export looks back |
| `retain_samples` / `retain_logs` / `retain_reports` | `35d` / `90d` / `180d` | deleted by `pan-ngfw-load prune` (TSF reports are kept) |
| `spike_threshold` | `10` | a core *spikes* while its load is this many points above the median of the other DP cores; per run: `--spike-threshold` |
| `spike_min_duration` | `15m` | ... for at least this long (dips under 5 min are bridged); per run: `--spike-min-duration` |
| `[device NAME] host` | – | management IP/FQDN |
| `[device NAME] key` | NAME | key file name in `secrets_dir` |
| `[device NAME] diag_key` | – | key allowed to run pow performance (layout A: same as `key`) |

Report contents: `*.pdf`, `charts/*.png`, `data/*.csv` (every table behind the report), `findings.txt` and `findings.json` (for monitoring or scripts).

## 7. Security notes

- **Sharing reports:** use `-a` / `--anonymize` (see README, "Anonymized reports"). It replaces hostname, serial number, the device's own IPs and a non-standard TSF file name everywhere in the output, and drops IPsec tunnel names and VPN peer addresses. In live reports only the management IP is known, because interface IPs come from a TSF. Client/server IPs, zone, rule and application names are kept.

- **Only reads leave the host.** `pan_ngfw_load/collect/api.py` allows op commands starting with `<show>`, the one command `debug dataplane pow performance all`, and log queries. Everything else raises an error before it's sent.
- **API keys** are equivalent to the admin's rights. Store them only in `secrets_dir` (700/600). Never print or log them. `pan-ngfw-load` doesn't.
- **TLS pinning:** a changed firewall certificate stops all communication until you re-run `pan-ngfw-load init` and confirm the new fingerprint.
- **The password** is only used for key generation and isn't stored. **Changing the admin's password invalidates its API key** (observed on PAN-OS 11.2.13: every request then gets HTTP 403). After a password change, re-run `pan-ngfw-load init --device <name>` to create a new key.
- **Collected data** (logs with IP addresses, hostnames, rule names) is sensitive. Keep `data_dir`/`report_dir` access restricted; pan-ngfw-load creates files with umask 027.

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `HTTP 403` on every request | The key is invalid: the admin's password was changed (this invalidates the key), or the admin was deleted or renamed. Fix: `pan-ngfw-load init --device X`. |
| `HTTP 403` only for `pow performance` | Expected with a read-only (superreader) key. Use layout A or a diag admin. |
| `TLS certificate ... changed` | Certificate replaced on the firewall, or interception. Verify, then `pan-ngfw-load init --device X`. |
| `blocked by local allow-list` | A request other than show/pow/log was attempted. That's intentional. |
| Login works for `admin` only, new admins fail with "Authentication profile not found" | PAN-OS 11.2.6 bug, see section 3. Upgrade. |
| Template admin from Panorama can't log in | Check `show config merged` on the firewall. On affected versions create the admin locally. |
| No samples | `pan-ngfw-load status` (last sample), `tail <data_dir>/pan-ngfw-load.log`, `crontab -l` (block present?), cron running (`systemctl status cron`/`crond`)? |
| `more than 5000 ... logs in one second` | Extremely high log rate. Some logs in that second may be missing; narrow `--since/--until` or add `--filter`. |
| Report shows "0 days" / few charts | Not enough data yet. Several samples are needed for rates; the DP breakdown needs the diag key. |
| Crontab lines point to the extracted source folder instead of the installed copy | Bug in 0.3.1 and older when `pan-ngfw-load` was run from inside the extracted folder and `~/.local/bin` wasn't in `PATH`. Fixed in 0.3.2: update, then run `pan-ngfw-load cron --install` (replaces the block). |
| `Python 3.10+ required` | See [packages per OS](#packages-per-os); `PYTHON=python3.11 ./install.sh`. |

## 9. Uninstall

```sh
pan-ngfw-load cron --remove
rm -rf ~/.local/share/pan-ngfw-load ~/.local/bin/pan-ngfw-load
rm -rf ~/.config/pan-ngfw-load ~/pan-ngfw-load          # config, keys, data, reports - only if no longer needed
```
On the firewall, delete the admin and the role, then commit.
