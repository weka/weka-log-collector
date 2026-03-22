# weka-log-collector

A standalone diagnostic log collector for [Weka](https://www.weka.io/) clusters.

Drop a single binary on any Weka node and collect a comprehensive, compressed archive of logs and diagnostics — from one node or the entire cluster — in seconds.

---

## Why this tool?

For most support cases, `weka diags` is your starting point. This tool is a complement for situations where you need more targeted or flexible log collection.

- **Profile-based collection** — gather only what's relevant: default, full, perf, NFS, S3, SMB-W, client, or all
- **Time-windowed journalctl** — scope `journalctl` to an incident window with `--from`/`--to`; all log files collected in full
- **Full container log coverage** — all container log trees collected including rotated variants
- **Cluster-wide in one shot** — auto-deploys itself to each node via SCP, collects in parallel, merges into a single archive
- **IP-based node discovery** — uses node IPs directly, no DNS required
- **Space-safe** — checks available disk before writing; aborts with a clear error if space is insufficient
- **No upload** — produces a local `.tar.gz` you control; stream to stdout with `--output -` if needed

---

## Quick start

### Single node

```bash
# Copy to the node
scp weka-log-collector root@<node-ip>:/usr/local/bin/weka-log-collector

# Run locally on that node
weka-log-collector --local
# → /tmp/<hostname>-weka-logs-<timestamp>.tar.gz
```

### Entire cluster (run from any backend node)

```bash
# Run from any backend node — binary is auto-deployed to /tmp on each node
weka-log-collector
# → /tmp/<cluster>-weka-logs-<timestamp>.tar.gz
```

The tool automatically SCPs itself to `/tmp/weka-log-collector` on each remote host before collecting, then removes it when done. No manual pre-deployment required.

```bash
# If you prefer to pre-deploy manually (e.g. binary already on all nodes):
weka-log-collector --no-self-deploy --remote-binary /usr/local/bin/weka-log-collector
```

### Time-windowed collection (journalctl only)

```bash
# Collect journalctl for last 2 hours; file logs are always collected in full
weka-log-collector --local --from -2h

# Specific window
weka-log-collector --local --from 2026-03-20T14:00 --to 2026-03-20T16:00
```

---

## Installation

Pre-built Linux binary (static, no dependencies):

```bash
# Build from source
git clone https://github.com/manmeet-weka/weka-log-collector
cd weka-log-collector
task build-linux          # produces weka-log-collector_linux_amd64
```

Or on macOS for local testing:
```bash
task build                # native binary
```

See [Developer Guide](#developer-guide) for build toolchain setup.

---

## Usage

```
Usage: weka-log-collector [flags]

Flags:
  --local            Collect from local host only (no SSH, no cluster discovery)
  --profile          Collection profile: default|full|perf|nfs|s3|smbw|client|all  (default: default)
  --from             Start of time window for journalctl (e.g. -2h, -30m, -1d, 2026-03-20T14:00)
  --to               End of time window for journalctl (default: now)
  --output           Output .tar.gz path (default: /tmp/<hostname>-weka-logs-<ts>.tar.gz). Use - for stdout.
  --host             Collect from this host only (repeatable; default: auto-discover all cluster nodes)
  --no-self-deploy   Skip auto-deployment; use --remote-binary path on remote hosts instead
  --remote-binary    Path to binary on remote hosts when using --no-self-deploy (default: /usr/local/bin/weka-log-collector)
  --ssh-user         SSH user for remote collection (default: root)
  --workers          Max parallel SSH workers (default: 10)
  --max-size         Abort if estimated size exceeds this MB (default: 2048)
  --cmd-timeout      Timeout per command (default: 60s)
  --dry-run          Show what would be collected without collecting
  --verbose          Print detailed progress for every file and command
  --version          Print version and exit
```

### Examples

```bash
# Local only, default profile
weka-log-collector --local

# Local, verbose, last 2 hours of journal
weka-log-collector --local --from -2h --verbose

# Full profile (includes extra logs, journalctl, cfgdump)
weka-log-collector --local --profile full

# S3 profile (adds S3/envoy logs and weka s3 commands)
weka-log-collector --local --profile s3

# SMBW profile (adds SMBW/pacemaker/corosync logs and weka smb commands)
weka-log-collector --local --profile smbw

# Cluster-wide, custom output path
weka-log-collector --output /data/weka-diags.tar.gz

# Specific hosts by IP
weka-log-collector --host 10.0.0.1 --host 10.0.0.2 --host 10.0.0.3

# Stream to stdout (for piping or remote capture)
weka-log-collector --local --output - | ssh admin@bastion "cat > /data/weka-logs.tar.gz"

# Dry run — show estimated size and what would be collected
weka-log-collector --dry-run
```

---

## Collection profiles

| Profile | What's included |
|---------|----------------|
| `default` | Weka CLI status commands + all system/container logs |
| `full` | + extra weka commands (events, cfgdump, hw info) + full journalctl |
| `perf` | + performance stats (CPU, SSD, ops, network, JRPC, latency) |
| `nfs` | + NFS/Ganesha commands and ganesha container logs |
| `s3` | + S3/envoy commands and S3 container logs |
| `smbw` | + SMB-W commands and smbw/pacemaker/corosync logs |
| `client` | + client NIC/OFED/routing info |
| `all` | Everything from all profiles |

---

## What gets collected

### System commands (always)

| Output file | Command |
|-------------|---------|
| `system/uname.txt` | `uname -a` |
| `system/os_release.txt` | `cat /etc/*release*` |
| `system/hostname.txt` | `hostname -f` |
| `system/uptime.txt` | `uptime` |
| `system/free_mem.txt` | `free -h` |
| `system/lscpu.txt` | `lscpu` |
| `system/ip_addr.txt` | `ip addr show` |
| `system/ip_route.txt` | `ip route` |
| `system/netstat_all.txt` | `netstat -nap` |
| `system/ps_elf.txt` | `ps -elf` |
| `system/df_h.txt` | `df -h` |
| `system/lspci.txt` | `lspci` |
| `system/lsblk.txt` | `lsblk -d` |
| `system/sysctl_conf.txt` | `cat /etc/sysctl.conf` |
| `system/dmesg.txt` | `dmesg -T` |
| `system/journalctl_weka_agent.txt` | `journalctl -u weka-agent --no-pager -n 50000` |
| `system/journalctl_weka_agent_verbose.txt` | `journalctl -xu weka-agent --no-pager -n 10000` |
| `system/journalctl.txt` | `journalctl` (time-windowed via `--from`/`--to`; full profile or when `--from` is set) |

### Weka CLI commands (always, default profile)

Weka status, cluster topology, filesystems, snapshots, debug traces, and local container resources. See `defaultCommands` in `main.go` for the full list.

### System log files (always, all rotated variants)

| Pattern | Notes |
|---------|-------|
| `/var/log/messages*` | RHEL/OCI/Rocky — rotated as `messages-YYYYMMDD` |
| `/var/log/secure*` | SSH/auth events, rotated |
| `/var/log/cron*` | Cron job log, rotated |
| `/var/log/syslog*` | Debian/Ubuntu |
| `/var/log/kern.log*` | Kernel log (Debian/Ubuntu) |
| `/var/log/boot.log*` | Boot log |
| `/var/log/dmesg*` | Kernel ring buffer saved to file |
| `/var/log/cloud-init.log` | Cloud-init log (OCI/AWS) |
| `/var/log/cloud-init-output.log` | Cloud-init console output |
| `/var/log/audit/audit.log*` | Linux audit log |
| `/var/log/dnf.log*` | DNF package manager log |
| `/var/log/yum.log*` | YUM package manager log |

### Weka container log files (always, all rotated variants)

All files collected from `/opt/weka/logs/` with two depth-level globs:

**Depth 1** — files directly in each container directory (`compute0/`, `drives0/`, `frontend0/`, `smbw/`, `default/`, etc.):
- `syslog.log*` — container syslog
- `supervisord.log*` — process supervisor
- `tsmb.log*` — TSMB (SMB-W)
- `config_fixer.log` — SMB-W config fixer
- `cluster-aliveness-*.log*` — cluster health
- `jrpcserver-*.log*` — JRPC server
- `upgrade.log*` — upgrade log
- `upgrade_report_*.json` — upgrade report
- All other `*.log*` and `*.json` files

**Depth 2** — files in subdirectories (`weka/`, `wtracer/`, `nginx/`, `pacemaker/`, `corosync/`, `pcsd/`):
- `weka/output.log*` — main weka process output
- `weka/shelld.log*` — shell daemon
- `weka/trace-server.log*` — trace server
- `weka/events.log*` — weka events
- `weka/nginx-stdout.log*` + `weka/nginx-stderr.log*` — nginx
- `weka/rotator.log*` — log rotator
- `weka/supervisord.log` — supervisord under weka/
- `weka/api-v2-stdout.log*` + `weka/api-v2-stderr.log` — REST API
- `weka/weka_init.log*` — container init
- `wtracer/wtracer-dumper.log` — wtracer state
- `nginx/access.log`, `nginx/error.log` — nginx (drives0)
- `pacemaker/pacemaker.log*` — pacemaker cluster (smbw)
- `corosync/corosync.log` — corosync cluster (smbw)
- `pcsd/pcsd.log` — pcsd cluster daemon (smbw)

### Vendor/driver logs

- `/var/log/mlnx/*.log*` — Mellanox OFED driver logs
- `/opt/weka/data/driver/weka-driver/log/*.log` — Weka kernel driver build logs

---

## Archive layout

```
<cluster>-weka-logs-<timestamp>.tar.gz
└── <cluster>-weka-logs-<timestamp>/
    ├── hosts/
    │   ├── <hostname-or-ip>/
    │   │   ├── system/
    │   │   │   ├── uname.txt
    │   │   │   ├── dmesg.txt
    │   │   │   ├── journalctl.txt
    │   │   │   ├── journalctl_weka_agent.txt
    │   │   │   ├── messages          (← from /var/log/messages)
    │   │   │   ├── messages-20260301 (← rotated)
    │   │   │   ├── audit/
    │   │   │   │   └── audit.log
    │   │   │   └── ...
    │   │   ├── weka/
    │   │   │   ├── weka_status.txt
    │   │   │   ├── weka_alerts.txt
    │   │   │   └── ...
    │   │   ├── weka/containers/
    │   │   │   ├── compute0/
    │   │   │   │   ├── syslog.log
    │   │   │   │   ├── syslog.log.1
    │   │   │   │   └── weka/
    │   │   │   │       ├── output.log
    │   │   │   │       ├── shelld.log
    │   │   │   │       └── ...
    │   │   │   ├── drives0/
    │   │   │   │   └── ...
    │   │   │   ├── frontend0/
    │   │   │   │   └── ...
    │   │   │   └── smbw/
    │   │   │       ├── tsmb.log
    │   │   │       ├── pacemaker/
    │   │   │       │   └── pacemaker.log
    │   │   │       └── ...
    │   │   ├── vendor/mlnx/          (Mellanox driver logs)
    │   │   └── weka/driver/          (Weka kernel driver logs)
    │   └── collection_manifest.json  (what was collected, what failed)
    └── ...
```

### `collection_manifest.json`

Every host directory contains a manifest:

```json
{
  "hostname": "cst-weka1",
  "collected_at": "2026-03-21T19:46:43Z",
  "profile": "default",
  "weka_version": "4.3.5.2",
  "total_commands": 48,
  "failed_commands": 0,
  "total_files": 236,
  "collected_files": 236,
  "failed_files": 0,
  "commands": [...],
  "files": [...]
}
```

---

## Time window: `--from` / `--to`

> **Important**: The time window applies **only to journalctl**, never to file collection.

All log files (system logs, weka container logs, rotated variants) are **always collected in full** regardless of `--from`/`--to`. This is intentional — log files may contain context that predates the incident window, and partial file collection leads to missing root causes.

The `--from`/`--to` flags control only what `journalctl` returns:

```bash
# Collect journalctl for last 2 hours; all files collected as usual
weka-log-collector --local --from -2h

# Relative formats: -2h, -30m, -1d, -90s
# Absolute format:  2026-03-20T14:30
```

---

## Space safety

Before writing, the tool checks:
1. At least 200 MB free on the output filesystem
2. Estimated compressed size does not exceed `--max-size` (default 2048 MB) or 80% of available space

If either check fails, the tool exits with an error and a suggested fix.

Use `--dry-run` to see the estimate before collecting:
```bash
weka-log-collector --dry-run
```

Use `--output` to write to a filesystem with more space:
```bash
weka-log-collector --output /data/weka-logs.tar.gz
```

---

## Cluster-wide SSH collection

When run without `--local`, the tool:
1. Discovers all backend node IPs via `weka cluster servers list --output ip --role backend`
2. **Auto-deploys itself** via `scp` to `/tmp/weka-log-collector` on each node
3. SSHs to each node in parallel (up to `--workers`, default 10) and runs collection
4. Cleans up the temporary binary after collection (via `trap ... EXIT`)
5. Merges all host archives into a single `.tar.gz`

No manual pre-deployment required — just copy the binary to one backend node and run.

```bash
# Copy binary to one backend node and collect from entire cluster
scp weka-log-collector root@<any-backend>:/usr/local/bin/weka-log-collector
ssh root@<any-backend> weka-log-collector
# → /tmp/<cluster>-weka-logs-<timestamp>.tar.gz

# Collect from specific nodes by IP
weka-log-collector --host 10.0.0.1 --host 10.0.0.2

# Skip auto-deploy (binary must already exist on all nodes)
weka-log-collector --no-self-deploy --remote-binary /usr/local/bin/weka-log-collector
```

---

## Developer guide

### Prerequisites

```bash
# Go 1.21+
go install github.com/go-task/task/v3/cmd/task@latest
go install honnef.co/go/tools/cmd/staticcheck@latest
```

### Commands

| Command | What it does |
|---------|-------------|
| `task fmt` | Format code (`gofmt -w .`) |
| `task vet` | Static analysis (`go vet ./...`) |
| `task lint` | Linter (`staticcheck ./...`) |
| `task test` | Unit tests (`go test ./... -v`) |
| `task build` | Build binary for current platform |
| `task build-linux` | Cross-compile static Linux binary (`CGO_ENABLED=0 GOOS=linux GOARCH=amd64`) |
| `task check` | All of the above in order |
| `task clean` | Remove built binaries |

### Before every commit

```bash
task check   # fmt → vet → lint → test → build
```

### Constraints

- **No external dependencies** — stdlib only (`go.mod` has no `require` entries)
- **No CGo** — `CGO_ENABLED=0` for static Linux binary
- **Single file** — all implementation in `main.go`, all tests in `main_test.go`

### Code structure

```
main.go
├── Time parsing        parseInputTime() — relative (-2h, -30m) and absolute (YYYY-MM-DDTHH:MM)
├── Profiles            profileEnabled() + per-profile command slices
├── Command specs       defaultCommands, systemCommands, fullCommands, perfCommands, ...
├── Log file specs      logFileSpecs — glob patterns for file collection
├── Space checking      checkDiskSpace(), estimateCollectionMB()
├── Collection          CollectLocal(), collectLogFile(), journalctlWithWindow()
├── SSH collection      collectFromHost(), collectCluster(), discoverClusterHosts()
├── Archive             writeArchive(), writeMergedArchive(), mergeArchive()
└── main()
```

---

## License

Internal tool — not for public distribution.
