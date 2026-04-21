# weka-log-collector

A standalone diagnostic log collector for [Weka](https://www.weka.io/) clusters.

Drop a single binary on any Weka node and collect a compressed archive of logs and diagnostics — from one node or the entire cluster — in seconds.

---

## Why this tool?

For most support cases, `weka diags` is your starting point. This tool is a complement for situations where you need more targeted or flexible log collection.

- **Profile-based collection** — gather only what's relevant: default, full, perf, NFS, S3, SMB-W, or all
- **Time-windowed journalctl** — scope `journalctl` to an incident window with `--start-time`/`--end-time`; all log files always collected in full
- **Full container log coverage** — all container log trees collected including rotated variants
- **Cluster-wide in one shot** — auto-deploys itself to each node via SCP, collects in parallel, merges into a single archive
- **Container-scoped collection** — target specific nodes by their Weka container ID (`--container-id`)
- **IP-based node discovery** — uses node IPs directly, no DNS required
- **Space-safe** — checks available disk before writing; warns if space is low
- **Upload to Weka Home** — use `--upload` to send the archive directly to Weka Home via the node's uploader daemon; or use `--output -` to stream to stdout
- **Bundle management** — list, remove, and clean up local bundles with `--list-bundles`, `--rm-bundle`, `--clean-bundles`
- **Extra commands** — extend collection with custom commands via `--extra-commands`

---

## Installation

```bash
git clone https://github.com/weka/weka-log-collector
scp weka-log-collector/weka-log-collector root@<node-ip>:/opt/weka/weka-log-collector/weka-log-collector
```

The binary is a static Linux amd64 build — no dependencies, works on any Weka node.

> The tool stores all files (archives, debug logs, the self-deployed binary) under `/opt/weka/weka-log-collector/`. This directory is created automatically on first use and on remote nodes during cluster-wide collection. `/opt/weka/` is used instead of `/tmp` to avoid `noexec` mount restrictions common on hardened systems.

### Tab completion

```bash
source <(./weka-log-collector --completion)
```

This also installs the completion script to `/etc/bash_completion.d/weka-log-collector` automatically, so future shell sessions pick it up without re-sourcing. Add the `source` line to your `.bashrc` for this session. Completes all flags, profile names, and common time values.

---

## Quick start

```bash
# Collect from local node only
weka-log-collector --local

# Collect from entire cluster (run from any backend node)
weka-log-collector

# Last 2 hours of journalctl, default profile
weka-log-collector --start-time -2h

# Specific incident window, full profile
weka-log-collector --profile full --start-time 2026-03-20T14:00 --end-time 2026-03-20T16:00
```

---

## Usage

```
Usage: weka-log-collector [flags]

Flags:
  --local              Collect from local host only (no SSH, no cluster discovery)
  --profile            Collection profile: default|perf|nfs|s3|smbw|all  (default: default)
  --start-time         Start of time window (e.g. -2h, -30m, -1d, 2026-03-20T14:00)
  --end-time           End of time window (default: now)
  --output             Output .tar.gz path (default: /opt/weka/weka-log-collector/bundles/<cluster>-weka-logs-<ts>.tar.gz). Use - for stdout.
  --host               Collect from this host by IP (repeatable; default: all cluster backends)
  --container-id       Collect from specific container IDs (comma-separated or repeatable; e.g. --container-id 0,1 or --container-id 0 --container-id 1)
  --upload             Upload collected archive to Weka Home (requires 'weka cloud enable')
  --upload-file        Upload a specific file to Weka Home (must be under /opt/weka/weka-log-collector, ≤50 MB, .tar.gz/.log/.txt/.json/.out)
  --clients            Include client nodes in cluster collection (default: backends only)
  --clients-only       Collect from client nodes only (skip backends)
  --extra-commands     Run extra commands from /opt/weka/weka-log-collector/extra-commands
  --cmd-timeout        Timeout per command (default: 120s)
  --verbose            Print detailed progress for every file and command
  --version            Print version and exit
  --completion         Print bash completion script to stdout (also installs to /etc/bash_completion.d/)

Bundle management:
  --list-bundles       List bundles in /opt/weka/weka-log-collector/bundles
  --rm-bundle          Remove a specific bundle (filename or full path)
  --clean-bundles      Remove all bundles
```

### Examples

```bash
# Local only, S3 profile, last 4 hours
weka-log-collector --local --profile s3 --start-time -4h

# Entire cluster, full profile
weka-log-collector --profile full

# Specific container IDs (comma-separated or repeatable)
weka-log-collector --container-id 36,171 --start-time -2h

# Upload to Weka Home after collecting
weka-log-collector --start-time -2h --upload

# Backends and clients
weka-log-collector --clients --start-time -2h

# Specific hosts by IP
weka-log-collector --host 10.0.0.1 --host 10.0.0.2

# Stream to stdout
weka-log-collector --local --output - | ssh admin@bastion "cat > /data/weka-logs.tar.gz"

# Run extra commands from /opt/weka/weka-log-collector/extra-commands
weka-log-collector --extra-commands --start-time -2h

# List collected bundles on this node
weka-log-collector --list-bundles

# Upload a previously collected archive to Weka Home
weka-log-collector --upload-file weka-logs-2026-04-20.tar.gz
```

---

## Collection profiles

| Profile | What's included |
|---------|----------------|
| `default` | Weka CLI status, events, cfgdump, hw info, system info, NIC/OFED/routing, all logs + journalctl — **scoped to last 8h by default** |
| `perf` | + performance stats (CPU, SSD, ops, network, JRPC, latency) — scoped to `--start-time`/`--end-time` |
| `nfs` | + NFS/Ganesha commands and ganesha container logs |
| `s3` | + S3/envoy commands and S3 container logs |
| `smbw` | + SMB-W commands and smbw/pacemaker/corosync logs |
| `all` | Everything from all profiles, **no time limit** — collects full log history |

> NIC/OFED/routing info (`lshw`, `ofed_info`, `lsmod`, `modinfo`, `ip rule`, `ip neighbor`, `rp_filter`) is always collected on every node — backends and clients alike.

---

## What gets collected

**System commands** — uname, os-release, uptime, free, lscpu, ip addr/route/rule/neighbor, netstat, ps, df, lspci, lsblk, sysctl -a, dmesg, journalctl (weka-agent + time-windowed full journal), lshw (network), ofed_info, lsmod, modinfo (mlx5_core, ice), rp_filter, ethtool (all interfaces)

**Clock sync** — timedatectl, timedatectl show-timesync, systemd-timesyncd status, chronyc tracking/sources, chronyd status, ntpd status, ptp4l/phc2sys status — whichever sync daemon is present on each node

**Weka CLI commands** — weka status, alerts, cluster topology, filesystems, snapshots, debug traces, local container resources, and profile-specific commands (events, cfgdump, perf stats, NFS/S3/SMB-W commands)

**System log files** — `/var/log/messages*`, `secure*`, `cron*`, `syslog*`, `kern.log*`, `audit/audit.log*`, `cloud-init*`, `dnf/yum.log*` — all rotated variants

**Weka container logs** — full `/opt/weka/logs/` tree: syslog, output, events, shelld, trace-server, nginx, supervisord, pacemaker, corosync, pcsd, wtracer — all containers, all rotated variants

**Vendor/driver logs** — `/var/log/mlnx/*.log*`, Weka kernel driver build logs

Every host directory includes a `collection_manifest.json` with counts of commands run, files collected, and any failures.

---

## Cluster-wide collection

When run without `--local`, the tool:
1. Discovers all backend node IPs via `weka cluster container --output id,ips,mode`
2. Auto-deploys itself via `scp` to `/opt/weka/weka-log-collector/` on each node
3. SSHs to each node in parallel and runs collection
4. Cleans up the temporary binary after collection
5. Merges all host archives into a single `.tar.gz`

Use `--container-id` to scope to specific nodes, `--clients` to include client nodes alongside backends, or `--clients-only` to collect from client nodes only.

> **Note:** `--clients` and `--clients-only` can significantly increase collection size — each client host adds roughly the same log volume as a backend. Only use it when investigating a client-side issue (e.g. Kubernetes/CSI clients, NFS/SMB clients). For most support cases, leave it off.

> **Signal handling:** If you press Ctrl+C during cluster collection, the tool will SSH to all active remote nodes, kill any running collection processes, and clean up the temporary binary before exiting.

### Large clusters (50+ nodes)

The default settings are tuned for small-to-medium clusters. For large clusters:

- **Always use `--start-time`** — without a time window, log collection per node can be very large. A 2–4 hour window is recommended for incident collection.
- **Set `--output` to a filesystem with enough space** — the default `/opt/weka/weka-log-collector/bundles/` may be limited. A 180-node cluster with a 2-hour window typically produces 5–15 GB.
- **Increase `--cmd-timeout`** — on busy large clusters, commands like `weka events` can take longer than the default 120s.

```bash
# Recommended for large clusters (100+ nodes)
weka-log-collector \
  --start-time -2h \
  --output /opt/weka/weka-logs.tar.gz \
  --cmd-timeout 180s
```

---

## Uploading to Weka Home

Add `--upload` to any collection command to send the archive directly to Weka Home:

```bash
weka-log-collector --start-time -2h --upload
weka-log-collector --local --upload
```

You can also upload a previously collected file:

```bash
weka-log-collector --upload-file /opt/weka/weka-log-collector/bundles/mycluster-weka-logs-2026-04-20.tar.gz
```

**Requirements:** `weka cloud enable` must be configured on the node. The tool uses the node's built-in uploader daemon (inotify-based) — no extra credentials needed.

**How it works:**
1. Archive is staged into an active Weka container directory (`/opt/weka/<container>/`)
2. A symlink named `wlc:<timestamp>:<hostname>:<filename>` is created in the support upload dir
3. The uploader daemon detects the symlink via inotify and uploads to `api.home.weka.io`
4. Symlink is cleaned up on success

> If the cluster uses **Local Weka Home (LWH)**, the tool will warn that LWH → Cloud Weka Home forwarding may not be configured.

### Distributed upload (`--upload` in cluster mode)

When `--upload` is used in cluster mode (without `--local`), collection and upload happen in a distributed fashion: each node independently collects its own archive and uploads it directly to Weka Home in parallel. No single-node bottleneck. The orchestrator handles cluster-wide commands and uploads its own archive; remote nodes each handle their own node-local data.

---

## Tab completion

```bash
source <(./weka-log-collector --completion)
```

This also installs the completion script to `/etc/bash_completion.d/weka-log-collector` so future shell sessions load it automatically. Add the line to your `.bashrc` for this session. Completes all flags, profile names, and common time values.

---

## Extra commands

Place custom shell commands in `/opt/weka/weka-log-collector/extra-commands` (one per line, `#` for comments) and pass `--extra-commands` to include their output in the archive. Commands already collected by the default profile are skipped automatically.

---

## Bundle management

Bundles are stored in `/opt/weka/weka-log-collector/bundles/` by default.

```bash
# List all bundles
weka-log-collector --list-bundles

# Remove a specific bundle
weka-log-collector --rm-bundle mycluster-weka-logs-2026-04-20T10-00-00.tar.gz

# Remove all bundles
weka-log-collector --clean-bundles
```

---

## Troubleshooting

Every run writes a debug log to `/opt/weka/weka-log-collector/logs/weka-log-collector-<timestamp>.log`. The path is printed at startup:

```
Debug log: /opt/weka/weka-log-collector/logs/weka-log-collector-2026-04-20T11-05-00.log
```

The log always includes verbose output (commands run, files collected/skipped, warnings, errors) regardless of the `--verbose` flag — useful for diagnosing issues after the fact without re-running.

---

## Space safety

Before writing, the tool checks:
- At least 200 MB free on the output filesystem (local and each remote node)
- Nodes with low disk space are warned but collection continues where possible

Use `--output` to write to a different filesystem if space is tight.

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
| `task fmt` | Format code |
| `task vet` | Static analysis |
| `task lint` | Linter (staticcheck) |
| `task test` | Unit tests |
| `task build` | Build binary for current platform |
| `task build-linux` | Cross-compile static Linux binary |
| `task check` | All of the above in order |

### Constraints

- No external dependencies — stdlib only
- No CGo — static Linux binary
- Single file — all implementation in `main.go`

---

## License

GPL v3.0 — see [LICENSE](LICENSE).
