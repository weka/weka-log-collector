# weka-log-collector

A standalone diagnostic log collector for [Weka](https://www.weka.io/) clusters.

Drop a single binary on any Weka node and collect a compressed archive of logs and diagnostics — from one node or the entire cluster — in seconds.

---

## Why this tool?

For most support cases, `weka diags` is your starting point. This tool is a complement for situations where you need more targeted or flexible log collection.

- **Profile-based collection** — gather only what's relevant: default, full, perf, NFS, S3, SMB-W, client, or all
- **Time-windowed journalctl** — scope `journalctl` to an incident window with `--from`/`--to`; all log files always collected in full
- **Full container log coverage** — all container log trees collected including rotated variants
- **Cluster-wide in one shot** — auto-deploys itself to each node via SCP, collects in parallel, merges into a single archive
- **Container-scoped collection** — target specific nodes by their Weka container ID (`--container-id`)
- **IP-based node discovery** — uses node IPs directly, no DNS required
- **Space-safe** — checks available disk before writing; aborts with a clear error if space is insufficient
- **No upload** — produces a local `.tar.gz` you control; stream to stdout with `--output -` if needed

---

## Installation

```bash
git clone https://github.com/manmeet-weka/weka-log-collector
scp weka-log-collector/weka-log-collector root@<node-ip>:/usr/local/bin/weka-log-collector
```

The binary is a static Linux amd64 build — no dependencies, works on any Weka node.

---

## Quick start

```bash
# Collect from local node only
weka-log-collector --local

# Collect from entire cluster (run from any backend node)
weka-log-collector

# Last 2 hours of journalctl, default profile
weka-log-collector --from -2h

# Specific incident window, full profile
weka-log-collector --profile full --from 2026-03-20T14:00 --to 2026-03-20T16:00
```

---

## Usage

```
Usage: weka-log-collector [flags]

Flags:
  --local              Collect from local host only (no SSH, no cluster discovery)
  --profile            Collection profile: default|full|perf|nfs|s3|smbw|client|all  (default: default)
  --from               Start of time window for journalctl (e.g. -2h, -30m, -1d, 2026-03-20T14:00)
  --to                 End of time window for journalctl (default: now)
  --output             Output .tar.gz path (default: /tmp/<cluster>-weka-logs-<ts>.tar.gz). Use - for stdout.
  --host               Collect from this host by IP (repeatable; default: all cluster backends)
  --container-id       Collect from this container ID only (repeatable; e.g. --container-id 0 --container-id 2)
  --clients            Include client nodes in cluster collection (default: backends only)
  --no-self-deploy     Skip auto-deployment; use --remote-binary path on remote hosts instead
  --remote-binary      Path to binary on remote hosts when using --no-self-deploy (default: /usr/local/bin/weka-log-collector)
  --ssh-user           SSH user for remote collection (default: root)
  --workers            Max parallel SSH workers (default: 10)
  --max-size           Abort if estimated size exceeds this MB (default: 2048)
  --cmd-timeout        Timeout per command (default: 60s)
  --dry-run            Show what would be collected without collecting
  --verbose            Print detailed progress for every file and command
  --version            Print version and exit
```

### Examples

```bash
# Local only, S3 profile, last 4 hours
weka-log-collector --local --profile s3 --from -4h

# Entire cluster, full profile
weka-log-collector --profile full

# Specific container IDs (as shown in 'weka cluster container')
weka-log-collector --container-id 0 --container-id 1 --from -2h

# Backends and clients
weka-log-collector --clients --from -2h

# Specific hosts by IP
weka-log-collector --host 10.0.0.1 --host 10.0.0.2

# Dry run — show estimated size and what would be collected
weka-log-collector --dry-run

# Stream to stdout
weka-log-collector --local --output - | ssh admin@bastion "cat > /data/weka-logs.tar.gz"
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

**System commands** — uname, os-release, uptime, free, lscpu, ip addr/route, netstat, ps, df, lspci, lsblk, sysctl.conf, dmesg, journalctl (weka-agent + time-windowed full journal)

**Weka CLI commands** — weka status, alerts, cluster topology, filesystems, snapshots, debug traces, local container resources, and profile-specific commands (events, cfgdump, perf stats, NFS/S3/SMB-W commands)

**System log files** — `/var/log/messages*`, `secure*`, `cron*`, `syslog*`, `kern.log*`, `audit/audit.log*`, `cloud-init*`, `dnf/yum.log*` — all rotated variants

**Weka container logs** — full `/opt/weka/logs/` tree: syslog, output, events, shelld, trace-server, nginx, supervisord, pacemaker, corosync, pcsd, wtracer — all containers, all rotated variants

**Vendor/driver logs** — `/var/log/mlnx/*.log*`, Weka kernel driver build logs

Every host directory includes a `collection_manifest.json` with counts of commands run, files collected, and any failures.

---

## Cluster-wide collection

When run without `--local`, the tool:
1. Discovers all backend node IPs via `weka cluster container --output id,ips,mode`
2. Auto-deploys itself via `scp` to `/tmp/weka-log-collector` on each node
3. SSHs to each node in parallel (up to `--workers`, default 10) and runs collection
4. Cleans up the temporary binary after collection
5. Merges all host archives into a single `.tar.gz`

Use `--container-id` to scope to specific nodes, or `--clients` to include client nodes.

### Large clusters (50+ nodes)

The default settings are tuned for small-to-medium clusters. For large clusters:

- **Always use `--from`** — without a time window, log collection per node can be very large. A 2–4 hour window is recommended for incident collection.
- **Set `--output` to a filesystem with enough space** — the default `/tmp` is often small. Use `/opt/weka/` or a dedicated data volume. A 180-node cluster with a 2-hour window typically produces 5–15 GB.
- **Raise `--max-size`** — the default 2048 MB limit will trigger on large clusters. Set it based on available space.
- **Increase `--workers`** — default is 10 parallel SSH connections. For faster collection on large clusters, `--workers 30` is reasonable if the orchestrator node can handle it.
- **Increase `--cmd-timeout`** — on busy large clusters, commands like `weka events` can take longer than the default 60s.

```bash
# Recommended for large clusters (100+ nodes)
weka-log-collector \
  --from -2h \
  --output /opt/weka/weka-logs.tar.gz \
  --max-size 20000 \
  --workers 30 \
  --cmd-timeout 120s
```

---

## Tab completion

Tab completion is installed automatically the first time you run the binary (writes `/etc/bash_completion.d/weka-log-collector`). Open a new shell and completion is active — all flags, profile names, and common time values.

---

## Space safety

Before writing, the tool checks:
- At least 200 MB free on the output filesystem
- Estimated compressed size does not exceed `--max-size` (default 2048 MB) or 80% of available space

Use `--dry-run` to preview estimated size before collecting. Use `--output` to write to a different filesystem if space is tight.

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

Internal tool — not for public distribution.
