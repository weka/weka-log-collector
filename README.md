# weka-log-collector

A standalone diagnostic log collector for [Weka](https://www.weka.io/) clusters.

Drop a single binary on any Weka node and collect a compressed archive of logs and diagnostics — from one node or the entire cluster — in seconds. Works for both bare-metal/VM Weka clusters and **Weka-on-Kubernetes** deployments.

---

## Why this tool?

A single binary that collects exactly what you need from one node or the entire cluster — fast, flexible, and zero-dependency.

- **Profile-based collection** — gather only what's relevant: default, full, perf, NFS, S3, SMB-W, or all
- **Time-windowed collection** — `--start-time`/`--end-time` scope `journalctl`, `weka stats` (perf profile), and rotated log files (filtered by mtime); active log files are always collected in full. Defaults to the last 8h if not specified.
- **Full container log coverage** — all container log trees collected including rotated variants
- **Cluster-wide in one shot** — auto-deploys itself to each node via SCP, collects in parallel, merges into a single archive
- **Container-scoped collection** — target specific nodes by their Weka container ID (`--container-id`)
- **IP-based node discovery** — uses node IPs directly, no DNS required
- **Space-safe** — checks available disk before writing; warns if space is low
- **Upload to Weka Home** — use `--upload` to send the archive directly to Weka Home via the node's uploader daemon; or use `--output -` to stream to stdout
- **Bundle management** — list, remove, and clean up local bundles with `--list-bundles`, `--rm-bundle`, `--clean-bundles`
- **Extra commands** — extend collection with custom commands via `--extra-commands`
- **Kubernetes support** — first-class `k8s` subcommand for Weka-on-Kubernetes deployments

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

# Specific incident window, all profiles
weka-log-collector --profile all --start-time 2026-03-20T14:00 --end-time 2026-03-20T16:00

# Collect from a Weka-on-Kubernetes cluster
weka-log-collector k8s --k8s-host jump.server.internal
```

---

## Usage

```
Usage: weka-log-collector [flags]
       weka-log-collector k8s [k8s-flags]

Flags:
  --local              Collect from local host only (no SSH, no cluster discovery)
  --profile            Collection profile: default|perf|nfs|s3|smbw|all  (default: default)
  --start-time         Start of time window (e.g. -2h, -30m, -1d, 2026-03-20T14:00)
  --end-time           End of time window (default: now)
  --output             Output .tar.gz path (default: /opt/weka/weka-log-collector/bundles/<cluster>-weka-logs-<ts>.tar.gz). Use - for stdout.
  --host               Collect from this host by IP (repeatable; default: all cluster backends)
  --container-id       Collect from specific container IDs (comma-separated or repeatable; e.g. --container-id 0,1 or --container-id 0 --container-id 1)
  --upload             Upload collected archive to Weka Home (requires 'weka cloud enable')
  --compression        Compression format: gzip|xz  (default: gzip; xz requires system xz binary, falls back to gzip if not found)
  --upload-file        Upload a specific file to Weka Home (must be under /opt/weka/weka-log-collector, ≤50 MB, .tar.gz/.tar.xz/.log/.txt/.json/.out)
  --clients            Include client nodes in cluster collection (default: backends only)
  --clients-only       Collect from client nodes only (skip backends)
  --extra-commands     Run extra commands from /opt/weka/weka-log-collector/extra-commands
  --cmd-timeout        Timeout per command (default: 120s)
  --verbose            Print detailed progress for every file and command
  --version            Print version and exit
  --completion         Print bash completion script to stdout (also installs to /etc/bash_completion.d/)

Bundle management:
  --list-bundles       List bundles across all cluster nodes (or just this node with --local)
  --rm-bundle          Remove a specific bundle (filename or full path)
  --clean-bundles      Remove all bundles on all cluster nodes (or just this node with --local)
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

# List collected bundles across all cluster nodes
weka-log-collector --list-bundles

# List bundles on local node only
weka-log-collector --list-bundles --local

# Upload a previously collected archive to Weka Home
weka-log-collector --upload-file weka-logs-2026-04-20.tar.gz
```

---

## Collection profiles

| Profile | What's included |
|---------|----------------|
| `default` | Weka CLI status, events, cfgdump, hw info, system info, NIC/OFED/routing, all logs + journalctl |
| `perf` | + performance stats (CPU, SSD, ops, network, JRPC, latency) |
| `nfs` | + NFS/Ganesha commands and ganesha container logs |
| `s3` | + S3/envoy commands and S3 container logs |
| `smbw` | + SMB-W commands and smbw/pacemaker/corosync logs |
| `all` | Everything from all profiles combined |

> **All profiles default to the last 8h.** `--start-time`/`--end-time` scope journalctl, `weka stats` (perf profile), and rotated log files (filtered by mtime). For longer windows, pass `--start-time -24h`, `-7d`, etc.

> NIC/OFED/routing info (`lshw`, `ofed_info`, `lsmod`, `modinfo`, `ip rule`, `ip neighbor`, `rp_filter`) is always collected on every node — backends and clients alike.

---

## What gets collected

**System commands** — uname, os-release, uptime, free, lscpu, ip addr/route/rule/neighbor, netstat, ps, df, lspci, lsblk, sysctl -a, dmesg, journalctl (weka-agent + time-windowed full journal), lshw (network), ofed_info, lsmod, modinfo (mlx5_core, ice), rp_filter, ethtool (all physical interfaces)

**Clock sync** — timedatectl, timedatectl show-timesync, systemd-timesyncd status, chronyc tracking/sources, chronyd status, ntpd status, ptp4l/phc2sys status — whichever sync daemon is present on each node

**Weka CLI commands** — weka status, alerts, cluster topology, filesystems, snapshots, debug traces, local container resources, and profile-specific commands (events, cfgdump, perf stats, NFS/S3/SMB-W commands)

**System log files** — `/var/log/messages*`, `secure*`, `cron*`, `syslog*`, `kern.log*`, `audit/audit.log*`, `cloud-init*`, `dnf/yum.log*` — active files always; rotated variants kept only when their mtime falls inside the time window

**Weka container logs** — full `/opt/weka/logs/` tree: syslog, output, events, shelld, trace-server, nginx, supervisord, pacemaker, corosync, pcsd, wtracer — all containers; rotated variants windowed by mtime

**Vendor/driver logs** — `/var/log/mlnx/*.log*`, Weka kernel driver build logs

Every host directory includes a `collection_manifest.json` with counts of commands run, files collected, and any failures.

> Commands that are expected to fail on some distros or node types (e.g. `chronyc` on systems using ntpd, `ofed_info` on nodes without OFED) are automatically excluded from the failure count so the manifest accurately reflects real problems.

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

## Kubernetes (Weka-on-K8s)

The `k8s` subcommand collects diagnostics from a Weka-on-Kubernetes deployment. It requires `kubectl` and a valid kubeconfig — either on the local machine or on an SSH jump host.

```
Usage: weka-log-collector k8s [flags]

Flags:
  --k8s-host HOST      SSH jump host with kubectl + kubeconfig (e.g. jump.server.internal)
                       Omit to run kubectl locally (kubeconfig must be configured on PATH)
  --kubeconfig PATH    Path to kubeconfig file (on the jump host when --k8s-host is set)
  --operator-ns NS     Override auto-detected Weka Operator namespace
                       (default: auto-detect, fall back to weka-operator-system)
  --cluster-ns NS      Override auto-detected WekaCluster pod namespace
                       (default: auto-detect via WekaCluster CRD)
  --cluster-name NAME  Target a specific WekaCluster CRD by name
                       (required when multiple WekaCluster CRDs exist in the same namespace)
  --csi-ns NS          Override auto-detected CSI plugin namespace
                       (default: auto-detect, fall back to weka-csi-plugin)
  --output PATH        Output .tar.gz path (default: ~/wlc-bundles/<cluster>-weka-logs-<ts>.tar.gz)
  --upload             Upload bundle to Weka Home after collection (requires 'weka cloud enable' on this node)
  --cmd-timeout        Timeout per kubectl command (default: 120s)
  --verbose            Print detailed progress
```

### Examples

```bash
# Collect via SSH jump server (most common for Weka-on-K8s)
weka-log-collector k8s --k8s-host jump.internal

# Run locally when kubectl is already configured
weka-log-collector k8s

# Override namespaces when auto-detection fails
weka-log-collector k8s --k8s-host jump.internal --cluster-ns my-weka --csi-ns my-csi

# Target a specific WekaCluster when multiple exist
weka-log-collector k8s --k8s-host jump.internal --cluster-name production-cluster

# Save bundle to specific path
weka-log-collector k8s --k8s-host jump.internal --output /tmp/k8s-bundle.tar.gz
```

### Namespace auto-detection

The tool automatically discovers Weka namespaces by querying the `wekacluster` CRD. Typical Weka-on-K8s deployments have the operator and WekaCluster pods in the same namespace (`weka-operator-system`); the tool handles this correctly and avoids duplicate collection. CSI is detected separately (typically `weka-csi-plugin`) and skipped gracefully if not installed.

### What the k8s subcommand collects

**Cluster level**
- `kubectl describe nodes` (all nodes — kubelet args, allocatable resources, conditions, events)
- Events across all namespaces
- Namespaces, StorageClasses, PersistentVolumes, PersistentVolumeClaims
- CSIDrivers, CSINodes, CSIStorageCapacities
- WekaCluster CRD (spec + status) and all optional Weka CRDs: WekaFilesystem, WekaSnapshot, WekaFilesystemGroup, WekaClientSet, WekaLocalVolume, WekaBackup, WekaQuota, WekaObjectStore

**Weka Operator**
- Controller-manager pod logs (current + previous)
- Node-agent daemonset pod logs (current + previous, one per K8s node)
- `weka-drivers-dist` pod logs
- Pod describe + events for all operator pods
- WekaCluster CRD instance describe

**WekaCluster pods** (compute, drive, frontend)
- Pod logs for all containers (current + previous)
- Pod describe + events per pod
- `weka status --json` — collected once cluster-wide from first responsive compute pod
- `weka alerts --json` — collected once cluster-wide
- `weka local ps` — per pod (node-local data)
- `weka local resources --json` — per pod (node-local data)
- Full `/opt/weka/logs/` tree via `kubectl exec` — syslog, output, supervisord, shelld, nginx, events, api logs, wtracer logs (PVC-backed, survives pod restarts)

**CSI plugin** (if installed)
- Controller pod logs (current + previous)
- Node daemonset pod logs (current + previous, one per K8s node)
- Pod describe + events
- Namespace events

A `collection_manifest.json` at the bundle root records the total commands run, failed commands, and timestamps.

### Bundle output

The k8s bundle is structured as:

```
<cluster>-weka-logs-<timestamp>/
  collection_manifest.json
  cluster/
    nodes_describe.txt
    events.txt
    storageclasses.txt
    persistentvolumes.txt
    persistentvolumeclaims.txt
    csidrivers.txt
    csinodes.txt
    wekacluster.yaml
    wekafilesystem.yaml
    ...
  operator/
    pods_wide.txt
    events.txt
    weka-operator-controller-manager-xxx/
      logs/current.log
      logs/previous.log
      describe.txt
    weka-operator-node-agent-xxx/  (one per node)
      ...
  wekacluster/
    pods_wide.txt
    events.txt
    weka-cli/
      weka_status.json
      weka_alerts.json
    <cluster>-compute-xxx/
      logs/current.log
      logs/previous.log
      describe.txt
      weka_local_ps.txt
      weka_local_resources.json
      opt-weka-logs/
        syslog
        output
        supervisord.log
        ...
    <cluster>-drive-xxx/
      ...
  csi/
    pods_wide.txt
    events.txt
    csi-wekafsplugin-controller-xxx/
      ...
    csi-wekafsplugin-node-xxx/  (one per node)
      ...
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

## Bundle management

Bundles are stored in `/opt/weka/weka-log-collector/bundles/` by default.

`--list-bundles` and `--clean-bundles` operate cluster-wide by default (SSH to all nodes), or locally with `--local`.

```bash
# List all bundles across the cluster
weka-log-collector --list-bundles

# List bundles on local node only
weka-log-collector --list-bundles --local

# Remove a specific bundle
weka-log-collector --rm-bundle mycluster-weka-logs-2026-04-20T10-00-00.tar.gz

# Remove all bundles on all cluster nodes
weka-log-collector --clean-bundles

# Remove all bundles on local node only
weka-log-collector --clean-bundles --local
```

---

## Tab completion

```bash
source <(./weka-log-collector --completion)
```

This also installs the completion script to `/etc/bash_completion.d/weka-log-collector` so future shell sessions load it automatically. Add the line to your `.bashrc` for this session. Completes all flags, profile names, and common time values. The `k8s` subcommand has its own completion branch with k8s-specific flags.

---

## Extra commands

Place custom shell commands in `/opt/weka/weka-log-collector/extra-commands` (one per line, `#` for comments) and pass `--extra-commands` to include their output in the archive. Commands already collected by the default profile are skipped automatically.

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

## Privacy & security

This tool is designed to collect diagnostic data only — no credentials or secret values are ever included in the bundle.

**What is deliberately excluded:**
- Kubernetes Secret values — only names and types are collected (`NAME` + `TYPE` columns, no `.data`)
- kubeconfig files
- Environment variables from pods
- Any files outside `/opt/weka/logs/` and `/opt/weka/data/`

**Credential redaction (applied to every collected command output):**
Any value whose key name contains a credential-like substring is automatically replaced with `[REDACTED]` before being written to the archive. This covers all weka CLI JSON outputs (e.g. `weka smb cluster info -J` → `pcsPass`), system command outputs, k8s ConfigMaps, and extra-command outputs. Patterns matched: `password`, `passwd`, `pwd`, `pass` (catches camelCase like `pcsPass`, `dbPass`), `token`, `secret`, `api-key` / `api_key`, `auth`, `credential`, `private-key`, `access-key`, `signing-key`. JSON formatting is preserved exactly (only the string value inside the quotes is replaced).

**What IS in the bundle that you should be aware of:**
- Pod logs and container logs — may contain hostnames, IP addresses, filesystem paths, and internal service URLs
- Weka cluster status — cluster name, node IPs, filesystem names, capacity figures
- ConfigMap content (credential keys redacted as above)
- Kubernetes node names, namespace names, and pod names

**Recommendation:** Review the bundle before sharing externally, especially if the cluster handles regulated data. The bundle can be inspected with `tar -tzf <bundle>.tar.gz` and individual files extracted for review.

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

Run `task check` before every commit. All fmt, vet, lint, and test failures must be resolved.

### Constraints

- No external dependencies — stdlib only
- No CGo — static Linux binary
- Single file — all implementation in `main.go`

---

## License

GPL v3.0 — see [LICENSE](LICENSE).
