// weka-log-collector: collect logs and diagnostics from a Weka cluster.
//
// Designed as a standalone tool that can be dropped on any Weka node and run
// without any external dependencies. Supports time-windowed collection,
// per-profile collection scopes, space-safety checks, and parallel multi-host
// collection over SSH.
//
// Usage: see --help or README.md
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ── version ──────────────────────────────────────────────────────────────────

const version = "0.1.0"

// ── time parsing (same approach as trace_extractor by Baruch) ─────────────────

var relativeTimeRe = regexp.MustCompile(
	`^-(\d+)\s*(d|day|days|h|hr|hour|hours|m|min|mins|minute|minutes|s|sec|secs|second|seconds)$`,
)

// rotatedFileSuffixRe matches filename suffixes that indicate a rotated/archived log file.
// Matches: .1  .2  .gz  -20260301 (date-stamped rotation)
// Does NOT match: .log  .json  (current active log extensions)
var rotatedFileSuffixRe = regexp.MustCompile(`(\.\d+|\.gz|-\d{8})$`)

// isRotatedFile returns true when the filename looks like a rotated log archive.
// Current active log files (syslog.log, output.log, messages) are always collected.
// Rotated files (syslog.log.1, syslog.log.2.gz, messages-20260301) are filtered by mtime.
func isRotatedFile(name string) bool {
	return rotatedFileSuffixRe.MatchString(name)
}

// baseWithoutRotation strips the rotation suffix from a filename so that files
// in the same rotation family share a common key.
// e.g. "syslog.log.1" → "syslog.log", "messages-20260301.gz" → "messages"
func baseWithoutRotation(name string) string {
	return rotatedFileSuffixRe.ReplaceAllString(name, "")
}

// filterByTimeWindow filters file paths to those whose content likely overlaps
// with [from, to]. Files are grouped by rotation family (same dir + base name
// without rotation suffix). Within each family, files are sorted by mtime and
// adjacent mtimes are used to approximate each file's content time range:
//
//	content_start = mtime of the next-older file in the family (zero for oldest)
//	content_end   = mtime of this file
//
// A file is skipped when:
//   - content_end < from  (file was rotated out before window started)
//   - content_start > to  (file started accumulating after window ended)
//
// Active (non-rotated) files are always kept — their content range is unknown.
func filterByTimeWindow(paths []string, from, to time.Time) []string {
	if from.IsZero() && to.IsZero() {
		return paths
	}

	type entry struct {
		path    string
		mtime   time.Time
		rotated bool
		statErr bool
	}

	// Group files into rotation families.
	familyKey := func(p string) string {
		return filepath.Dir(p) + "/" + baseWithoutRotation(filepath.Base(p))
	}
	order := []string{} // preserve insertion order for deterministic output
	families := map[string][]entry{}
	for _, p := range paths {
		info, err := os.Stat(p)
		e := entry{path: p, rotated: isRotatedFile(filepath.Base(p))}
		if err != nil {
			e.statErr = true
		} else {
			e.mtime = info.ModTime()
		}
		k := familyKey(p)
		if _, seen := families[k]; !seen {
			order = append(order, k)
		}
		families[k] = append(families[k], e)
	}

	var result []string
	for _, k := range order {
		files := families[k]
		// Sort oldest-first by mtime so adjacent pairs give content ranges.
		sort.Slice(files, func(i, j int) bool {
			return files[i].mtime.Before(files[j].mtime)
		})
		for i, f := range files {
			// Can't stat or not rotated → always include.
			if f.statErr || !f.rotated {
				result = append(result, f.path)
				continue
			}
			contentEnd := f.mtime
			// Content start = mtime of the next-older sibling (zero for oldest).
			var contentStart time.Time
			if i > 0 {
				contentStart = files[i-1].mtime
			}
			// Skip: content ended before our window started.
			if !from.IsZero() && contentEnd.Before(from) {
				vlogf("  time-filter SKIP %s: content ends %s before window start %s",
					f.path, contentEnd.Format(time.RFC3339), from.Format(time.RFC3339))
				continue
			}
			// Skip: content started after our window ended.
			if !to.IsZero() && !contentStart.IsZero() && contentStart.After(to) {
				vlogf("  time-filter SKIP %s: content starts %s after window end %s",
					f.path, contentStart.Format(time.RFC3339), to.Format(time.RFC3339))
				continue
			}
			result = append(result, f.path)
		}
	}
	return result
}

func parseInputTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if m := relativeTimeRe.FindStringSubmatch(strings.ToLower(s)); m != nil {
		n, _ := strconv.Atoi(m[1])
		unit := m[2]
		var dur time.Duration
		switch {
		case unit == "d" || strings.HasPrefix(unit, "day"):
			dur = time.Duration(n) * 24 * time.Hour
		case unit == "h" || unit == "hr" || strings.HasPrefix(unit, "hour"):
			dur = time.Duration(n) * time.Hour
		case unit == "m" || strings.HasPrefix(unit, "min"):
			dur = time.Duration(n) * time.Minute
		default:
			dur = time.Duration(n) * time.Second
		}
		return time.Now().Add(-dur), nil
	}
	// Try absolute formats: YYYY-MM-DDTHH:MM:SS then YYYY-MM-DDTHH:MM
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02T15:04"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse time %q: use YYYY-MM-DDTHH:MM[:SS] or relative like -2h, -30m, -1d", s)
}

// ── collection profiles ───────────────────────────────────────────────────────

// Profile names
const (
	ProfileDefault = "default" // core weka commands + logs, events, cfgdump, journalctl
	ProfilePerf    = "perf"    // + performance stats
	ProfileNFS     = "nfs"     // + ganesha logs and NFS commands
	ProfileS3      = "s3"      // + S3/envoy logs and S3 commands
	ProfileSMBW    = "smbw"    // + SMB logs and pcs status
	ProfileAll     = "all"     // everything
)

var validProfiles = []string{
	ProfileDefault, ProfilePerf,
	ProfileNFS, ProfileS3, ProfileSMBW, ProfileAll,
}

func profileEnabled(selected, check string) bool {
	if selected == ProfileAll {
		return true
	}
	return selected == check
}

// ── command spec ─────────────────────────────────────────────────────────────

// CommandSpec describes a shell command to run and capture.
type CommandSpec struct {
	Name      string // output filename (without extension)
	Cmd       string // shell command
	Profile   string // which profile this belongs to (empty = always run)
	Fatal     bool   // if true, collection fails if this command fails; default non-fatal
	NodeLocal bool   // if true, output varies per node (weka local *); otherwise cluster-wide
	JSON      bool   // if true, command outputs JSON; archive entry uses .json extension
}

// defaultCommands are run on every node that has the weka CLI available.
// These are always included in every profile.
var defaultCommands = []CommandSpec{
	// ── identity & status ──────────────────────────────────────────
	{Name: "weka_version", Cmd: "weka version -J", JSON: true},
	{Name: "weka_status", Cmd: "weka status -J", JSON: true},
	{Name: "weka_status_rebuild", Cmd: "weka status rebuild -J", JSON: true},
	{Name: "weka_alerts", Cmd: "weka alerts -J", JSON: true},
	{Name: "weka_user", Cmd: "weka user -J", JSON: true},
	{Name: "weka_cloud_status", Cmd: "weka cloud status -J", JSON: true},
	// ── cluster topology ──────────────────────────────────────────
	{Name: "weka_cluster_servers", Cmd: "weka cluster servers list -J", JSON: true},
	{Name: "weka_cluster_container", Cmd: "weka cluster container -l -J", JSON: true},
	{Name: "weka_cluster_container_net", Cmd: "weka cluster container net -J", JSON: true},
	{Name: "weka_cluster_process", Cmd: "weka cluster process -J", JSON: true},
	{Name: "weka_cluster_drive", Cmd: "weka cluster drive -J", JSON: true},
	{Name: "weka_cluster_bucket", Cmd: "weka cluster bucket -J", JSON: true},
	{Name: "weka_cluster_failure_domain", Cmd: "weka cluster failure-domain -J", JSON: true},
	{Name: "weka_cluster_task", Cmd: "weka cluster task -J", JSON: true},
	{Name: "weka_cluster_resources", Cmd: "weka cluster container resources 0 -J", JSON: true},
	// ── filesystems & snapshots ────────────────────────────────────
	{Name: "weka_fs", Cmd: "weka fs -v -J", JSON: true},
	{Name: "weka_fs_group", Cmd: "weka fs group -J", JSON: true},
	{Name: "weka_fs_snapshot", Cmd: "weka fs snapshot -v -J", JSON: true},
	{Name: "weka_fs_tier_s3", Cmd: "weka fs tier s3 -v -J", JSON: true},
	// ── debug & traces ─────────────────────────────────────────────
	{Name: "weka_debug_traces_status", Cmd: "weka debug traces status -J", JSON: true},
	{Name: "weka_debug_traces_freeze", Cmd: "weka debug traces freeze show -J", JSON: true},
	{Name: "weka_debug_net_links", Cmd: "weka debug net links -J", JSON: true},
	{Name: "weka_debug_override_list", Cmd: "weka debug override list -J", JSON: true},
	{Name: "weka_debug_blacklist", Cmd: "weka debug blacklist list -J", JSON: true},
	{Name: "weka_debug_buckets_dist", Cmd: "weka debug buckets dist -J", JSON: true},
	// ── security ───────────────────────────────────────────────────
	{Name: "weka_security_kms", Cmd: "weka security kms -J", JSON: true},
	// ── local container info (node-local: different per host) ─────────────
	{Name: "weka_local_ps", Cmd: "weka local ps -v -J", NodeLocal: true, JSON: true},
	{Name: "weka_local_resources_drives0", Cmd: "weka local resources -C drives0 -J", NodeLocal: true, JSON: true},
	{Name: "weka_local_resources_compute0", Cmd: "weka local resources -C compute0 -J", NodeLocal: true, JSON: true},
	{Name: "weka_local_resources_frontend0", Cmd: "weka local resources -C frontend0 -J", NodeLocal: true, JSON: true},
	// ── host hw info (node-local: different per host) ──────────────────────
	{Name: "weka_cluster_host_info_hw", Cmd: "weka cluster host info-hw -J", NodeLocal: true, JSON: true},
	// ── events, config dump, network peers (merged from former "full" profile) ──
	{Name: "weka_events_major", Cmd: "weka events --severity major -J", JSON: true},
	{Name: "weka_debug_net_peers", Cmd: "weka debug net peers 1 -J", JSON: true},
	{Name: "weka_cluster_container_info_hw", Cmd: "weka cluster container info-hw -J", JSON: true},
	{Name: "weka_cfgdump", Cmd: "weka local exec -C drives0 -- /weka/cfgdump", NodeLocal: true}, // raw exec, no -J
}

// buildPerfCommands returns the perf-profile command list, translating the
// --start-time/--end-time window into weka stats --start-time/--end-time flags.
func buildPerfCommands(from, to time.Time) []CommandSpec {
	// Build the time-window flags for weka stats.
	// weka stats accepts relative values like "-2h" or absolute ISO timestamps.
	timeFlags := ""
	if !from.IsZero() {
		timeFlags += fmt.Sprintf(" --start-time %s", from.Format("2006-01-02T15:04:05"))
	}
	if !to.IsZero() {
		timeFlags += fmt.Sprintf(" --end-time %s", to.Format("2006-01-02T15:04:05"))
	}

	stats := func(name, flags string) CommandSpec {
		return CommandSpec{
			Name:    name,
			Cmd:     "weka stats" + flags + timeFlags,
			Profile: ProfilePerf,
		}
	}

	return []CommandSpec{
		// CPU — per-process breakdown is critical for pinpointing hot nodes/roles.
		stats("weka_stats_cpu_per_process", " --show-internal --category cpu --per-process -s value"),
		stats("weka_stats_cpu_per_role", " --show-internal --category cpu --per-role -s value"),

		// SSD / drive I/O throughput and latency.
		stats("weka_stats_ssd", " --show-internal --category ssd --per-process"),
		stats("weka_stats_ssd_read_latency", " --show-internal --stat SSD_READ_LATENCY --per-process"),
		stats("weka_stats_ssd_write_latency", " --show-internal --stat SSD_WRITE_LATENCY --per-process"),
		stats("weka_stats_drive_read_latency", " --show-internal --stat DRIVE_READ_LATENCY --per-process"),
		stats("weka_stats_drive_write_latency", " --show-internal --stat DRIVE_WRITE_LATENCY --per-process"),
		// Client-visible I/O ops and latency.
		stats("weka_stats_ops_driver", " --show-internal --category ops_driver --per-process"),
		stats("weka_stats_ops", " --show-internal --category ops --per-process"),
		stats("weka_stats_read_latency", " --category ops --show-internal --stat READ_LATENCY --per-process"),
		stats("weka_stats_write_latency", " --category ops --show-internal --stat WRITE_LATENCY --per-process"),

		// Network throughput, goodput, and packet errors.
		stats("weka_stats_network", " --show-internal --category network --per-process"),
		stats("weka_stats_goodput_tx", " --show-internal --stat GOODPUT_TX_RATIO --per-process"),
		stats("weka_stats_goodput_rx", " --show-internal --stat GOODPUT_RX_RATIO --per-process"),
		stats("weka_stats_port_tx", " --show-internal --stat PORT_TX_BYTES --per-process"),
		stats("weka_stats_port_rx", " --show-internal --stat PORT_RX_BYTES --per-process"),
		stats("weka_stats_dropped_packets", " --show-internal --stat DROPPED_PACKETS --per-process"),
		stats("weka_stats_corrupt_packets", " --show-internal --stat CORRUPT_PACKETS --per-process"),

		// RPC/JRPC internals.
		stats("weka_stats_jrpc", " --show-internal --category jrpc --per-process"),
		stats("weka_stats_rpc", " --show-internal --category rpc --per-process"),

		// Realtime snapshot — always current 1s window, cannot take --start-time/--end-time.
		{
			Name:    "weka_stats_realtime",
			Cmd:     "weka stats realtime -s -cpu -o node,hostname,role,mode,writeps,writebps,wlatency,readps,readbps,rlatency,ops,cpu,l6recv,l6send,upload,download",
			Profile: ProfilePerf,
		},
	}
}

// nfsCommands are added for profile "nfs" or "all".
var nfsCommands = []CommandSpec{
	{Name: "weka_nfs_client_group", Cmd: "weka nfs client-group -J", Profile: ProfileNFS, JSON: true},
	{Name: "weka_nfs_interface_group", Cmd: "weka nfs interface-group -J", Profile: ProfileNFS, JSON: true},
	{Name: "weka_nfs_permission", Cmd: "weka nfs permission -J", Profile: ProfileNFS, JSON: true},
	{Name: "weka_nfs_global_config", Cmd: "weka nfs global-config show -J", Profile: ProfileNFS, JSON: true},
	{Name: "weka_nfs_custom_options", Cmd: "weka nfs custom-options -J", Profile: ProfileNFS, JSON: true},
	{Name: "showmount", Cmd: "showmount -e", Profile: ProfileNFS, NodeLocal: true},
	{Name: "weka_local_resources_ganesha", Cmd: "weka local resources -C ganesha -J", Profile: ProfileNFS, NodeLocal: true, JSON: true},
	{Name: "nfs_ganesha_config", Cmd: "weka local run /weka/cfgdump --container frontend0 | grep -i nfsGaneshaConfig -A 20", Profile: ProfileNFS, NodeLocal: true},
	{Name: "nfs_ganesha_queue", Cmd: "weka local exec --container ganesha cat /proc/wekafs/frontend0/queue", Profile: ProfileNFS, NodeLocal: true},
	{Name: "weka_stats_ops_nfsw", Cmd: "weka stats --category ops_nfsw --per-node -Z", Profile: ProfileNFS},
	{Name: "netstat_nfs", Cmd: "netstat -tupnl", Profile: ProfileNFS, NodeLocal: true},
}

// s3Commands are added for profile "s3" or "all".
var s3Commands = []CommandSpec{
	{Name: "weka_s3_cluster", Cmd: "weka s3 cluster -v -J", Profile: ProfileS3, JSON: true},
	{Name: "weka_s3_cluster_status", Cmd: "weka s3 cluster status -J", Profile: ProfileS3, JSON: true},
	{Name: "weka_s3_bucket_list", Cmd: "weka s3 bucket list -v -J", Profile: ProfileS3, JSON: true},
	{Name: "weka_s3_bucket_lifecycle", Cmd: "weka s3 bucket lifecycle-rule list -J", Profile: ProfileS3, JSON: true},
	{Name: "weka_s3_policy_list", Cmd: "weka s3 policy list -J", Profile: ProfileS3, JSON: true},
	{Name: "weka_s3_service_account", Cmd: "weka s3 service-account list -J", Profile: ProfileS3, JSON: true},
	{Name: "weka_s3_containers_list", Cmd: "weka s3 cluster containers list -J", Profile: ProfileS3, JSON: true},
	{Name: "weka_stats_ops_s3", Cmd: "weka stats --show-internal --category ops_s3 -Z", Profile: ProfileS3},
	{Name: "s3_cgroup_memory", Cmd: "cat /sys/fs/cgroup/memory/weka-s3/memory.limit_in_bytes && cat /sys/fs/cgroup/memory/weka-s3/memory.usage_in_bytes", Profile: ProfileS3, NodeLocal: true},
	{Name: "netstat_s3", Cmd: "netstat -tuln | grep 9001", Profile: ProfileS3, NodeLocal: true},
}

// smbwCommands are added for profile "smbw" or "all".
var smbwCommands = []CommandSpec{
	{Name: "weka_smb_cluster", Cmd: "weka smb cluster -J", Profile: ProfileSMBW, JSON: true},
	{Name: "weka_smb_cluster_status", Cmd: "weka smb cluster status -J", Profile: ProfileSMBW, JSON: true},
	{Name: "weka_smb_domain", Cmd: "weka smb domain -J", Profile: ProfileSMBW, JSON: true},
	{Name: "weka_smb_share", Cmd: "weka smb share -J", Profile: ProfileSMBW, JSON: true},
	{Name: "weka_smb_cluster_info", Cmd: "weka debug config show sambaClusterInfo -J", Profile: ProfileSMBW, JSON: true},
	{Name: "pcs_cluster_status", Cmd: "weka local exec --container smbw /usr/sbin/pcs cluster status", Profile: ProfileSMBW, NodeLocal: true},
	{Name: "pcs_status", Cmd: "weka local exec --container smbw /usr/sbin/pcs status", Profile: ProfileSMBW, NodeLocal: true},
	{Name: "pcs_status_resources", Cmd: "weka local exec --container smbw /usr/sbin/pcs status resources", Profile: ProfileSMBW, NodeLocal: true},
	{Name: "pcs_constraint", Cmd: "weka local exec --container smbw /usr/sbin/pcs constraint", Profile: ProfileSMBW, NodeLocal: true},
	{Name: "sssd_conf", Cmd: "cat /etc/sssd/sssd.conf", Profile: ProfileSMBW, NodeLocal: true},
}

// systemCommands run directly on the OS (not via weka CLI).
// These are always collected regardless of profile.
var systemCommands = []CommandSpec{
	// ── identity & hardware ───────────────────────────────────────────────
	{Name: "uname", Cmd: "uname -a"},
	{Name: "os_release", Cmd: "cat /etc/*release*"},
	{Name: "hostname", Cmd: "hostname -f"},
	{Name: "uptime", Cmd: "uptime"},
	{Name: "free_mem", Cmd: "free -h"},
	{Name: "lscpu", Cmd: "lscpu"},
	{Name: "lspci", Cmd: "lspci"},
	{Name: "lsblk", Cmd: "lsblk -d"},
	{Name: "numactl_hardware", Cmd: "numactl -H"},
	// ── processes & disk ─────────────────────────────────────────────────
	{Name: "ps_elf", Cmd: "ps -elf"},
	{Name: "df_h", Cmd: "df -h"},
	{Name: "netstat_all", Cmd: "netstat -nap"},
	// ── services ─────────────────────────────────────────────────────────
	{Name: "systemctl_failed", Cmd: "systemctl list-units --failed --no-pager"},
	// ── swap (must be disabled on Weka backends) ──────────────────────────
	{Name: "swapon", Cmd: "swapon --show"},
	// ── clock synchronization (critical for Weka cluster consistency) ─────
	// timedatectl works on all systemd distros
	{Name: "timedatectl", Cmd: "timedatectl status"},
	// chrony (RHEL 8+, Rocky, Ubuntu 20.04+)
	{Name: "chronyc_tracking", Cmd: "chronyc tracking"},
	{Name: "chronyc_sources", Cmd: "chronyc sources -v"},
	{Name: "chronyd_status", Cmd: "systemctl status chronyd --no-pager"},
	// ntpd fallback (older distros)
	{Name: "ntpd_status", Cmd: "systemctl status ntpd --no-pager"},
	// ── kernel parameters ─────────────────────────────────────────────────
	// sysctl -a captures all live values including numa_balancing, kernel.panic, etc.
	{Name: "sysctl_all", Cmd: "sysctl -a"},
	// kernel ring buffer with timestamps
	{Name: "dmesg", Cmd: "dmesg -T"},
	// ── kdump (should be enabled for crash diagnostics) ───────────────────
	{Name: "kdump_status", Cmd: "systemctl status kdump --no-pager"},
	// Ubuntu uses kdump-tools instead
	{Name: "kdump_tools_status", Cmd: "systemctl status kdump-tools --no-pager"},
	// ── NIC / OFED / routing ──────────────────────────────────────────────
	{Name: "lshw_network", Cmd: "lshw -C network -businfo"},
	{Name: "ofed_info", Cmd: "ofed_info -s"},
	{Name: "lsmod", Cmd: "lsmod"},
	{Name: "modinfo_mlx5_core", Cmd: "modinfo mlx5_core"},
	{Name: "modinfo_ice", Cmd: "modinfo ice"},
	// ethtool per interface: link speed, duplex, driver, MTU validation
	{Name: "ethtool_all", Cmd: `for iface in $(ls /sys/class/net/); do echo "=== $iface ==="; ethtool "$iface" 2>&1; ethtool -i "$iface" 2>&1; done`},
	{Name: "ip_rule", Cmd: "ip rule"},
	{Name: "ip_neighbor", Cmd: "ip neighbor"},
	{Name: "ip_route_all_tables", Cmd: "ip route show table all"},
	{Name: "rp_filter", Cmd: "sysctl -a | grep -w rp_filter"},
	// ── Mellanox firmware settings (ADVANCED_PCI_SETTINGS, PCI_WR_ORDERING) ─
	// mst/mlxconfig only present on nodes with ConnectX NICs + MFT package;
	// fails gracefully on Intel/other NIC nodes
	{Name: "mst_status", Cmd: "mst status -v"},
	{Name: "mlxconfig_query", Cmd: `for d in /dev/mst/mt*_pciconf0; do echo "=== $d ==="; mlxconfig -d "$d" query 2>&1; done`},
	// weka-agent service journal — full history, no line cap
	{Name: "journalctl_weka_agent", Cmd: "journalctl -u weka-agent --no-pager"},
}

// LogFileSpec describes a set of log files to collect.
// All matched files are always collected in full — no time-window filtering.
// The --start-time/--end-time window applies only to journalctl, not to file collection.
type LogFileSpec struct {
	// SrcGlob is a shell glob pattern for source files
	SrcGlob string
	// DestDir is the subdirectory inside the archive
	DestDir string
	// Profile — empty means always collect regardless of profile
	Profile string
}

var logFileSpecs = []LogFileSpec{
	// ── system logs — collected in full, all rotated variants ─────────────
	// RHEL/OCI family (/var/log/messages, /var/log/secure, /var/log/cron)
	{SrcGlob: "/var/log/messages", DestDir: "system"},
	{SrcGlob: "/var/log/messages-*", DestDir: "system"},
	{SrcGlob: "/var/log/messages.?", DestDir: "system"},
	{SrcGlob: "/var/log/secure", DestDir: "system"},
	{SrcGlob: "/var/log/secure-*", DestDir: "system"},
	{SrcGlob: "/var/log/cron", DestDir: "system"},
	{SrcGlob: "/var/log/cron-*", DestDir: "system"},
	// Debian/Ubuntu family
	{SrcGlob: "/var/log/syslog", DestDir: "system"},
	{SrcGlob: "/var/log/syslog.*", DestDir: "system"},
	{SrcGlob: "/var/log/kern.log", DestDir: "system"},
	{SrcGlob: "/var/log/kern.log.*", DestDir: "system"},
	// Boot and init
	{SrcGlob: "/var/log/boot.log", DestDir: "system"},
	{SrcGlob: "/var/log/boot.log-*", DestDir: "system"},
	{SrcGlob: "/var/log/dmesg", DestDir: "system"},
	{SrcGlob: "/var/log/dmesg.*", DestDir: "system"},
	// Cloud-init (important on OCI/AWS instances)
	{SrcGlob: "/var/log/cloud-init.log", DestDir: "system"},
	{SrcGlob: "/var/log/cloud-init-output.log", DestDir: "system"},
	// Audit log
	{SrcGlob: "/var/log/audit/audit.log", DestDir: "system/audit"},
	{SrcGlob: "/var/log/audit/audit.log.*", DestDir: "system/audit"},
	// Package manager logs (useful for kernel/driver upgrade history)
	{SrcGlob: "/var/log/dnf.log", DestDir: "system"},
	{SrcGlob: "/var/log/dnf.log-*", DestDir: "system"},
	{SrcGlob: "/var/log/yum.log", DestDir: "system"},
	{SrcGlob: "/var/log/yum.log-*", DestDir: "system"},
	// Kernel parameter config files (Weka best-practice settings live in 99-weka.conf)
	{SrcGlob: "/etc/sysctl.conf", DestDir: "system/sysctl.d"},
	{SrcGlob: "/etc/sysctl.d/*.conf", DestDir: "system/sysctl.d"},
	{SrcGlob: "/usr/lib/sysctl.d/*.conf", DestDir: "system/sysctl.d"},
	{SrcGlob: "/run/sysctl.d/*.conf", DestDir: "system/sysctl.d"},
	// kdump config (RHEL/Rocky path; Ubuntu uses /etc/default/kdump-tools)
	{SrcGlob: "/etc/kdump.conf", DestDir: "system"},
	{SrcGlob: "/etc/default/kdump-tools", DestDir: "system"},

	// ── weka container logs — broad catch-alls cover the full tree ────────
	//
	// Directory structure (confirmed from live cluster):
	//   /opt/weka/logs/<container>/<file>           depth-1: syslog.log*, supervisord.log*, upgrade.log*, tsmb.log*, etc.
	//   /opt/weka/logs/<container>/weka/<file>      depth-2: output.log*, shelld.log*, events.log*, trace-server.log*, nginx-stdout.log*, rotator.log*, etc.
	//   /opt/weka/logs/<container>/wtracer/<file>   depth-2: wtracer-dumper.log
	//   /opt/weka/logs/<container>/nginx/<file>     depth-2: access.log, error.log
	//   /opt/weka/logs/<container>/pacemaker/<file> depth-2: pacemaker.log*
	//   /opt/weka/logs/<container>/corosync/<file>  depth-2: corosync.log
	//   /opt/weka/logs/<container>/pcsd/<file>      depth-2: pcsd.log
	//
	// Two depth levels cover everything. seenSrcPaths deduplicates overlaps.
	//
	// Core containers (drives*, compute*, frontend*) are always collected.
	// Protocol containers (ganesha*, s3*, envoy*, smbw*) are only collected
	// when the matching profile is active — their log directories only exist
	// on nodes where the protocol is actually running, so on non-protocol
	// nodes the globs simply match nothing.

	// ── core containers (always collected) ───────────────────────────────
	{SrcGlob: "/opt/weka/logs/drives*/*.log*", DestDir: "weka/containers"},
	{SrcGlob: "/opt/weka/logs/drives*/*.json", DestDir: "weka/containers"},
	{SrcGlob: "/opt/weka/logs/drives*/*/*.log*", DestDir: "weka/containers"},
	{SrcGlob: "/opt/weka/logs/compute*/*.log*", DestDir: "weka/containers"},
	{SrcGlob: "/opt/weka/logs/compute*/*.json", DestDir: "weka/containers"},
	{SrcGlob: "/opt/weka/logs/compute*/*/*.log*", DestDir: "weka/containers"},
	{SrcGlob: "/opt/weka/logs/frontend*/*.log*", DestDir: "weka/containers"},
	{SrcGlob: "/opt/weka/logs/frontend*/*.json", DestDir: "weka/containers"},
	{SrcGlob: "/opt/weka/logs/frontend*/*/*.log*", DestDir: "weka/containers"},

	// ── NFS / Ganesha container logs (profile: nfs) ───────────────────────
	{SrcGlob: "/opt/weka/logs/ganesha*/*.log*", DestDir: "weka/containers", Profile: ProfileNFS},
	{SrcGlob: "/opt/weka/logs/ganesha*/*.json", DestDir: "weka/containers", Profile: ProfileNFS},
	{SrcGlob: "/opt/weka/logs/ganesha*/*/*.log*", DestDir: "weka/containers", Profile: ProfileNFS},

	// ── S3 / Envoy container logs (profile: s3) ───────────────────────────
	{SrcGlob: "/opt/weka/logs/s3*/*.log*", DestDir: "weka/containers", Profile: ProfileS3},
	{SrcGlob: "/opt/weka/logs/s3*/*.json", DestDir: "weka/containers", Profile: ProfileS3},
	{SrcGlob: "/opt/weka/logs/s3*/*/*.log*", DestDir: "weka/containers", Profile: ProfileS3},
	{SrcGlob: "/opt/weka/logs/envoy*/*.log*", DestDir: "weka/containers", Profile: ProfileS3},
	{SrcGlob: "/opt/weka/logs/envoy*/*/*.log*", DestDir: "weka/containers", Profile: ProfileS3},

	// ── SMB-W / Pacemaker / Corosync container logs (profile: smbw) ──────
	{SrcGlob: "/opt/weka/logs/smbw*/*.log*", DestDir: "weka/containers", Profile: ProfileSMBW},
	{SrcGlob: "/opt/weka/logs/smbw*/*.json", DestDir: "weka/containers", Profile: ProfileSMBW},
	{SrcGlob: "/opt/weka/logs/smbw*/*/*.log*", DestDir: "weka/containers", Profile: ProfileSMBW},

	// ── vendor/driver logs ────────────────────────────────────────────────
	{SrcGlob: "/var/log/mlnx/*.log", DestDir: "vendor/mlnx"},
	{SrcGlob: "/var/log/mlnx/*.log.*", DestDir: "vendor/mlnx"},
	{SrcGlob: "/opt/weka/data/driver/weka-driver/log/*.log", DestDir: "weka/driver"},
	{SrcGlob: "/opt/weka/data/driver/weka-driver/log/*.log.*", DestDir: "weka/driver"},
}

// ── space checking ────────────────────────────────────────────────────────────

const (
	// minFreeSpaceMB is the minimum free space (MB) we require on the output
	// filesystem before starting collection. Writing even a compressed bundle
	// can temporarily use more than the final size.
	minFreeSpaceMB = 200
	// safetyMarginFraction: we refuse to use more than this fraction of total
	// available space (so we don't fill the disk).
	safetyMarginFraction = 0.80
)

type diskInfo struct {
	AvailMB uint64
	TotalMB uint64
	Path    string
}

func checkDiskSpace(path string) (diskInfo, error) {
	var stat syscall.Statfs_t
	// Walk up to find the mount point if path doesn't exist yet
	dir := path
	for {
		if err := syscall.Statfs(dir, &stat); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return diskInfo{}, fmt.Errorf("could not stat any parent of %s", path)
		}
		dir = parent
	}
	blockSize := uint64(stat.Bsize)
	availMB := (stat.Bavail * blockSize) / (1024 * 1024)
	totalMB := (stat.Blocks * blockSize) / (1024 * 1024)
	return diskInfo{AvailMB: availMB, TotalMB: totalMB, Path: dir}, nil
}

// estimateCollectionMB returns a rough upper-bound estimate of how much disk
// space the collection will use after compression.
// nodeCount should be 1 for local collection, or the number of remote hosts
// for cluster collection — log files scale linearly with node count.
func estimateCollectionMB(profile string, logSpecs []LogFileSpec, nodeCount int) uint64 {
	var totalBytes int64
	for _, spec := range logSpecs {
		if spec.Profile != "" && spec.Profile != profile && profile != ProfileAll {
			continue
		}
		matches, err := filepath.Glob(spec.SrcGlob)
		if err != nil || len(matches) == 0 {
			continue
		}
		for _, f := range matches {
			info, err := os.Stat(f)
			if err != nil {
				continue
			}
			totalBytes += info.Size()
		}
	}
	// Scale log files by node count (cluster commands run once, not per node,
	// so only multiply the per-node portion — approximated as 80% of total).
	if nodeCount > 1 {
		perNodeBytes := totalBytes * 80 / 100
		clusterOnceBytes := totalBytes - perNodeBytes
		totalBytes = perNodeBytes*int64(nodeCount) + clusterOnceBytes
	}
	// Add ~20MB overhead for command outputs per node
	totalBytes += int64(max(1, nodeCount)) * 20 * 1024 * 1024
	// Assume ~30% compression ratio for mixed log content
	compressedMB := uint64(totalBytes/1024/1024) * 30 / 100
	if compressedMB < 5 {
		compressedMB = 5
	}
	return compressedMB
}

// ── collection result tracking ────────────────────────────────────────────────

// CollectionStatus records what happened during collection.
type CollectionStatus int

const (
	StatusOK      CollectionStatus = iota
	StatusWarning                  // collected but some items missing
	StatusFailed                   // host/command collection failed
)

// CommandResult records the outcome of a single command.
type CommandResult struct {
	Name     string        `json:"name"`
	Command  string        `json:"command"`
	ExitCode int           `json:"exit_code"`
	Duration time.Duration `json:"duration_ms"`
	Error    string        `json:"error,omitempty"`
	Skipped  bool          `json:"skipped,omitempty"`
	SkipNote string        `json:"skip_reason,omitempty"`
}

// FileResult records the outcome of a single log file collection.
type FileResult struct {
	SrcPath   string `json:"src_path"`
	DestPath  string `json:"dest_path"`
	SizeBytes int64  `json:"size_bytes"`
	Error     string `json:"error,omitempty"`
	Skipped   bool   `json:"skipped,omitempty"`
	SkipNote  string `json:"skip_reason,omitempty"`
}

// HostManifest is written into the archive as collection_manifest.json
// for each host, describing everything that was attempted and what succeeded.
type HostManifest struct {
	Hostname       string          `json:"hostname"`
	CollectedAt    time.Time       `json:"collected_at"`
	Profile        string          `json:"profile"`
	From           *time.Time      `json:"from,omitempty"`
	To             *time.Time      `json:"to,omitempty"`
	WekaVersion    string          `json:"weka_version,omitempty"`
	Commands       []CommandResult `json:"commands"`
	Files          []FileResult    `json:"files"`
	Errors         []string        `json:"errors,omitempty"`
	TotalFiles     int             `json:"total_files"`
	CollectedFiles int             `json:"collected_files"`
	FailedFiles    int             `json:"failed_files"`
	TotalCommands  int             `json:"total_commands"`
	FailedCommands int             `json:"failed_commands"`
}

// ── progress output ───────────────────────────────────────────────────────────

// verbose controls whether verbose output is printed to stderr.
var verbose bool

// debugLog receives all log output (including verbose) regardless of the
// --verbose flag. It is set to a real file early in main; until then it
// discards writes so the functions are safe to call before main initialises it.
var debugLog io.Writer = io.Discard

func logf(format string, args ...interface{}) {
	line := fmt.Sprintf(format+"\n", args...)
	fmt.Fprint(os.Stderr, line)
	fmt.Fprint(debugLog, line)
}

func vlogf(format string, args ...interface{}) {
	line := fmt.Sprintf("[verbose] "+format+"\n", args...)
	if verbose {
		fmt.Fprint(os.Stderr, line)
	}
	fmt.Fprint(debugLog, line) // always written to log file
}

func warnf(format string, args ...interface{}) {
	line := fmt.Sprintf("[WARN]  "+format+"\n", args...)
	fmt.Fprint(os.Stderr, line)
	fmt.Fprint(debugLog, line)
}

func errorf(format string, args ...interface{}) {
	line := fmt.Sprintf("[ERROR] "+format+"\n", args...)
	fmt.Fprint(os.Stderr, line)
	fmt.Fprint(debugLog, line)
}

func phase(name string) {
	line := fmt.Sprintf("\n==> %s\n", name)
	fmt.Fprint(os.Stderr, line)
	fmt.Fprint(debugLog, line)
}

// ── command runner ────────────────────────────────────────────────────────────

// cmdWorkers is the number of commands run in parallel within a single host collection.
// Commands are weka CLI calls (API calls to the management plane) and OS commands
// that are independent of each other — running them concurrently gives a large
// speedup over sequential execution.
const cmdWorkers = 8

// cmdOutput holds the result of a single command execution.
type cmdOutput struct {
	result CommandResult
	out    []byte
}

// runCommandsParallel runs specs concurrently (up to cmdWorkers at a time) and
// returns results in the same order as specs. It is safe to call from a single
// goroutine; tar writes happen after this returns.
func runCommandsParallel(specs []CommandSpec, timeout time.Duration) []cmdOutput {
	outputs := make([]cmdOutput, len(specs))
	sem := make(chan struct{}, cmdWorkers)
	var wg sync.WaitGroup
	for i, spec := range specs {
		i, spec := i, spec
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			result, out := runCommand(spec, timeout)
			outputs[i] = cmdOutput{result, out}
		}()
	}
	wg.Wait()
	return outputs
}

// runCommand executes a shell command with a timeout and returns its output.
// It is always non-fatal: errors are captured in the returned CommandResult.
func runCommand(spec CommandSpec, timeout time.Duration) (CommandResult, []byte) {
	start := time.Now()
	result := CommandResult{
		Name:    spec.Name,
		Command: spec.Cmd,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", spec.Cmd)
	out, err := cmd.Output()
	result.Duration = time.Since(start)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
			// Include stderr in output for diagnosis
			if len(exitErr.Stderr) > 0 {
				result.Error = strings.TrimSpace(string(exitErr.Stderr))
			} else {
				result.Error = err.Error()
			}
		} else {
			result.Error = err.Error()
		}
		vlogf("  command %q: exit %d: %s", spec.Name, result.ExitCode, result.Error)
	} else {
		vlogf("  command %q: OK (%s, %d bytes)", spec.Name, result.Duration.Round(time.Millisecond), len(out))
	}
	return result, out
}

// journalctlWithWindow runs journalctl filtered to the collection time window.
func journalctlWithWindow(from, to time.Time, timeout time.Duration) (CommandResult, []byte) {
	var cmd string
	switch {
	case !from.IsZero() && !to.IsZero():
		cmd = fmt.Sprintf("journalctl --no-pager -S '%s' -U '%s'",
			from.Format("2006-01-02 15:04:05"),
			to.Format("2006-01-02 15:04:05"))
	case !from.IsZero():
		cmd = fmt.Sprintf("journalctl --no-pager -S '%s'",
			from.Format("2006-01-02 15:04:05"))
	default:
		cmd = "journalctl --no-pager -n 10000"
	}
	return runCommand(CommandSpec{Name: "journalctl", Cmd: cmd}, timeout)
}

// ── log file collector ────────────────────────────────────────────────────────

// globBase returns the static prefix of a glob pattern — everything before the
// first wildcard character. Used to strip the base from matched paths so that
// directory structure is preserved in the archive.
//
// Examples:
//
//	/opt/weka/logs/*/syslog.log   → "/opt/weka/logs/"
//	/var/log/messages             → "/var/log/"
//	/opt/weka/logs/smbw/pacemaker/pacemaker.log → "/opt/weka/logs/smbw/pacemaker/"
func globBase(pattern string) string {
	idx := strings.IndexAny(pattern, "*?[")
	if idx < 0 {
		// No wildcard — use the directory containing the file.
		return filepath.Dir(pattern) + "/"
	}
	// Use the directory that *contains* the first wildcard component.
	// e.g. /var/log/messages-*  → /var/log/   (not /var/log/messages-)
	// e.g. /opt/weka/logs/*/syslog.log → /opt/weka/logs/
	// e.g. /var/log/audit/audit.log.*  → /var/log/audit/
	return filepath.Dir(pattern[:idx]) + "/"
}

// prepareFileReader returns the reader, size, and archive destination name to
// use when adding srcPath to the tar archive.
//
// For .gz rotated log files the file is decompressed into a temp file so that
// the outer gzip archive can compress the plaintext data — individually
// pre-compressed chunks inside a tar.gz are opaque to the outer compressor and
// produce no savings. Decompressing first lets gzip work across all log content
// together, significantly improving the overall compression ratio.
//
// On any decompression error the function falls back to the original compressed
// file so collection always succeeds. The returned cleanup func (if non-nil)
// must be called after the caller is done reading.
func prepareFileReader(f *os.File, info os.FileInfo, srcPath, destPath string) (reader io.Reader, size int64, archiveDest string, cleanup func()) {
	if !strings.HasSuffix(srcPath, ".gz") {
		// Not gzip — use LimitReader to guard against live-growing files.
		return io.LimitReader(f, info.Size()), info.Size(), destPath, nil
	}

	gz, err := gzip.NewReader(f)
	if err != nil {
		// Not a valid gzip stream — fall back to raw copy.
		_, _ = f.Seek(0, 0)
		return io.LimitReader(f, info.Size()), info.Size(), destPath, nil
	}

	tmp, err := os.CreateTemp("", "wlc-decomp-*")
	if err != nil {
		gz.Close()
		_, _ = f.Seek(0, 0)
		return io.LimitReader(f, info.Size()), info.Size(), destPath, nil
	}

	if _, err := io.Copy(tmp, gz); err != nil {
		gz.Close()
		tmp.Close()
		os.Remove(tmp.Name())
		_, _ = f.Seek(0, 0)
		return io.LimitReader(f, info.Size()), info.Size(), destPath, nil
	}
	gz.Close()

	tmpInfo, err := tmp.Stat()
	if err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		_, _ = f.Seek(0, 0)
		return io.LimitReader(f, info.Size()), info.Size(), destPath, nil
	}
	_, _ = tmp.Seek(0, 0)

	return tmp, tmpInfo.Size(), strings.TrimSuffix(destPath, ".gz"), func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}
}

// collectLogFile adds a single log file to the tar writer.
// destPath is the full path inside the archive (archiveRoot already included).
// .gz rotated files are transparently decompressed before archiving so the
// outer gzip can compress all log content together for a better overall ratio.
// Returns a FileResult describing success or failure.
func collectLogFile(tw *tar.Writer, srcPath, destPath string) FileResult {
	result := FileResult{
		SrcPath:  srcPath,
		DestPath: destPath,
	}

	f, err := os.Open(srcPath)
	if err != nil {
		result.Error = fmt.Sprintf("open: %v", err)
		vlogf("  file %s: SKIP: %s", srcPath, result.Error)
		result.Skipped = true
		return result
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		result.Error = fmt.Sprintf("stat: %v", err)
		result.Skipped = true
		return result
	}

	reader, size, archiveDest, cleanup := prepareFileReader(f, info, srcPath, destPath)
	if cleanup != nil {
		defer cleanup()
	}
	result.DestPath = archiveDest
	result.SizeBytes = size

	hdr := &tar.Header{
		Name:    archiveDest,
		Mode:    0644,
		Size:    size,
		ModTime: info.ModTime(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		result.Error = fmt.Sprintf("tar header: %v", err)
		return result
	}
	if _, err := io.Copy(tw, reader); err != nil {
		result.Error = fmt.Sprintf("tar copy: %v", err)
		return result
	}
	vlogf("  file %s: OK (%d bytes)", srcPath, size)
	return result
}

// addBytesToArchive adds in-memory bytes as a file in the tar archive.
func addBytesToArchive(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0644,
		Size:    int64(len(data)),
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

// ── local collection ──────────────────────────────────────────────────────────

// CollectLocal collects all logs and command outputs from the local host and
// writes them into the provided tar.Writer under archiveRoot.
// When nodeOnly is true, cluster-wide weka commands (those with NodeLocal==false
// in defaultCommands and profile command slices) are skipped — they will be run
// once by the cluster orchestrator instead.
// Returns a HostManifest describing what was collected.
func CollectLocal(tw *tar.Writer, archiveRoot, profile string, from, to time.Time, cmdTimeout time.Duration, nodeOnly bool) HostManifest {
	hostname, _ := os.Hostname()
	manifest := HostManifest{
		Hostname:    hostname,
		CollectedAt: time.Now(),
		Profile:     profile,
	}
	if !from.IsZero() {
		t := from
		manifest.From = &t
	}
	if !to.IsZero() {
		t := to
		manifest.To = &t
	}

	hostRoot := filepath.Join(archiveRoot, "hosts", hostname)

	// ── phase: system commands (parallel) ────────────────────────────────
	phase(fmt.Sprintf("[%s] System commands (%d parallel)", hostname, cmdWorkers))
	sysOutputs := runCommandsParallel(systemCommands, cmdTimeout)
	for i, spec := range systemCommands {
		co := sysOutputs[i]
		manifest.Commands = append(manifest.Commands, co.result)
		if co.result.Error != "" {
			warnf("[%s] command %q failed (exit %d): %s", hostname, spec.Name, co.result.ExitCode, co.result.Error)
		}
		content := co.out
		if co.result.Error != "" && len(co.out) == 0 {
			content = []byte(fmt.Sprintf("# command: %s\n# error: %s\n", spec.Cmd, co.result.Error))
		}
		ext := ".txt"
		if spec.JSON {
			ext = ".json"
		}
		dest := filepath.Join(hostRoot, "system", spec.Name+ext)
		if err := addBytesToArchive(tw, dest, content); err != nil {
			warnf("[%s] could not add %s to archive: %v", hostname, spec.Name, err)
		}
	}

	// ── phase: weka CLI commands (parallel) ───────────────────────────────
	phase(fmt.Sprintf("[%s] Weka commands (profile: %s, %d parallel)", hostname, profile, cmdWorkers))

	allWekaCmds := append(append([]CommandSpec{}, defaultCommands...), buildProfileCommands(profile, from, to)...)

	// Filter to the commands we'll actually run on this node before parallelising.
	var wekaToRun []CommandSpec
	for _, spec := range allWekaCmds {
		if nodeOnly && !spec.NodeLocal {
			vlogf("  [%s] skipping cluster-wide command %s (--node-only)", hostname, spec.Name)
			continue
		}
		wekaToRun = append(wekaToRun, spec)
	}
	logf("  [%s] running %d weka commands", hostname, len(wekaToRun))
	wekaOutputs := runCommandsParallel(wekaToRun, cmdTimeout)
	for i, spec := range wekaToRun {
		co := wekaOutputs[i]
		manifest.Commands = append(manifest.Commands, co.result)
		if co.result.Error != "" {
			if spec.Profile != "" {
				// Protocol-specific command — failure is expected when the protocol
				// is not deployed on this cluster. Log to verbose/debug only.
				vlogf("[%s] command %q failed (exit %d): %s", hostname, spec.Name, co.result.ExitCode, co.result.Error)
			} else {
				warnf("[%s] command %q failed (exit %d): %s", hostname, spec.Name, co.result.ExitCode, co.result.Error)
			}
		}
		content := co.out
		if co.result.Error != "" && len(co.out) == 0 {
			content = []byte(fmt.Sprintf("# command: %s\n# error: %s\n", spec.Cmd, co.result.Error))
		}
		ext := ".txt"
		if spec.JSON {
			ext = ".json"
		}
		dest := filepath.Join(hostRoot, "weka", spec.Name+ext)
		if err := addBytesToArchive(tw, dest, content); err != nil {
			warnf("[%s] could not add %s to archive: %v", hostname, spec.Name, err)
		}
		if spec.Name == "weka_version" && len(co.out) > 0 {
			manifest.WekaVersion = strings.TrimSpace(string(co.out))
		}
	}

	// ── phase: journalctl ────────────────────────────────────────────────
	if true {
		phase(fmt.Sprintf("[%s] Journalctl (time-windowed)", hostname))
		result, out := journalctlWithWindow(from, to, 2*cmdTimeout)
		manifest.Commands = append(manifest.Commands, result)
		if result.Error != "" {
			warnf("[%s] journalctl failed: %s", hostname, result.Error)
		}
		_ = addBytesToArchive(tw, filepath.Join(hostRoot, "system", "journalctl.txt"), out)
	}

	// ── phase: log files ──────────────────────────────────────────────────
	// seenSrcPaths prevents the same source file being added twice when
	// multiple glob specs overlap (e.g. specific spec + catch-all).
	seenSrcPaths := map[string]bool{}

	phase(fmt.Sprintf("[%s] Log files", hostname))
	for _, spec := range logFileSpecs {
		if spec.Profile != "" && !profileEnabled(profile, spec.Profile) {
			vlogf("[%s] skipping log spec %s (profile %s not active)", hostname, spec.SrcGlob, spec.Profile)
			continue
		}
		matches, err := filepath.Glob(spec.SrcGlob)
		if err != nil {
			warnf("[%s] glob %s failed: %v", hostname, spec.SrcGlob, err)
			continue
		}
		if len(matches) == 0 {
			vlogf("[%s] no files match %s", hostname, spec.SrcGlob)
			continue
		}
		matches = filterByTimeWindow(matches, from, to)
		if len(matches) == 0 {
			vlogf("[%s] no files in time window for %s", hostname, spec.SrcGlob)
			continue
		}
		for _, srcPath := range matches {
			if seenSrcPaths[srcPath] {
				vlogf("[%s] skip duplicate %s", hostname, srcPath)
				continue
			}
			seenSrcPaths[srcPath] = true
			vlogf("  [%s] collecting: %s", hostname, srcPath)
			// Preserve directory structure relative to the glob base so that
			// e.g. /opt/weka/logs/compute0/syslog.log ends up at
			// hosts/<host>/weka/containers/compute0/syslog.log, not
			// hosts/<host>/weka/containers/syslog.log (which would overwrite
			// the same filename from drives0, frontend0, etc.)
			base := globBase(spec.SrcGlob)
			relPath := strings.TrimPrefix(srcPath, base)
			destPath := filepath.Join(archiveRoot, "hosts", hostname, spec.DestDir, relPath)
			fr := collectLogFile(tw, srcPath, destPath)
			manifest.Files = append(manifest.Files, fr)
			if fr.Error != "" {
				warnf("[%s] file %s: %s", hostname, srcPath, fr.Error)
			}
		}
	}

	// ── tally results ─────────────────────────────────────────────────────
	manifest.TotalCommands = len(manifest.Commands)
	for _, r := range manifest.Commands {
		if r.Error != "" {
			manifest.FailedCommands++
		}
	}
	manifest.TotalFiles = len(manifest.Files)
	for _, r := range manifest.Files {
		if r.Error != "" {
			manifest.FailedFiles++
		} else if !r.Skipped {
			manifest.CollectedFiles++
		}
	}
	return manifest
}

// buildProfileCommands returns the additional commands for a given profile.
func buildProfileCommands(profile string, from, to time.Time) []CommandSpec {
	var cmds []CommandSpec
	addIfProfile := func(list []CommandSpec, p string) {
		if profileEnabled(profile, p) {
			cmds = append(cmds, list...)
		}
	}
	if profileEnabled(profile, ProfilePerf) {
		cmds = append(cmds, buildPerfCommands(from, to)...)
	}
	addIfProfile(nfsCommands, ProfileNFS)
	addIfProfile(s3Commands, ProfileS3)
	addIfProfile(smbwCommands, ProfileSMBW)
	return cmds
}

// buildClusterWideCmds returns all commands (default + profile) that produce
// identical output on every node and should be run exactly once by the orchestrator.
// These are commands with NodeLocal==false.
func buildClusterWideCmds(profile string, from, to time.Time) []CommandSpec {
	all := append(append([]CommandSpec{}, defaultCommands...), buildProfileCommands(profile, from, to)...)
	var cmds []CommandSpec
	for _, spec := range all {
		if !spec.NodeLocal {
			cmds = append(cmds, spec)
		}
	}
	return cmds
}

// ── multi-host SSH collection ─────────────────────────────────────────────────

// HostResult is the outcome of collecting from a single remote host.
type HostResult struct {
	Host     string
	Manifest *HostManifest
	TempFile string // path to temp .tar.gz on disk; caller must os.Remove when done
	Err      error
}

// sshArgs returns the common SSH option flags used for all SSH/SCP calls.
func sshArgs() []string {
	return []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=30",
		"-o", "BatchMode=yes",
	}
}

// collectFromHost SSHs into a host, runs weka-log-collector --local, and
// streams the tar.gz back.
//
// When selfDeploy is true (the default), it first creates /opt/weka/tools/ on
// the remote host, scps the running binary there, runs it, then removes it on
// exit — so no manual pre-deployment is required. /opt/weka/tools/ is used
// instead of /tmp to avoid noexec mount issues common on hardened systems.
//
// When selfDeploy is false, binaryPath must already exist on the remote host.
func collectFromHost(host, selfPath, binaryPath, profile string, from, to time.Time, sshUser string, selfDeploy bool, sshTimeout time.Duration) HostResult {
	result := HostResult{Host: host}

	sshTarget := host
	if sshUser != "" {
		sshTarget = sshUser + "@" + host
	}

	// ── auto-deploy: scp binary to /tmp on the remote host ────────────────
	remoteBin := binaryPath
	if selfDeploy {
		// Use a PID-suffixed name so the orchestrator never overwrites its own
		// running binary when it is also a member of the cluster being collected.
		// /opt/weka/tools/ is always present and executable on Weka nodes;
		// /tmp is often mounted noexec on hardened systems.
		remoteBin = fmt.Sprintf("/opt/weka/tools/weka-log-collector-%d", os.Getpid())

		// Ensure the tools directory exists on the remote host.
		mkdirArgs := append(sshArgs(), sshTarget, "mkdir -p /opt/weka/tools")
		mkdirCmd := exec.Command("ssh", mkdirArgs...)
		if out, err := mkdirCmd.CombinedOutput(); err != nil {
			result.Err = fmt.Errorf("mkdir /opt/weka/tools failed: %v: %s", err, strings.TrimSpace(string(out)))
			errorf("[%s] collection failed: %v", host, result.Err)
			return result
		}

		logf("  [%s] deploying binary via scp...", host)
		scpArgs := append(sshArgs(), selfPath, sshTarget+":"+remoteBin)
		scpCmd := exec.Command("scp", scpArgs...)
		if out, err := scpCmd.CombinedOutput(); err != nil {
			result.Err = fmt.Errorf("scp failed: %v: %s", err, strings.TrimSpace(string(out)))
			errorf("[%s] collection failed: %v", host, result.Err)
			return result
		}
		vlogf("[%s] binary deployed to %s", host, remoteBin)
	}

	// ── build the remote command ───────────────────────────────────────────
	// When self-deployed, wrap in a shell that removes the binary on exit
	// (whether collection succeeds or fails) to keep /tmp clean.
	// --node-only tells the remote to skip cluster-wide commands (run once by orchestrator).
	collectionCmd := strings.Join(append([]string{
		remoteBin,
		"--local",
		"--node-only",
		"--profile", profile,
		"--output", "-",
	}, func() []string {
		var extra []string
		if !from.IsZero() {
			extra = append(extra, "--start-time", from.Format("2006-01-02T15:04"))
		}
		if !to.IsZero() {
			extra = append(extra, "--end-time", to.Format("2006-01-02T15:04"))
		}
		if verbose {
			extra = append(extra, "--verbose")
		}
		return extra
	}()...), " ")

	var remoteShellCmd string
	if selfDeploy {
		// trap ensures cleanup even if collection fails or connection drops
		remoteShellCmd = fmt.Sprintf(
			"chmod +x %s; trap 'rm -f %s' EXIT; %s",
			remoteBin, remoteBin, collectionCmd,
		)
	} else {
		remoteShellCmd = collectionCmd
	}

	// ── run collection via SSH, streaming output to a temp file ──────────
	// Streaming to disk (not RAM) prevents accumulating 200-400 MB per host
	// in memory simultaneously when collecting a large cluster in parallel.
	logf("  [%s] collecting...", host)
	tmpFile, err := os.CreateTemp("", "wlc-host-*.tar.gz")
	if err != nil {
		result.Err = fmt.Errorf("create temp file: %w", err)
		errorf("[%s] collection failed: %v", host, result.Err)
		return result
	}
	tmpPath := tmpFile.Name()

	var stderrBuf bytes.Buffer
	sshCmd := exec.Command("ssh", append(sshArgs(), sshTarget, remoteShellCmd)...)
	sshCmd.Stdout = tmpFile
	sshCmd.Stderr = &stderrBuf
	runErr := sshCmd.Run()
	tmpFile.Close()

	if runErr != nil {
		os.Remove(tmpPath)
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			result.Err = fmt.Errorf("SSH command failed (exit %d): %s",
				exitErr.ExitCode(), strings.TrimSpace(stderrBuf.String()))
		} else {
			result.Err = fmt.Errorf("SSH error: %v", runErr)
		}
		errorf("[%s] collection failed: %v", host, result.Err)
		return result
	}

	if info, err := os.Stat(tmpPath); err == nil {
		logf("  [%s] collected %d KB", host, info.Size()/1024)
	}
	result.TempFile = tmpPath
	return result
}

// clusterNode represents a Weka cluster container with its numeric ID, primary IP, and mode.
type clusterNode struct {
	ID   int
	IP   string
	Mode string // "backend", "client", "nfs", "smb", "s3"
}

// discoverClusterNodes returns cluster containers with their IDs, IPs, and modes.
// Uses `weka cluster container --output id,ips,mode` — node IPs avoid hostname-resolution failures.
// If includeClients is true, client-mode containers are included alongside backends.
func discoverClusterNodes(includeClients bool) ([]clusterNode, error) {
	out, err := exec.Command("weka", "cluster", "container",
		"--no-header", "--output", "id,ips,mode").Output()
	if err != nil {
		// Fallback for older Weka versions without the mode column
		out2, err2 := exec.Command("weka", "cluster", "container",
			"--no-header", "--output", "id,ips").Output()
		if err2 != nil {
			return nil, fmt.Errorf("weka cluster container list failed: %v; fallback also failed: %v", err, err2)
		}
		out = out2
	}
	seenIP := map[string]bool{}
	var nodes []clusterNode
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		id, err := strconv.Atoi(fields[0])
		if err != nil {
			continue // skip unparseable lines
		}
		// IPs column may be comma-separated; take the first one
		ip := strings.SplitN(fields[1], ",", 2)[0]
		if ip == "" || seenIP[ip] {
			continue
		}
		mode := "backend"
		if len(fields) >= 3 {
			mode = strings.ToLower(fields[2])
		}
		isBackend := mode == "backend"
		isClient := mode == "client"
		if !isBackend && !(includeClients && isClient) {
			continue
		}
		seenIP[ip] = true
		nodes = append(nodes, clusterNode{ID: id, IP: ip, Mode: mode})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].IP < nodes[j].IP })
	return nodes, nil
}

// filterNodesByContainerID returns only the nodes whose IDs are in the given set.
// If ids is empty, all nodes are returned unchanged.
func filterNodesByContainerID(nodes []clusterNode, ids []int) []clusterNode {
	if len(ids) == 0 {
		return nodes
	}
	idSet := make(map[int]bool, len(ids))
	for _, id := range ids {
		idSet[id] = true
	}
	var out []clusterNode
	for _, n := range nodes {
		if idSet[n.ID] {
			out = append(out, n)
		}
	}
	return out
}

// filterClientNodes returns only nodes with mode "client".
func filterClientNodes(nodes []clusterNode) []clusterNode {
	var out []clusterNode
	for _, n := range nodes {
		if n.Mode == "client" {
			out = append(out, n)
		}
	}
	return out
}

// nodeIPs extracts the IP from each clusterNode, preserving order.
func nodeIPs(nodes []clusterNode) []string {
	ips := make([]string, len(nodes))
	for i, n := range nodes {
		ips[i] = n.IP
	}
	return ips
}

// getClusterName returns the Weka cluster name by parsing `weka status`.
// Falls back to the local hostname if weka is unavailable or the output
// cannot be parsed.
func getClusterName() string {
	out, err := exec.Command("weka", "status").Output()
	if err == nil {
		// Look for a line like:  "       cluster: CST-LTS (uuid)"
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "cluster:") {
				// "cluster: CST-LTS (8cfb113b-...)"
				rest := strings.TrimPrefix(line, "cluster:")
				rest = strings.TrimSpace(rest)
				// Take everything before the first '(' (the UUID part)
				if idx := strings.IndexByte(rest, '('); idx > 0 {
					rest = strings.TrimSpace(rest[:idx])
				}
				if rest != "" {
					return sanitizeHostname(rest)
				}
			}
		}
	}
	// Fallback: use local hostname
	h, _ := os.Hostname()
	return sanitizeHostname(h)
}

// ── upload to Weka Home ───────────────────────────────────────────────────────

// checkCloudEnabled verifies that weka cloud is registered and the uploader
// daemon is active on at least one host.
func checkCloudEnabled() error {
	out, err := exec.Command("weka", "cloud", "status").Output()
	if err != nil {
		return fmt.Errorf("could not check cloud status: %v", err)
	}
	var hasURL, isRegistered bool
	totalHosts, disabledHosts := 0, 0
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "url:") && len(strings.TrimSpace(strings.TrimPrefix(lower, "url:"))) > 0 {
			hasURL = true
		}
		if strings.HasPrefix(lower, "registration:") && strings.Contains(lower, "registered") {
			isRegistered = true
		}
		// Count per-host uploader status lines (e.g. "HostId<0>   DISABLED")
		if strings.Contains(trimmed, "HostId<") {
			totalHosts++
			if strings.HasSuffix(strings.ToUpper(trimmed), "DISABLED") {
				disabledHosts++
			}
		}
	}
	if !hasURL || !isRegistered {
		return fmt.Errorf("weka cloud is not registered — run 'weka cloud enable' first")
	}
	if totalHosts > 0 && totalHosts == disabledHosts {
		return fmt.Errorf("weka uploader daemon is DISABLED on all hosts — check 'weka cloud status' and ensure the uploader is active before using --upload")
	}
	return nil
}

// findSupportDirs returns all writable /opt/weka/*/support directories.
// Prefers known backend container names (drives0, compute0, frontend0).
func findSupportDirs() ([]string, error) {
	preferred := []string{"drives0", "compute0", "frontend0"}
	candidates := []string{}
	for _, name := range preferred {
		candidates = append(candidates, fmt.Sprintf("/opt/weka/%s/support", name))
	}
	if matches, _ := filepath.Glob("/opt/weka/*/support"); len(matches) > 0 {
		known := map[string]bool{}
		for _, c := range candidates {
			known[c] = true
		}
		for _, m := range matches {
			if !known[m] {
				candidates = append(candidates, m)
			}
		}
	}
	var result []string
	for _, dir := range candidates {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		probe := filepath.Join(dir, ".wlc_probe")
		f, err := os.Create(probe)
		if err != nil {
			continue
		}
		f.Close()
		os.Remove(probe)
		result = append(result, dir)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no writable weka support directory found under /opt/weka/*/support — is this a backend node with weka running?")
	}
	return result, nil
}

// cleanStaleSymlinks removes leftover wlc-* / wlc:* symlinks from supportDir.
// Removes any symlink whose target is missing (broken), and any wlc- (dash)
// format symlinks regardless — the uploader requires wlc:<id>:<host>:<file>
// format and silently ignores the old dash format.
func cleanStaleSymlinks(supportDir string) {
	entries, err := os.ReadDir(supportDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "wlc-") && !strings.HasPrefix(name, "wlc:") {
			continue
		}
		stalePath := filepath.Join(supportDir, name)
		target, err := os.Readlink(stalePath)
		if err != nil {
			continue
		}
		// Always remove old wlc- (dash) format: uploader won't process them.
		// Also remove any symlink whose target no longer exists.
		broken := func() bool { _, err := os.Stat(target); return err != nil }()
		if strings.HasPrefix(name, "wlc-") || broken {
			if removeErr := os.Remove(stalePath); removeErr == nil {
				logf("Removed leftover upload symlink: %s", name)
			}
		}
	}
}

// uploadBundle symlinks the archive into a weka support directory and waits
// for the weka background uploader daemon to process it.
//
// The weka uploader (inside wekanode) watches support/ via inotify and uploads
// each file to Weka Home. If a container's uploader is in FAILURE state (as
// shown by 'weka cloud status') it will not respond; we try each available
// container in sequence, moving on after a per-dir timeout.
func uploadBundle(archivePath string) error {
	phase("Uploading to Weka Home")

	if err := checkCloudEnabled(); err != nil {
		return err
	}

	supportDirs, err := findSupportDirs()
	if err != nil {
		return err
	}

	absArchive, err := filepath.Abs(archivePath)
	if err != nil {
		return fmt.Errorf("resolve archive path: %w", err)
	}

	filename := filepath.Base(archivePath)
	// The weka uploader daemon requires the structured format wlc:<id>:<host>:<file>
	// to recognize and process the file. A plain prefix like "wlc-" is ignored.
	hostname, _ := os.Hostname()
	linkName := fmt.Sprintf("wlc:%d:%s:%s", time.Now().UnixNano(), hostname, filename)

	// Stage the file under /opt/weka/ so all container uploaders can reach it.
	// Wekanode containers have /opt/weka/ bind-mounted but not /tmp/.
	// Hard-link is instant; fall back to copy if cross-filesystem (tmpfs→ext4).
	stagedPath := filepath.Join(supportDirs[0], "..", filename)
	staged := false
	if err := os.Link(absArchive, stagedPath); err == nil {
		absArchive = stagedPath
		staged = true
		vlogf("Staged via hard-link: %s", stagedPath)
	} else {
		if i, e := os.Stat(absArchive); e == nil {
			logf("Hard-link not possible (cross-filesystem), copying %d MB to /opt/weka/...", i.Size()/(1024*1024))
		}
		if copyErr := func() error {
			src, err := os.Open(absArchive)
			if err != nil {
				return err
			}
			defer src.Close()
			dst, err := os.Create(stagedPath)
			if err != nil {
				return err
			}
			defer dst.Close()
			_, err = io.Copy(dst, src)
			return err
		}(); copyErr == nil {
			absArchive = stagedPath
			staged = true
		} else {
			warnf("Could not stage archive under /opt/weka/ (%v); uploader may not be able to access it", copyErr)
		}
	}
	defer func() {
		if staged {
			os.Remove(stagedPath)
		}
	}()

	info, _ := os.Stat(absArchive)
	var sizeMB int64
	if info != nil {
		sizeMB = info.Size() / (1024 * 1024)
	}
	estMins := (sizeMB / 60) + 1

	// Track the currently active symlink for signal cleanup.
	var mu sync.Mutex
	var activeLinkPath string
	setActive := func(p string) { mu.Lock(); activeLinkPath = p; mu.Unlock() }
	getActive := func() string { mu.Lock(); defer mu.Unlock(); return activeLinkPath }

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		if _, ok := <-sigCh; ok {
			if lp := getActive(); lp != "" {
				os.Remove(lp)
			}
			if staged {
				os.Remove(stagedPath)
			}
			warnf("Upload interrupted — cleaned up staging files")
			os.Exit(1)
		}
	}()
	defer signal.Stop(sigCh)
	defer close(sigCh)

	// A healthy uploader picks up inotify events nearly immediately and moves
	// the symlink to .uploaded/ when done. Allow at least 5 min per container
	// (network to Weka Home can be slow); also scale by file size at ~0.5 MB/s
	// to handle large archives. If nothing happens in that window the uploader
	// for that container is likely broken (e.g. HostId FAILURE in cloud status).
	perDirTimeout := time.Duration(max(300, sizeMB*2)) * time.Second

	for i, supportDir := range supportDirs {
		containerName := filepath.Base(filepath.Dir(supportDir))
		if len(supportDirs) > 1 {
			logf("Trying uploader via container %s (%d/%d)...", containerName, i+1, len(supportDirs))
		}

		cleanStaleSymlinks(supportDir)

		linkPath := filepath.Join(supportDir, linkName)
		uploadedPath := filepath.Join(supportDir, ".uploaded", linkName)

		if err := os.Symlink(absArchive, linkPath); err != nil {
			warnf("Could not create symlink in %s: %v", supportDir, err)
			continue
		}
		setActive(linkPath)

		logf("Queued %s (%d MB) in %s", filename, sizeMB, supportDir)
		if i == 0 {
			logf("Waiting for weka uploader daemon (~1 MB/s, estimated ~%d min)...", estMins)
		}

		start := time.Now()
		lastLog := start
		perDirDeadline := start.Add(perDirTimeout)
		overallDeadline := start.Add(20 * time.Minute)
		success := false

		for time.Now().Before(overallDeadline) {
			time.Sleep(3 * time.Second)

			if _, err := os.Stat(uploadedPath); err == nil {
				logf("Upload complete (%.0fs)", time.Since(start).Seconds())
				success = true
				break
			}
			if _, err := os.Lstat(linkPath); os.IsNotExist(err) {
				logf("Upload complete (%.0fs)", time.Since(start).Seconds())
				success = true
				break
			}

			// Per-dir timeout: uploader for this container is not responding
			if time.Now().After(perDirDeadline) {
				if i+1 < len(supportDirs) {
					warnf("Uploader via %s did not respond within %v — trying next container...", containerName, perDirTimeout)
				}
				break
			}

			if time.Since(lastLog) >= 60*time.Second {
				logf("Still uploading... elapsed: %s", time.Since(start).Round(time.Second))
				lastLog = time.Now()
			}
		}

		setActive("")
		if _, err := os.Lstat(linkPath); err == nil {
			os.Remove(linkPath)
		}
		// Clean up the symlink the uploader moved to .uploaded/ — our staged
		// file gets deleted by the defer below, which would leave it broken.
		os.Remove(uploadedPath)

		if success {
			return nil
		}
	}

	return fmt.Errorf("upload failed — no weka uploader processed the file; check 'weka cloud status'")
}

// ── bash completion ───────────────────────────────────────────────────────────

const bashCompletionScript = `# bash completion for weka-log-collector
_weka_log_collector() {
    local cur prev opts profiles
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    profiles="default perf nfs s3 smbw all"

    opts="--local --upload --clients --clients-only --dry-run --verbose --version
          --start-time --end-time --profile --output --host --container-id
          --max-size --ssh-user --workers --cmd-timeout
          --no-self-deploy --remote-binary"

    case "$prev" in
        --profile)
            COMPREPLY=( $(compgen -W "$profiles" -- "$cur") )
            return 0
            ;;
        --output|--remote-binary)
            COMPREPLY=( $(compgen -f -- "$cur") )
            return 0
            ;;
        --start-time|--end-time)
            now=$(date +%Y-%m-%dT%H:%M)
            today=$(date +%Y-%m-%d)
            COMPREPLY=( $(compgen -W "-1h -2h -4h -8h -12h -24h -1d -2d ${now} ${today}T00:00 ${today}T06:00 ${today}T12:00 ${today}T18:00" -- "$cur") )
            return 0
            ;;
        --ssh-user)
            COMPREPLY=( $(compgen -W "root" -- "$cur") )
            return 0
            ;;
    esac

    COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
    return 0
}
complete -F _weka_log_collector weka-log-collector
`

const bashCompletionPath = "/etc/bash_completion.d/weka-log-collector"

// installCompletion writes the bash completion script to /etc/bash_completion.d/.
// Errors are silently ignored — this is best-effort.
func installCompletion() {
	// Skip if already installed with current content
	existing, err := os.ReadFile(bashCompletionPath)
	if err == nil && string(existing) == bashCompletionScript {
		return
	}
	_ = os.MkdirAll("/etc/bash_completion.d", 0755)
	_ = os.WriteFile(bashCompletionPath, []byte(bashCompletionScript), 0644)
}

// ── archive merging ───────────────────────────────────────────────────────────

// mergeArchive reads a tar.gz from src and re-writes every entry into
// the destination tar.Writer under a new root prefix.
func mergeArchive(tw *tar.Writer, src io.Reader, newRoot string) error {
	gr, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("gzip open: %w", err)
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read: %w", err)
		}
		// strip old root prefix (first path component) and replace with newRoot
		parts := strings.SplitN(hdr.Name, "/", 2)
		var rest string
		if len(parts) > 1 {
			rest = parts[1]
		}
		hdr.Name = filepath.Join(newRoot, rest)
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("tar write header: %w", err)
		}
		if _, err := io.Copy(tw, tr); err != nil {
			return fmt.Errorf("tar copy: %w", err)
		}
	}
	return nil
}

// ── main ──────────────────────────────────────────────────────────────────────

// multiStringFlag implements flag.Value for repeatable string flags.
type multiStringFlag []string

func (f *multiStringFlag) String() string     { return strings.Join(*f, ",") }
func (f *multiStringFlag) Set(v string) error { *f = append(*f, v); return nil }

// multiIntFlag implements flag.Value for repeatable integer flags (e.g. --container-id).
type multiIntFlag []int

func (f *multiIntFlag) String() string {
	s := make([]string, len(*f))
	for i, v := range *f {
		s[i] = strconv.Itoa(v)
	}
	return strings.Join(s, ",")
}
func (f *multiIntFlag) Set(v string) error {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return fmt.Errorf("invalid container ID %q: must be an integer", v)
	}
	*f = append(*f, n)
	return nil
}

func main() {
	var (
		startTimeStr = flag.String("start-time", "", "Start of time window (e.g. -2h, -30m, 2026-03-04T10:30)")
		endTimeStr   = flag.String("end-time", "", "End of time window (default: now)")
		profileStr   = flag.String("profile", ProfileDefault, fmt.Sprintf("Collection profile: %s", strings.Join(validProfiles, "|")))
		outputPath   = flag.String("output", "", "Output .tar.gz path (default: /tmp/<hostname>-weka-logs-<ts>.tar.gz). Use - for stdout.")
		localOnly    = flag.Bool("local", false, "Collect from local host only (no SSH, no cluster query)")
		nodeOnly     = flag.Bool("node-only", false, "Skip cluster-wide weka commands; collect only node-local data (used internally by SSH collection)")
		upload       = flag.Bool("upload", false, "Upload the collected archive to Weka Home (requires 'weka cloud enable')")
		dryRun       = flag.Bool("dry-run", false, "Show what would be collected and estimated size; do not collect")
		maxSizeMB    = flag.Uint64("max-size", 10000, "Abort if estimated collection size exceeds this value (MB)")
		sshUser      = flag.String("ssh-user", "root", "SSH user for remote host collection")
		remoteBinary = flag.String("remote-binary", "/opt/weka/tools/weka-log-collector", "Path to weka-log-collector binary on remote hosts (used only with --no-self-deploy)")
		noSelfDeploy = flag.Bool("no-self-deploy", false, "Do not auto-deploy binary to remote hosts; use --remote-binary path instead")
		workerCount  = flag.Int("workers", 10, "Max parallel SSH workers for cluster collection")
		cmdTimeout   = flag.Duration("cmd-timeout", 120*time.Second, "Timeout per command")
		ver          = flag.Bool("version", false, "Print version and exit")
	)
	var hosts multiStringFlag
	var containerIDs multiIntFlag
	withClients := flag.Bool("clients", false, "Include client nodes in cluster collection (default: backends only)")
	clientsOnly := flag.Bool("clients-only", false, "Collect from client nodes only (skip backends)")
	flag.BoolVar(&verbose, "verbose", false, "Print detailed progress for every file and command")
	flag.Var(&hosts, "host", "Collect only from these hosts by IP (repeatable; default: all cluster backends)")
	flag.Var(&containerIDs, "container-id", "Collect from specific container IDs only (repeatable; e.g. --container-id 0 --container-id 2)")
	flag.Usage = usageFunc
	flag.Parse()

	if args := flag.Args(); len(args) > 0 {
		fmt.Fprintf(os.Stderr, "error: unexpected argument(s): %s\n", strings.Join(args, ", "))
		fmt.Fprintf(os.Stderr, "       (flags require -- prefix, e.g. --profile %s)\n", args[0])
		os.Exit(1)
	}

	if *ver {
		fmt.Printf("weka-log-collector %s\n", version)
		return
	}

	// ── open debug log file ───────────────────────────────────────────────
	// Skip when output is stdout (--output -): this is a remote node collection
	// invoked by the orchestrator via SSH. The orchestrator has its own debug log;
	// creating one on the remote node too would leave stale files and confuse users
	// on nodes that are also the orchestrator.
	if *outputPath != "-" {
		_ = os.MkdirAll("/opt/weka/tools", 0755)
		logPath := fmt.Sprintf("/opt/weka/tools/weka-log-collector-%s.log", time.Now().Format("2006-01-02T15-04-05"))
		if lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644); err == nil {
			debugLog = lf
			defer lf.Close()
			fmt.Fprintf(os.Stderr, "Debug log: %s\n", logPath)
		} else {
			fmt.Fprintf(os.Stderr, "[WARN] could not open debug log %s: %v\n", logPath, err)
		}
	}

	// Silently install bash completion on first run (best-effort, no noise on failure).
	go installCompletion()

	// ── validate profile ──────────────────────────────────────────────────
	validProfile := false
	for _, p := range validProfiles {
		if *profileStr == p {
			validProfile = true
			break
		}
	}
	if !validProfile {
		errorf("unknown profile %q. Valid profiles: %s", *profileStr, strings.Join(validProfiles, ", "))
		os.Exit(1)
	}

	// ── parse time window ─────────────────────────────────────────────────
	var from, to time.Time
	if *startTimeStr != "" {
		t, err := parseInputTime(*startTimeStr)
		if err != nil {
			errorf("--start-time: %v", err)
			os.Exit(1)
		}
		from = t
	}
	if *endTimeStr != "" {
		t, err := parseInputTime(*endTimeStr)
		if err != nil {
			errorf("--end-time: %v", err)
			os.Exit(1)
		}
		to = t
	}
	if !from.IsZero() && !to.IsZero() && to.Before(from) {
		errorf("--end-time (%s) is before --start-time (%s)", to.Format(time.RFC3339), from.Format(time.RFC3339))
		os.Exit(1)
	}

	// ── default time window ───────────────────────────────────────────────
	// Unless --profile all is given (which means "collect everything"),
	// default to the last 8 hours when no --start-time was specified.
	defaultWindow := from.IsZero() && *profileStr != ProfileAll
	if defaultWindow {
		from = time.Now().Add(-8 * time.Hour)
	}

	// ── determine output path ─────────────────────────────────────────────
	toStdout := *outputPath == "-"
	outPath := *outputPath
	if !toStdout && outPath == "" {
		clusterName := getClusterName()
		ts := time.Now().Format("2006-01-02T15-04-05")
		outPath = fmt.Sprintf("/tmp/%s-weka-logs-%s.tar.gz", clusterName, ts)
	}

	// ── print collection plan ─────────────────────────────────────────────
	logf("weka-log-collector %s", version)
	logf("Profile:  %s", *profileStr)
	if !from.IsZero() {
		if defaultWindow {
			logf("From:     %s  (default: last 8h — use --profile all for no limit)", from.Format(time.RFC3339))
		} else {
			logf("From:     %s", from.Format(time.RFC3339))
		}
	} else {
		logf("From:     (no lower bound)")
	}
	if !to.IsZero() {
		logf("To:       %s", to.Format(time.RFC3339))
	} else {
		logf("To:       now")
	}
	if !toStdout {
		logf("Output:   %s", outPath)
	} else {
		logf("Output:   <stdout>")
	}

	// ── pre-discover node count for accurate space estimation ────────────
	// For cluster mode we need to know how many nodes we're collecting from
	// before the space check. Discover early and reuse the result later.
	// For --local or explicit --host flags we already know the count.
	var preDiscoveredHosts []string
	spaceCheckNodeCount := 1
	if !*localOnly && !toStdout {
		if len(hosts) > 0 {
			spaceCheckNodeCount = len(hosts)
		} else {
			if nodes, err := discoverClusterNodes(*withClients || *clientsOnly); err == nil {
				if *clientsOnly {
					nodes = filterClientNodes(nodes)
				}
				if len(containerIDs) > 0 {
					nodes = filterNodesByContainerID(nodes, []int(containerIDs))
				}
				preDiscoveredHosts = nodeIPs(nodes)
				spaceCheckNodeCount = len(preDiscoveredHosts)
			}
			// If discovery fails here we fall back to 1; the cluster section
			// will retry and produce a proper error message if needed.
		}
	}

	// ── space check (skip for stdout) ─────────────────────────────────────
	if !toStdout && !*dryRun {
		outputDir := filepath.Dir(outPath)
		di, err := checkDiskSpace(outputDir)
		if err != nil {
			errorf("disk space check failed for %s: %v", outputDir, err)
			errorf("Tip: use --output to write to a different location (e.g. --output /data/weka-logs.tar.gz)")
			os.Exit(1)
		}
		estimated := estimateCollectionMB(*profileStr, logFileSpecs, spaceCheckNodeCount)
		logf("Disk:     %d MB available on %s (estimated collection: ~%d MB compressed)", di.AvailMB, di.Path, estimated)

		if di.AvailMB < minFreeSpaceMB {
			errorf("Not enough free space on %s: only %d MB available, need at least %d MB.",
				di.Path, di.AvailMB, minFreeSpaceMB)
			errorf("Tip: use --output /path/on/bigger/disk to write to a different filesystem.")
			errorf("     Or free up space on %s first.", di.Path)
			os.Exit(1)
		}
		maxAllowed := uint64(float64(di.AvailMB) * safetyMarginFraction)
		if estimated > *maxSizeMB || estimated > maxAllowed {
			limit := *maxSizeMB
			if maxAllowed < limit {
				limit = maxAllowed
			}
			errorf("Estimated collection size (~%d MB) exceeds limit (%d MB).", estimated, limit)
			errorf("Tip: narrow the time window with --start-time -2h to reduce the amount collected.")
			errorf("     Or increase the limit with --max-size <MB>.")
			errorf("     Use --output to write to a larger filesystem (e.g. /opt/weka/).")
			errorf("     Or use --dry-run to see exactly what would be collected.")
			os.Exit(1)
		}
	}

	if *dryRun {
		phase("DRY RUN — showing what would be collected")
		estimated := estimateCollectionMB(*profileStr, logFileSpecs, spaceCheckNodeCount)
		logf("  Profile:   %s", *profileStr)
		logf("  Nodes:     %d", spaceCheckNodeCount)
		logf("  Estimated: ~%d MB compressed", estimated)
		logf("  Commands:  %d weka + %d system", len(defaultCommands)+len(buildProfileCommands(*profileStr, from, to)), len(systemCommands))
		logf("  Log specs: %d file patterns", len(logFileSpecs))
		if !toStdout {
			di, _ := checkDiskSpace(filepath.Dir(outPath))
			logf("  Disk avail on %s: %d MB", di.Path, di.AvailMB)
		}
		return
	}

	// ── single local collection ───────────────────────────────────────────
	if *localOnly {
		phase("Local collection")
		writeArchive(outPath, toStdout, *profileStr, from, to, *cmdTimeout, *nodeOnly, nil)
		if *upload && !toStdout {
			if err := uploadBundle(outPath); err != nil {
				errorf("Upload failed: %v", err)
			}
		}
		return
	}

	// ── cluster collection ────────────────────────────────────────────────
	phase("Discovering cluster hosts")
	clusterHosts := []string(hosts)
	if len(clusterHosts) == 0 {
		if len(preDiscoveredHosts) > 0 {
			// Reuse result from early discovery (already filtered by --container-id)
			clusterHosts = preDiscoveredHosts
			if len(containerIDs) > 0 {
				logf("Filtered to %d node(s) matching --container-id %v", len(clusterHosts), []int(containerIDs))
			}
			logf("Discovered %d cluster host(s): %s", len(clusterHosts), strings.Join(clusterHosts, ", "))
		} else {
			nodes, err := discoverClusterNodes(*withClients || *clientsOnly)
			if err != nil {
				warnf("Could not discover cluster hosts: %v", err)
				warnf("Falling back to local-only collection. Use --host to specify hosts manually.")
				writeArchive(outPath, toStdout, *profileStr, from, to, *cmdTimeout, false, nil)
				if *upload && !toStdout {
					if err := uploadBundle(outPath); err != nil {
						errorf("Upload failed: %v", err)
					}
				}
				return
			}
			if *clientsOnly {
				nodes = filterClientNodes(nodes)
				if len(nodes) == 0 {
					errorf("No client nodes found in cluster. Are there any Weka client containers?")
					os.Exit(1)
				}
				logf("Filtered to %d client node(s)", len(nodes))
			}
			if len(containerIDs) > 0 {
				nodes = filterNodesByContainerID(nodes, []int(containerIDs))
				if len(nodes) == 0 {
					errorf("No nodes found matching --container-id %v", []int(containerIDs))
					os.Exit(1)
				}
				logf("Filtered to %d node(s) matching --container-id %v", len(nodes), []int(containerIDs))
			}
			clusterHosts = nodeIPs(nodes)
			logf("Discovered %d cluster host(s): %s", len(clusterHosts), strings.Join(clusterHosts, ", "))
		}
	} else {
		logf("Collecting from %d specified host(s): %s", len(clusterHosts), strings.Join(clusterHosts, ", "))
	}

	// Determine self-deploy settings
	selfDeploy := !*noSelfDeploy
	selfPath := ""
	if selfDeploy {
		var err error
		selfPath, err = os.Executable()
		if err != nil {
			warnf("Could not determine executable path (%v); falling back to --remote-binary mode", err)
			selfDeploy = false
		} else {
			logf("Auto-deploying binary from %s to /opt/weka/tools/weka-log-collector-<pid> on each host", selfPath)
			logf("(use --no-self-deploy to skip auto-deployment and use --remote-binary instead)")
		}
	}

	// Collect from all hosts in parallel
	phase("Collecting from cluster hosts")
	results := collectCluster(clusterHosts, selfPath, *remoteBinary, *profileStr, from, to, *sshUser, selfDeploy, *cmdTimeout, *workerCount)

	// Write merged archive
	phase("Writing archive")
	writeMergedArchive(outPath, toStdout, results, *profileStr, from, to, *cmdTimeout)
	if *upload && !toStdout {
		if err := uploadBundle(outPath); err != nil {
			errorf("Upload failed: %v", err)
		}
	}
}

// collectCluster fans out collection to all hosts in parallel.
func collectCluster(hosts []string, selfPath, binaryPath, profile string, from, to time.Time, sshUser string, selfDeploy bool, cmdTimeout time.Duration, workers int) []HostResult {
	sem := make(chan struct{}, workers)
	var mu sync.Mutex
	var results []HostResult
	var wg sync.WaitGroup

	for _, host := range hosts {
		host := host
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := collectFromHost(host, selfPath, binaryPath, profile, from, to, sshUser, selfDeploy, 5*cmdTimeout)
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return results
}

// writeArchive performs a local collection and writes to outPath (or stdout).
func writeArchive(outPath string, toStdout bool, profile string, from, to time.Time, cmdTimeout time.Duration, nodeOnly bool, extraManifests []HostManifest) {
	clusterName := getClusterName()
	ts := time.Now().Format("2006-01-02T15-04-05")
	archiveRoot := fmt.Sprintf("%s-weka-logs-%s", clusterName, ts)

	var outWriter io.Writer
	var outDesc string

	if toStdout {
		outWriter = os.Stdout
		outDesc = "<stdout>"
	} else {
		f, err := os.Create(outPath)
		if err != nil {
			errorf("Cannot create output file %s: %v", outPath, err)
			errorf("Tip: check write permissions or use --output /tmp/weka-logs.tar.gz")
			os.Exit(1)
		}
		defer f.Close()
		outWriter = f
		outDesc = outPath
	}

	gz, err := gzip.NewWriterLevel(outWriter, gzip.BestCompression)
	if err != nil {
		errorf("gzip init: %v", err)
		os.Exit(1)
	}
	tw := tar.NewWriter(gz)

	manifest := CollectLocal(tw, archiveRoot, profile, from, to, cmdTimeout, nodeOnly)

	// Write manifest
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err == nil {
		_ = addBytesToArchive(tw, filepath.Join(archiveRoot, "collection_manifest.json"), manifestJSON)
	}

	if err := tw.Close(); err != nil {
		errorf("Finalizing tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		errorf("Finalizing gzip: %v", err)
	}

	logf("\nCollection complete → %s", outDesc)
	logf("  Commands: %d total, %d failed", manifest.TotalCommands, manifest.FailedCommands)
	logf("  Files:    %d collected, %d failed",
		manifest.CollectedFiles, manifest.FailedFiles)
	if !toStdout {
		if info, err := os.Stat(outPath); err == nil {
			logf("  Size:     %d KB", info.Size()/1024)
		}
	}
}

// writeMergedArchive merges results from all cluster hosts into a single archive.
func writeMergedArchive(outPath string, toStdout bool, results []HostResult, profile string, from, to time.Time, cmdTimeout time.Duration) {
	clusterName := getClusterName()
	ts := time.Now().Format("2006-01-02T15-04-05")
	archiveRoot := fmt.Sprintf("%s-weka-logs-%s", clusterName, ts)

	var outWriter io.Writer
	var outDesc string

	if toStdout {
		outWriter = os.Stdout
		outDesc = "<stdout>"
	} else {
		f, err := os.Create(outPath)
		if err != nil {
			errorf("Cannot create output file %s: %v", outPath, err)
			errorf("Tip: check write permissions or use --output /tmp/weka-logs.tar.gz")
			os.Exit(1)
		}
		defer f.Close()
		outWriter = f
		outDesc = outPath
	}

	// DefaultCompression (level 6) for the merge pass: the content is raw log
	// data just like the per-node archives, compresses well at any level, and
	// level 9 costs 3-4x more CPU for <5% size benefit — too expensive on a
	// live Weka node receiving parallel SSH streams from the whole cluster.
	gz, err := gzip.NewWriterLevel(outWriter, gzip.DefaultCompression)
	if err != nil {
		errorf("gzip init: %v", err)
		os.Exit(1)
	}
	tw := tar.NewWriter(gz)

	// ── run cluster-wide weka commands once on the orchestrator ───────────
	// These commands produce identical output on every node; running them once
	// avoids duplicating the same files N times (once per cluster host).
	clusterCmds := buildClusterWideCmds(profile, from, to)
	phase(fmt.Sprintf("Cluster-wide Weka commands (run once, %d parallel)", cmdWorkers))
	logf("  [cluster] running %d cluster-wide commands", len(clusterCmds))
	clusterOutputs := runCommandsParallel(clusterCmds, cmdTimeout)
	for i, spec := range clusterCmds {
		co := clusterOutputs[i]
		if co.result.Error != "" {
			if spec.Profile != "" {
				vlogf("[cluster] command %q failed (exit %d): %s", spec.Name, co.result.ExitCode, co.result.Error)
			} else {
				warnf("[cluster] command %q failed (exit %d): %s", spec.Name, co.result.ExitCode, co.result.Error)
			}
		}
		content := co.out
		if co.result.Error != "" && len(co.out) == 0 {
			content = []byte(fmt.Sprintf("# command: %s\n# error: %s\n", spec.Cmd, co.result.Error))
		}
		ext := ".txt"
		if spec.JSON {
			ext = ".json"
		}
		dest := filepath.Join(archiveRoot, "cluster", "weka", spec.Name+ext)
		if addErr := addBytesToArchive(tw, dest, content); addErr != nil {
			warnf("[cluster] could not add %s to archive: %v", spec.Name, addErr)
		}
	}

	var succeeded, failed int
	var failedHosts []string

	for _, r := range results {
		if r.Err != nil {
			failed++
			failedHosts = append(failedHosts, r.Host)
			errorf("[%s] FAILED: %v", r.Host, r.Err)
			// Write a placeholder error file so the host is visible in the archive
			errContent := []byte(fmt.Sprintf("Collection failed for host %s\nError: %v\n", r.Host, r.Err))
			_ = addBytesToArchive(tw,
				filepath.Join(archiveRoot, "hosts", r.Host, "COLLECTION_FAILED.txt"),
				errContent)
			continue
		}
		// Open temp file, merge, then delete — only one host archive in memory at a time.
		f, openErr := os.Open(r.TempFile)
		if openErr != nil {
			errorf("[%s] failed to open temp archive %s: %v", r.Host, r.TempFile, openErr)
			failed++
			failedHosts = append(failedHosts, r.Host)
			os.Remove(r.TempFile)
			continue
		}
		stat, _ := f.Stat()
		mergeErr := mergeArchive(tw, f, archiveRoot)
		f.Close()
		os.Remove(r.TempFile)
		if mergeErr != nil {
			errorf("[%s] failed to merge archive: %v", r.Host, mergeErr)
			failed++
			failedHosts = append(failedHosts, r.Host)
			continue
		}
		succeeded++
		logf("  [%s] merged OK (%d KB)", r.Host, stat.Size()/1024)
	}

	// Write cluster-level summary
	type clusterSummary struct {
		CollectedAt time.Time `json:"collected_at"`
		Profile     string    `json:"profile"`
		From        string    `json:"from,omitempty"`
		To          string    `json:"to,omitempty"`
		TotalHosts  int       `json:"total_hosts"`
		Succeeded   int       `json:"succeeded"`
		Failed      int       `json:"failed"`
		FailedHosts []string  `json:"failed_hosts,omitempty"`
	}
	summary := clusterSummary{
		CollectedAt: time.Now(),
		Profile:     profile,
		TotalHosts:  len(results),
		Succeeded:   succeeded,
		Failed:      failed,
		FailedHosts: failedHosts,
	}
	if !from.IsZero() {
		summary.From = from.Format(time.RFC3339)
	}
	if !to.IsZero() {
		summary.To = to.Format(time.RFC3339)
	}
	summaryJSON, _ := json.MarshalIndent(summary, "", "  ")
	_ = addBytesToArchive(tw, filepath.Join(archiveRoot, "cluster_summary.json"), summaryJSON)

	if err := tw.Close(); err != nil {
		errorf("Finalizing tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		errorf("Finalizing gzip: %v", err)
	}

	logf("\nCluster collection complete → %s", outDesc)
	logf("  Hosts:    %d total, %d succeeded, %d failed", len(results), succeeded, failed)
	if len(failedHosts) > 0 {
		logf("  Failed:   %s", strings.Join(failedHosts, ", "))
		logf("  Tip: check SSH access and ensure weka-log-collector binary is at the expected path on failed hosts.")
	}
	if !toStdout {
		if info, err := os.Stat(outPath); err == nil {
			logf("  Size:     %d KB", info.Size()/1024)
		}
	}
}

func sanitizeHostname(h string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9_-]`)
	return re.ReplaceAllString(h, "-")
}

func usageFunc() {
	fmt.Fprint(os.Stderr, `weka-log-collector — collect logs and diagnostics from a Weka cluster

USAGE
  weka-log-collector [options]          cluster-wide (auto-discovers all backends via weka CLI)
  weka-log-collector --local [options]  this host only

TIME
  --start-time TIME  Relative: -2h, -30m, -1d  |  Absolute: 2026-03-04T10:30[:00]
  --end-time   TIME  Default: now
  Default window: last 8h. Use --profile all for no time limit.

PROFILES  (--profile NAME)
  default  status, events, cfgdump, system info, NIC/OFED, logs + journalctl  [default]
  perf     + performance stats
  nfs      + NFS/Ganesha commands and logs
  s3       + S3/envoy commands and logs
  smbw     + SMB-W/pacemaker/corosync commands and logs
  all      everything, no time limit

OPTIONS
  --host IP            Target specific host(s) by IP (repeatable)
  --container-id N     Target specific container ID(s) (repeatable)
  --clients            Include client nodes (default: backends only)
  --clients-only       Client nodes only; skip backends
  --local              This host only; no SSH
  --dry-run            Show what would be collected; do not collect
  --output PATH        Archive path (default: /tmp/<cluster>-weka-logs-<ts>.tar.gz); - for stdout
  --upload             Upload archive to Weka Home (requires weka cloud enabled)
  --max-size MB        Abort if estimated size exceeds this (default: 2048)
  --ssh-user USER      SSH user (default: root)
  --workers N          Parallel SSH workers (default: 10)
  --cmd-timeout DUR    Per-command timeout (default: 60s)
  --no-self-deploy     Skip auto-deploy; use --remote-binary instead
  --remote-binary PATH Binary path on remote hosts (default: /opt/weka/tools/weka-log-collector)
  --verbose            Detailed per-file/command progress
  --version            Print version and exit

EXAMPLES
  # Last 2 hours from all cluster nodes
  weka-log-collector --start-time -2h

  # Specific incident window
  weka-log-collector --start-time 2026-03-04T10:00 --end-time 2026-03-04T12:00

  # S3 profile, this node only
  weka-log-collector --local --profile s3 --start-time -4h

  # Backends and clients
  weka-log-collector --clients --start-time -2h

  # Specific hosts by IP
  weka-log-collector --host 10.0.0.1 --host 10.0.0.2 --start-time -1h

`)
}
