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
	"net"
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

// wlcBaseDir is the unified on-node home for weka-log-collector files:
//   - output archives  (bundles/ subdirectory)
//   - per-run debug logs  (logs/ subdirectory)
//   - self-deployed binary
const (
	wlcBaseDir        = "/opt/weka/weka-log-collector"
	wlcBundlesDir     = wlcBaseDir + "/bundles"
	wlcLogsDir        = wlcBaseDir + "/logs"
	uploadFileMaxSize = 50 * 1024 * 1024 // 50 MB
)

// ── time parsing ─────────────────────────────────────────────────────────────

var relativeTimeRe = regexp.MustCompile(
	`^-(\d+)\s*(d|day|days|h|hr|hour|hours|m|min|mins|minute|minutes|s|sec|secs|second|seconds)$`,
)

// rotatedFileSuffixRe matches filename suffixes that indicate a rotated/archived log file.
// Matches: .1  .2  .gz  -20260301 (date-stamped rotation)
// Does NOT match: .log  .json  (current active log extensions)
var rotatedFileSuffixRe = regexp.MustCompile(`(\.\d+|\.gz|-\d{8})$`)

// ansiEscape matches ANSI/VT100 escape sequences (e.g. ESC[32m, ESC[0m).
// Some containers (e.g. the Weka operator manager) emit colored log output;
// kubectl captures the raw bytes, so these appear literally in saved log files.
var ansiEscape = regexp.MustCompile("\x1b\\[[0-9;]*[a-zA-Z]")

func stripANSI(b []byte) []byte { return ansiEscape.ReplaceAll(b, nil) }

// sensitiveKeyRe matches YAML/text keys that likely hold credentials or tokens.
// Used to redact configmap values before archiving — secrets are never collected,
// but some operators store tokens or API keys in configmaps.
var sensitiveKeyRe = regexp.MustCompile(
	`(?i)(password|passwd|token|secret|api[-_]?key|auth|credential|private[-_]?key|access[-_]?key|signing[-_]?key)\s*:`)

// redactSensitiveYAML replaces the value of any YAML key whose name matches
// sensitiveKeyRe with [REDACTED]. Only single-line scalar values are redacted;
// multiline blocks are left as-is (they do not contain credentials in practice).
func redactSensitiveYAML(b []byte) []byte {
	lines := bytes.Split(b, []byte("\n"))
	for i, line := range lines {
		if sensitiveKeyRe.Match(line) {
			// Find the colon and replace everything after it.
			idx := bytes.Index(line, []byte(":"))
			if idx >= 0 && idx < len(line)-1 {
				lines[i] = append(line[:idx+1], []byte(" [REDACTED]")...)
			}
		}
	}
	return bytes.Join(lines, []byte("\n"))
}

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
func filterByTimeWindow(paths []string, from, to time.Time) ([]string, int) {
	if from.IsZero() && to.IsZero() {
		return paths, 0
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
	var skipped int
	for _, k := range order {
		files := families[k]
		// Sort oldest-first by mtime so adjacent pairs give content ranges.
		sort.Slice(files, func(i, j int) bool {
			return files[i].mtime.Before(files[j].mtime)
		})
		for i, f := range files {
			if f.statErr {
				result = append(result, f.path)
				continue
			}
			// Non-rotated files (active logs) are usually always included because
			// their mtime is "now" and content range is unknown. However, some
			// files embed a timestamp in their base name (e.g. build-20241220T234445.log)
			// and are one-off historical files, not continuously-written active logs.
			// If a non-rotated file's mtime is before the window start, it cannot
			// contain entries in our window — skip it.
			if !f.rotated {
				if !from.IsZero() && f.mtime.Before(from) {
					skipped++
					continue
				}
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
				skipped++
				continue
			}
			// Skip: content started after our window ended.
			if !to.IsZero() && !contentStart.IsZero() && contentStart.After(to) {
				skipped++
				continue
			}
			result = append(result, f.path)
		}
	}
	return result, skipped
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
	Name         string // output filename (without extension)
	Cmd          string // shell command
	Profile      string // which profile this belongs to (empty = always run)
	Fatal        bool   // if true, collection fails if this command fails; default non-fatal
	NodeLocal    bool   // if true, output varies per node (weka local *); otherwise cluster-wide
	JSON         bool   // if true, command outputs JSON; archive entry uses .json extension
	NodeOptional bool   // if true, failure is expected on some nodes/distros — logged at verbose only, not WARN
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
	// weka local resources collected dynamically per container in CollectLocal
	// ── events, config dump, network peers (merged from former "full" profile) ──
	{Name: "weka_events_major", Cmd: "weka events --severity major -J", JSON: true},
	{Name: "weka_debug_net_peers", Cmd: "weka debug net peers 1 -J", JSON: true},
	{Name: "weka_cfgdump", Cmd: "weka local exec -C drives0 -- /weka/cfgdump"}, // raw exec, no -J
}

// buildPerfCommands returns the perf-profile command list, translating the
// --start-time/--end-time window into weka stats --start-time/--end-time flags.
func buildPerfCommands(from, to time.Time) []CommandSpec {
	// Two collection modes depending on whether the user gave an explicit time window:
	//
	// No explicit --start-time (from.IsZero):
	//   Collect cluster-averaged stats for the last 4h. No --per-process or --per-role.
	//   Rationale: weka stats without --start-time returns only ~1min of data (misleading).
	//   --per-process over an implicit long window produces excessive data. 4h cluster
	//   average gives a useful health overview without the noise.
	//
	// Explicit --start-time given:
	//   Use the user's window with full --per-process breakdown — ideal for incident analysis.

	explicitWindow := !from.IsZero()

	effectiveFrom := from
	if !explicitWindow {
		effectiveFrom = time.Now().Add(-4 * time.Hour)
	}

	timeFlags := fmt.Sprintf(" --start-time %s", effectiveFrom.Format("2006-01-02T15:04:05"))
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

	if explicitWindow {
		// Full per-process/per-role breakdown for incident analysis.
		return []CommandSpec{
			stats("weka_stats_cpu_per_process", " --show-internal --category cpu --per-process -s value"),
			stats("weka_stats_cpu_per_role", " --show-internal --category cpu --per-role -s value"),
			stats("weka_stats_ssd", " --show-internal --category ssd --per-process"),
			stats("weka_stats_ssd_read_latency", " --show-internal --stat SSD_READ_LATENCY --per-process"),
			stats("weka_stats_ssd_write_latency", " --show-internal --stat SSD_WRITE_LATENCY --per-process"),
			stats("weka_stats_drive_read_latency", " --show-internal --stat DRIVE_READ_LATENCY --per-process"),
			stats("weka_stats_drive_write_latency", " --show-internal --stat DRIVE_WRITE_LATENCY --per-process"),
			stats("weka_stats_ops_driver", " --show-internal --category ops_driver --per-process"),
			stats("weka_stats_ops", " --show-internal --category ops --per-process"),
			stats("weka_stats_read_latency", " --category ops --show-internal --stat READ_LATENCY --per-process"),
			stats("weka_stats_write_latency", " --category ops --show-internal --stat WRITE_LATENCY --per-process"),
			stats("weka_stats_network", " --show-internal --category network --per-process"),
			stats("weka_stats_goodput_tx", " --show-internal --stat GOODPUT_TX_RATIO --per-process"),
			stats("weka_stats_goodput_rx", " --show-internal --stat GOODPUT_RX_RATIO --per-process"),
			stats("weka_stats_port_tx", " --show-internal --stat PORT_TX_BYTES --per-process"),
			stats("weka_stats_port_rx", " --show-internal --stat PORT_RX_BYTES --per-process"),
			stats("weka_stats_dropped_packets", " --show-internal --stat DROPPED_PACKETS --per-process"),
			stats("weka_stats_corrupt_packets", " --show-internal --stat CORRUPT_PACKETS --per-process"),
			stats("weka_stats_jrpc", " --show-internal --category jrpc --per-process"),
			stats("weka_stats_rpc", " --show-internal --category rpc --per-process"),
			{Name: "weka_stats_realtime", Cmd: "weka stats realtime -s -cpu -o node,hostname,role,mode,writeps,writebps,wlatency,readps,readbps,rlatency,ops,cpu,l6recv,l6send,upload,download", Profile: ProfilePerf},
		}
	}

	// Cluster-averaged overview for last 4h (no explicit window given).
	return []CommandSpec{
		stats("weka_stats_cpu", " --show-internal --category cpu -s value"),
		stats("weka_stats_ssd", " --show-internal --category ssd"),
		stats("weka_stats_ssd_read_latency", " --show-internal --stat SSD_READ_LATENCY"),
		stats("weka_stats_ssd_write_latency", " --show-internal --stat SSD_WRITE_LATENCY"),
		stats("weka_stats_drive_read_latency", " --show-internal --stat DRIVE_READ_LATENCY"),
		stats("weka_stats_drive_write_latency", " --show-internal --stat DRIVE_WRITE_LATENCY"),
		stats("weka_stats_ops_driver", " --show-internal --category ops_driver"),
		stats("weka_stats_ops", " --show-internal --category ops"),
		stats("weka_stats_read_latency", " --category ops --show-internal --stat READ_LATENCY"),
		stats("weka_stats_write_latency", " --category ops --show-internal --stat WRITE_LATENCY"),
		stats("weka_stats_network", " --show-internal --category network"),
		stats("weka_stats_goodput_tx", " --show-internal --stat GOODPUT_TX_RATIO"),
		stats("weka_stats_goodput_rx", " --show-internal --stat GOODPUT_RX_RATIO"),
		stats("weka_stats_port_tx", " --show-internal --stat PORT_TX_BYTES"),
		stats("weka_stats_port_rx", " --show-internal --stat PORT_RX_BYTES"),
		stats("weka_stats_dropped_packets", " --show-internal --stat DROPPED_PACKETS"),
		stats("weka_stats_corrupt_packets", " --show-internal --stat CORRUPT_PACKETS"),
		stats("weka_stats_jrpc", " --show-internal --category jrpc"),
		stats("weka_stats_rpc", " --show-internal --category rpc"),
		{Name: "weka_stats_realtime", Cmd: "weka stats realtime -s -cpu -o node,hostname,role,mode,writeps,writebps,wlatency,readps,readbps,rlatency,ops,cpu,l6recv,l6send,upload,download", Profile: ProfilePerf},
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
	// timedatectl works on all systemd distros — always present, always warn if missing
	{Name: "timedatectl", Cmd: "timedatectl status"},
	{Name: "timedatectl_timesync", Cmd: "timedatectl show-timesync --no-pager", NodeOptional: true},
	// systemd-timesyncd (Ubuntu/Debian default)
	{Name: "timesyncd_status", Cmd: "systemctl status systemd-timesyncd --no-pager", NodeOptional: true},
	// ── kernel parameters ─────────────────────────────────────────────────
	// sysctl -a captures all live values including numa_balancing, kernel.panic, etc.
	{Name: "sysctl_all", Cmd: "sysctl -a"},
	// kernel ring buffer with timestamps
	{Name: "dmesg", Cmd: "dmesg -T"},
	// ── NIC / OFED / routing ──────────────────────────────────────────────
	{Name: "lshw_network", Cmd: "lshw -C network -businfo"},
	{Name: "ofed_info", Cmd: "ofed_info -s"},
	{Name: "lsmod", Cmd: "lsmod"},
	{Name: "modinfo_mlx5_core", Cmd: "modinfo mlx5_core"},
	{Name: "modinfo_ice", Cmd: "modinfo ice"},
	// ethtool per interface: link speed, duplex, driver, MTU validation
	// NodeOptional: ethtool may not be installed. Skip virtual interfaces (lo, etc.) that
	// have no physical device and cause ethtool -i to exit non-zero.
	{Name: "ethtool_all", Cmd: `for iface in $(ls /sys/class/net/); do [ -e /sys/class/net/$iface/device ] || continue; echo "=== $iface ==="; ethtool "$iface" 2>&1; ethtool -i "$iface" 2>&1; done`, NodeOptional: true},
	{Name: "ip_rule", Cmd: "ip rule"},
	{Name: "ip_neighbor", Cmd: "ip neighbor"},
	{Name: "ip_route_all_tables", Cmd: "ip route show table all"},
	{Name: "rp_filter", Cmd: "sysctl -a | grep -w rp_filter"},
	// ── Mellanox firmware settings (ADVANCED_PCI_SETTINGS, PCI_WR_ORDERING) ─
	// mst/mlxconfig only present on nodes with ConnectX NICs + MFT package;
	// fails gracefully on Intel/other NIC nodes
	{Name: "mst_status", Cmd: "mst status -v"},
	{Name: "mlxconfig_query", Cmd: `for d in /dev/mst/mt*_pciconf0; do echo "=== $d ==="; mlxconfig -d "$d" query 2>&1; done`},
	// weka-agent journal — collected separately in CollectLocal with time window support
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
	// Core containers (drives*, compute*, frontend*, client*) are always collected.
	// Protocol containers (ganesha*, s3*, envoy*, smbw*) are only collected
	// when the matching profile is active — their log directories only exist
	// on nodes where the protocol is actually running, so on non-protocol
	// nodes the globs simply match nothing.

	// ── core containers (always collected) ───────────────────────────────
	// Covers backends (drives*/compute*/frontend*) and clients (client*).
	// Globs that match nothing on a given node are silently skipped.
	{SrcGlob: "/opt/weka/logs/drives*/*.log*", DestDir: "weka/containers"},
	{SrcGlob: "/opt/weka/logs/drives*/*.json", DestDir: "weka/containers"},
	{SrcGlob: "/opt/weka/logs/drives*/*/*.log*", DestDir: "weka/containers"},
	{SrcGlob: "/opt/weka/logs/compute*/*.log*", DestDir: "weka/containers"},
	{SrcGlob: "/opt/weka/logs/compute*/*.json", DestDir: "weka/containers"},
	{SrcGlob: "/opt/weka/logs/compute*/*/*.log*", DestDir: "weka/containers"},
	{SrcGlob: "/opt/weka/logs/frontend*/*.log*", DestDir: "weka/containers"},
	{SrcGlob: "/opt/weka/logs/frontend*/*.json", DestDir: "weka/containers"},
	{SrcGlob: "/opt/weka/logs/frontend*/*/*.log*", DestDir: "weka/containers"},
	{SrcGlob: "/opt/weka/logs/client*/*.log*", DestDir: "weka/containers"},
	{SrcGlob: "/opt/weka/logs/client*/*.json", DestDir: "weka/containers"},
	{SrcGlob: "/opt/weka/logs/client*/*/*.log*", DestDir: "weka/containers"},

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

// checkRemoteDiskSpace SSHes to sshTarget and returns available space on the
// filesystem containing path, walking up to an existing ancestor if needed.
// Path in the returned diskInfo is the ancestor that was actually checked
// (not the df mount point), so the caller can display a meaningful location.
func checkRemoteDiskSpace(sshTarget, path string) (diskInfo, error) {
	// Walk up to an existing ancestor, run df -m, then echo available + the
	// resolved path. Reporting the resolved path (not the df "Mounted on"
	// column) keeps the display consistent whether or not the directory exists
	// yet: it shows where we checked, not the underlying mount root.
	cmd := fmt.Sprintf(
		`p=%s; while [ ! -e "$p" ] && [ "$p" != "/" ]; do p=$(dirname "$p"); done; avail=$(df -m "$p" | awk 'END{print $(NF-2)}'); echo "$avail $p"`,
		path,
	)
	args := append(sshArgs(), sshTarget, cmd)
	out, err := exec.Command("ssh", args...).Output()
	if err != nil {
		return diskInfo{}, err
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) < 2 {
		return diskInfo{}, fmt.Errorf("unexpected df output: %q", strings.TrimSpace(string(out)))
	}
	avail, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return diskInfo{}, fmt.Errorf("cannot parse available MB %q", fields[0])
	}
	return diskInfo{AvailMB: avail, Path: fields[1]}, nil
}

// ── extra commands ────────────────────────────────────────────────────────────

// extraCommandsFile is the template file shipped with the repo. Users add
// custom commands here; they are collected from the orchestrator node only.
const extraCommandsFile = wlcBaseDir + "/extra-commands"

// blockedBinaries lists command names (matched against the base of the first
// word) that are never permitted in extra-commands — destructive or
// state-changing system utilities.
var blockedBinaries = []string{
	"rm", "rmdir",
	"dd",
	"mkfs",
	"shred", "wipefs",
	"fdisk", "parted", "gdisk", "sgdisk",
	"reboot", "shutdown", "halt", "poweroff",
}

// blockedPrefixes lists full command prefixes that are never permitted.
// Matched against the trimmed command line as: exact match OR prefix+" ".
var blockedPrefixes = []string{
	// Weka state-changing / destructive operations
	"weka cluster stop-io",
	"weka cluster start-io",
	"weka cluster update",
	"weka cluster container deactivate",
	"weka cluster container remove",
	"weka cluster container requested-action",
	"weka cluster drive deactivate",
	"weka cluster drive remove",
	"weka local stop",
	"weka local restart",
	"weka local reset-data",
	"weka fs remove",
	"weka fs group remove",
	"weka org remove",
	"weka user remove",
	"weka security",
	"weka smb cluster destroy",
	"weka agent uninstall",
	// systemctl state-changing subcommands
	"systemctl stop",
	"systemctl start",
	"systemctl restart",
	"systemctl disable",
	"systemctl enable",
	"systemctl mask",
	"systemctl daemon-reload",
}

// isBlockedCommand returns (true, reason) if the command matches the denylist.
// Checks the binary name (base of first word) and full command prefix.
// Note: does not catch shell tricks such as piping through a blocked binary.
func isBlockedCommand(line string) (bool, string) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false, ""
	}
	bin := filepath.Base(fields[0])
	for _, b := range blockedBinaries {
		if bin == b {
			return true, fmt.Sprintf("%q is not permitted in extra-commands", b)
		}
	}
	if strings.HasPrefix(bin, "mkfs.") {
		return true, fmt.Sprintf("%q is not permitted in extra-commands", bin)
	}
	for _, prefix := range blockedPrefixes {
		if line == prefix || strings.HasPrefix(line, prefix+" ") {
			return true, fmt.Sprintf("%q is not permitted in extra-commands", prefix)
		}
	}
	return false, ""
}

// loadExtraCommands reads extraCommandsFile, strips blank lines and # comments,
// deduplicates against the built-in command set, and returns CommandSpecs ready
// to run. Each spec gets a stable archive name: NN_<binary>.txt.
func loadExtraCommands(builtinCmds []CommandSpec) []CommandSpec {
	data, err := os.ReadFile(extraCommandsFile)
	if err != nil {
		if !os.IsNotExist(err) {
			warnf("Could not read %s: %v", extraCommandsFile, err)
		}
		return nil
	}

	builtinSet := make(map[string]bool, len(builtinCmds))
	for _, c := range builtinCmds {
		builtinSet[strings.TrimSpace(c.Cmd)] = true
	}

	var cmds []CommandSpec
	seen := make(map[string]bool)
	idx := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		if builtinSet[line] {
			logf("  extra-commands: skipping %q (already in built-in collection)", line)
			continue
		}
		if blocked, reason := isBlockedCommand(line); blocked {
			warnf("extra-commands: skipping %q — %s", line, reason)
			continue
		}
		idx++
		// Use the binary name (last path component of first word) for readability.
		binName := filepath.Base(strings.Fields(line)[0])
		name := fmt.Sprintf("%02d_%s", idx, binName)
		cmds = append(cmds, CommandSpec{Name: name, Cmd: line})
	}
	return cmds
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
	Optional bool          `json:"optional,omitempty"`
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
		Name:     spec.Name,
		Command:  spec.Cmd,
		Optional: spec.NodeOptional,
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
func CollectLocal(tw *tar.Writer, archiveRoot, profile string, from, to time.Time, cmdTimeout time.Duration, nodeOnly bool, containerNames []string, extraCmds []CommandSpec) HostManifest {
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
			if spec.NodeOptional {
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
		dest := filepath.Join(hostRoot, "system", spec.Name+ext)
		if err := addBytesToArchive(tw, dest, content); err != nil {
			warnf("[%s] could not add %s to archive: %v", hostname, spec.Name, err)
		}
	}

	// ── phase: weka CLI commands (parallel) ───────────────────────────────
	phase(fmt.Sprintf("[%s] Weka commands (profile: %s, %d parallel)", hostname, profile, cmdWorkers))

	// Auth probe: run weka status first. Exit 41 = authentication required.
	// If auth fails, skip all Weka CLI commands to avoid 30+ identical warnings.
	wekaAvailable := true
	{
		probe := CommandSpec{Name: "weka_auth_probe", Cmd: "weka status"}
		probeResult, _ := runCommand(probe, cmdTimeout)
		if probeResult.ExitCode == 41 {
			wekaAvailable = false
			warnf("[%s] Weka authentication required — run 'weka user login' first. Skipping all Weka CLI commands.", hostname)
		}
	}

	allWekaCmds := append(append([]CommandSpec{}, defaultCommands...), buildProfileCommands(profile, from, to)...)

	// Filter to the commands we'll actually run on this node before parallelising.
	var wekaToRun []CommandSpec
	var skippedClusterCmds int
	for _, spec := range allWekaCmds {
		if !wekaAvailable {
			break
		}
		if nodeOnly && !spec.NodeLocal {
			skippedClusterCmds++
			continue
		}
		wekaToRun = append(wekaToRun, spec)
	}
	if skippedClusterCmds > 0 {
		vlogf("  [%s] skipping %d cluster-wide commands (--node-only)", hostname, skippedClusterCmds)
	}
	if wekaAvailable {
		logf("  [%s] running %d weka commands", hostname, len(wekaToRun))
	}
	wekaOutputs := runCommandsParallel(wekaToRun, cmdTimeout)
	for i, spec := range wekaToRun {
		co := wekaOutputs[i]
		manifest.Commands = append(manifest.Commands, co.result)
		if co.result.Error != "" {
			if spec.Profile != "" || spec.NodeOptional {
				// Protocol-specific or node-optional command — failure is expected on
				// some nodes/distros. Log to verbose/debug only, not as a WARN.
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
		wekaSubdir := "weka"
		if spec.Profile == ProfilePerf {
			wekaSubdir = "weka/perf"
		}
		dest := filepath.Join(hostRoot, wekaSubdir, spec.Name+ext)
		if err := addBytesToArchive(tw, dest, content); err != nil {
			warnf("[%s] could not add %s to archive: %v", hostname, spec.Name, err)
		}
		if spec.Name == "weka_version" && len(co.out) > 0 {
			manifest.WekaVersion = strings.TrimSpace(string(co.out))
		}
	}

	// ── phase: weka local resources (dynamic, per container) ─────────────
	// Parse weka local ps output to discover which containers exist on this
	// node (differs between backends: drives0/compute0/frontend0, and clients:
	// client), then collect resources for each.
	if wekaAvailable {
		var localPSOut []byte
		for i, spec := range wekaToRun {
			if spec.Name == "weka_local_ps" {
				localPSOut = wekaOutputs[i].out
				break
			}
		}
		var containers []struct {
			Name string `json:"name"`
		}
		if len(localPSOut) > 0 {
			_ = json.Unmarshal(localPSOut, &containers)
		}
		for _, c := range containers {
			name := c.Name
			spec := CommandSpec{
				Name:      "weka_local_resources_" + name,
				Cmd:       "weka local resources -C " + name + " -J",
				NodeLocal: true,
				JSON:      true,
			}
			result, out := runCommand(spec, cmdTimeout)
			manifest.Commands = append(manifest.Commands, result)
			if result.Error != "" {
				warnf("[%s] weka local resources -C %s failed: %s", hostname, name, result.Error)
			}
			content := out
			if result.Error != "" && len(out) == 0 {
				content = []byte(fmt.Sprintf("# command: %s\n# error: %s\n", spec.Cmd, result.Error))
			}
			dest := filepath.Join(hostRoot, "weka", spec.Name+".json")
			if err := addBytesToArchive(tw, dest, content); err != nil {
				warnf("[%s] could not add %s to archive: %v", hostname, spec.Name, err)
			}
		}
	}

	// ── phase: journalctl ────────────────────────────────────────────────
	phase(fmt.Sprintf("[%s] Journalctl (time-windowed)", hostname))
	result, out := journalctlWithWindow(from, to, 2*cmdTimeout)
	manifest.Commands = append(manifest.Commands, result)
	if result.Error != "" {
		warnf("[%s] journalctl failed: %s", hostname, result.Error)
	}
	_ = addBytesToArchive(tw, filepath.Join(hostRoot, "system", "journalctl.txt"), out)

	// weka-agent journal: scoped to time window when given, capped at 50k lines
	// otherwise. No-cap collection caused OOM on memory-constrained nodes when
	// running --profile all with no time window.
	{
		var agentCmd string
		switch {
		case !from.IsZero() && !to.IsZero():
			agentCmd = fmt.Sprintf("journalctl -u weka-agent --no-pager -S '%s' -U '%s'",
				from.Format("2006-01-02 15:04:05"), to.Format("2006-01-02 15:04:05"))
		case !from.IsZero():
			agentCmd = fmt.Sprintf("journalctl -u weka-agent --no-pager -S '%s'",
				from.Format("2006-01-02 15:04:05"))
		default:
			agentCmd = "journalctl -u weka-agent --no-pager -n 50000"
		}
		agentResult, agentOut := runCommand(CommandSpec{Name: "journalctl_weka_agent", Cmd: agentCmd}, 2*cmdTimeout)
		manifest.Commands = append(manifest.Commands, agentResult)
		if agentResult.Error != "" {
			warnf("[%s] journalctl weka-agent failed: %s", hostname, agentResult.Error)
		}
		_ = addBytesToArchive(tw, filepath.Join(hostRoot, "system", "journalctl_weka_agent.txt"), agentOut)
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
		var skipped int
		matches, skipped = filterByTimeWindow(matches, from, to)
		if len(matches) == 0 {
			vlogf("[%s] no files in time window for %s (%d skipped)", hostname, spec.SrcGlob, skipped)
			continue
		}
		if skipped > 0 {
			vlogf("[%s] %s: %d file(s) skipped (outside time window)", hostname, spec.SrcGlob, skipped)
		}
		for _, srcPath := range matches {
			if seenSrcPaths[srcPath] {
				vlogf("[%s] skip duplicate %s", hostname, srcPath)
				continue
			}
			// When --container-name is set, restrict /opt/weka/logs/ collection
			// to only the named container directories; all other paths are unaffected.
			if len(containerNames) > 0 && strings.HasPrefix(srcPath, "/opt/weka/logs/") {
				rest := srcPath[len("/opt/weka/logs/"):]
				containerDir := strings.SplitN(rest, "/", 2)[0]
				allowed := false
				for _, name := range containerNames {
					if containerDir == name {
						allowed = true
						break
					}
				}
				if !allowed {
					vlogf("[%s] skipping container log (not in scope): %s", hostname, srcPath)
					continue
				}
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

	// ── phase: extra commands (orchestrator only, never on remote nodes) ──
	if !nodeOnly && len(extraCmds) > 0 {
		hostRoot := filepath.Join(archiveRoot, "hosts", hostname)
		phase(fmt.Sprintf("[%s] Extra commands (%d)", hostname, len(extraCmds)))
		extraOutputs := runCommandsParallel(extraCmds, cmdTimeout)
		for i, spec := range extraCmds {
			co := extraOutputs[i]
			manifest.Commands = append(manifest.Commands, co.result)
			content := co.out
			if co.result.Error != "" {
				if len(co.out) == 0 {
					content = []byte(fmt.Sprintf("# command: %s\n# error: %s\n", spec.Cmd, co.result.Error))
				}
				warnf("[%s] extra command %q failed (exit %d): %s", hostname, spec.Cmd, co.result.ExitCode, co.result.Error)
			}
			dest := filepath.Join(hostRoot, "extra", spec.Name+".txt")
			if err := addBytesToArchive(tw, dest, content); err != nil {
				warnf("[%s] could not add %s to archive: %v", hostname, spec.Name, err)
			}
		}
	}

	// ── tally results ─────────────────────────────────────────────────────
	manifest.TotalCommands = len(manifest.Commands)
	for _, r := range manifest.Commands {
		if r.Error != "" && !r.Optional {
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

// activeRemoteHosts tracks hosts currently being collected/uploaded via SSH.
// Key: host IP (string), Value: remote binary path (string).
// Used by the signal handler to kill orphaned remote processes on interrupt.
var activeRemoteHosts sync.Map

// sshArgs returns the common SSH option flags used for all SSH/SCP calls.
func sshArgs() []string {
	return []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=30",
		"-o", "BatchMode=yes",
	}
}

// remoteBinPath returns the path used for the self-deployed binary on remote hosts.
// The PID suffix ensures the orchestrator (when also a cluster node) never overwrites
// its own running binary.
func remoteBinPath() string {
	return fmt.Sprintf("%s/weka-log-collector-%d", wlcBaseDir, os.Getpid())
}

// deployToHost copies the running binary to a remote host via SCP.
func deployToHost(host, selfPath string) error {
	sshTarget := "root@" + host
	remoteBin := remoteBinPath()
	mkdirArgs := append(sshArgs(), sshTarget, "mkdir -p "+wlcBaseDir)
	if out, err := exec.Command("ssh", mkdirArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("mkdir %s: %v: %s", wlcBaseDir, err, strings.TrimSpace(string(out)))
	}
	scpArgs := append(sshArgs(), selfPath, sshTarget+":"+remoteBin)
	if out, err := exec.Command("scp", scpArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("scp: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// deployWorkers is the number of concurrent SCP operations during the deploy phase.
// Higher than collection workers because SCP is lightweight — just file transfer.
const deployWorkers = 20

// deployAll copies the running binary to all hosts in parallel.
// Returns the subset of hosts that were successfully deployed to.
// Failed hosts are logged immediately and excluded from collection.
func deployAll(hosts []string, displayNames map[string]string, selfPath string) []string {
	sem := make(chan struct{}, deployWorkers)
	var mu sync.Mutex
	var succeeded []string
	var wg sync.WaitGroup

	for _, host := range hosts {
		host := host
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			display := displayNames[host]
			if display == "" {
				display = host
			}
			if err := deployToHost(host, selfPath); err != nil {
				errorf("  [%s] deploy failed: %v", display, err)
				return
			}
			logf("  [%s] deployed", display)
			mu.Lock()
			succeeded = append(succeeded, host)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return succeeded
}

// collectFromHost SSHs into a host, runs weka-log-collector --local (binary already
// deployed by deployAll), streams the tar.gz back, then removes the deployed binary on exit.
// The caller prints start/completion lines with progress counters; this function is silent.
func collectFromHost(host, displayName, selfPath, profile string, from, to time.Time, sshTimeout time.Duration, containerNames []string) HostResult {
	result := HostResult{Host: host}
	if displayName == "" {
		displayName = host
	}

	sshTarget := "root@" + host
	remoteBin := remoteBinPath()

	// Register this host as active so the signal handler can kill it on interrupt.
	activeRemoteHosts.Store(host, remoteBin)
	defer activeRemoteHosts.Delete(host)

	// ── build the remote command ───────────────────────────────────────────
	// trap cleans up the binary even if collection fails or connection drops.
	// timeout kills the process if it exceeds the SSH timeout, preventing orphans
	// when the orchestrator can no longer wait (e.g. after SSH connection drops).
	// --node-only skips cluster-wide commands (run once by the orchestrator locally).
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
		if len(containerNames) > 0 {
			extra = append(extra, "--container-name", strings.Join(containerNames, ","))
		}
		return extra
	}()...), " ")

	timeoutSecs := int(sshTimeout.Seconds())
	remoteShellCmd := fmt.Sprintf(
		"chmod +x %s; trap 'rm -f %s' EXIT; timeout %d %s",
		remoteBin, remoteBin, timeoutSecs, collectionCmd,
	)

	// ── run collection via SSH, streaming output to a temp file ──────────
	// Streaming to disk (not RAM) prevents accumulating 200-400 MB per host
	// in memory simultaneously when collecting a large cluster in parallel.
	tmpFile, err := os.CreateTemp("", "wlc-host-*.tar.gz")
	if err != nil {
		result.Err = fmt.Errorf("create temp file: %w", err)
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
			exitCode := exitErr.ExitCode()
			errMsg := strings.TrimSpace(stderrBuf.String())
			if exitCode == 124 {
				result.Err = fmt.Errorf("timed out after %s — collection took too long", sshTimeout)
			} else if exitCode == 137 {
				result.Err = fmt.Errorf("process killed (OOM) on remote host — try --start-time to reduce collection size: %s", errMsg)
			} else {
				result.Err = fmt.Errorf("SSH command failed (exit %d): %s", exitCode, errMsg)
			}
		} else {
			result.Err = fmt.Errorf("SSH error: %v", runErr)
		}
		return result
	}

	result.TempFile = tmpPath
	return result
}

// clusterNode represents a physical host in the Weka cluster.
// IDs holds all container IDs running on this host; ID is the representative (lowest) one.
type clusterNode struct {
	ID       int
	IDs      []int
	IP       string
	Mode     string // "backend", "client"
	Hostname string
}

// nodeDisplay returns "hostname (ip)" when a hostname is known, otherwise just the IP.
func nodeDisplay(n clusterNode) string {
	if n.Hostname != "" {
		return fmt.Sprintf("%s (%s)", n.Hostname, n.IP)
	}
	return n.IP
}

// discoverClusterNodes discovers Weka cluster hosts by issuing four separate
// clean 2-field queries (id,ips  id,hostname  id,status  id,mode), joining
// the results by container ID, aggregating containers per hostname, and
// filtering to hosts that have at least one UP container.
//
// Using separate queries avoids the parsing ambiguity in --output id,ips,mode
// where Weka formats multi-IP HA addresses as "172.x.x.x, 172.x.x.x" (space
// after comma), causing fields to be misaligned.  It also avoids silently
// dropping standard container modes (drives, compute, frontend) that the old
// code did not recognise.
//
// If includeClients is true, client-mode hosts are included alongside backends.
func discoverClusterNodes(includeClients bool) ([]clusterNode, error) {
	// Helper: run a 2-field query and return map[containerID]value.
	query2 := func(col string) (map[int]string, error) {
		out, err := exec.Command("weka", "cluster", "container",
			"--no-header", "--output", "id,"+col).Output()
		if err != nil {
			return nil, err
		}
		m := map[int]string{}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) < 2 {
				continue
			}
			id, err := strconv.Atoi(fields[0])
			if err != nil {
				continue
			}
			m[id] = fields[1]
		}
		return m, nil
	}

	// id,ips: first IP for each container (take everything up to first comma).
	ipsOut, err := query2("ips")
	if err != nil {
		return nil, fmt.Errorf("weka cluster container list failed: %v", err)
	}
	hostOut, _ := query2("hostname") // best-effort
	statusOut, _ := query2("status") // best-effort; missing → treated as UP
	modeOut, _ := query2("mode")     // best-effort; missing → treated as backend

	// Normalise IPs: strip trailing comma/space artifacts from multi-IP columns.
	for id, v := range ipsOut {
		ipsOut[id] = strings.SplitN(strings.TrimRight(v, ", "), ",", 2)[0]
	}

	// Collect all container IDs so we can iterate deterministically.
	var allIDs []int
	for id := range ipsOut {
		allIDs = append(allIDs, id)
	}
	sort.Ints(allIDs)

	// Aggregate containers per hostname (fall back to IP when hostname unknown).
	type hostEntry struct {
		ip       string
		hostname string
		ids      []int
		hasUp    bool
		isClient bool
	}
	byHost := map[string]*hostEntry{} // keyed by hostname (or IP)
	for _, id := range allIDs {
		ip := ipsOut[id]
		if ip == "" {
			continue
		}
		hostname := hostOut[id] // may be ""
		key := hostname
		if key == "" {
			key = ip
		}
		e, ok := byHost[key]
		if !ok {
			e = &hostEntry{ip: ip, hostname: hostname}
			byHost[key] = e
		}
		e.ids = append(e.ids, id)
		if strings.ToUpper(statusOut[id]) == "UP" {
			e.hasUp = true
		}
		m := strings.ToLower(modeOut[id])
		if m == "client" {
			e.isClient = true
		}
	}

	// Build clusterNode list, filtered by UP status and mode.
	var nodes []clusterNode
	for _, e := range byHost {
		if !e.hasUp {
			continue // skip hosts with no UP containers (dead / repurposed nodes)
		}
		mode := "backend"
		if e.isClient {
			mode = "client"
		}
		if mode == "client" && !includeClients {
			continue
		}
		sort.Ints(e.ids)
		nodes = append(nodes, clusterNode{
			ID:       e.ids[0],
			IDs:      e.ids,
			IP:       e.ip,
			Mode:     mode,
			Hostname: e.hostname,
		})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].IP < nodes[j].IP })
	return nodes, nil
}

// filterNodesByContainerID returns only nodes that have at least one container
// ID in the given set. A node may host multiple containers (drives0, compute0,
// frontend0 …); any matching ID is sufficient to select the host.
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
		for _, id := range n.IDs {
			if idSet[id] {
				out = append(out, n)
				break
			}
		}
	}
	return out
}

// resolveContainerNames maps container IDs to their names (e.g. 36 → "drives0").
// Uses a separate --output id,container query — clean 2-field output, no parsing ambiguity.
// Returns an empty map on failure; callers treat missing entries as "collect all".
func resolveContainerNames(ids []int) map[int]string {
	out, err := exec.Command("weka", "cluster", "container",
		"--no-header", "--output", "id,container").Output()
	if err != nil {
		return nil
	}
	idSet := make(map[int]bool, len(ids))
	for _, id := range ids {
		idSet[id] = true
	}
	result := make(map[int]string)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		id, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		if idSet[id] {
			result[id] = fields[1]
		}
	}
	return result
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

// isLocalIP returns true if ip matches any local network interface address.
// Used to identify the orchestrator node in the cluster host list so we can
// run full local collection (with cluster-wide commands) instead of SSH.
func isLocalIP(ip string) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var a net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				a = v.IP
			case *net.IPAddr:
				a = v.IP
			}
			if a != nil && a.String() == ip {
				return true
			}
		}
	}
	return false
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
// checkCloudEnabled verifies that weka cloud is registered and the uploader
// daemon is active on at least one host. Returns the configured cloud URL so
// the caller can distinguish Local Weka Home from Cloud Weka Home.
func checkCloudEnabled() (cloudURL string, err error) {
	out, runErr := exec.Command("weka", "cloud", "status").Output()
	if runErr != nil {
		return "", fmt.Errorf("could not check cloud status: %v", runErr)
	}
	var hasURL, isRegistered bool
	totalHosts, disabledHosts := 0, 0
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "url:") {
			u := strings.TrimSpace(strings.TrimPrefix(trimmed, strings.SplitN(trimmed, ":", 2)[0]+":"))
			if u != "" {
				hasURL = true
				cloudURL = u
			}
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
		return "", fmt.Errorf("weka cloud is not registered — run 'weka cloud enable' first")
	}
	if totalHosts > 0 && totalHosts == disabledHosts {
		return "", fmt.Errorf("weka uploader daemon is DISABLED on all hosts — check 'weka cloud status' and ensure the uploader is active before using --upload")
	}
	return cloudURL, nil
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
// sessionID is the shared nanosecond timestamp used in the wlc:<id>:… symlink
// name. When all nodes in a distributed upload share the same sessionID, Weka
// Home groups their archives under a single session entry. Pass 0 to generate
// a fresh ID (standalone / single-node uploads).
//
// The weka uploader (inside wekanode) watches support/ via inotify and uploads
// each file to Weka Home. If a container's uploader is in FAILURE state (as
// shown by 'weka cloud status') it will not respond; we try each available
// container in sequence, moving on after a per-dir timeout.
// validateUploadFile checks that path is safe to upload:
//   - resolves to an absolute path under wlcBaseDir
//   - is a regular file (not a symlink or directory)
//   - does not exceed uploadFileMaxSize (50 MB)
//   - has an allowed extension (.tar.gz, .log, .txt, .json)
func validateUploadFile(path string) (string, error) {
	// Accept bare filename — resolve relative to wlcBaseDir.
	if !filepath.IsAbs(path) {
		path = filepath.Join(wlcBaseDir, path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("cannot resolve path: %w", err)
	}
	// Hard path restriction: must be inside wlcBaseDir.
	allowed := filepath.Clean(wlcBaseDir) + "/"
	if !strings.HasPrefix(filepath.Clean(abs)+"/", allowed) {
		return "", fmt.Errorf("file must be under %s (got %s)", wlcBaseDir, abs)
	}
	// Must be a regular file.
	fi, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("file not found: %s", abs)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", abs)
	}
	// Size check.
	if fi.Size() > uploadFileMaxSize {
		return "", fmt.Errorf("file is %d MB, exceeds the %d MB limit", fi.Size()/(1024*1024), uploadFileMaxSize/(1024*1024))
	}
	// Extension allowlist.
	name := fi.Name()
	allowed_exts := []string{".tar.gz", ".log", ".txt", ".json", ".out"}
	ok := false
	for _, ext := range allowed_exts {
		if strings.HasSuffix(name, ext) {
			ok = true
			break
		}
	}
	if !ok {
		return "", fmt.Errorf("file extension not allowed (must be one of: %s)", strings.Join(allowed_exts, ", "))
	}
	return abs, nil
}

func uploadBundle(archivePath string, sessionID int64) error {
	phase("Uploading to Weka Home")

	cloudURL, err := checkCloudEnabled()
	if err != nil {
		return err
	}

	logf("Target: %s", cloudURL)

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
	// Use the caller-supplied sessionID so all nodes in a cluster upload share
	// the same ID and appear as one session in Weka Home.
	if sessionID == 0 {
		sessionID = time.Now().UnixNano()
	}
	hostname, _ := os.Hostname()
	linkName := fmt.Sprintf("wlc:%d:%s:%s", sessionID, hostname, filename)

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

// uploadK8sBundle uploads the collected archive to Weka Home by exec-ing into a
// compute pod and using the weka uploader daemon that runs inside it.
//
// On a K8s node the weka binary does not exist — all weka commands must be
// run inside pods. This function:
//  1. Finds a live compute/drive/frontend pod in clusterNS.
//  2. Verifies cloud is registered via `weka cloud status` inside the pod.
//  3. Streams the archive into the pod at /tmp/<filename> via stdin.
//  4. Finds the support directory (e.g. /opt/weka/drives0/support) in the pod.
//  5. Creates the wlc:<id>:<host>:<file> symlink the uploader expects.
//  6. Polls until the uploader moves the symlink to .uploaded/ or removes it.
func uploadK8sBundle(kc *kubectlRunner, clusterNS, archivePath string) error {
	phase("Uploading to Weka Home (via K8s pod)")

	// 1. Find a compute/drive/frontend pod.
	podOut, err := kc.run("get", "pods", "-n", clusterNS, "--no-headers")
	if err != nil {
		return fmt.Errorf("list pods in %s: %w", clusterNS, err)
	}
	var computePod string
	for _, name := range parsePodNames(podOut) {
		if isWekaContainerPod(name) {
			computePod = name
			break
		}
	}
	if computePod == "" {
		return fmt.Errorf("no compute/drive/frontend pod found in namespace %s", clusterNS)
	}
	logf("  Using pod: %s/%s", clusterNS, computePod)

	// 2. Verify cloud is registered inside the pod.
	cloudOut, err := kc.execInPod(clusterNS, computePod, "", "weka", "cloud", "status")
	if err != nil {
		return fmt.Errorf("'weka cloud status' in pod %s: %w", computePod, err)
	}
	var hasURL, isRegistered bool
	cloudURL := ""
	totalHosts, disabledHosts := 0, 0
	for _, line := range strings.Split(string(cloudOut), "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "url:") {
			u := strings.TrimSpace(strings.TrimPrefix(trimmed, strings.SplitN(trimmed, ":", 2)[0]+":"))
			if u != "" {
				hasURL = true
				cloudURL = u
			}
		}
		if strings.HasPrefix(lower, "registration:") && strings.Contains(lower, "registered") {
			isRegistered = true
		}
		if strings.Contains(trimmed, "HostId<") {
			totalHosts++
			if strings.HasSuffix(strings.ToUpper(trimmed), "DISABLED") {
				disabledHosts++
			}
		}
	}
	if !hasURL || !isRegistered {
		return fmt.Errorf("weka cloud is not registered — run 'weka cloud enable' inside a compute pod first")
	}
	if totalHosts > 0 && totalHosts == disabledHosts {
		return fmt.Errorf("weka uploader daemon is DISABLED on all hosts — check 'weka cloud status' inside a compute pod")
	}
	if cloudURL != "" {
		logf("  Target: %s", cloudURL)
	}

	// 3. Find the support directory inside the pod.
	findOut, err := kc.execInPod(clusterNS, computePod, "",
		"find", "/opt/weka", "-maxdepth", "4", "-name", "support", "-type", "d")
	if err != nil || len(strings.TrimSpace(string(findOut))) == 0 {
		return fmt.Errorf("no support directory found in pod %s under /opt/weka", computePod)
	}
	supportDir := strings.TrimSpace(strings.SplitN(string(findOut), "\n", 2)[0])
	logf("  Support dir: %s", supportDir)

	// 4. Stream archive into the pod under /opt/weka/ (one level above support/).
	// The weka uploader agent runs with /opt/weka/ bind-mounted; /tmp is not
	// accessible to it, so the symlink target must be inside /opt/weka/.
	// This mirrors the bare-metal uploadBundle() staging approach exactly.
	filename := filepath.Base(archivePath)
	podStagedDir := filepath.Dir(supportDir) // e.g. /opt/weka/compute<uuid>
	podArchivePath := podStagedDir + "/" + filename

	info, _ := os.Stat(archivePath)
	var sizeMB int64
	if info != nil {
		sizeMB = info.Size() / (1024 * 1024)
	}
	logf("  Transferring archive (%d MB) to pod...", sizeMB)
	if err := kc.copyFileToPod(clusterNS, computePod, archivePath, podArchivePath); err != nil {
		return fmt.Errorf("transfer archive to pod: %w", err)
	}
	// Always clean up the copied archive from the pod.
	defer func() {
		kc.execInPod(clusterNS, computePod, "", "rm", "-f", podArchivePath) //nolint:errcheck
	}()

	// 5. Create the wlc symlink in the support directory.
	sessionID := time.Now().UnixNano()
	hostname, _ := os.Hostname()
	linkName := fmt.Sprintf("wlc:%d:%s:%s", sessionID, hostname, filename)
	linkPath := supportDir + "/" + linkName
	uploadedPath := supportDir + "/.uploaded/" + linkName

	if _, err := kc.execInPod(clusterNS, computePod, "", "ln", "-s", podArchivePath, linkPath); err != nil {
		return fmt.Errorf("create upload symlink in pod: %w", err)
	}

	estMins := (sizeMB / 60) + 1
	logf("  Queued %s (%d MB) — waiting for weka uploader (~1 MB/s, est. ~%d min)...", filename, sizeMB, estMins)

	// 6. Poll until the uploader daemon signals completion.
	perDirTimeout := time.Duration(max(300, sizeMB*2)) * time.Second
	start := time.Now()
	lastLog := start
	deadline := start.Add(perDirTimeout)

	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Second)

		// .uploaded/<linkName> appears when the uploader finishes.
		if _, err := kc.execInPod(clusterNS, computePod, "", "test", "-e", uploadedPath); err == nil {
			logf("  Upload complete (%.0fs)", time.Since(start).Seconds())
			kc.execInPod(clusterNS, computePod, "", "rm", "-f", uploadedPath) //nolint:errcheck
			return nil
		}
		// Uploader may also simply remove the symlink when done.
		if _, err := kc.execInPod(clusterNS, computePod, "", "test", "-L", linkPath); err != nil {
			logf("  Upload complete (%.0fs)", time.Since(start).Seconds())
			return nil
		}

		if time.Since(lastLog) >= 60*time.Second {
			logf("  Still uploading... elapsed: %s", time.Since(start).Round(time.Second))
			lastLog = time.Now()
		}
	}

	// Timed out — clean up the symlink to stop the uploader from picking it up later.
	kc.execInPod(clusterNS, computePod, "", "rm", "-f", linkPath) //nolint:errcheck
	return fmt.Errorf("upload timed out after %v — check 'weka cloud status' inside a compute pod", perDirTimeout)
}

// ── bash completion ───────────────────────────────────────────────────────────

const bashCompletionScript = `# bash completion for weka-log-collector
_weka_log_collector() {
    local cur prev word opts profiles subcommands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    subcommands="k8s"
    profiles="default perf nfs s3 smbw all"

    # Detect if we are completing inside the k8s subcommand
    local in_k8s=0
    for word in "${COMP_WORDS[@]}"; do
        if [[ "$word" == "k8s" ]]; then
            in_k8s=1
            break
        fi
    done

    if [[ $in_k8s -eq 1 ]]; then
        # k8s-specific flags
        local k8s_opts="--k8s-host --kubeconfig --operator-ns --cluster-ns --csi-ns
                        --output --upload --cmd-timeout --verbose --version"
        case "$prev" in
            --output|--kubeconfig)
                COMPREPLY=( $(compgen -f -- "$cur") )
                return 0
                ;;
            --cmd-timeout)
                COMPREPLY=( $(compgen -W "30s 60s 120s 180s 300s" -- "$cur") )
                return 0
                ;;
        esac
        COMPREPLY=( $(compgen -W "$k8s_opts" -- "$cur") )
        return 0
    fi

    opts="--local --upload --upload-file --clients --clients-only --verbose --version
          --start-time --end-time --profile --output --host --container-id
          --extra-commands --cmd-timeout
          --list-bundles --rm-bundle --clean-bundles"

    case "$prev" in
        --profile)
            COMPREPLY=( $(compgen -W "$profiles" -- "$cur") )
            return 0
            ;;
        --output)
            COMPREPLY=( $(compgen -f -- "$cur") )
            return 0
            ;;
        --start-time|--end-time)
            now=$(date +%Y-%m-%dT%H:%M)
            today=$(date +%Y-%m-%d)
            COMPREPLY=( $(compgen -W "-1h -2h -4h -8h -12h -24h -1d -2d ${now} ${today}T00:00 ${today}T06:00 ${today}T12:00 ${today}T18:00" -- "$cur") )
            return 0
            ;;
    esac

    # Offer subcommands when the user has typed nothing yet or is completing first word
    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$subcommands $opts" -- "$cur") )
    else
        COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
    fi
    return 0
}
complete -F _weka_log_collector weka-log-collector ./weka-log-collector
`

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

// ── kubernetes collection ─────────────────────────────────────────────────────
//
// The `k8s` subcommand collects diagnostic data from a Weka-on-Kubernetes
// deployment. It uses kubectl to access the cluster, optionally routing through
// an SSH jump host that has kubeconfig configured.
//
// Architecture:
//   - Weka Operator: manages WekaCluster CRDs; typically in weka-operator-system
//   - WekaCluster pods: compute/drive/frontend/management pods running Weka
//     NOTE: in many deployments these share the same namespace as the operator
//   - CSI plugin: controller + node daemonset; typically in weka-csi-plugin ns

// kubectlRunner wraps kubectl invocations. When jumpHost is set, all commands
// are transparently routed through SSH to that host.
type kubectlRunner struct {
	jumpHost   string        // empty ⟹ invoke kubectl locally
	kubeconfig string        // empty ⟹ use default kubeconfig
	timeout    time.Duration // per-command timeout
}

// shellQuote wraps s in single quotes with internal single-quote escaping,
// safe for embedding in a shell command string.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// buildKubectlArgs prepends --kubeconfig=... when set.
func (k *kubectlRunner) buildKubectlArgs(args []string) []string {
	if k.kubeconfig != "" {
		return append([]string{"--kubeconfig=" + k.kubeconfig}, args...)
	}
	return args
}

// run invokes kubectl (locally or via SSH jump host) with a timeout and returns
// combined stdout+stderr. Non-zero exit returns an error containing the output.
func (k *kubectlRunner) run(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), k.timeout)
	defer cancel()

	kcArgs := k.buildKubectlArgs(args)

	var cmd *exec.Cmd
	if k.jumpHost != "" {
		// Serialize kubectl args as a single shell string for SSH transport.
		parts := make([]string, len(kcArgs))
		for i, a := range kcArgs {
			parts[i] = shellQuote(a)
		}
		remoteCmd := "kubectl " + strings.Join(parts, " ")
		sshOpts := append(sshArgs(), "root@"+k.jumpHost, remoteCmd)
		cmd = exec.CommandContext(ctx, "ssh", sshOpts...)
	} else {
		cmd = exec.CommandContext(ctx, "kubectl", kcArgs...)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("kubectl %s: %w: %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// runLenient runs kubectl but silently swallows errors, returning whatever
// output was produced. Use for resources that may not exist on all clusters.
func (k *kubectlRunner) runLenient(args ...string) []byte {
	out, _ := k.run(args...)
	return out
}

// execInPod runs a command inside a pod via kubectl exec.
// container may be "" to use the pod's default container.
func (k *kubectlRunner) execInPod(ns, pod, container string, cmd ...string) ([]byte, error) {
	args := []string{"exec", pod, "-n", ns}
	if container != "" {
		args = append(args, "-c", container)
	}
	args = append(args, "--")
	args = append(args, cmd...)
	return k.run(args...)
}

// podLogs fetches logs for a pod. When container is "", collects all containers
// with --prefix=true so each line is tagged with the container name.
func (k *kubectlRunner) podLogs(ns, pod, container string) ([]byte, error) {
	if container == "" {
		return k.run("logs", pod, "-n", ns,
			"--all-containers=true", "--prefix=true", "--tail=50000")
	}
	return k.run("logs", pod, "-n", ns, "-c", container, "--tail=50000")
}

// copyFileToPod streams a local file into remotePath inside the pod via stdin,
// using `kubectl exec -i -- sh -c 'cat > path'`. Works transparently through
// the SSH jump host because stdin is forwarded through the SSH tunnel.
func (k *kubectlRunner) copyFileToPod(ns, pod, localPath, remotePath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", localPath, err)
	}
	defer f.Close()

	remoteCmd := "cat > " + shellQuote(remotePath)
	kcArgs := k.buildKubectlArgs([]string{"exec", "-i", pod, "-n", ns, "--", "sh", "-c", remoteCmd})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var cmd *exec.Cmd
	if k.jumpHost != "" {
		parts := make([]string, len(kcArgs))
		for i, a := range kcArgs {
			parts[i] = shellQuote(a)
		}
		sshCmd := "kubectl " + strings.Join(parts, " ")
		sshOpts := append(sshArgs(), "root@"+k.jumpHost, sshCmd)
		cmd = exec.CommandContext(ctx, "ssh", sshOpts...)
	} else {
		cmd = exec.CommandContext(ctx, "kubectl", kcArgs...)
	}
	cmd.Stdin = f
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("copy to pod: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// safeName replaces characters unsafe for tar paths (/, :, space) with _.
func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '/', ':', ' ', '\t':
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// parsePodNames parses the first column (pod name) from kubectl get pods --no-headers output.
// Skips blank lines, header lines, and the "No resources found..." message that kubectl
// prints when a namespace exists but contains no pods.
func parsePodNames(out []byte) []string {
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "NAME") || strings.HasPrefix(line, "No ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			names = append(names, fields[0])
		}
	}
	return names
}

// isOperatorPod returns true for pods belonging to the Weka Operator itself
// (controller-manager, node-agents, driver distribution pod).
func isOperatorPod(pod string) bool {
	return strings.HasPrefix(pod, "weka-operator-") || pod == "weka-drivers-dist"
}

// isWekaContainerPod returns true for pods that run weka processes (compute/drive/frontend).
// Only these pods have the weka binary on PATH and /opt/weka/logs on a mounted PVC.
func isWekaContainerPod(pod string) bool {
	return strings.Contains(pod, "-compute-") ||
		strings.Contains(pod, "-drive-") ||
		strings.Contains(pod, "-frontend-")
}

// wekaK8sNamespaces holds the discovered (or user-overridden) namespace for each
// Weka component in the K8s cluster.
type wekaK8sNamespaces struct {
	Operator    string // weka-operator deployment
	Cluster     string // WekaCluster pods (compute/drive/frontend); often same as Operator
	ClusterName string // WekaCluster CRD instance name (e.g. "mycluster-1")
	CSI         string // CSI plugin controller + node daemonset
}

// discoverWekaK8sNamespaces auto-detects namespaces and the WekaCluster name.
// In most deployments all Weka pods share a single namespace (weka-operator-system).
func discoverWekaK8sNamespaces(kc *kubectlRunner) wekaK8sNamespaces {
	ns := wekaK8sNamespaces{
		Operator: "weka-operator-system",
		Cluster:  "weka-operator-system", // default: same namespace as operator
		CSI:      "weka-csi-plugin",
	}

	// Operator: deployment name contains "weka-operator"
	out := kc.runLenient("get", "deployments", "--all-namespaces", "--no-headers",
		"-o", "custom-columns=NS:.metadata.namespace,NAME:.metadata.name")
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.Contains(strings.ToLower(fields[1]), "weka-operator") {
			ns.Operator = fields[0]
			ns.Cluster = fields[0] // align cluster default to discovered operator ns
			break
		}
	}

	// WekaCluster CRD: get both namespace and instance name
	out = kc.runLenient("get", "wekacluster", "--all-namespaces", "--no-headers",
		"-o", "custom-columns=NS:.metadata.namespace,NAME:.metadata.name")
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && !strings.HasPrefix(fields[0], "No") {
			ns.Cluster = fields[0]
			ns.ClusterName = fields[1]
			break
		}
	}

	// CSI: deployment or daemonset name contains "csi-wekafs"
	out = kc.runLenient("get", "deployments,daemonsets", "--all-namespaces", "--no-headers",
		"-o", "custom-columns=NS:.metadata.namespace,NAME:.metadata.name")
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.Contains(strings.ToLower(fields[1]), "csi-wekafs") {
			ns.CSI = fields[0]
			break
		}
	}

	return ns
}

// kubectlToArchive runs kubectl args, writes output into tw at archivePath.
// Errors are logged as verbose and return false; partial output is still archived.
func kubectlToArchive(tw *tar.Writer, kc *kubectlRunner, archivePath string, args ...string) bool {
	out, err := kc.run(args...)
	if len(out) > 0 {
		_ = addBytesToArchive(tw, archivePath, out)
	}
	if err != nil {
		vlogf("k8s: %s: %v", archivePath, err)
		return false
	}
	return true
}

// k8sManifest is written as collection_manifest.json at the k8s/ archive root.
type k8sManifest struct {
	CollectedAt       time.Time `json:"collected_at"`
	Version           string    `json:"version"`
	JumpHost          string    `json:"jump_host,omitempty"`
	ClusterName       string    `json:"cluster_name,omitempty"`
	OperatorNamespace string    `json:"operator_namespace"`
	ClusterNamespace  string    `json:"cluster_namespace"`
	CSINamespace      string    `json:"csi_namespace"`
	TotalCommands     int       `json:"total_commands"`
	FailedCommands    int       `json:"failed_commands"`
	Errors            []string  `json:"errors,omitempty"`
}

// collectK8sClusterLevel gathers cluster-wide K8s resources: nodes, events,
// CRDs, storage classes, PVs/PVCs, and all Weka CRD instances.
func collectK8sClusterLevel(tw *tar.Writer, kc *kubectlRunner, root string, m *k8sManifest) {
	base := root + "/cluster"

	// run counts failures (required resources).
	run := func(name string, args ...string) {
		m.TotalCommands++
		if !kubectlToArchive(tw, kc, base+"/"+name, args...) {
			m.FailedCommands++
		}
	}
	// soft: optional resources — not counted as failures when missing.
	soft := func(name string, args ...string) {
		out := kc.runLenient(args...)
		if len(out) > 0 {
			_ = addBytesToArchive(tw, base+"/"+name, out)
		}
	}

	logf("  Collecting cluster-level resources...")

	run("version.txt", "version")
	run("nodes_wide.txt", "get", "nodes", "-o", "wide")
	run("nodes.yaml", "get", "nodes", "-o", "yaml")
	run("nodes_describe.txt", "describe", "nodes") // conditions, events, resource pressure per node
	run("cluster_info_dump.txt", "cluster-info", "dump")
	run("namespaces.txt", "get", "namespaces")
	run("events_all.txt", "get", "events", "--all-namespaces", "--sort-by=.lastTimestamp")
	run("crds.txt", "get", "crd", "-o", "wide")
	run("storageclasses_wide.txt", "get", "storageclass", "-o", "wide")
	run("storageclasses.yaml", "get", "storageclass", "-o", "yaml")
	run("pvc_all.txt", "get", "pvc", "--all-namespaces")
	run("pvc_all.yaml", "get", "pvc", "--all-namespaces", "-o", "yaml")
	run("pv_all.txt", "get", "pv", "-o", "wide")
	run("pv_all.yaml", "get", "pv", "-o", "yaml")
	run("csidrivers.txt", "get", "csidrivers")
	run("csidrivers.yaml", "get", "csidriver", "-o", "yaml")
	run("csinodes.yaml", "get", "csinode", "-o", "yaml")

	// Cluster-wide pod listing — useful for spotting co-located workloads and
	// understanding scheduling when diagnosing node-level issues.
	run("pods_all_wide.txt", "get", "pods", "--all-namespaces", "-o", "wide")

	// kubectl top — requires metrics-server; skipped gracefully if unavailable.
	soft("nodes_top.txt", "top", "nodes")
	soft("pods_top.txt", "top", "pods", "--all-namespaces")

	// helm list — deployment config (kubelet path, CSI version) is a frequent root cause.
	soft("helm_releases.txt", "helm", "list", "--all-namespaces")

	// Required Weka CRD (counts as failure if missing)
	run("wekacluster.yaml", "get", "wekacluster", "--all-namespaces", "-o", "yaml")

	// Optional Weka CRDs — may not be installed depending on features in use.
	// Not counted as failures when absent.
	// WekaContainer is the per-pod CRD managed by the operator — its status shows
	// reconciliation errors, resource allocation, and container health per node.
	for _, c := range []struct{ file, crd string }{
		{"wekacontainer.yaml", "wekacontainer"},
		{"wekafilesystem.yaml", "wekafilesystem"},
		{"wekafilesystemgroup.yaml", "wekafilesystemgroup"},
		{"wekanfsinterface.yaml", "wekanfsinterface"},
		{"wekasnapshot.yaml", "wekasnapshot"},
		{"wekauploadimage.yaml", "wekauploadimage"},
		{"wekanfspermission.yaml", "wekanfspermission"},
		{"wekasmb.yaml", "wekasmb"},
		{"wekaclient.yaml", "wekaclient"},
		{"wekaclientconfig.yaml", "wekaclientconfig"},
	} {
		soft(c.file, "get", c.crd, "--all-namespaces", "-o", "yaml")
	}
}

// collectK8sNamespaceMeta collects namespace-level resources (pods listing, events,
// workloads, services) into root/ and returns the list of pod names.
// podFilter, when non-nil, restricts which pod names are returned for per-pod
// collection; namespace-level resources are always collected in full.
func collectK8sNamespaceMeta(tw *tar.Writer, kc *kubectlRunner, root, ns string, m *k8sManifest, podFilter func(string) bool) []string {
	run := func(name string, args ...string) {
		m.TotalCommands++
		if !kubectlToArchive(tw, kc, root+"/"+name, args...) {
			m.FailedCommands++
		}
	}

	run("pods_wide.txt", "get", "pods", "-n", ns, "-o", "wide")
	run("events.txt", "get", "events", "-n", ns, "--sort-by=.lastTimestamp")
	run("workloads.txt", "get", "deployments,statefulsets,daemonsets,replicasets", "-n", ns)
	run("services.txt", "get", "svc,endpoints", "-n", ns)
	run("configmaps.txt", "get", "configmap", "-n", ns)
	// configmaps.yaml: redact any sensitive-looking keys before archiving.
	// Secrets are never collected (names only), but some operators store tokens
	// or API endpoints in configmaps — redact as a precaution.
	m.TotalCommands++
	if cmOut, cmErr := kc.run("get", "configmap", "-n", ns, "-o", "yaml"); cmErr == nil {
		_ = addBytesToArchive(tw, root+"/configmaps.yaml", redactSensitiveYAML(cmOut))
	} else {
		m.FailedCommands++
	}
	run("secrets_names.txt", "get", "secret", "-n", ns, "--no-headers",
		"-o", "custom-columns=NAME:.metadata.name,TYPE:.type")
	run("pvcs.txt", "get", "pvc", "-n", ns, "-o", "wide")
	// Leader election leases — diagnoses split-brain and controller restart issues.
	run("leases.txt", "get", "lease", "-n", ns)

	m.TotalCommands++
	podsOut, err := kc.run("get", "pods", "-n", ns, "--no-headers")
	if err != nil {
		m.FailedCommands++
		warnf("k8s: cannot list pods in namespace %s: %v", ns, err)
		return nil
	}
	pods := parsePodNames(podsOut)
	if podFilter == nil {
		return pods
	}
	var filtered []string
	for _, p := range pods {
		if podFilter(p) {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// collectK8sPodLogs collects describe + stdout logs + previous logs for one pod.
func collectK8sPodLogs(tw *tar.Writer, kc *kubectlRunner, ns, pod, podDir string, m *k8sManifest) {
	m.TotalCommands++
	if !kubectlToArchive(tw, kc, podDir+"/describe.txt", "describe", "pod", pod, "-n", ns) {
		m.FailedCommands++
	}

	m.TotalCommands++
	logsOut, logsErr := kc.podLogs(ns, pod, "")
	if logsErr != nil {
		m.FailedCommands++
		vlogf("k8s: logs %s/%s: %v", ns, pod, logsErr)
	} else if len(logsOut) > 0 {
		_ = addBytesToArchive(tw, podDir+"/logs/stdout.log", stripANSI(logsOut))
	}

	// Previous container logs are valuable when a pod has crashed/restarted
	prevOut := kc.runLenient("logs", pod, "-n", ns,
		"--all-containers=true", "--prefix=true", "--previous=true", "--tail=10000")
	if len(prevOut) > 0 {
		_ = addBytesToArchive(tw, podDir+"/logs/previous.log", stripANSI(prevOut))
	}
}

// clusterWideCLICommands are run once per cluster from the first responsive
// compute pod. Output is identical on every pod so there is no value running
// them per-pod — doing so only inflates the failure count on non-compute pods.
var clusterWideCLICommands = []struct {
	name string
	cmd  []string
}{
	{"weka_status.json", []string{"weka", "status", "--json"}},
	{"weka_alerts.json", []string{"weka", "alerts", "--json"}},
}

// perPodCLICommands are run on each compute/drive pod individually because
// they return node-local data that differs per container.
var perPodCLICommands = []struct {
	name string
	cmd  []string
}{
	{"weka_local_ps.txt", []string{"weka", "local", "ps"}},
	{"weka_local_resources.json", []string{"weka", "local", "resources", "--json"}},
}

// collectK8sOptWekaLogs tries to enumerate and cat file-based weka process logs
// from inside the pod. These live on PVCs and survive pod restarts.
// / Path: /opt/weka/logs (PVC-backed, survives pod restarts).
func collectK8sOptWekaLogs(tw *tar.Writer, kc *kubectlRunner, ns, pod, archiveDir string, m *k8sManifest) {
	logPaths := []string{"/opt/weka/logs"}

	for _, logPath := range logPaths {
		m.TotalCommands++
		findOut, findErr := kc.execInPod(ns, pod, "",
			"find", logPath, "-maxdepth", "3", "-type", "f",
			"(", "-name", "*.log", "-o", "-name", "syslog",
			"-o", "-name", "output", "-o", "-name", "events", ")",
		)
		if findErr != nil {
			m.FailedCommands++
			vlogf("k8s: find %s in %s/%s: %v", logPath, ns, pod, findErr)
			continue
		}

		files := strings.Fields(string(findOut))
		if len(files) == 0 {
			continue
		}
		logf("    Pod %s: %d files under %s", pod, len(files), logPath)

		// Cap at 100 files to avoid overwhelming the archive
		if len(files) > 100 {
			files = files[:100]
		}
		for _, f := range files {
			m.TotalCommands++
			content, catErr := kc.execInPod(ns, pod, "", "cat", f)
			if catErr != nil {
				m.FailedCommands++
				vlogf("k8s: cat %s in %s/%s: %v", f, ns, pod, catErr)
				continue
			}
			// Strip leading slash, replace remaining / with __ for flat filename
			rel := strings.TrimPrefix(f, "/")
			destName := strings.ReplaceAll(rel, "/", "__")
			_ = addBytesToArchive(tw, archiveDir+"/"+destName, content)
		}
	}
}

// collectK8sOperator collects Weka Operator pods (controller-manager, node-agents,
// driver-dist), their logs, and the WekaCluster CRD spec/status.
// When operatorNS == clusterNS the namespace is shared; podFilter restricts
// per-pod collection to operator pods only so WekaCluster pods are not duplicated.
func collectK8sOperator(tw *tar.Writer, kc *kubectlRunner, root, operatorNS, clusterNS string, m *k8sManifest) {
	logf("  Collecting Weka Operator (namespace: %s)...", operatorNS)

	var podFilter func(string) bool
	if operatorNS == clusterNS {
		podFilter = isOperatorPod // only weka-operator-* and weka-drivers-dist
	}

	pods := collectK8sNamespaceMeta(tw, kc, root, operatorNS, m, podFilter)
	logf("    %d operator pods", len(pods))

	for _, pod := range pods {
		podDir := root + "/" + safeName(pod)
		vlogf("k8s: operator pod %s/%s", operatorNS, pod)
		collectK8sPodLogs(tw, kc, operatorNS, pod, podDir, m)
	}

	// WekaCluster CRD status — most useful single resource for diagnosing operator issues
	m.TotalCommands++
	if !kubectlToArchive(tw, kc, root+"/wekacluster_status.yaml",
		"get", "wekacluster", "-n", operatorNS, "-o", "yaml") {
		m.FailedCommands++
	}
}

// collectK8sWekaCluster collects WekaCluster pod diagnostics.
// When clusterNS == operatorNS, operator pods are excluded via podFilter.
// Cluster-wide weka CLI (status/alerts) is run once from the first compute pod.
// Per-pod CLI (local ps/resources) and /opt/weka/logs are only attempted on
// compute/drive/frontend pods that actually have the weka binary.
func collectK8sWekaCluster(tw *tar.Writer, kc *kubectlRunner, root, clusterNS, operatorNS string, m *k8sManifest) {
	logf("  Collecting WekaCluster pods (namespace: %s)...", clusterNS)

	var podFilter func(string) bool
	if clusterNS == operatorNS {
		podFilter = func(p string) bool { return !isOperatorPod(p) }
	}

	pods := collectK8sNamespaceMeta(tw, kc, root, clusterNS, m, podFilter)
	logf("    %d WekaCluster pods", len(pods))

	// Cluster-wide CLI: run once from the first responsive compute pod.
	// weka status / weka alerts return the same output on every pod.
	for _, spec := range clusterWideCLICommands {
		for _, pod := range pods {
			if !isWekaContainerPod(pod) {
				continue
			}
			m.TotalCommands++
			out, err := kc.execInPod(clusterNS, pod, "", spec.cmd...)
			if err != nil {
				m.FailedCommands++
				vlogf("k8s: cluster CLI %s from %s: %v", spec.cmd[0], pod, err)
				continue
			}
			_ = addBytesToArchive(tw, root+"/weka-cli/"+spec.name, out)
			break // success — no need to try other pods
		}
	}

	// Per-pod collection
	for _, pod := range pods {
		podDir := root + "/" + safeName(pod)
		vlogf("k8s: wekacluster pod %s/%s", clusterNS, pod)

		collectK8sPodLogs(tw, kc, clusterNS, pod, podDir, m)

		// weka local ps/resources and /opt/weka/logs only on compute/drive/frontend pods
		if isWekaContainerPod(pod) {
			for _, spec := range perPodCLICommands {
				m.TotalCommands++
				out, err := kc.execInPod(clusterNS, pod, "", spec.cmd...)
				if err != nil {
					m.FailedCommands++
					vlogf("k8s: exec %s %s: %v", pod, spec.cmd[0], err)
					continue
				}
				_ = addBytesToArchive(tw, podDir+"/weka-cli/"+spec.name, out)
			}
			collectK8sOptWekaLogs(tw, kc, clusterNS, pod, podDir+"/opt-weka-logs", m)
		}
	}
}

// collectK8sCSI collects CSI plugin diagnostics: controller + node daemonset
// pods and their stdout logs. Skips gracefully when the namespace does not exist.
func collectK8sCSI(tw *tar.Writer, kc *kubectlRunner, root, ns string, m *k8sManifest) {
	logf("  Collecting CSI plugin (namespace: %s)...", ns)

	// Check namespace exists before attempting collection — CSI may not be installed.
	if _, err := kc.run("get", "namespace", ns); err != nil {
		logf("  CSI namespace %q not found — skipping", ns)
		logf("  (CSI plugin may not be installed; use --csi-ns to override)")
		return
	}

	pods := collectK8sNamespaceMeta(tw, kc, root, ns, m, nil)
	logf("    %d CSI pods", len(pods))

	for _, pod := range pods {
		podDir := root + "/" + safeName(pod)
		vlogf("k8s: CSI pod %s/%s", ns, pod)
		collectK8sPodLogs(tw, kc, ns, pod, podDir, m)

		// /run/weka-fs-mounts/ is a hostPath bind-mount directory created by the
		// CSI node plugin. Its contents (or absence) reveal stale/rotated bind anchors
		// that cause FailedMount errors — the primary signal for CSI mount failures.
		if strings.Contains(pod, "-node-") {
			out := kc.runLenient("exec", pod, "-n", ns, "--", "ls", "-la", "/run/weka-fs-mounts/")
			if len(out) > 0 {
				_ = addBytesToArchive(tw, podDir+"/weka_fs_mounts.txt", out)
			}
		}
	}
}

func k8sUsageFunc() {
	fmt.Fprint(os.Stderr, `weka-log-collector k8s — collect diagnostics from a Weka-on-Kubernetes deployment

USAGE
  weka-log-collector k8s [options]

OPTIONS
  --k8s-host HOST      SSH jump host with kubectl + kubeconfig (e.g. jump.server.internal)
                       Omit to run kubectl locally (kubeconfig must be on PATH host)
  --kubeconfig PATH    Path to kubeconfig file (on the jump host when --k8s-host is set)
  --operator-ns NS     Override auto-detected Weka Operator namespace
                       (default: auto-detect, fall back to weka-operator-system)
  --cluster-ns NS      Override auto-detected WekaCluster pod namespace
                       (default: auto-detect via WekaCluster CRD)
  --csi-ns NS          Override auto-detected CSI plugin namespace
                       (default: auto-detect, fall back to weka-csi-plugin)
  --output PATH        Output .tar.gz path (default: /opt/weka/weka-log-collector/bundles/<cluster>-weka-logs-<ts>.tar.gz)
  --upload             Upload bundle to Weka Home after collection (requires 'weka cloud enable' inside a compute pod)
  --cmd-timeout DUR    Per-kubectl-command timeout (default: 60s)
  --verbose            Verbose output (show every kubectl call)
  --version            Print version and exit

EXAMPLES
  # Collect via SSH jump server (most common for Weka-on-K8s)
  weka-log-collector k8s --k8s-host jump.internal

  # Run locally when kubectl is already on PATH
  weka-log-collector k8s

  # Override namespaces when auto-detection fails
  weka-log-collector k8s --k8s-host jump.internal --cluster-ns my-weka --csi-ns my-csi

  # Save to specific path
  weka-log-collector k8s --k8s-host jump.internal --output /tmp/k8s-bundle.tar.gz

  # Collect and upload bundle to Weka Home (requires 'weka cloud enable' inside a compute pod)
  weka-log-collector k8s --upload

`)
}

// runK8sMode is the entry point for `weka-log-collector k8s [args]`.
// It parses k8s-specific flags, discovers Weka namespaces, collects diagnostics
// from all Weka components in the K8s cluster, and produces a .tar.gz bundle.
func runK8sMode(args []string) {
	fs := flag.NewFlagSet("k8s", flag.ExitOnError)
	fs.Usage = k8sUsageFunc

	k8sHost := fs.String("k8s-host", "", "SSH jump host with kubectl/kubeconfig")
	kubeconfig := fs.String("kubeconfig", "", "Path to kubeconfig (on jump host when --k8s-host is set)")
	operatorNS := fs.String("operator-ns", "", "Override Weka Operator namespace")
	clusterNS := fs.String("cluster-ns", "", "Override WekaCluster pod namespace")
	csiNS := fs.String("csi-ns", "", "Override CSI plugin namespace")
	outputPath := fs.String("output", "", fmt.Sprintf("Output .tar.gz path (default: %s/<cluster>-weka-logs-<ts>.tar.gz)", wlcBundlesDir))
	upload := fs.Bool("upload", false, "Upload bundle to Weka Home after collection (requires 'weka cloud enable' inside a compute pod)")
	cmdTimeout := fs.Duration("cmd-timeout", 60*time.Second, "Per-kubectl-command timeout")
	verboseFlag := fs.Bool("verbose", false, "Verbose output")
	ver := fs.Bool("version", false, "Print version and exit")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *ver {
		fmt.Printf("weka-log-collector %s\n", version)
		return
	}

	if extra := fs.Args(); len(extra) > 0 {
		fmt.Fprintf(os.Stderr, "error: unexpected argument(s): %s\n", strings.Join(extra, ", "))
		os.Exit(1)
	}

	verbose = *verboseFlag

	// Open debug log (best-effort; use same logs dir as regular collection)
	_ = os.MkdirAll(wlcLogsDir, 0755)
	logPath := filepath.Join(wlcLogsDir, fmt.Sprintf("weka-log-collector-k8s-%s.log",
		time.Now().Format("2006-01-02T15-04-05")))
	if lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644); err == nil {
		debugLog = lf
		defer lf.Close()
		fmt.Fprintf(os.Stderr, "Debug log: %s\n", logPath)
	}

	collectionStart := time.Now()

	outPath := *outputPath
	// Default output goes to the standard bundles directory, named after the cluster.
	// Resolved after namespace discovery so we have the cluster name.

	kc := &kubectlRunner{
		jumpHost:   *k8sHost,
		kubeconfig: *kubeconfig,
		timeout:    *cmdTimeout,
	}

	if *k8sHost != "" {
		logf("K8s jump host: %s", *k8sHost)
	} else {
		logf("K8s collection: using local kubectl")
	}

	// Verify kubectl is reachable before doing anything else
	phase("Checking kubectl connectivity")
	verOut, verErr := kc.run("version")
	if verErr != nil {
		errorf("Cannot reach kubectl: %v", verErr)
		if *k8sHost != "" {
			errorf("Check SSH access to %s and that kubectl is installed there", *k8sHost)
		} else {
			errorf("Ensure kubectl is installed and kubeconfig is accessible")
		}
		os.Exit(1)
	}
	logf("  %s", strings.SplitN(strings.TrimSpace(string(verOut)), "\n", 2)[0])

	// Namespace discovery
	phase("Discovering Weka namespaces")
	ns := discoverWekaK8sNamespaces(kc)
	if *operatorNS != "" {
		ns.Operator = *operatorNS
	}
	if *clusterNS != "" {
		ns.Cluster = *clusterNS
	}
	if *csiNS != "" {
		ns.CSI = *csiNS
	}
	logf("  Operator namespace:    %s", ns.Operator)
	logf("  WekaCluster namespace: %s", ns.Cluster)
	if ns.ClusterName != "" {
		logf("  WekaCluster name:      %s", ns.ClusterName)
	}
	logf("  CSI namespace:         %s", ns.CSI)
	if ns.Operator == ns.Cluster {
		logf("  (operator and cluster share namespace — operator pods will be separated by name prefix)")
	}

	// Resolve default output path now that we have the cluster name.
	if outPath == "" {
		_ = os.MkdirAll(wlcBundlesDir, 0755)
		clusterLabel := ns.ClusterName
		if clusterLabel == "" {
			clusterLabel = "k8s"
		}
		ts := time.Now().Format("2006-01-02T15-04-05")
		outPath = filepath.Join(wlcBundlesDir, fmt.Sprintf("%s-weka-logs-%s.tar.gz", clusterLabel, ts))
	}
	logf("  Output: %s", outPath)

	// Open output archive
	outFile, err := os.Create(outPath)
	if err != nil {
		errorf("Cannot create output file %s: %v", outPath, err)
		os.Exit(1)
	}

	gz, gzErr := gzip.NewWriterLevel(outFile, gzip.BestCompression)
	if gzErr != nil {
		outFile.Close()
		errorf("gzip init: %v", gzErr)
		os.Exit(1)
	}
	tw := tar.NewWriter(gz)

	archiveRoot := "k8s"
	m := &k8sManifest{
		CollectedAt:       time.Now(),
		Version:           version,
		JumpHost:          *k8sHost,
		ClusterName:       ns.ClusterName,
		OperatorNamespace: ns.Operator,
		ClusterNamespace:  ns.Cluster,
		CSINamespace:      ns.CSI,
	}

	phase("Collecting cluster-level resources")
	collectK8sClusterLevel(tw, kc, archiveRoot, m)

	phase("Collecting Weka Operator")
	collectK8sOperator(tw, kc, archiveRoot+"/operator", ns.Operator, ns.Cluster, m)

	phase("Collecting WekaCluster pods")
	collectK8sWekaCluster(tw, kc, archiveRoot+"/wekacluster", ns.Cluster, ns.Operator, m)

	phase("Collecting CSI plugin")
	collectK8sCSI(tw, kc, archiveRoot+"/csi", ns.CSI, m)

	// Write manifest
	manifestJSON, _ := json.MarshalIndent(m, "", "  ")
	_ = addBytesToArchive(tw, archiveRoot+"/collection_manifest.json", manifestJSON)

	if err := tw.Close(); err != nil {
		errorf("Finalizing tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		errorf("Finalizing gzip: %v", err)
	}
	outFile.Close()

	elapsed := time.Since(collectionStart).Round(time.Second)
	if info, err := os.Stat(outPath); err == nil {
		logf("\nK8s collection complete → %s (%d KB, took %s)",
			outPath, info.Size()/1024, elapsed)
	} else {
		logf("\nK8s collection complete → %s (took %s)", outPath, elapsed)
	}
	logf("  Commands: %d total, %d failed", m.TotalCommands, m.FailedCommands)

	if *upload {
		if err := uploadK8sBundle(kc, ns.Cluster, outPath); err != nil {
			errorf("Upload failed: %v", err)
		}
	}
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
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return fmt.Errorf("invalid container ID %q: must be an integer", part)
		}
		*f = append(*f, n)
	}
	return nil
}

// ── bundle management ─────────────────────────────────────────────────────────

func listBundleEntries() ([]os.FileInfo, error) {
	entries, err := os.ReadDir(wlcBundlesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var infos []os.FileInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tar.gz") {
			continue
		}
		info, err := e.Info()
		if err == nil {
			infos = append(infos, info)
		}
	}
	return infos, nil
}

// listExtractedDirs returns subdirectories in wlcBundlesDir (extracted bundles).
func listExtractedDirs() ([]os.DirEntry, error) {
	entries, err := os.ReadDir(wlcBundlesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var dirs []os.DirEntry
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e)
		}
	}
	return dirs, nil
}

// dirSize returns the total size of all files under path.
func dirSize(path string) int64 {
	var total int64
	_ = filepath.Walk(path, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			total += fi.Size()
		}
		return nil
	})
	return total
}

func handleListBundles() {
	hostname, _ := os.Hostname()

	// ── local node ────────────────────────────────────────────────────────
	infos, err := listBundleEntries()
	if err != nil {
		errorf("Cannot read %s: %v", wlcBundlesDir, err)
		os.Exit(1)
	}
	dirs, err := listExtractedDirs()
	if err != nil {
		errorf("Cannot read %s: %v", wlcBundlesDir, err)
		os.Exit(1)
	}
	fmt.Printf("[%s] %s:\n", hostname, wlcBundlesDir)
	if len(infos) == 0 && len(dirs) == 0 {
		fmt.Printf("  (none)\n")
	} else {
		var totalBytes int64
		var totalCount int
		for _, fi := range infos {
			totalBytes += fi.Size()
			totalCount++
			fmt.Printf("  %-60s  %6d MB   %s\n",
				fi.Name(),
				fi.Size()/(1024*1024),
				fi.ModTime().Format("2006-01-02 15:04"),
			)
		}
		for _, de := range dirs {
			path := filepath.Join(wlcBundlesDir, de.Name())
			sz := dirSize(path)
			totalBytes += sz
			totalCount++
			info, _ := de.Info()
			modTime := ""
			if info != nil {
				modTime = info.ModTime().Format("2006-01-02 15:04")
			}
			fmt.Printf("  %-60s  %6d MB   %s  (extracted)\n",
				de.Name(),
				sz/(1024*1024),
				modTime,
			)
		}
		fmt.Printf("  Total: %d bundle(s), %d MB\n", totalCount, totalBytes/(1024*1024))
	}

	// ── remote nodes ──────────────────────────────────────────────────────
	nodes, err := discoverClusterNodes(false)
	if err != nil || len(nodes) == 0 {
		return
	}
	listCmd := fmt.Sprintf("ls -lh %s/bundles/*.tar.gz 2>/dev/null || true", wlcBaseDir)
	for _, n := range nodes {
		display := nodeDisplay(n)
		if n.IP == hostname || n.Hostname == hostname {
			continue
		}
		out, _ := exec.Command("ssh", append(sshArgs(), "root@"+n.IP, listCmd)...).Output()
		lines := strings.TrimSpace(string(out))
		if lines == "" {
			continue // skip nodes with nothing
		}
		fmt.Printf("[%s] %s/bundles:\n", display, wlcBaseDir)
		for _, line := range strings.Split(lines, "\n") {
			if line != "" {
				fmt.Printf("  %s\n", line)
			}
		}
	}
}

func handleRmBundle(name string) {
	// Accept bare filename or full path; always resolve under wlcBundlesDir.
	target := name
	if !strings.Contains(name, "/") {
		target = filepath.Join(wlcBundlesDir, name)
	}
	// Safety: must be inside wlcBundlesDir.
	if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(wlcBundlesDir)+"/") {
		errorf("Path %s is outside %s — refusing to remove", target, wlcBundlesDir)
		os.Exit(1)
	}
	fi, err := os.Stat(target)
	if err != nil {
		errorf("Bundle not found: %s", target)
		os.Exit(1)
	}
	var sz int64
	if fi.IsDir() {
		sz = dirSize(target)
		err = os.RemoveAll(target)
	} else {
		sz = fi.Size()
		err = os.Remove(target)
	}
	if err != nil {
		errorf("Failed to remove %s: %v", target, err)
		os.Exit(1)
	}
	fmt.Printf("Removed %s (%d MB)\n", filepath.Base(target), sz/(1024*1024))
}

func handleCleanBundles() {
	infos, err := listBundleEntries()
	if err != nil {
		errorf("Cannot read %s: %v", wlcBundlesDir, err)
		os.Exit(1)
	}
	dirs, err := listExtractedDirs()
	if err != nil {
		errorf("Cannot read %s: %v", wlcBundlesDir, err)
		os.Exit(1)
	}
	if len(infos) == 0 && len(dirs) == 0 {
		fmt.Printf("No bundles in %s\n", wlcBundlesDir)
	} else {
		var totalBytes int64
		for _, fi := range infos {
			totalBytes += fi.Size()
		}
		for _, de := range dirs {
			totalBytes += dirSize(filepath.Join(wlcBundlesDir, de.Name()))
		}
		fmt.Printf("Removing %d bundle(s) from %s (%d MB total)...\n",
			len(infos)+len(dirs), wlcBundlesDir, totalBytes/(1024*1024))
		for _, fi := range infos {
			path := filepath.Join(wlcBundlesDir, fi.Name())
			if err := os.Remove(path); err != nil {
				errorf("  failed to remove %s: %v", fi.Name(), err)
			} else {
				fmt.Printf("  removed %s (%d MB)\n", fi.Name(), fi.Size()/(1024*1024))
			}
		}
		for _, de := range dirs {
			path := filepath.Join(wlcBundlesDir, de.Name())
			sz := dirSize(path)
			if err := os.RemoveAll(path); err != nil {
				errorf("  failed to remove %s: %v", de.Name(), err)
			} else {
				fmt.Printf("  removed %s/ (%d MB)\n", de.Name(), sz/(1024*1024))
			}
		}
	} // end else (local bundles exist)

	// Also clean debug log files from the logs/ directory.
	logEntries, err := os.ReadDir(wlcLogsDir)
	if err != nil && !os.IsNotExist(err) {
		errorf("Cannot read %s: %v", wlcLogsDir, err)
		return
	}
	var logCount int
	for _, e := range logEntries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		path := filepath.Join(wlcLogsDir, e.Name())
		if err := os.Remove(path); err != nil {
			errorf("  failed to remove log %s: %v", e.Name(), err)
		} else {
			logCount++
		}
	}
	if logCount > 0 {
		fmt.Printf("Removed %d debug log(s) from %s\n", logCount, wlcLogsDir)
	}

	// ── cluster-wide cleanup ───────────────────────────────────────────────
	// If we can discover cluster nodes, SSH to each and clean up their
	// logs/ and bundles/ as well.
	nodes, err := discoverClusterNodes(false)
	if err != nil || len(nodes) == 0 {
		return
	}
	hostname, _ := os.Hostname()
	cleanCmd := fmt.Sprintf("rm -f %s/logs/*.log %s/bundles/*.tar.gz", wlcBaseDir, wlcBaseDir)
	fmt.Printf("Cleaning remote nodes...\n")
	var remoteCount int
	for _, n := range nodes {
		display := nodeDisplay(n)
		// Skip self — already cleaned above.
		if n.IP == hostname || n.Hostname == hostname {
			continue
		}
		cmd := exec.Command("ssh", append(sshArgs(), "root@"+n.IP, cleanCmd)...)
		if err := cmd.Run(); err != nil {
			errorf("  [%s] cleanup failed: %v", display, err)
		} else {
			remoteCount++
		}
	}
	fmt.Printf("Cleaned %d remote node(s)\n", remoteCount)
}

func main() {
	// Subcommand routing: must precede flag.Parse() so k8s-specific flags are
	// not seen by the global flag set and --help stays uncluttered.
	if len(os.Args) > 1 && os.Args[1] == "k8s" {
		runK8sMode(os.Args[2:])
		return
	}

	var (
		startTimeStr    = flag.String("start-time", "", "Start of time window (e.g. -2h, -30m, 2026-03-04T10:30)")
		endTimeStr      = flag.String("end-time", "", "End of time window (default: now)")
		profileStr      = flag.String("profile", ProfileDefault, fmt.Sprintf("Collection profile: %s", strings.Join(validProfiles, "|")))
		outputPath      = flag.String("output", "", "Output .tar.gz path (default: /opt/weka/weka-log-collector/bundles/<name>-weka-logs-<ts>.tar.gz). Use - for stdout.")
		localOnly       = flag.Bool("local", false, "Collect from local host only (no SSH, no cluster query)")
		nodeOnly        = flag.Bool("node-only", false, "Skip cluster-wide weka commands; collect only node-local data (used internally by SSH collection)")
		upload          = flag.Bool("upload", false, "Upload the collected archive to Weka Home (requires 'weka cloud enable')")
		cmdTimeout      = flag.Duration("cmd-timeout", 120*time.Second, "Timeout per command")
		extraCommands   = flag.Bool("extra-commands", false, fmt.Sprintf("Run extra commands from %s and include output in the archive", extraCommandsFile))
		ver             = flag.Bool("version", false, "Print version and exit")
		completion      = flag.Bool("completion", false, "Print bash completion script to stdout (source with: source <(./weka-log-collector --completion))")
		listBundles     = flag.Bool("list-bundles", false, fmt.Sprintf("List bundles in %s", wlcBundlesDir))
		rmBundle        = flag.String("rm-bundle", "", fmt.Sprintf("Remove a specific bundle from %s (filename or full path)", wlcBundlesDir))
		cleanBundles    = flag.Bool("clean-bundles", false, fmt.Sprintf("Remove all bundles from %s", wlcBundlesDir))
		uploadFile      = flag.String("upload-file", "", fmt.Sprintf("Upload a specific file to Weka Home (must be under %s, ≤50 MB, .tar.gz/.log/.txt/.json/.out)", wlcBaseDir))
		uploadSessionID = flag.Int64("upload-session-id", 0, "Internal: shared session ID for wlc: symlink grouping across cluster nodes")
	)
	var hosts multiStringFlag
	var containerIDs multiIntFlag
	var containerNamesFlag multiStringFlag
	withClients := flag.Bool("clients", false, "Include client nodes in cluster collection (default: backends only)")
	clientsOnly := flag.Bool("clients-only", false, "Collect from client nodes only (skip backends)")
	flag.BoolVar(&verbose, "verbose", false, "Print detailed progress for every file and command")
	flag.Var(&hosts, "host", "Collect only from these hosts (repeatable; accepts hostname or any IP; default: all cluster backends)")
	flag.Var(&containerIDs, "container-id", "Collect from specific container IDs only (comma-separated or repeatable; e.g. --container-id 0,1 or --container-id 0 --container-id 1)")
	flag.Var(&containerNamesFlag, "container-name", "Internal: restrict /opt/weka/logs/ collection to these container names (set by orchestrator when --container-id is used)")
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

	if *completion {
		os.Stdout.WriteString(bashCompletionScript) //nolint
		// Also install to /etc/bash_completion.d/ so future sessions load it
		// automatically without needing to re-source.
		const sysComp = "/etc/bash_completion.d/weka-log-collector"
		if err := os.WriteFile(sysComp, []byte(bashCompletionScript), 0644); err == nil {
			fmt.Fprintf(os.Stderr, "Completion installed to %s — active in new sessions\n", sysComp)
			fmt.Fprintln(os.Stderr, "For this session: source <(./weka-log-collector --completion)")
		}
		return
	}

	if *listBundles {
		handleListBundles()
		return
	}

	if *rmBundle != "" {
		handleRmBundle(*rmBundle)
		return
	}

	if *cleanBundles {
		handleCleanBundles()
		return
	}

	if *uploadFile != "" {
		abs, err := validateUploadFile(*uploadFile)
		if err != nil {
			errorf("--upload-file: %v", err)
			os.Exit(1)
		}
		if err := uploadBundle(abs, 0); err != nil {
			errorf("Upload failed: %v", err)
			os.Exit(1)
		}
		return
	}

	// ── open debug log file ───────────────────────────────────────────────
	// Skip when output is stdout (--output -): this is a remote node collection
	// invoked by the orchestrator via SSH. The orchestrator has its own debug log;
	// creating one on the remote node too would leave stale files and confuse users
	// on nodes that are also the orchestrator.
	if *outputPath != "-" {
		logsDir := filepath.Join(wlcBaseDir, "logs")
		_ = os.MkdirAll(logsDir, 0755)
		logPath := filepath.Join(logsDir, fmt.Sprintf("weka-log-collector-%s.log", time.Now().Format("2006-01-02T15-04-05")))
		if lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644); err == nil {
			debugLog = lf
			defer lf.Close()
			fmt.Fprintf(os.Stderr, "Debug log: %s\n", logPath)
		} else {
			fmt.Fprintf(os.Stderr, "[WARN] could not open debug log %s: %v\n", logPath, err)
		}
	}

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
	if !toStdout {
		clusterName := getClusterName()
		ts := time.Now().Format("2006-01-02T15-04-05")
		archiveName := fmt.Sprintf("%s-weka-logs-%s.tar.gz", clusterName, ts)
		if outPath == "" {
			_ = os.MkdirAll(wlcBundlesDir, 0755)
			outPath = filepath.Join(wlcBundlesDir, archiveName)
		} else if info, err := os.Stat(outPath); err == nil && info.IsDir() {
			// User gave a directory — place the archive inside it
			outPath = filepath.Join(outPath, archiveName)
		}
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

	// ── pre-discover for cluster mode (cache result for later use) ───────
	var preDiscoveredHosts []string
	var preDiscoveredDisplayMap map[string]string
	if !*localOnly && !toStdout {
		if len(hosts) == 0 {
			if nodes, err := discoverClusterNodes(*withClients || *clientsOnly); err == nil {
				if *clientsOnly {
					nodes = filterClientNodes(nodes)
				}
				if len(containerIDs) > 0 {
					nodes = filterNodesByContainerID(nodes, []int(containerIDs))
				}
				preDiscoveredHosts = nodeIPs(nodes)
				preDiscoveredDisplayMap = make(map[string]string, len(nodes))
				for _, n := range nodes {
					preDiscoveredDisplayMap[n.IP] = nodeDisplay(n)
				}
			}
			// If discovery fails here the cluster section will retry and error.
		}
	}

	// ── space check (skip for stdout) ─────────────────────────────────────
	if !toStdout {
		outputDir := filepath.Dir(outPath)
		di, err := checkDiskSpace(outputDir)
		if err != nil {
			errorf("disk space check failed for %s: %v", outputDir, err)
			errorf("Tip: use --output to write to a different location (e.g. --output /data/weka-logs.tar.gz)")
			os.Exit(1)
		}
		logf("Disk:     %d MB available on %s", di.AvailMB, di.Path)
		if di.AvailMB < minFreeSpaceMB {
			errorf("Not enough free space on %s: only %d MB available, need at least %d MB.",
				di.Path, di.AvailMB, minFreeSpaceMB)
			errorf("Tip: use --output /path/on/bigger/disk to write to a different filesystem.")
			errorf("     Or free up space on %s first.", di.Path)
			os.Exit(1)
		}
	}

	// ── resolve container names from IDs (for log scoping) ───────────────
	// When --container-id is given, resolve IDs to names (e.g. 36 → drives0)
	// so remote nodes only collect /opt/weka/logs/<name>/ for those containers.
	// --container-name is an internal flag set by the orchestrator; honour it
	// directly when running as a remote node (--local --node-only).
	containerNames := []string(containerNamesFlag)
	if len(containerNames) == 0 && len(containerIDs) > 0 {
		nameMap := resolveContainerNames([]int(containerIDs))
		for _, id := range containerIDs {
			if name, ok := nameMap[id]; ok {
				containerNames = append(containerNames, name)
			}
		}
		if len(containerNames) > 0 {
			logf("Container IDs %v resolve to: %s", []int(containerIDs), strings.Join(containerNames, ", "))
		}
	}

	// ── load extra commands (orchestrator only) ───────────────────────────
	var extraCmds []CommandSpec
	if *extraCommands {
		allBuiltin := append(append([]CommandSpec{}, defaultCommands...), buildProfileCommands(*profileStr, from, to)...)
		extraCmds = loadExtraCommands(allBuiltin)
		if len(extraCmds) > 0 {
			logf("Extra commands: %d loaded from %s", len(extraCmds), extraCommandsFile)
		} else {
			logf("Extra commands: none to run (file empty or all duplicates)")
		}
	}

	// ── single local collection ───────────────────────────────────────────
	if *localOnly {
		localStart := time.Now()
		phase("Local collection")
		writeArchive(outPath, toStdout, *profileStr, from, to, *cmdTimeout, *nodeOnly, containerNames, nil, extraCmds)
		if !toStdout {
			elapsed := time.Since(localStart).Round(time.Second)
			logf("Collection complete → %s  (took %s)", outPath, elapsed)
		}
		if *upload && !toStdout {
			if err := uploadBundle(outPath, *uploadSessionID); err != nil {
				errorf("Upload failed: %v", err)
			} else {
				os.Remove(outPath) // uploaded; no need to keep local copy
			}
		}
		return
	}

	// ── cluster collection ────────────────────────────────────────────────
	collectionStart := time.Now()
	phase("Discovering cluster hosts")
	clusterHosts := []string(hosts)
	nodeDisplayMap := map[string]string{} // ip → "hostname (ip)" for log output
	if len(clusterHosts) == 0 {
		if len(preDiscoveredHosts) > 0 {
			// Reuse result from early discovery (already filtered by --container-id)
			clusterHosts = preDiscoveredHosts
			nodeDisplayMap = preDiscoveredDisplayMap
			if len(containerIDs) > 0 {
				logf("Filtered to %d node(s) matching --container-id %v", len(clusterHosts), []int(containerIDs))
			}
			displays := make([]string, len(clusterHosts))
			for i, ip := range clusterHosts {
				if d := nodeDisplayMap[ip]; d != "" {
					displays[i] = d
				} else {
					displays[i] = ip
				}
			}
			logf("Discovered %d cluster host(s): %s", len(clusterHosts), strings.Join(displays, ", "))
		} else {
			nodes, err := discoverClusterNodes(*withClients || *clientsOnly)
			if err != nil {
				warnf("Could not discover cluster hosts: %v", err)
				warnf("Falling back to local-only collection. Use --host to specify hosts manually.")
				writeArchive(outPath, toStdout, *profileStr, from, to, *cmdTimeout, false, containerNames, nil, extraCmds)
				if *upload && !toStdout {
					if err := uploadBundle(outPath, 0); err != nil {
						errorf("Upload failed: %v", err)
					} else {
						os.Remove(outPath)
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
			displays := make([]string, len(nodes))
			for i, n := range nodes {
				displays[i] = nodeDisplay(n)
				nodeDisplayMap[n.IP] = nodeDisplay(n)
			}
			logf("Discovered %d cluster host(s): %s", len(nodes), strings.Join(displays, ", "))
		}
	} else {
		logf("Collecting from %d specified host(s): %s", len(clusterHosts), strings.Join(clusterHosts, ", "))
	}

	// Resolve the running binary path for self-deploy to remote hosts.
	selfPath, err := os.Executable()
	if err != nil {
		errorf("Could not determine executable path: %v", err)
		os.Exit(1)
	}
	// ── signal handler: clean up remote processes on interrupt ───────────
	// If the user hits Ctrl+C (or SIGTERM arrives), SSH to every host that is
	// currently being collected and kill the remote weka-log-collector process
	// and its binary. We wait for all kills to complete before exiting so we
	// don't leave orphaned processes consuming CPU/disk on production nodes.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		logf("\nInterrupted — killing remote processes and cleaning up...")
		remoteBin := remoteBinPath()
		killCmd := fmt.Sprintf("pkill -f '%s' 2>/dev/null; rm -f %s; true",
			filepath.Base(remoteBin), remoteBin)
		var cleanupWg sync.WaitGroup
		activeRemoteHosts.Range(func(k, _ interface{}) bool {
			host := k.(string)
			cleanupWg.Add(1)
			go func() {
				defer cleanupWg.Done()
				args := append(sshArgs(), "root@"+host, killCmd)
				exec.Command("ssh", args...).Run() //nolint:errcheck // best-effort cleanup
			}()
			return true
		})
		cleanupWg.Wait()
		logf("Cleanup complete.")
		os.Exit(1)
	}()
	defer signal.Stop(sigCh)

	// ── per-node space pre-check ──────────────────────────────────────────
	// Check available space on every cluster node in parallel before collection
	// starts. Default path is wlcBundlesDir; if --output was explicitly set,
	// check that path's filesystem (upload mode writes per-node bundles there).
	{
		// Default: always check /opt/weka — present on every Weka node and the
		// filesystem that matters for bundle storage. Custom --output: check
		// the specified path's filesystem directly (walk up if not yet created).
		remoteSpaceCheckPath := "/opt/weka"
		if *outputPath != "" {
			remoteSpaceCheckPath = filepath.Dir(outPath)
		}

		type nodeSpaceResult struct {
			display string
			di      diskInfo
			err     error
		}
		var spaceResults []nodeSpaceResult
		var spaceMu sync.Mutex
		var spaceWg sync.WaitGroup

		for _, host := range clusterHosts {
			host := host
			spaceWg.Add(1)
			go func() {
				defer spaceWg.Done()
				display := nodeDisplayMap[host]
				if display == "" {
					display = host
				}
				var di diskInfo
				var err error
				if isLocalIP(host) {
					di, err = checkDiskSpace(remoteSpaceCheckPath)
				} else {
					di, err = checkRemoteDiskSpace("root@"+host, remoteSpaceCheckPath)
				}
				spaceMu.Lock()
				spaceResults = append(spaceResults, nodeSpaceResult{display, di, err})
				spaceMu.Unlock()
			}()
		}
		spaceWg.Wait()

		sort.Slice(spaceResults, func(i, j int) bool {
			return spaceResults[i].display < spaceResults[j].display
		})

		logf("Disk space on cluster nodes (%s):", remoteSpaceCheckPath)
		var lowSpaceNodes []string
		for _, r := range spaceResults {
			if r.err != nil {
				logf("  %-35s  check failed: %v", r.display, r.err)
			} else {
				marker := ""
				if r.di.AvailMB < minFreeSpaceMB {
					marker = "  ← LOW"
					lowSpaceNodes = append(lowSpaceNodes, r.display)
				}
				logf("  %-35s  %6d MB on %s%s", r.display, r.di.AvailMB, r.di.Path, marker)
			}
		}
		if len(lowSpaceNodes) > 0 {
			warnf("Low disk space on %d node(s): %s", len(lowSpaceNodes), strings.Join(lowSpaceNodes, ", "))
			warnf("Collection may fail on these nodes. Free up space on %s or use --output to redirect.", remoteSpaceCheckPath)
		}
	}

	if *upload && !toStdout {
		// ── distributed upload ────────────────────────────────────────────────
		// Each node independently collects and uploads its own archive in parallel.
		// The orchestrator runs full local collection (cluster-wide commands included);
		// remote nodes run --local --node-only --upload via SSH.
		// No central archive is written — uploads complete faster and avoid a
		// single-node bandwidth bottleneck.
		phase("Uploading from cluster nodes (distributed)")

		// Fail fast if Weka Home is unreachable from the orchestrator.
		if _, err := checkCloudEnabled(); err != nil {
			errorf("Cannot upload: %v", err)
			os.Exit(1)
		}

		// Single session ID shared by all nodes so Weka Home groups their
		// archives under one session entry instead of one entry per node.
		// If the user supplied --upload-session-id (remote node invoked by
		// orchestrator), use that; otherwise generate a fresh one.
		sharedSessionID := *uploadSessionID
		if sharedSessionID == 0 {
			sharedSessionID = time.Now().UnixNano()
		}

		type nodeUploadResult struct {
			display string
			err     error
		}
		var mu sync.Mutex
		var wg sync.WaitGroup
		var allResults []nodeUploadResult

		// Orchestrator: full local collection (cluster-wide commands) + upload.
		wg.Add(1)
		go func() {
			defer wg.Done()
			logf("  [local] collecting (cluster-wide commands + node-local data)...")
			writeArchive(outPath, false, *profileStr, from, to, *cmdTimeout, false, containerNames, nil, extraCmds)
			logf("  [local] uploading to Weka Home...")
			err := uploadBundle(outPath, sharedSessionID)
			if err == nil {
				os.Remove(outPath) // uploaded; no need to keep local copy
			} else {
				errorf("[local] upload failed: %v", err)
			}
			mu.Lock()
			allResults = append(allResults, nodeUploadResult{"local", err})
			mu.Unlock()
		}()

		// Remote nodes: exclude local IPs (orchestrator already handled above),
		// then SSH to each with --local --node-only --upload.
		var remoteHosts []string
		for _, h := range clusterHosts {
			if !isLocalIP(h) {
				remoteHosts = append(remoteHosts, h)
			}
		}
		if len(remoteHosts) > 0 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				remoteResults := uploadCluster(remoteHosts, nodeDisplayMap, selfPath, *profileStr, from, to, *cmdTimeout, 10, containerNames, sharedSessionID)
				mu.Lock()
				for _, r := range remoteResults {
					display := nodeDisplayMap[r.Host]
					if display == "" {
						display = r.Host
					}
					allResults = append(allResults, nodeUploadResult{display, r.Err})
				}
				mu.Unlock()
			}()
		}

		wg.Wait()

		var succeeded, failed int
		var failedDisplays []string
		for _, r := range allResults {
			if r.err != nil {
				failed++
				failedDisplays = append(failedDisplays, r.display)
			} else {
				succeeded++
			}
		}
		elapsed := time.Since(collectionStart).Round(time.Second)
		logf("\nCluster upload complete  —  Duration: %s", elapsed)
		logf("  Nodes:    %d total, %d uploaded, %d failed", len(allResults), succeeded, failed)
		if len(failedDisplays) > 0 {
			logf("  Failed:   %s", strings.Join(failedDisplays, ", "))
			logf("  Tip: check SSH access and 'weka cloud status' on failed nodes.")
		}
		return
	}

	// Non-upload path: collect all nodes, merge into single central archive.
	phase("Collecting from cluster hosts")
	results := collectCluster(clusterHosts, nodeDisplayMap, selfPath, *profileStr, from, to, *cmdTimeout, 10, containerNames)
	phase("Writing archive")
	writeMergedArchive(outPath, toStdout, results, *profileStr, from, to, *cmdTimeout, collectionStart, extraCmds)
}

// collectCluster deploys the binary to all hosts first, then fans out collection
// in parallel (up to workers at a time). Logs each host's result atomically with
// a [done/total] progress counter so output stays readable on large clusters.
func collectCluster(hosts []string, displayNames map[string]string, selfPath, profile string, from, to time.Time, cmdTimeout time.Duration, workers int, containerNames []string) []HostResult {
	// ── phase 1: deploy binary to all hosts ───────────────────────────────
	phase("Deploying binary to cluster hosts")
	deployed := deployAll(hosts, displayNames, selfPath)
	if len(deployed) == 0 {
		errorf("Deploy failed on all hosts — nothing to collect.")
		return nil
	}
	if len(deployed) < len(hosts) {
		logf("  Deploy: %d/%d succeeded — collecting from reachable nodes only", len(deployed), len(hosts))
	}

	// ── phase 2: collect from successfully deployed hosts ─────────────────
	total := len(deployed)
	sem := make(chan struct{}, workers)
	var mu sync.Mutex
	var results []HostResult
	var done int
	var wg sync.WaitGroup

	for _, host := range deployed {
		host := host
		display := displayNames[host]
		if display == "" {
			display = host
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			logf("  [%s] collecting...", display)
			r := collectFromHost(host, display, selfPath, profile, from, to, 5*cmdTimeout, containerNames)
			mu.Lock()
			done++
			n := done
			results = append(results, r)
			mu.Unlock()
			if r.Err != nil {
				errorf("  [%s] failed [%d/%d]: %v", display, n, total, r.Err)
			} else if info, err := os.Stat(r.TempFile); err == nil {
				logf("  [%s] collected %d KB  [%d/%d]", display, info.Size()/1024, n, total)
			}
		}()
	}
	wg.Wait()
	return results
}

// uploadFromHost runs collection + upload on a remote host (binary already deployed
// by deployAll). The remote node collects its own logs, uploads to Weka Home via its
// local uploader, and cleans up the local archive. The caller handles start/completion logs.
func uploadFromHost(host, displayName, selfPath, profile string, from, to time.Time, sshTimeout time.Duration, containerNames []string, sessionID int64) error {
	if displayName == "" {
		displayName = host
	}
	sshTarget := "root@" + host
	remoteBin := remoteBinPath()

	// Register this host as active so the signal handler can kill it on interrupt.
	activeRemoteHosts.Store(host, remoteBin)
	defer activeRemoteHosts.Delete(host)

	// Build remote command: --local --node-only --upload [flags]
	// --node-only: skip cluster-wide commands (run once by orchestrator locally).
	// timeout kills the process if it exceeds the SSH timeout, preventing orphans.
	args := []string{remoteBin, "--local", "--node-only", "--upload", "--profile", profile,
		"--upload-session-id", strconv.FormatInt(sessionID, 10)}
	if !from.IsZero() {
		args = append(args, "--start-time", from.Format("2006-01-02T15:04"))
	}
	if !to.IsZero() {
		args = append(args, "--end-time", to.Format("2006-01-02T15:04"))
	}
	if verbose {
		args = append(args, "--verbose")
	}
	if len(containerNames) > 0 {
		args = append(args, "--container-name", strings.Join(containerNames, ","))
	}
	collectionCmd := strings.Join(args, " ")
	timeoutSecs := int(sshTimeout.Seconds())
	remoteShellCmd := fmt.Sprintf(
		"chmod +x %s; trap 'rm -f %s' EXIT; timeout %d %s",
		remoteBin, remoteBin, timeoutSecs, collectionCmd,
	)

	var stderrBuf bytes.Buffer
	sshCmd := exec.Command("ssh", append(sshArgs(), sshTarget, remoteShellCmd)...)
	sshCmd.Stderr = &stderrBuf
	if err := sshCmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode := exitErr.ExitCode()
			errMsg := strings.TrimSpace(stderrBuf.String())
			if exitCode == 124 {
				return fmt.Errorf("timed out after %s — collection/upload took too long", sshTimeout)
			}
			if exitCode == 137 {
				return fmt.Errorf("process killed (OOM) — try --start-time to reduce size: %s", errMsg)
			}
			return fmt.Errorf("SSH command failed (exit %d): %s", exitCode, errMsg)
		}
		return fmt.Errorf("SSH error: %v", err)
	}
	// Clean up remote logs/ and bundles/ after successful upload.
	// Debug logs are already inside the uploaded bundle; no need to keep them on disk.
	cleanupCmd := fmt.Sprintf("rm -f %s/logs/*.log %s/bundles/*.tar.gz", wlcBaseDir, wlcBaseDir)
	exec.Command("ssh", append(sshArgs(), sshTarget, cleanupCmd)...).Run() //nolint:errcheck
	return nil
}

// uploadCluster deploys the binary to all remote hosts first, then fans out
// collect+upload in parallel (up to workers at a time).
func uploadCluster(hosts []string, displayNames map[string]string, selfPath, profile string, from, to time.Time, cmdTimeout time.Duration, workers int, containerNames []string, sessionID int64) []HostResult {
	// ── phase 1: deploy binary to all remote hosts ────────────────────────
	phase("Deploying binary to remote hosts")
	deployed := deployAll(hosts, displayNames, selfPath)
	if len(deployed) == 0 {
		errorf("Deploy failed on all remote hosts — nothing to upload.")
		return nil
	}
	if len(deployed) < len(hosts) {
		logf("  Deploy: %d/%d succeeded — uploading from reachable nodes only", len(deployed), len(hosts))
	}

	// ── phase 2: collect + upload from successfully deployed hosts ─────────
	total := len(deployed)
	sem := make(chan struct{}, workers)
	var mu sync.Mutex
	var results []HostResult
	var done int
	var wg sync.WaitGroup

	for _, host := range deployed {
		host := host
		display := displayNames[host]
		if display == "" {
			display = host
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			logf("  [%s] collecting and uploading...", display)
			err := uploadFromHost(host, display, selfPath, profile, from, to, 10*cmdTimeout, containerNames, sessionID)
			mu.Lock()
			done++
			n := done
			results = append(results, HostResult{Host: host, Err: err})
			mu.Unlock()
			if err != nil {
				errorf("  [%s] failed [%d/%d]: %v", display, n, total, err)
			} else {
				logf("  [%s] upload complete  [%d/%d]", display, n, total)
			}
		}()
	}
	wg.Wait()
	return results
}

// writeArchive performs a local collection and writes to outPath (or stdout).
func writeArchive(outPath string, toStdout bool, profile string, from, to time.Time, cmdTimeout time.Duration, nodeOnly bool, containerNames []string, extraManifests []HostManifest, extraCmds []CommandSpec) {
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
			errorf("Tip: check write permissions or use --output /data/weka-logs.tar.gz")
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

	manifest := CollectLocal(tw, archiveRoot, profile, from, to, cmdTimeout, nodeOnly, containerNames, extraCmds)

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
func writeMergedArchive(outPath string, toStdout bool, results []HostResult, profile string, from, to time.Time, cmdTimeout time.Duration, collectionStart time.Time, extraCmds []CommandSpec) {
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
			errorf("Tip: check write permissions or use --output /data/weka-logs.tar.gz")
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
		wekaSubdir := "weka"
		if spec.Profile == ProfilePerf {
			wekaSubdir = "weka/perf"
		}
		dest := filepath.Join(archiveRoot, "cluster", wekaSubdir, spec.Name+ext)
		if addErr := addBytesToArchive(tw, dest, content); addErr != nil {
			warnf("[cluster] could not add %s to archive: %v", spec.Name, addErr)
		}
	}

	// ── run extra commands on the orchestrator ────────────────────────────
	if len(extraCmds) > 0 {
		phase(fmt.Sprintf("Extra commands (%d)", len(extraCmds)))
		extraOutputs := runCommandsParallel(extraCmds, cmdTimeout)
		for i, spec := range extraCmds {
			co := extraOutputs[i]
			content := co.out
			if co.result.Error != "" {
				if len(co.out) == 0 {
					content = []byte(fmt.Sprintf("# command: %s\n# error: %s\n", spec.Cmd, co.result.Error))
				}
				warnf("extra command %q failed (exit %d): %s", spec.Cmd, co.result.ExitCode, co.result.Error)
			}
			dest := filepath.Join(archiveRoot, "cluster", "extra", spec.Name+".txt")
			if addErr := addBytesToArchive(tw, dest, content); addErr != nil {
				warnf("could not add extra/%s to archive: %v", spec.Name, addErr)
			}
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

	elapsed := time.Since(collectionStart).Round(time.Second)
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
	logf("  Duration: %s", elapsed)
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
  weka-log-collector k8s [options]      Weka-on-Kubernetes (run --help after k8s for flags)

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
  --output PATH        Archive path (default: /opt/weka/weka-log-collector/bundles/<cluster>-weka-logs-<ts>.tar.gz); - for stdout
  --upload             Upload archive to Weka Home (requires weka cloud enabled)
  --upload-file FILE   Upload a specific file to Weka Home (must be under /opt/weka/weka-log-collector, ≤50 MB, .tar.gz/.log/.txt/.json/.out)
  --extra-commands     Run extra commands from /opt/weka/weka-log-collector/extra-commands (orchestrator only)
  --cmd-timeout DUR    Per-command timeout (default: 60s)
  --verbose            Detailed per-file/command progress
  --version            Print version and exit

BUNDLE MANAGEMENT
  --list-bundles       List bundles in /opt/weka/weka-log-collector/bundles
  --rm-bundle NAME     Remove a specific bundle (filename or full path)
  --clean-bundles      Remove all bundles

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
