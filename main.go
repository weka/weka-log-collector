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
	// Try absolute: YYYY-MM-DDTHH:MM
	t, err := time.ParseInLocation("2006-01-02T15:04", s, time.Local)
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot parse time %q: use YYYY-MM-DDTHH:MM or relative like -2h, -30m, -1d", s)
	}
	return t, nil
}

// ── collection profiles ───────────────────────────────────────────────────────

// Profile names
const (
	ProfileDefault = "default" // core weka commands + logs
	ProfileFull    = "full"    // + container logs, journalctl, events, core dumps
	ProfilePerf    = "perf"    // + performance stats
	ProfileNFS     = "nfs"     // + ganesha logs and NFS commands
	ProfileS3      = "s3"      // + S3/envoy logs and S3 commands
	ProfileSMBW    = "smbw"    // + SMB logs and pcs status
	ProfileClient  = "client"  // + client NIC/OFED/routing info
	ProfileAll     = "all"     // everything
)

var validProfiles = []string{
	ProfileDefault, ProfileFull, ProfilePerf,
	ProfileNFS, ProfileS3, ProfileSMBW, ProfileClient, ProfileAll,
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
}

// defaultCommands are run on every node that has the weka CLI available.
// These are always included in every profile.
var defaultCommands = []CommandSpec{
	// ── identity & status ──────────────────────────────────────────
	{Name: "weka_version", Cmd: "weka version"},
	{Name: "weka_status", Cmd: "weka status"},
	{Name: "weka_status_rebuild", Cmd: "weka status rebuild"},
	{Name: "weka_alerts", Cmd: "weka alerts"},
	{Name: "weka_user", Cmd: "weka user"},
	{Name: "weka_cloud_status", Cmd: "weka cloud status"},
	// ── cluster topology ──────────────────────────────────────────
	{Name: "weka_cluster_servers", Cmd: "weka cluster servers list"},
	{Name: "weka_cluster_container", Cmd: "weka cluster container -l"},
	{Name: "weka_cluster_container_net", Cmd: "weka cluster container net"},
	{Name: "weka_cluster_process", Cmd: "weka cluster process"},
	{Name: "weka_cluster_drive", Cmd: "weka cluster drive"},
	{Name: "weka_cluster_bucket", Cmd: "weka cluster bucket"},
	{Name: "weka_cluster_failure_domain", Cmd: "weka cluster failure-domain"},
	{Name: "weka_cluster_task", Cmd: "weka cluster task"},
	{Name: "weka_cluster_resources", Cmd: "weka cluster container resources 0"},
	// ── filesystems & snapshots ────────────────────────────────────
	{Name: "weka_fs", Cmd: "weka fs -v"},
	{Name: "weka_fs_group", Cmd: "weka fs group"},
	{Name: "weka_fs_snapshot", Cmd: "weka fs snapshot -v"},
	{Name: "weka_fs_tier_s3", Cmd: "weka fs tier s3 -v"},
	// ── debug & traces ─────────────────────────────────────────────
	{Name: "weka_debug_traces_status", Cmd: "weka debug traces status"},
	{Name: "weka_debug_traces_freeze", Cmd: "weka debug traces freeze show"},
	{Name: "weka_debug_net_links", Cmd: "weka debug net links"},
	{Name: "weka_debug_override_list", Cmd: "weka debug override list"},
	{Name: "weka_debug_blacklist", Cmd: "weka debug blacklist list"},
	{Name: "weka_debug_buckets_dist", Cmd: "weka debug buckets dist"},
	// ── security ───────────────────────────────────────────────────
	{Name: "weka_security_kms", Cmd: "weka security kms"},
	// ── local container info (node-local: different per host) ─────────────
	{Name: "weka_local_ps", Cmd: "weka local ps -v", NodeLocal: true},
	{Name: "weka_local_resources_drives0", Cmd: "weka local resources -C drives0", NodeLocal: true},
	{Name: "weka_local_resources_compute0", Cmd: "weka local resources -C compute0", NodeLocal: true},
	{Name: "weka_local_resources_frontend0", Cmd: "weka local resources -C frontend0", NodeLocal: true},
}

// fullCommands are added when profile is "full" or "all".
var fullCommands = []CommandSpec{
	{Name: "weka_events_major", Cmd: "weka events --severity major", Profile: ProfileFull},
	{Name: "weka_debug_net_peers", Cmd: "weka debug net peers 1", Profile: ProfileFull},
	{Name: "weka_cluster_container_info_hw", Cmd: "weka cluster container info-hw", Profile: ProfileFull},
	{Name: "weka_cfgdump", Cmd: "weka local exec -C drives0 -- /weka/cfgdump", Profile: ProfileFull, NodeLocal: true},
}

// perfCommands are added for profile "perf" or "all".
var perfCommands = []CommandSpec{
	{Name: "weka_stats_cpu", Cmd: "weka stats --show-internal --category cpu --per-process -s value -Z", Profile: ProfilePerf},
	{Name: "weka_stats_ssd", Cmd: "weka stats --show-internal --category ssd -Z", Profile: ProfilePerf},
	{Name: "weka_stats_ops_driver", Cmd: "weka stats --show-internal --category ops_driver -Z", Profile: ProfilePerf},
	{Name: "weka_stats_ops", Cmd: "weka stats --show-internal --category ops -Z", Profile: ProfilePerf},
	{Name: "weka_stats_network", Cmd: "weka stats --show-internal --category network -Z", Profile: ProfilePerf},
	{Name: "weka_stats_jrpc", Cmd: "weka stats --show-internal --category jrpc -Z", Profile: ProfilePerf},
	{Name: "weka_stats_rpc", Cmd: "weka stats --show-internal --category rpc -Z", Profile: ProfilePerf},
	{Name: "weka_stats_read_latency", Cmd: "weka stats --category ops --show-internal --stat READ_LATENCY -Z", Profile: ProfilePerf},
	{Name: "weka_stats_write_latency", Cmd: "weka stats --category ops --show-internal --stat WRITE_LATENCY -Z", Profile: ProfilePerf},
	{Name: "weka_stats_ssd_read_latency", Cmd: "weka stats --show-internal --stat SSD_READ_LATENCY -Z", Profile: ProfilePerf},
	{Name: "weka_stats_ssd_write_latency", Cmd: "weka stats --show-internal --stat SSD_WRITE_LATENCY -Z", Profile: ProfilePerf},
	{Name: "weka_stats_drive_read_latency", Cmd: "weka stats --show-internal --stat DRIVE_READ_LATENCY -Z", Profile: ProfilePerf},
	{Name: "weka_stats_drive_write_latency", Cmd: "weka stats --show-internal --stat DRIVE_WRITE_LATENCY -Z", Profile: ProfilePerf},
	{Name: "weka_stats_goodput_tx", Cmd: "weka stats --show-internal --stat GOODPUT_TX_RATIO -Z", Profile: ProfilePerf},
	{Name: "weka_stats_goodput_rx", Cmd: "weka stats --show-internal --stat GOODPUT_RX_RATIO -Z", Profile: ProfilePerf},
	{Name: "weka_stats_port_tx", Cmd: "weka stats --show-internal --stat PORT_TX_BYTES -Z", Profile: ProfilePerf},
	{Name: "weka_stats_port_rx", Cmd: "weka stats --show-internal --stat PORT_RX_BYTES -Z", Profile: ProfilePerf},
	{Name: "weka_stats_realtime", Cmd: "weka stats realtime -s -cpu -o node,hostname,role,mode,writeps,writebps,wlatency,readps,readbps,rlatency,ops,cpu,l6recv,l6send,upload,download", Profile: ProfilePerf},
}

// nfsCommands are added for profile "nfs" or "all".
var nfsCommands = []CommandSpec{
	{Name: "weka_nfs_client_group", Cmd: "weka nfs client-group", Profile: ProfileNFS},
	{Name: "weka_nfs_interface_group", Cmd: "weka nfs interface-group", Profile: ProfileNFS},
	{Name: "weka_nfs_permission", Cmd: "weka nfs permission", Profile: ProfileNFS},
	{Name: "weka_nfs_global_config", Cmd: "weka nfs global-config show", Profile: ProfileNFS},
	{Name: "weka_nfs_custom_options", Cmd: "weka nfs custom-options", Profile: ProfileNFS},
	{Name: "showmount", Cmd: "showmount -e", Profile: ProfileNFS},
	{Name: "weka_local_resources_ganesha", Cmd: "weka local resources -C ganesha -J", Profile: ProfileNFS, NodeLocal: true},
	{Name: "nfs_ganesha_config", Cmd: "weka local run /weka/cfgdump --container frontend0 | grep -i nfsGaneshaConfig -A 20", Profile: ProfileNFS, NodeLocal: true},
	{Name: "nfs_ganesha_queue", Cmd: "weka local exec --container ganesha cat /proc/wekafs/frontend0/queue", Profile: ProfileNFS, NodeLocal: true},
	{Name: "weka_stats_ops_nfsw", Cmd: "weka stats --category ops_nfsw --per-node -Z", Profile: ProfileNFS},
	{Name: "netstat_nfs", Cmd: "netstat -tupnl", Profile: ProfileNFS, NodeLocal: true},
}

// s3Commands are added for profile "s3" or "all".
var s3Commands = []CommandSpec{
	{Name: "weka_s3_cluster", Cmd: "weka s3 cluster -v", Profile: ProfileS3},
	{Name: "weka_s3_cluster_status", Cmd: "weka s3 cluster status", Profile: ProfileS3},
	{Name: "weka_s3_bucket_list", Cmd: "weka s3 bucket list -v", Profile: ProfileS3},
	{Name: "weka_s3_bucket_lifecycle", Cmd: "weka s3 bucket lifecycle-rule list", Profile: ProfileS3},
	{Name: "weka_s3_policy_list", Cmd: "weka s3 policy list", Profile: ProfileS3},
	{Name: "weka_s3_service_account", Cmd: "weka s3 service-account list", Profile: ProfileS3},
	{Name: "weka_s3_containers_list", Cmd: "weka s3 cluster containers list", Profile: ProfileS3},
	{Name: "weka_stats_ops_s3", Cmd: "weka stats --show-internal --category ops_s3 -Z", Profile: ProfileS3},
	{Name: "s3_cgroup_memory", Cmd: "cat /sys/fs/cgroup/memory/weka-s3/memory.limit_in_bytes && cat /sys/fs/cgroup/memory/weka-s3/memory.usage_in_bytes", Profile: ProfileS3, NodeLocal: true},
	{Name: "netstat_s3", Cmd: "netstat -tuln | grep 9001", Profile: ProfileS3, NodeLocal: true},
}

// smbwCommands are added for profile "smbw" or "all".
var smbwCommands = []CommandSpec{
	{Name: "weka_smb_cluster", Cmd: "weka smb cluster", Profile: ProfileSMBW},
	{Name: "weka_smb_cluster_status", Cmd: "weka smb cluster status", Profile: ProfileSMBW},
	{Name: "weka_smb_domain", Cmd: "weka smb domain", Profile: ProfileSMBW},
	{Name: "weka_smb_share", Cmd: "weka smb share", Profile: ProfileSMBW},
	{Name: "weka_smb_cluster_info", Cmd: "weka debug config show sambaClusterInfo", Profile: ProfileSMBW},
	{Name: "pcs_cluster_status", Cmd: "weka local exec --container smbw /usr/sbin/pcs cluster status", Profile: ProfileSMBW, NodeLocal: true},
	{Name: "pcs_status", Cmd: "weka local exec --container smbw /usr/sbin/pcs status", Profile: ProfileSMBW, NodeLocal: true},
	{Name: "pcs_status_resources", Cmd: "weka local exec --container smbw /usr/sbin/pcs status resources", Profile: ProfileSMBW, NodeLocal: true},
	{Name: "pcs_constraint", Cmd: "weka local exec --container smbw /usr/sbin/pcs constraint", Profile: ProfileSMBW, NodeLocal: true},
	{Name: "sssd_conf", Cmd: "cat /etc/sssd/sssd.conf", Profile: ProfileSMBW, NodeLocal: true},
}

// clientCommands are added for profile "client" or "all".
var clientCommands = []CommandSpec{
	{Name: "lshw_network", Cmd: "lshw -C network -businfo", Profile: ProfileClient, NodeLocal: true},
	{Name: "ofed_info", Cmd: "ofed_info -s", Profile: ProfileClient, NodeLocal: true},
	{Name: "lsmod", Cmd: "lsmod", Profile: ProfileClient, NodeLocal: true},
	{Name: "modinfo_mlx5_core", Cmd: "modinfo mlx5_core", Profile: ProfileClient, NodeLocal: true},
	{Name: "modinfo_ice", Cmd: "modinfo ice", Profile: ProfileClient, NodeLocal: true},
	{Name: "ip_rule", Cmd: "ip rule", Profile: ProfileClient, NodeLocal: true},
	{Name: "ip_route", Cmd: "ip route show", Profile: ProfileClient, NodeLocal: true},
	{Name: "ip_neighbor", Cmd: "ip neighbor", Profile: ProfileClient, NodeLocal: true},
	{Name: "netstat", Cmd: "netstat -tunlp", Profile: ProfileClient, NodeLocal: true},
	{Name: "rp_filter", Cmd: "sysctl -a | grep -w rp_filter", Profile: ProfileClient, NodeLocal: true},
	{Name: "weka_cluster_host_info_hw", Cmd: "weka cluster host info-hw -J", Profile: ProfileClient},
}

// systemCommands run directly on the OS (not via weka CLI).
// These are always collected regardless of profile.
var systemCommands = []CommandSpec{
	{Name: "uname", Cmd: "uname -a"},
	{Name: "os_release", Cmd: "cat /etc/*release*"},
	{Name: "hostname", Cmd: "hostname -f"},
	{Name: "uptime", Cmd: "uptime"},
	{Name: "free_mem", Cmd: "free -h"},
	{Name: "lscpu", Cmd: "lscpu"},
	{Name: "ip_addr", Cmd: "ip addr show"},
	{Name: "ip_route", Cmd: "ip route"},
	{Name: "netstat_all", Cmd: "netstat -nap"},
	{Name: "ps_elf", Cmd: "ps -elf"},
	{Name: "df_h", Cmd: "df -h"},
	{Name: "lspci", Cmd: "lspci"},
	{Name: "lsblk", Cmd: "lsblk -d"},
	{Name: "sysctl_conf", Cmd: "cat /etc/sysctl.conf"},
	// weka-agent service journal (last 50k lines; full journal captured via journalctlWithWindow)
	{Name: "journalctl_weka_agent", Cmd: "journalctl -u weka-agent --no-pager -n 50000"},
	{Name: "journalctl_weka_agent_verbose", Cmd: "journalctl -xu weka-agent --no-pager -n 10000"},
	// kernel ring buffer with timestamps
	{Name: "dmesg", Cmd: "dmesg -T"},
}

// LogFileSpec describes a set of log files to collect.
// All matched files are always collected in full — no time-window filtering.
// The --from/--to window applies only to journalctl, not to file collection.
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

	// Depth-1: all *.log* and *.json files directly in each container dir
	{SrcGlob: "/opt/weka/logs/*/*.log*", DestDir: "weka/containers"},
	{SrcGlob: "/opt/weka/logs/*/*.json", DestDir: "weka/containers"},

	// Depth-2: all *.log* files one level deeper (weka/, nginx/, wtracer/, pacemaker/, corosync/, pcsd/)
	{SrcGlob: "/opt/weka/logs/*/*/*.log*", DestDir: "weka/containers"},
	{SrcGlob: "/opt/weka/logs/*/*/*.json", DestDir: "weka/containers"},

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
// space the collection will use (before compression).
func estimateCollectionMB(profile string, logSpecs []LogFileSpec) uint64 {
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
	// Add ~10MB overhead for command outputs
	totalBytes += 10 * 1024 * 1024
	// Assume ~30% compression ratio for mixed content
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

// verbose controls whether verbose output is printed to stderr
var verbose bool

func logf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func vlogf(format string, args ...interface{}) {
	if verbose {
		fmt.Fprintf(os.Stderr, "[verbose] "+format+"\n", args...)
	}
}

func warnf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[WARN]  "+format+"\n", args...)
}

func errorf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[ERROR] "+format+"\n", args...)
}

func phase(name string) {
	fmt.Fprintf(os.Stderr, "\n==> %s\n", name)
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

// collectLogFile adds a single log file to the tar writer.
// destPath is the full path inside the archive (archiveRoot already included).
// from is the --from time window: rotated log files (*.1, *.gz, -YYYYMMDD) whose
// mtime predates from are skipped and recorded in the manifest with a note.
// Current active log files are always collected regardless of from.
// Returns a FileResult describing success or failure.
func collectLogFile(tw *tar.Writer, srcPath, destPath string, from time.Time) FileResult {
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

	// Time-window filtering: only apply to rotated/archived files.
	// Current active log files are always collected (mtime doesn't reliably
	// reflect their content range — they're still being written to).
	if !from.IsZero() && isRotatedFile(filepath.Base(srcPath)) && info.ModTime().Before(from) {
		note := fmt.Sprintf("rotated file mtime %s is before --from %s; skipped to reduce bundle size",
			info.ModTime().UTC().Format(time.RFC3339), from.UTC().Format(time.RFC3339))
		result.Skipped = true
		result.SkipNote = note
		logf("  SKIP %s: %s", srcPath, note)
		return result
	}

	result.SizeBytes = info.Size()
	hdr := &tar.Header{
		Name:    result.DestPath,
		Mode:    0644,
		Size:    info.Size(),
		ModTime: info.ModTime(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		result.Error = fmt.Sprintf("tar header: %v", err)
		return result
	}
	// Use LimitReader to cap at the stat'd size: live log files can grow
	// between Stat() and Copy(), which causes "write too long" in the tar
	// writer. We only write what we promised in the header.
	if _, err := io.Copy(tw, io.LimitReader(f, info.Size())); err != nil {
		result.Error = fmt.Sprintf("tar copy: %v", err)
		return result
	}
	vlogf("  file %s: OK (%d bytes)", srcPath, info.Size())
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
		dest := filepath.Join(hostRoot, "system", spec.Name+".txt")
		if err := addBytesToArchive(tw, dest, content); err != nil {
			warnf("[%s] could not add %s to archive: %v", hostname, spec.Name, err)
		}
	}

	// ── phase: weka CLI commands (parallel) ───────────────────────────────
	phase(fmt.Sprintf("[%s] Weka commands (profile: %s, %d parallel)", hostname, profile, cmdWorkers))

	allWekaCmds := append(append([]CommandSpec{}, defaultCommands...), buildProfileCommands(profile)...)

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
			warnf("[%s] command %q failed (exit %d): %s", hostname, spec.Name, co.result.ExitCode, co.result.Error)
		}
		content := co.out
		if co.result.Error != "" && len(co.out) == 0 {
			content = []byte(fmt.Sprintf("# command: %s\n# error: %s\n", spec.Cmd, co.result.Error))
		}
		dest := filepath.Join(hostRoot, "weka", spec.Name+".txt")
		if err := addBytesToArchive(tw, dest, content); err != nil {
			warnf("[%s] could not add %s to archive: %v", hostname, spec.Name, err)
		}
		if spec.Name == "weka_version" && len(co.out) > 0 {
			manifest.WekaVersion = strings.TrimSpace(string(co.out))
		}
	}

	// ── phase: journalctl (full/all only, or if time window specified) ─────
	if profileEnabled(profile, ProfileFull) || profileEnabled(profile, ProfileAll) || !from.IsZero() {
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
		for _, srcPath := range matches {
			if seenSrcPaths[srcPath] {
				vlogf("[%s] skip duplicate %s", hostname, srcPath)
				continue
			}
			seenSrcPaths[srcPath] = true
			logf("  [%s] collecting: %s", hostname, srcPath)
			// Preserve directory structure relative to the glob base so that
			// e.g. /opt/weka/logs/compute0/syslog.log ends up at
			// hosts/<host>/weka/containers/compute0/syslog.log, not
			// hosts/<host>/weka/containers/syslog.log (which would overwrite
			// the same filename from drives0, frontend0, etc.)
			base := globBase(spec.SrcGlob)
			relPath := strings.TrimPrefix(srcPath, base)
			destPath := filepath.Join(archiveRoot, "hosts", hostname, spec.DestDir, relPath)
			fr := collectLogFile(tw, srcPath, destPath, from)
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
func buildProfileCommands(profile string) []CommandSpec {
	var cmds []CommandSpec
	addIfProfile := func(list []CommandSpec, p string) {
		if profileEnabled(profile, p) {
			cmds = append(cmds, list...)
		}
	}
	addIfProfile(fullCommands, ProfileFull)
	addIfProfile(perfCommands, ProfilePerf)
	addIfProfile(nfsCommands, ProfileNFS)
	addIfProfile(s3Commands, ProfileS3)
	addIfProfile(smbwCommands, ProfileSMBW)
	addIfProfile(clientCommands, ProfileClient)
	return cmds
}

// buildClusterWideCmds returns all commands (default + profile) that produce
// identical output on every node and should be run exactly once by the orchestrator.
// These are commands with NodeLocal==false.
func buildClusterWideCmds(profile string) []CommandSpec {
	all := append(append([]CommandSpec{}, defaultCommands...), buildProfileCommands(profile)...)
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
// When selfDeploy is true (the default), it first scps the running binary to
// /tmp/weka-log-collector on the remote host, runs it there, then removes it
// on exit — so no manual pre-deployment is required.
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
		remoteBin = "/tmp/weka-log-collector"
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
			extra = append(extra, "--from", from.Format("2006-01-02T15:04"))
		}
		if !to.IsZero() {
			extra = append(extra, "--to", to.Format("2006-01-02T15:04"))
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

// cleanStaleSymlinks removes broken wlc-* / wlc:* symlinks from supportDir.
// The uploader queue is sequential; a stale broken symlink blocks all later uploads.
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
		if _, err := os.Stat(target); err != nil {
			if removeErr := os.Remove(stalePath); removeErr == nil {
				logf("Removed stale upload symlink: %s → %s", name, target)
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
	linkName := "wlc-" + filename

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
				elapsed := time.Since(start)
				var pct int
				if sizeMB > 0 {
					pct = int(elapsed.Seconds()) * 100 / int(sizeMB)
					if pct > 99 {
						pct = 99
					}
				}
				logf("Uploading... ~%d%% elapsed: %s", pct, elapsed.Round(time.Second))
				lastLog = time.Now()
			}
		}

		setActive("")
		if _, err := os.Lstat(linkPath); err == nil {
			os.Remove(linkPath)
		}

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

    profiles="default full perf nfs s3 smbw client all"

    opts="--local --upload --clients --dry-run --verbose --version
          --from --to --profile --output --host --container-id
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
        --from|--to)
            COMPREPLY=( $(compgen -W "-1h -2h -4h -8h -12h -24h -1d -2d" -- "$cur") )
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
		fromStr      = flag.String("from", "", "Start of time window (e.g. -2h, -30m, 2026-03-04T10:30)")
		toStr        = flag.String("to", "", "End of time window (default: now)")
		profileStr   = flag.String("profile", ProfileDefault, fmt.Sprintf("Collection profile: %s", strings.Join(validProfiles, "|")))
		outputPath   = flag.String("output", "", "Output .tar.gz path (default: /tmp/<hostname>-weka-logs-<ts>.tar.gz). Use - for stdout.")
		localOnly    = flag.Bool("local", false, "Collect from local host only (no SSH, no cluster query)")
		nodeOnly     = flag.Bool("node-only", false, "Skip cluster-wide weka commands; collect only node-local data (used internally by SSH collection)")
		upload       = flag.Bool("upload", false, "Upload the collected archive to Weka Home (requires 'weka cloud enable')")
		dryRun       = flag.Bool("dry-run", false, "Show what would be collected and estimated size; do not collect")
		maxSizeMB    = flag.Uint64("max-size", 2048, "Abort if estimated collection size exceeds this value (MB)")
		sshUser      = flag.String("ssh-user", "root", "SSH user for remote host collection")
		remoteBinary = flag.String("remote-binary", "/usr/local/bin/weka-log-collector", "Path to weka-log-collector binary on remote hosts (used only with --no-self-deploy)")
		noSelfDeploy = flag.Bool("no-self-deploy", false, "Do not auto-deploy binary to remote hosts; use --remote-binary path instead")
		workerCount  = flag.Int("workers", 10, "Max parallel SSH workers for cluster collection")
		cmdTimeout   = flag.Duration("cmd-timeout", 60*time.Second, "Timeout per command")
		ver          = flag.Bool("version", false, "Print version and exit")
	)
	var hosts multiStringFlag
	var containerIDs multiIntFlag
	withClients := flag.Bool("clients", false, "Include client nodes in cluster collection (default: backends only)")
	flag.BoolVar(&verbose, "verbose", false, "Print detailed progress for every file and command")
	flag.Var(&hosts, "host", "Collect only from these hosts by IP (repeatable; default: all cluster backends)")
	flag.Var(&containerIDs, "container-id", "Collect from specific container IDs only (repeatable; e.g. --container-id 0 --container-id 2)")
	flag.Usage = usageFunc
	flag.Parse()

	if *ver {
		fmt.Printf("weka-log-collector %s\n", version)
		return
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
	if *fromStr != "" {
		t, err := parseInputTime(*fromStr)
		if err != nil {
			errorf("--from: %v", err)
			os.Exit(1)
		}
		from = t
	}
	if *toStr != "" {
		t, err := parseInputTime(*toStr)
		if err != nil {
			errorf("--to: %v", err)
			os.Exit(1)
		}
		to = t
	}
	if !from.IsZero() && !to.IsZero() && to.Before(from) {
		errorf("--to (%s) is before --from (%s)", to.Format(time.RFC3339), from.Format(time.RFC3339))
		os.Exit(1)
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
		logf("From:     %s", from.Format(time.RFC3339))
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

	// ── space check (skip for stdout) ─────────────────────────────────────
	if !toStdout && !*dryRun {
		outputDir := filepath.Dir(outPath)
		di, err := checkDiskSpace(outputDir)
		if err != nil {
			errorf("disk space check failed for %s: %v", outputDir, err)
			errorf("Tip: use --output to write to a different location (e.g. --output /data/weka-logs.tar.gz)")
			os.Exit(1)
		}
		estimated := estimateCollectionMB(*profileStr, logFileSpecs)
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
			errorf("Tip: narrow the time window with --from -2h to reduce the amount collected.")
			errorf("     Or increase the limit with --max-size <MB>.")
			errorf("     Or use --dry-run to see exactly what would be collected.")
			os.Exit(1)
		}
	}

	if *dryRun {
		phase("DRY RUN — showing what would be collected")
		estimated := estimateCollectionMB(*profileStr, logFileSpecs)
		logf("  Profile:   %s", *profileStr)
		logf("  Estimated: ~%d MB compressed", estimated)
		logf("  Commands:  %d weka + %d system", len(defaultCommands)+len(buildProfileCommands(*profileStr)), len(systemCommands))
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
		nodes, err := discoverClusterNodes(*withClients)
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
			logf("Auto-deploying binary from %s to /tmp/weka-log-collector on each host", selfPath)
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
	clusterCmds := buildClusterWideCmds(profile)
	phase(fmt.Sprintf("Cluster-wide Weka commands (run once, %d parallel)", cmdWorkers))
	logf("  [cluster] running %d cluster-wide commands", len(clusterCmds))
	clusterOutputs := runCommandsParallel(clusterCmds, cmdTimeout)
	for i, spec := range clusterCmds {
		co := clusterOutputs[i]
		if co.result.Error != "" {
			warnf("[cluster] command %q failed (exit %d): %s", spec.Name, co.result.ExitCode, co.result.Error)
		}
		content := co.out
		if co.result.Error != "" && len(co.out) == 0 {
			content = []byte(fmt.Sprintf("# command: %s\n# error: %s\n", spec.Cmd, co.result.Error))
		}
		dest := filepath.Join(archiveRoot, "cluster", "weka", spec.Name+".txt")
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
  weka-log-collector [--from TIME] [--to TIME] [--profile PROFILE] [options]
  weka-log-collector --local [--from TIME] [--profile PROFILE]
  weka-log-collector --dry-run [--from TIME] [--profile PROFILE]

COLLECTION MODES
  Default (no --local):  discover all cluster hosts via 'weka cluster container',
                         SSH to each, run collection, merge into one archive.
  --local:               collect from this host only; stream to --output.
  --dry-run:             show what would be collected and estimated size.

TIME WINDOW
  --from TIME  Start time. Logs before this are excluded.
               Relative: -2h, -30m, -1d
               Absolute: 2026-03-04T10:30
  --to   TIME  End time (default: now). Same formats.

  Examples:
    --from -2h                    last 2 hours
    --from -1d --to -12h          yesterday morning
    --from 2026-03-04T10:00 --to 2026-03-04T12:00

PROFILES
  default   Core weka commands + key logs (~30MB/node compressed)
  full      + container logs, journalctl, events, core dumps
  perf      + performance stats (use with --from/-to for the incident window)
  nfs       + Ganesha logs and NFS commands
  s3        + S3/envoy logs and S3 commands
  smbw      + SMB-W logs and Pacemaker status
  client    + client-side NIC/OFED/routing info
  all       Everything

OPTIONS
  --host HOST          Collect from this host by IP (repeatable; default: all cluster backends)
  --container-id N     Collect from this container ID only (repeatable; e.g. --container-id 0 --container-id 2)
  --clients            Include client nodes in cluster collection (default: backends only)
  --local              Collect from local host only
  --upload             Upload collected archive to Weka Home (requires weka cloud to be enabled)
  --dry-run            Show collection plan; do not collect
  --output PATH        Output archive path (default: /tmp/<hostname>-weka-logs-<ts>.tar.gz)
                       Use - to write to stdout (useful for piping over SSH)
  --max-size MB        Abort if estimated size exceeds this (default: 2048 MB)
  --ssh-user USER      SSH username (default: root)
  --workers N          Parallel SSH workers (default: 10)
  --cmd-timeout DUR    Per-command timeout, e.g. 60s, 2m (default: 60s)
  --verbose            Print every file/command included or skipped and why
  --version            Print version and exit

EXAMPLES
  # Collect last 2 hours from all cluster nodes (run on any backend)
  weka-log-collector --from -2h

  # Collect full profile for a specific incident window
  weka-log-collector --profile full --from 2026-03-04T10:00 --to 2026-03-04T12:00

  # Collect S3-specific logs from this node only
  weka-log-collector --local --profile s3 --from -4h

  # Dry run: see what would be collected
  weka-log-collector --profile full --from -2h --dry-run

  # Collect from specific container IDs (as shown in 'weka cluster container')
  weka-log-collector --container-id 0 --container-id 1 --from -2h

  # Collect from all backends and clients
  weka-log-collector --clients --from -2h

  # Collect from specific hosts by IP
  weka-log-collector --host 10.0.0.1 --host 10.0.0.2 --from -1h

  # Stream to remote machine
  weka-log-collector --local --from -1h --output - | ssh analyst@host 'cat > weka-logs.tar.gz'

`)
}
