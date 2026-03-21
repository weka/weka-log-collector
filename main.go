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
	Name    string // output filename (without extension)
	Cmd     string // shell command
	Profile string // which profile this belongs to (empty = always run)
	Fatal   bool   // if true, collection fails if this command fails; default non-fatal
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
	// ── local container info ───────────────────────────────────────
	{Name: "weka_local_ps", Cmd: "weka local ps -v"},
	{Name: "weka_local_resources_drives0", Cmd: "weka local resources -C drives0"},
	{Name: "weka_local_resources_compute0", Cmd: "weka local resources -C compute0"},
	{Name: "weka_local_resources_frontend0", Cmd: "weka local resources -C frontend0"},
}

// fullCommands are added when profile is "full" or "all".
var fullCommands = []CommandSpec{
	{Name: "weka_events_major", Cmd: "weka events --severity major", Profile: ProfileFull},
	{Name: "weka_debug_net_peers", Cmd: "weka debug net peers 1", Profile: ProfileFull},
	{Name: "weka_cluster_container_info_hw", Cmd: "weka cluster container info-hw", Profile: ProfileFull},
	{Name: "weka_cfgdump", Cmd: "weka local exec -C drives0 -- /weka/cfgdump", Profile: ProfileFull},
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
	{Name: "weka_local_resources_ganesha", Cmd: "weka local resources -C ganesha -J", Profile: ProfileNFS},
	{Name: "nfs_ganesha_config", Cmd: "weka local run /weka/cfgdump --container frontend0 | grep -i nfsGaneshaConfig -A 20", Profile: ProfileNFS},
	{Name: "nfs_ganesha_queue", Cmd: "weka local exec --container ganesha cat /proc/wekafs/frontend0/queue", Profile: ProfileNFS},
	{Name: "weka_stats_ops_nfsw", Cmd: "weka stats --category ops_nfsw --per-node -Z", Profile: ProfileNFS},
	{Name: "netstat_nfs", Cmd: "netstat -tupnl", Profile: ProfileNFS},
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
	{Name: "s3_cgroup_memory", Cmd: "cat /sys/fs/cgroup/memory/weka-s3/memory.limit_in_bytes && cat /sys/fs/cgroup/memory/weka-s3/memory.usage_in_bytes", Profile: ProfileS3},
	{Name: "netstat_s3", Cmd: "netstat -tuln | grep 9001", Profile: ProfileS3},
}

// smbwCommands are added for profile "smbw" or "all".
var smbwCommands = []CommandSpec{
	{Name: "weka_smb_cluster", Cmd: "weka smb cluster", Profile: ProfileSMBW},
	{Name: "weka_smb_cluster_status", Cmd: "weka smb cluster status", Profile: ProfileSMBW},
	{Name: "weka_smb_domain", Cmd: "weka smb domain", Profile: ProfileSMBW},
	{Name: "weka_smb_share", Cmd: "weka smb share", Profile: ProfileSMBW},
	{Name: "weka_smb_cluster_info", Cmd: "weka debug config show sambaClusterInfo", Profile: ProfileSMBW},
	{Name: "pcs_cluster_status", Cmd: "weka local exec --container smbw /usr/sbin/pcs cluster status", Profile: ProfileSMBW},
	{Name: "pcs_status", Cmd: "weka local exec --container smbw /usr/sbin/pcs status", Profile: ProfileSMBW},
	{Name: "pcs_status_resources", Cmd: "weka local exec --container smbw /usr/sbin/pcs status resources", Profile: ProfileSMBW},
	{Name: "pcs_constraint", Cmd: "weka local exec --container smbw /usr/sbin/pcs constraint", Profile: ProfileSMBW},
	{Name: "sssd_conf", Cmd: "cat /etc/sssd/sssd.conf", Profile: ProfileSMBW},
}

// clientCommands are added for profile "client" or "all".
var clientCommands = []CommandSpec{
	{Name: "lshw_network", Cmd: "lshw -C network -businfo", Profile: ProfileClient},
	{Name: "ofed_info", Cmd: "ofed_info -s", Profile: ProfileClient},
	{Name: "lsmod", Cmd: "lsmod", Profile: ProfileClient},
	{Name: "modinfo_mlx5_core", Cmd: "modinfo mlx5_core", Profile: ProfileClient},
	{Name: "modinfo_ice", Cmd: "modinfo ice", Profile: ProfileClient},
	{Name: "ip_rule", Cmd: "ip rule", Profile: ProfileClient},
	{Name: "ip_route", Cmd: "ip route show", Profile: ProfileClient},
	{Name: "ip_neighbor", Cmd: "ip neighbor", Profile: ProfileClient},
	{Name: "netstat", Cmd: "netstat -tunlp", Profile: ProfileClient},
	{Name: "rp_filter", Cmd: "sysctl -a | grep -w rp_filter", Profile: ProfileClient},
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
// Returns a HostManifest describing what was collected.
func CollectLocal(tw *tar.Writer, archiveRoot, profile string, from, to time.Time, cmdTimeout time.Duration) HostManifest {
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

	// ── phase: system commands ────────────────────────────────────────────
	phase(fmt.Sprintf("[%s] System commands", hostname))
	for _, spec := range systemCommands {
		result, out := runCommand(spec, cmdTimeout)
		manifest.Commands = append(manifest.Commands, result)
		if result.Error != "" {
			warnf("[%s] command %q failed (exit %d): %s", hostname, spec.Name, result.ExitCode, result.Error)
		}
		dest := filepath.Join(hostRoot, "system", spec.Name+".txt")
		content := out
		if result.Error != "" && len(out) == 0 {
			content = []byte(fmt.Sprintf("# command: %s\n# error: %s\n", spec.Cmd, result.Error))
		}
		if err := addBytesToArchive(tw, dest, content); err != nil {
			warnf("[%s] could not add %s to archive: %v", hostname, spec.Name, err)
		}
	}

	// dmesg separately (timestamped)
	result, out := runCommand(CommandSpec{Name: "dmesg", Cmd: "dmesg -T"}, cmdTimeout)
	manifest.Commands = append(manifest.Commands, result)
	_ = addBytesToArchive(tw, filepath.Join(hostRoot, "system", "dmesg.txt"), out)

	// ── phase: weka CLI commands ──────────────────────────────────────────
	phase(fmt.Sprintf("[%s] Weka commands (profile: %s)", hostname, profile))

	allWekaCmds := append(append([]CommandSpec{}, defaultCommands...), buildProfileCommands(profile)...)

	for _, spec := range allWekaCmds {
		logf("  [%s] running: %s", hostname, spec.Name)
		result, out := runCommand(spec, cmdTimeout)
		manifest.Commands = append(manifest.Commands, result)
		if result.Error != "" {
			warnf("[%s] command %q failed (exit %d): %s", hostname, spec.Name, result.ExitCode, result.Error)
		}
		dest := filepath.Join(hostRoot, "weka", spec.Name+".txt")
		content := out
		if result.Error != "" && len(out) == 0 {
			content = []byte(fmt.Sprintf("# command: %s\n# error: %s\n", spec.Cmd, result.Error))
		}
		if err := addBytesToArchive(tw, dest, content); err != nil {
			warnf("[%s] could not add %s to archive: %v", hostname, spec.Name, err)
		}
		// capture weka version for manifest
		if spec.Name == "weka_version" && len(out) > 0 {
			manifest.WekaVersion = strings.TrimSpace(string(out))
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

// ── multi-host SSH collection ─────────────────────────────────────────────────

// HostResult is the outcome of collecting from a single remote host.
type HostResult struct {
	Host     string
	Manifest *HostManifest
	Archive  []byte // tar.gz bytes from remote host
	Err      error
}

// collectFromHost SSHs into a host, runs weka-log-collector --local, and
// streams the tar.gz back. The remote binary must be pre-deployed or available
// via PATH. Falls back to running via sudo if needed.
func collectFromHost(host, binaryPath, profile string, from, to time.Time, sshUser string, sshTimeout time.Duration) HostResult {
	result := HostResult{Host: host}

	// Build the remote command
	remoteArgs := []string{
		binaryPath,
		"--local",
		"--profile", profile,
		"--output", "-", // stream to stdout
	}
	if !from.IsZero() {
		remoteArgs = append(remoteArgs, "--from", from.Format("2006-01-02T15:04"))
	}
	if !to.IsZero() {
		remoteArgs = append(remoteArgs, "--to", to.Format("2006-01-02T15:04"))
	}
	if verbose {
		remoteArgs = append(remoteArgs, "--verbose")
	}

	sshTarget := host
	if sshUser != "" {
		sshTarget = sshUser + "@" + host
	}

	sshCmd := exec.Command("ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=30",
		"-o", "BatchMode=yes",
		sshTarget,
		strings.Join(remoteArgs, " "),
	)

	logf("  [%s] connecting via SSH...", host)
	out, err := sshCmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.Err = fmt.Errorf("SSH command failed (exit %d): %s",
				exitErr.ExitCode(), strings.TrimSpace(string(exitErr.Stderr)))
		} else {
			result.Err = fmt.Errorf("SSH error: %v", err)
		}
		errorf("[%s] collection failed: %v", host, result.Err)
		return result
	}
	result.Archive = out
	logf("  [%s] collected %d KB", host, len(out)/1024)
	return result
}

// discoverClusterHosts returns the list of backend node IPs by running
// `weka cluster servers list --output ip --role backend`.
// Using IPs (like wekachecker) avoids hostname-resolution failures.
func discoverClusterHosts() ([]string, error) {
	out, err := exec.Command("weka", "cluster", "servers", "list",
		"--no-header", "--output", "ip", "--role", "backend").Output()
	if err != nil {
		// Fall back to container hostname listing if servers list isn't available
		out2, err2 := exec.Command("weka", "cluster", "container", "-l",
			"--no-header", "--output", "ips").Output()
		if err2 != nil {
			return nil, fmt.Errorf("weka cluster servers list failed: %v; fallback also failed: %v", err, err2)
		}
		out = out2
	}
	seen := map[string]bool{}
	var hosts []string
	for _, line := range strings.Split(string(out), "\n") {
		h := strings.TrimSpace(line)
		// servers list may return comma-separated IPs per server; take first
		if idx := strings.IndexByte(h, ','); idx >= 0 {
			h = strings.TrimSpace(h[:idx])
		}
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts, nil
}

// ── archive merging ───────────────────────────────────────────────────────────

// mergeArchive extracts the tar.gz in srcData and re-writes every entry into
// the destination tar.Writer under a new root prefix.
func mergeArchive(tw *tar.Writer, srcData []byte, newRoot string) error {
	gr, err := gzip.NewReader(bytes.NewReader(srcData))
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

func main() {
	var (
		fromStr      = flag.String("from", "", "Start of time window (e.g. -2h, -30m, 2026-03-04T10:30)")
		toStr        = flag.String("to", "", "End of time window (default: now)")
		profileStr   = flag.String("profile", ProfileDefault, fmt.Sprintf("Collection profile: %s", strings.Join(validProfiles, "|")))
		outputPath   = flag.String("output", "", "Output .tar.gz path (default: /tmp/<hostname>-weka-logs-<ts>.tar.gz). Use - for stdout.")
		localOnly    = flag.Bool("local", false, "Collect from local host only (no SSH, no cluster query)")
		dryRun       = flag.Bool("dry-run", false, "Show what would be collected and estimated size; do not collect")
		maxSizeMB    = flag.Uint64("max-size", 2048, "Abort if estimated collection size exceeds this value (MB)")
		sshUser      = flag.String("ssh-user", "root", "SSH user for remote host collection")
		remoteBinary = flag.String("remote-binary", "/usr/local/bin/weka-log-collector", "Path to weka-log-collector binary on remote hosts")
		workerCount  = flag.Int("workers", 10, "Max parallel SSH workers for cluster collection")
		cmdTimeout   = flag.Duration("cmd-timeout", 60*time.Second, "Timeout per command")
		ver          = flag.Bool("version", false, "Print version and exit")
	)
	var hosts multiStringFlag
	flag.BoolVar(&verbose, "verbose", false, "Print detailed progress for every file and command")
	flag.Var(&hosts, "host", "Collect only from these hosts (repeatable; default: all cluster nodes)")
	flag.Usage = usageFunc
	flag.Parse()

	if *ver {
		fmt.Printf("weka-log-collector %s\n", version)
		return
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
		hostname, _ := os.Hostname()
		hostname = sanitizeHostname(hostname)
		ts := time.Now().Format("2006-01-02T15-04-05")
		outPath = fmt.Sprintf("/tmp/%s-weka-logs-%s.tar.gz", hostname, ts)
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
		writeArchive(outPath, toStdout, *profileStr, from, to, *cmdTimeout, nil)
		return
	}

	// ── cluster collection ────────────────────────────────────────────────
	phase("Discovering cluster hosts")
	clusterHosts := []string(hosts)
	if len(clusterHosts) == 0 {
		discovered, err := discoverClusterHosts()
		if err != nil {
			warnf("Could not discover cluster hosts: %v", err)
			warnf("Falling back to local-only collection. Use --host to specify hosts manually.")
			writeArchive(outPath, toStdout, *profileStr, from, to, *cmdTimeout, nil)
			return
		}
		clusterHosts = discovered
		logf("Discovered %d cluster hosts: %s", len(clusterHosts), strings.Join(clusterHosts, ", "))
	} else {
		logf("Collecting from %d specified hosts: %s", len(clusterHosts), strings.Join(clusterHosts, ", "))
	}

	// Collect from all hosts in parallel
	phase("Collecting from cluster hosts")
	results := collectCluster(clusterHosts, *remoteBinary, *profileStr, from, to, *sshUser, *cmdTimeout, *workerCount)

	// Write merged archive
	phase("Writing archive")
	writeMergedArchive(outPath, toStdout, results, *profileStr, from, to, *cmdTimeout)
}

// collectCluster fans out collection to all hosts in parallel.
func collectCluster(hosts []string, binaryPath, profile string, from, to time.Time, sshUser string, cmdTimeout time.Duration, workers int) []HostResult {
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
			r := collectFromHost(host, binaryPath, profile, from, to, sshUser, 5*cmdTimeout)
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return results
}

// writeArchive performs a local collection and writes to outPath (or stdout).
func writeArchive(outPath string, toStdout bool, profile string, from, to time.Time, cmdTimeout time.Duration, extraManifests []HostManifest) {
	hostname, _ := os.Hostname()
	hostname = sanitizeHostname(hostname)
	ts := time.Now().Format("2006-01-02T15-04-05")
	archiveRoot := fmt.Sprintf("%s-weka-logs-%s", hostname, ts)

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

	gz := gzip.NewWriter(outWriter)
	tw := tar.NewWriter(gz)

	manifest := CollectLocal(tw, archiveRoot, profile, from, to, cmdTimeout)

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
	hostname, _ := os.Hostname()
	hostname = sanitizeHostname(hostname)
	ts := time.Now().Format("2006-01-02T15-04-05")
	archiveRoot := fmt.Sprintf("cluster-weka-logs-%s-%s", hostname, ts)

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

	gz := gzip.NewWriter(outWriter)
	tw := tar.NewWriter(gz)

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
		if err := mergeArchive(tw, r.Archive, archiveRoot); err != nil {
			errorf("[%s] failed to merge archive: %v", r.Host, err)
			failed++
			failedHosts = append(failedHosts, r.Host)
			continue
		}
		succeeded++
		logf("  [%s] merged OK", r.Host)
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
  --host HOST          Collect only from this host (repeatable; default: all cluster nodes)
  --local              Collect from local host only
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

  # Collect from specific hosts only
  weka-log-collector --host backend01 --host backend02 --from -1h

  # Stream to remote machine
  weka-log-collector --local --from -1h --output - | ssh analyst@host 'cat > weka-logs.tar.gz'

`)
}
