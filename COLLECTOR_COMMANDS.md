# Commands the TA Tool Uses but weka-log-collector Does NOT Capture

Generated: 2026-05-08

This document identifies system commands and weka CLI commands that the TA tool
scripts (`weka-tools/install/scripts.d/ta/`) use for analysis, but which are NOT
currently captured by `weka-log-collector`. Only commands whose output would be
useful for **offline analysis** are listed. Pure live tests (ping, SSH, DNS
resolution, clockdiff, MTU ping tests) are excluded.

---

## List 1: Per-Host System Commands

These commands should be collected on every host and saved into
`hosts/<hostname>/system/`.

| Command | Destination Filename | TA Script(s) | What It Enables |
|---------|---------------------|---------------|-----------------|
| `getenforce` | `getenforce.txt` | `105_selinux.sh` | SELinux enforcement state - needed to check if SELinux is Enforcing/Permissive/Disabled |
| `sestatus` | `sestatus.txt` | `105_selinux.sh` | Detailed SELinux status including config file vs runtime state |
| `cat /etc/selinux/config` | `selinux_config.txt` | `105_selinux.sh` | SELinux boot-time configuration - detects config vs runtime mismatch |
| `cat /proc/cmdline` | `proc_cmdline.txt` | `200_checkiommu.sh`, `250_irqconflict.sh` | Kernel boot parameters - needed for IOMMU check, initcall_blacklist, hugepages boot config |
| `mount` | `mount.txt` | `215_checktmpmount.sh`, `630_opt_weka_exists_but_not_mounted.sh`, `810_use_only_readcache_for_protocols.sh` | All mounted filesystems - detects /tmp noexec, /opt/weka mount state, wekafs mount options |
| `cat /etc/fstab` | `fstab.txt` | `560_check_for_swap.sh`, `630_opt_weka_exists_but_not_mounted.sh`, `870_wekafs_requires_netdev.sh` | Filesystem table - detects swap at boot, /opt/weka boot-mount config, wekafs _netdev option |
| `cat /etc/resolv.conf` | `resolv_conf.txt` | (general networking) | DNS resolver config - needed for DNS troubleshooting, nameserver validation |
| `cat /etc/mtab` | `mtab.txt` | `630_opt_weka_exists_but_not_mounted.sh` | Currently mounted filesystems (proc-style) - detects /opt/weka mount mismatch |
| `iptables -L -v -n` | `iptables_rules.txt` | `140_checkiptables.sh`, `550_iptables_nats_local_traffic.sh` | Firewall filter rules - detects rules that block Weka traffic |
| `iptables -L -n -t nat` | `iptables_nat.txt` | `550_iptables_nats_local_traffic.sh` | NAT table rules - detects NAT rewriting of Weka local traffic |
| `iptables-save` | `iptables_save.txt` | `140_checkiptables.sh`, `550_iptables_nats_local_traffic.sh` | Full iptables ruleset in restorable format - complete firewall audit |
| `systemctl status firewalld` | `firewalld_status.txt` | `140_checkiptables.sh` | Firewalld service state - detects active firewall on RHEL systems |
| `cat /sys/devices/system/cpu/smt/active` | `smt_active.txt` | `150_htcputest.sh` | Hyperthreading/SMT state - Weka recommends disabling SMT |
| `grep -m1 aes /proc/cpuinfo` | `cpuinfo_aes.txt` | `160_checkaes.sh` | CPU AES instruction support - required for Weka encryption |
| `cat /proc/cpuinfo` | `proc_cpuinfo.txt` | `160_checkaes.sh` | Full CPU feature flags - enables offline CPU capability analysis |
| `cat /proc/meminfo` | `proc_meminfo.txt` | `560_check_for_swap.sh`, `120_freeram.sh` | Full memory info including SwapTotal, HugePages, NUMA details |
| `cat /proc/sys/kernel/numa_balancing` | `numa_balancing.txt` | `180_numabalancing.sh` | NUMA auto-balancing state - should be 0 for Weka |
| `grep squashfs /etc/modprobe.d/*` | `modprobe_squashfs.txt` | `210_checksquashfs.sh` | Squashfs module blacklist status - squashfs must be enabled for Weka |
| `ls /etc/modprobe.d/` | `modprobe_d_listing.txt` | `210_checksquashfs.sh`, `250_irqconflict.sh` | Modprobe config files - detects driver blacklists and options |
| `nvme id-ns /dev/nvme*n* (for each namespace)` | `nvme_id_ns.txt` | `223_checknvmelba.sh` | NVMe namespace LBA format info - detects wrong block size, metadata size, relative performance |
| `nvme list` | `nvme_list.txt` | `223_checknvmelba.sh`, `220_checknvmebus.sh` | All NVMe devices with model, serial, firmware, size |
| `mokutil --sb-state` | `secureboot_state.txt` | `225_checksecureboot.sh` | Secure Boot state - Weka requires Secure Boot disabled |
| `ls /sys/class/iommu/ && ls /sys/kernel/iommu_groups/` | `iommu_state.txt` | `200_checkiommu.sh` | IOMMU device and group presence - detects enabled IOMMU |
| `grep MemTotal /sys/devices/system/node/node*/meminfo` | `numa_meminfo.txt` | `420_check_cross-numa_zone_memory_balance.sh` | Per-NUMA-zone memory totals - detects memory imbalance across NUMA nodes |
| `ls -d /sys/devices/system/node/node*` | `numa_nodes.txt` | `470_number_of_numa_domains.sh` | Number of NUMA domains - Weka has version-specific limits |
| `systemctl is-enabled weka-agent` | `weka_agent_enabled.txt` | `480_check_weka_agent.sh` | Weka agent systemd enable state - must be enabled for Weka to start on boot |
| `cat /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages` | `hugepages_1g.txt` | `660_hugepages_check.sh` | 1G hugepage allocation count |
| `cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages` | `hugepages_2m.txt` | `660_hugepages_check.sh` | 2M hugepage allocation count |
| `grep -E 'weka.*huge' /proc/*/numa_maps 2>/dev/null` | `weka_hugepages_numa_maps.txt` | `660_hugepages_check.sh` | Weka hugepage allocation per NUMA zone - detects allocation discrepancy |
| `systemctl status falcon-sensor` | `falcon_sensor_status.txt` | `670_crowdstrike_check.sh` | CrowdStrike Falcon status - known to cause kernel module unload issues |
| `NetworkManager --print-config` | `nm_config.txt` | `670_nm_ignore_carrier.sh` | NetworkManager config - checks ignore-carrier setting |
| `nmcli dev status` | `nmcli_dev_status.txt` | `670_nm_ignore_carrier.sh` | Network device status via NetworkManager |
| `cat /proc/net/bonding/*` | `bonding_info.txt` | `805_bonding_check.sh` | Bonding interface details - mode, slaves, hash policy, state |
| `cat /sys/class/net/*/bonding/mode` | `bonding_modes.txt` | `805_bonding_check.sh` | Bond mode per interface (active-backup vs LACP) |
| `cat /sys/class/net/*/bonding/slaves` | `bonding_slaves.txt` | `805_bonding_check.sh` | Slave interfaces per bond |
| `cat /sys/class/net/*/bonding/xmit_hash_policy` | `bonding_hash_policy.txt` | `805_bonding_check.sh` | Bond transmit hash policy - layer2 is problematic |
| `cat /sys/class/net/*/type` | `net_device_types.txt` | `740_mlx_settings.sh`, `865_infiniband_lid_mismatch.sh` | Network device type codes (1=Ethernet, 32=InfiniBand) |
| `cat /sys/class/net/*/mode` | `ib_device_modes.txt` | `740_mlx_settings.sh` | InfiniBand device mode (datagram vs connected) |
| `cat /sys/class/net/*/device/infiniband/*/ports/*/lid` | `ib_lid_values.txt` | `865_infiniband_lid_mismatch.sh` | InfiniBand LID values - detects LID mismatch between OS and Weka |
| `cat /sys/bus/pci/devices/*/net/*/mtu` | `pci_net_mtu.txt` | `620_same_mtu_across_nics.sh` | Per-PCI-device MTU values - detects MTU mismatch across Weka NICs |
| `grep ib_uverbs /proc/modules` | `ib_uverbs_module.txt` | `740_mlx_settings.sh` | IB userspace verbs module state - required for Mellanox cards |
| `stat -fc %T /sys/fs/cgroup` | `cgroup_type.txt` | `740_ensure_cgroups_v1_with_protocols.sh`, `875_cgroup_validation.sh` | Cgroup filesystem type (tmpfs=v1, cgroup2fs=v2) |
| `cat /sys/fs/cgroup/weka-*/cpuset.cpus.effective` | `cgroup_cpuset.txt` | `875_cgroup_validation.sh` | Effective CPU set for Weka cgroup containers |
| `cat /proc/mdstat` | `mdstat.txt` | `880_all_mdadm_devices_good.sh` | Software RAID status - detects degraded mdadm arrays |
| `mdadm --detail --test /dev/md*` | `mdadm_detail.txt` | `880_all_mdadm_devices_good.sh` | Detailed mdadm device health |
| `weka local status` | `weka_local_status.txt` | `580_weka_version_available_everywhere.sh`, `875_cgroup_validation.sh` | Agent version, cgroup mode/version/enabled status |
| `cat /etc/wekaio/service.conf` | `weka_service_conf.txt` | `875_cgroup_validation.sh` | Weka agent service configuration including cgroups_mode |
| `ps -eo pid,comm \| grep weka_init` | `weka_init_pids.txt` | `570_does_weka_use_swap.sh` | Weka init PIDs - needed to check container swap usage |
| `cat /opt/weka/dist/release/*.spec` | `weka_release_spec.txt` | `450_custom_ca_certs.sh` | Weka release spec - detects custom CA certificates |
| `xfs_info /opt/weka/*.loop` | `xfs_loop_info.txt` | `635_loopback_fs_free_space.sh` | XFS loopback filesystem info - detects low free space |
| `ls -la /opt/weka/data/agent/containers/state/*/huge*/*` | `weka_hugepage_files.txt` | `845_mem_alloc.sh` | Hugepage file sizes per container - calculates Weka memory consumption |
| `ps -o rsz -C wekanode` | `wekanode_rss.txt` | `845_mem_alloc.sh` | Weka process RSS memory - detects excessive memory usage |
| `cat /proc/net/if_inet6` | `ipv6_interfaces.txt` | `885_nfsw_resources.sh` | IPv6 interface presence - disabling IPv6 can impair NFSW health checks |
| `ss -Hnt sport = :2049` | `nfs_tcp_connections.txt` | `885_nfsw_resources.sh`, `920_nfs_tcp_connections.sh` | NFS TCP connection count - detects connection limit approach |
| `ip -j -o addr show` | `ip_addr_json.txt` | `460_ip_source-based_routing.sh`, `510_check_for_noprefixroute.sh`, `795_netmask_mismatch.sh`, `825_ha_mgmt_ip.sh` | JSON IP address info - enables SBR validation, noprefixroute detection, netmask mismatch |
| `ip -4 --json route` | `ip_route_json.txt` | `490_ip_route_metrics.sh` | JSON IPv4 routes - detects overlapping routes with metrics |

---

## List 2: Cluster-Level Weka CLI Commands

These commands produce cluster-wide data and only need to be run once (not per
host). They should be saved into `cluster/weka/`.

| Command | Destination Filename | TA Script(s) | What It Enables |
|---------|---------------------|---------------|-----------------|
| `weka version` | `weka_version_list.json` | `280_check_only_one_weka_version.sh`, `730_large_drives.sh`, `700_wekapp351707.sh` | List of ALL installed Weka versions (not just current) - detects leftover old versions |
| `weka version current` | `weka_version_current.txt` | `200_checkiommu.sh`, `370_version_specific_checks.sh`, `390_data_folder.sh`, `400_s3_using_etcd.sh`, many more | The currently active version string - needed by every version-specific check |
| `weka cluster container --output release --no-header` | `weka_container_releases.txt` | `280_check_only_one_weka_version.sh` | Per-container release versions - detects version inconsistency |
| `weka cluster client-target-version show` | `weka_client_target_version.txt` | `280_check_only_one_weka_version.sh` | Client target version - validates if non-default versions are still in use |
| `weka cluster host --leader --no-header --output id` | `weka_cluster_leader.txt` | `380_check_leader_is_running_on_drive_process.sh` | Cluster leader container ID - validates leader runs on a DRIVES host |
| `weka cluster host resources <ID>` | `weka_leader_host_resources.txt` | `380_check_leader_is_running_on_drive_process.sh` | Leader host resource roles - confirms DRIVES role on leader |
| `weka debug config show obsBuckets[*]._scarceMode` | `weka_obs_scarce_mode.txt` | `540_check_for_obs_in_scarce_mode.sh` | OBS scarce mode flag per bucket - detects tiering problems |
| `weka debug config show snapViews` | `weka_debug_snapviews.json` | `835_s2o_unmigrated.sh` | Snap2Obj snapView details - detects unmigrated downloaded filesystems |
| `weka debug config show nfsGaneshaConfig.maxOpenFDs` | `weka_nfs_max_fds.txt` | `885_nfsw_resources.sh` | NFS Ganesha max open FDs config |
| `weka debug config show nfsGaneshaConfig.customGlobalOptions` | `weka_nfs_custom_global_options.txt` | `885_nfsw_resources.sh` | NFS custom global options including RPC_Max_Connections |
| `weka debug config show sambaClusterInfo` | (already collected as `weka_smb_cluster_info.json`) | `755_wekapp424920_smbw_mask.sh` | Already present - no action needed |
| `weka debug override list-keys --output key,defaultValue` | `weka_debug_override_keys.json` | `850_heartbeat_gt_cluster_lease.sh` | Override key defaults - validates heartbeat_grace vs cluster_lease relationship |
| `weka debug net peers <process_id> --output inMTU,outMTU` (for each DRIVES process) | `weka_debug_net_peers_mtu.txt` | `785_asymmetric_mtu.sh` | Per-peer MTU values - detects asymmetric MTU between peers |
| `weka debug net ports <process_id>` (for each backend process) | `weka_debug_net_ports.txt` | `765_process_network_mode.sh` | Per-process network port info - validates DPDK/UDP port registrations |
| `weka debug manhole -s 1 network_get_dpdk_ports -P <port>` (per container) | `weka_dpdk_ports.txt` | `795_netmask_mismatch.sh` | DPDK port details including netmask, IP, device name - detects netmask mismatch |
| `weka debug manhole get_aggregated_cluster_status table_names="floatingIps"` | `weka_floating_ips_cluster.txt` | `855_nfsw_fips_sanity.sh` | Cluster-wide floating IP state table - detects stale/inconsistent FIPs |
| `weka debug manhole get_localstate table_names="floatingIps" -n <process_id>` | `weka_floating_ips_local.txt` | `855_nfsw_fips_sanity.sh` | Per-process local floating IP state - cross-validated against cluster state |
| `weka cluster process -F role=COMPUTE --output memory --no-header --raw-units` | `weka_compute_ram.txt` | `720_low_compute_ram_to_ssd.sh` | Total COMPUTE RAM - validates RAM-to-SSD ratio |
| `weka cluster drive --output size --sort size --raw-units --no-header` | `weka_drive_sizes.txt` | `730_large_drives.sh` | Drive sizes sorted - detects oversized drives for version |
| `weka cluster drive --output block --no-header` | `weka_drive_block_sizes.txt` | `920_nvme_bs.sh` | Drive block sizes - detects mixed block sizes across cluster |
| `weka cluster process -b -F role=<ROLE> -o netmode --no-header` (per role) | `weka_process_netmode.txt` | `765_process_network_mode.sh` | Per-role network mode - detects inconsistent DPDK/UDP modes |
| `weka cluster container -b -o container,cores,memory --no-header` | `weka_container_resources_summary.txt` | `935_container_resource_alloc.sh` | Per-container core/memory allocation - detects inconsistencies |
| `weka cluster container --output ips,machineIdentifier,hostname --no-header` | `weka_container_uuids.txt` | `030_dup_uuid_check.sh`, `775_dup_arp_check.sh` | Container UUIDs and IPs - detects duplicate UUIDs and ARP conflicts |
| `weka cluster bucket -o fillLevel --no-header` | `weka_bucket_fill_levels.txt` | `910_disparate_bucket_fill_level.sh` | Bucket fill levels - detects dangerous fill disparity |
| `weka cluster bucket --json -s -uptime` | `weka_bucket_uptime.json` | `520_bucket_and_process_uptime.sh` | Bucket uptime sorted - detects recent restarts |
| `weka cluster process --json -s -uptime` | `weka_process_uptime.json` | `520_bucket_and_process_uptime.sh` | Process uptime sorted - detects recent restarts |
| `weka fs -o name,usedSSD,availableSSD,stores --no-header -R` | `weka_fs_detailed.txt` | `700_wekapp351707.sh`, `890_hot_spare_capacity.sh` | FS SSD usage and stores - validates capacity for hot-spare scenarios |
| `weka status -J` (fields: hot_spare, stripe_data_drives) | (partially collected - need raw JSON for hot_spare/stripe fields) | `890_hot_spare_capacity.sh`, `430_nvme_used_capacity_vs_maximum.sh`, `790_raft_agents.sh` | Hot spare count, stripe data drives, bucket count - multiple capacity checks |
| `weka nfs interface-group assignment` | `weka_nfs_ig_assignment.txt` | `610_nfs_aliases_sbr.sh`, `855_nfsw_fips_sanity.sh`, `920_nfs_tcp_connections.sh` | NFS floating IP assignments per host - validates SBR and FIP health |
| `weka events --type-list LeaderIterationTooSlow --show-internal --no-header --start-time -1d` | `weka_events_leader_too_slow.txt` | `930_leader_iteration_too_slow.sh` | Recent LeaderIterationTooSlow events - performance diagnostic |
| `weka local exec -C smbw cat /tmp/smbw-config-fs/.smbw/tsmb.conf` | `tsmb_conf.txt` | `755_wekapp424920_smbw_mask.sh` | SMBW config file - detects missing force_create_mode/force_directory_mode |
| `weka local exec -C smbw /usr/local/bin/tsmb-server -v` | `tsmb_version.txt` | `755_wekapp424920_smbw_mask.sh` | TSMB server version - version-specific vulnerability check |
| `weka local exec -C ganesha -- dbus-send --print-reply --system --dest=org.ganesha.nfsd /org/ganesha/nfsd/ExportMgr org.ganesha.nfsd.exportstats.ShowCacheInode` | `nfs_ganesha_fds.txt` | `885_nfsw_resources.sh` | Ganesha file descriptor usage - detects FD exhaustion |
| `weka stats --show-internal --stat DRIVE_READ_RATIO_PER_SSD_READ --start-time -1h` | `weka_stats_drive_read_ratio.txt` | `530_high_drive_read_ssd_ratio.sh` | Drive-to-SSD read ratio - detects read amplification |
| `weka stats --show-internal --stat RDMA_NET_ERR_RETRY_EXCEEDED,RDMA_BINDING_FAILOVERS,RDMA_SERVER_BINDING_RESTARTS,RDMA_COMP_FAILURES,RDMA_WAIT_TIMEOUT --start-time -10m -Z --no-header` | `weka_stats_rdma_errors.txt` | `915_rdma_network_errors.sh` | RDMA error counters - detects hardware/network issues |
| `weka stats --show-internal --stat PUMPS_TXQ_FULL,BAD_RECV_CSUM,CORRUPT_PACKETS,RDMA_COMP_STATUSES --per-process --interval 600` | `weka_stats_outliers.txt` | `780_statistical_outlier.sh` | Internal stat outliers per process - flags abnormal per-container behavior |
| `weka stats --category object_storage --stat RESPONSE_COUNT_BAD_GATEWAY,RESPONSE_COUNT_GATEWAY_TIMEOUT,RESPONSE_COUNT_HTTP_VERSION_NOT_SUPPORTED,RESPONSE_COUNT_NOT_IMPLEMENTED,RESPONSE_COUNT_SERVER_ERROR,RESPONSE_COUNT_SERVICE_UNAVAILABLE --start-time -30m -Z --per-process` | `weka_stats_obs_errors.txt` | `945_obs_conn_check.sh` | OBS server error stats - detects S3/OBS connectivity issues |
| `weka fs tier s3 -o downloadBandwidth,uploadBandwidth,removeBandwidth,downloads,uploads,removals,maxUploadExtents,maxUploadSize --no-header` | `weka_obs_perf_config.txt` | `925_no_default_obs_configs.sh` | OBS performance tuning parameters - detects untuned default configs |

---

## Per-Host Weka Commands (run inside each host, saved to hosts/<hostname>/weka/)

| Command | Destination Filename | TA Script(s) | What It Enables |
|---------|---------------------|---------------|-----------------|
| `weka local resources -C <container> net --stable -J` (per container) | `weka_local_resources_net_<container>.json` | `260_compare_dpdk_gateways.sh`, `270_weka_local_resources_gateways.sh`, `460_ip_source-based_routing.sh`, `620_same_mtu_across_nics.sh`, `740_mlx_settings.sh`, `805_bonding_check.sh`, `865_infiniband_lid_mismatch.sh` | Per-container network device details with gateway, netmask, PCI ID - critical for SBR, MTU, bonding, IB analysis |
| `weka local resources -C <container> --stable` | `weka_local_resources_stable_<container>.txt` | `690_auto_core_in_mcb.sh`, `825_ha_mgmt_ip.sh` | Container resource config (stable) - detects auto-core allocation, management IP issues |
| `weka local resources -C <container> --stable -J` | `weka_local_resources_stable_<container>.json` | `875_cgroup_validation.sh` | JSON container resources (stable) - validates core_id assignments for cgroup checks |
| `weka local exec --container <protocol> mount -t wekafs` | `weka_protocol_mounts.txt` | `810_use_only_readcache_for_protocols.sh` | Protocol container wekafs mounts - detects writecache usage on protocols |

---

## Summary of Gaps by Category

### SELinux / Security (not collected at all)
- `getenforce`, `sestatus`, `/etc/selinux/config`, `mokutil --sb-state`

### IOMMU / Boot Config (not collected at all)
- `/proc/cmdline`, IOMMU sysfs entries

### Firewall (not collected at all)
- `iptables -L -v -n`, `iptables -L -n -t nat`, `iptables-save`, `firewalld` status

### Mount / Filesystem Config (not collected at all)
- `mount` output, `/etc/fstab`, `/etc/mtab`

### NVMe Details (not collected at all)
- `nvme id-ns` per namespace, `nvme list`

### Hugepages (not collected at all)
- `/sys/kernel/mm/hugepages/*/nr_hugepages`, Weka hugepage numa_maps

### Bonding (not collected at all)
- `/proc/net/bonding/*`, bonding sysfs attributes

### cgroup State (not collected at all)
- cgroup filesystem type, Weka cgroup cpuset, `/etc/wekaio/service.conf`

### RAID (not collected at all)
- `/proc/mdstat`, `mdadm --detail`

### CPU Features (partially via lscpu, missing /proc/cpuinfo detail)
- Full `/proc/cpuinfo`, SMT state, AES flag

### Network (partially collected - missing JSON forms and some data)
- `ip -j -o addr show`, `ip -4 --json route`, bonding info

### Weka Debug/Config Commands (many not collected)
- `weka debug config show` for various keys (obsBuckets scarceMode, snapViews, nfsGaneshaConfig)
- `weka debug override list-keys`
- `weka debug net peers` with MTU columns
- `weka debug net ports`
- `weka debug manhole` calls (floatingIps, DPDK ports)
- `weka local status` (cgroup info)
- Protocol container mounts

### Weka Stats (partially collected - missing specific diagnostic stats)
- RDMA error stats
- DRIVE_READ_RATIO_PER_SSD_READ
- OBS server error response stats
- PUMPS_TXQ_FULL, BAD_RECV_CSUM outlier stats

---

## Implementation Priority — What to Add First

### Phase 1: HIGH IMPACT (enables 8+ new log_analyzer checks)

These are the most common real-world misconfigurations caught by the TA tool.
Adding these commands to weka-log-collector would immediately unlock offline
analysis for the most frequently failing checks.

| Priority | Commands to Add | New Checks Enabled | Why |
|----------|----------------|-------------------|-----|
| **P1** | `mount`, `/etc/fstab`, `/etc/mtab` | `215_checktmpmount` (noexec), `630_opt_weka_mount`, `870_wekafs_netdev` | Multiple TA scripts depend on mount state; /tmp noexec is a common blocker |
| **P1** | `iptables -L -v -n`, `iptables-save`, `firewalld status` | `140_checkiptables`, `550_iptables_nats` | Firewall rules blocking Weka traffic is a top-5 installation issue |
| **P1** | `rpm -qa` / `dpkg -l`, `python3 --version` | `145_checkwekapackages` | Missing kernel-devel or elfutils blocks Weka agent start |
| **P1** | `nvme id-ns` per device, `nvme list` | `223_checknvmelba`, improved `220_checknvmebus` | Wrong NVMe LBA format causes silent performance degradation |
| **P1** | `ip -j -o addr show` | `510_noprefixroute`, `795_netmask_mismatch` | noprefixroute breaks floating IP failover (WEKAPP-298483) |
| **P2** | Bonding sysfs (`/sys/class/net/*/bonding/*`, `/proc/net/bonding/*`) | `015_mtu_bonding`, `805_bonding_check` | Bond MTU and hash policy issues affect HA setups |
| **P2** | `/proc/cmdline`, IOMMU sysfs | `200_checkiommu` | IOMMU breaks DPDK in Weka 4.1.2-4.2.2 |
| **P2** | `mokutil --sb-state`, `/sys/firmware/efi/` | `225_checksecureboot` | Secure Boot prevents Weka kernel module load |
| **P2** | `weka local resources net --stable -J` per container | `260_dpdk_gateways` (improved), `620_mtu` (improved), SBR checks | Most important missing per-host weka command — used by 7 TA scripts |

### Phase 2: MEDIUM IMPACT (enables 7+ new checks)

| Priority | Commands to Add | New Checks Enabled | Why |
|----------|----------------|-------------------|-----|
| **P3** | `/proc/mdstat`, `mdadm --detail` | `880_mdadm_devices` | Degraded RAID arrays block cluster operation |
| **P3** | `nmcli dev status`, `NM --print-config` | `670_nm_ignore_carrier` | NetworkManager carrier settings affect failover |
| **P3** | `/proc/net/if_inet6`, `ss -Hnt sport = :2049` | `885_nfsw_resources`, `920_nfs_tcp` | NFS FD/RPC limits and TCP connection count |
| **P3** | cgroup sysfs, `/etc/wekaio/service.conf` | `740_cgroups_v1`, `875_cgroup_validation` | cgroup misconfiguration is a growing issue with newer OS |
| **P3** | Hugepages sysfs, Weka numa_maps | `660_hugepages` (improved) | Hugepage NUMA imbalance causes latency spikes |
| **P3** | `weka local status` per host | `580_weka_version_everywhere`, cgroup info | Agent version mismatch and cgroup state |

### Phase 3: WEKA STATS AND DEBUG (enables deep diagnostics)

| Priority | Commands to Add | New Checks Enabled | Why |
|----------|----------------|-------------------|-----|
| **P4** | `weka stats` RDMA error counters | `915_rdma_network_errors` | RDMA errors indicate hardware/fabric issues |
| **P4** | `weka stats` DRIVE_READ_RATIO | `530_high_drive_read_ratio` | Read amplification diagnostics |
| **P4** | `weka stats` PUMPS_TXQ_FULL etc. | `780_statistical_outlier` | Per-process outlier detection |
| **P4** | `weka stats` OBS error responses | `945_obs_conn_check` | S3/OBS connectivity diagnostics |
| **P4** | `weka debug config show` various keys | `850_heartbeat`, improved OBS/NFS checks | Heartbeat vs cluster lease tuning |
| **P4** | `weka debug manhole` floatingIps | `855_nfsw_fips_sanity` | Stale floating IP detection |

### Live-Only Tests (28 scripts — cannot be collected)

These TA scripts require live cluster interaction and cannot work from bundles:
`010_ping`, `020_ssh`, `060_clockdiff`, `125_checkinternet`, `135_checkdns`,
`270_weka_local_resources_gw`, `400_s3_using_etcd`, `510_noprefixroute` (partial),
`530_high_drive_read_ratio` (needs stats), `570_does_weka_use_swap`,
`580_weka_version_everywhere`, `590_single_dns_entry`, `610_nfs_aliases_sbr`,
`650_firewall_check_quick`, `700_wekapp351707`, `780_statistical_outlier`,
`782_statistical_thresholds`, `795_netmask_mismatch` (partial),
`805_bonding_check` (partial), `850_heartbeat`, `855_nfsw_fips_sanity`,
`865_infiniband_lid_mismatch`, `915_rdma_network_errors`,
`920_nfs_tcp_connections`, `920_nvme_bs`, `945_obs_conn_check`

Some of these can become partially implementable if the collector adds the
corresponding `weka stats` / `weka debug` commands listed in Phase 3.

---

## Current Log Analyzer Coverage

**62 checks implemented** covering these TA scripts:
`030`, `105`, `110`, `115`, `120`, `130`, `150`, `155`, `160`, `180`, `185`,
`190`, `195`, `210`, `220`, `250`, `260`, `280`, `290`, `330`, `360`, `370`,
`380`, `420`, `430`, `440`, `460`, `470`, `500`, `520`, `540`, `560`, `620`,
`635`, `660`, `670`, `680`, `690`, `710`, `720`, `730`, `740`, `755`, `765`,
`775`, `785`, `790`, `810`, `815`, `825`, `835`, `845`, `890`, `900`, `910`,
`925`, `930`, `935` + cluster alerts, cloud status, events, failure domains,
systemd failed services, cross-node consistency.

---

## Notes

1. The collector already captures `sysctl -a` which covers `numa_balancing`,
   `rp_filter`, and other sysctl values that several TA scripts check individually.

2. The collector already captures `ip rule`, `ip route show table all`, and
   `ip neighbor` which cover some of the routing checks. The JSON forms
   (`ip -j -o addr show`, `ip -4 --json route`) would be more useful for
   programmatic analysis.

3. The collector already captures `ethtool` per interface, `lspci`, `lsblk`,
   `ofed_info`, `modinfo mlx5_core`, `mst status`, and `mlxconfig query`
   which cover many NIC/OFED checks.

4. The collector already captures `weka local resources -C <container> -J` for
   each container discovered via `weka local ps`. However, it does not capture
   the **net** sub-resource (`weka local resources -C <container> net --stable -J`)
   which many TA scripts need for gateway, PCI ID, and device name details.

5. The collector already captures `weka debug traces status` and
   `weka debug override list`, so those TA script data sources are covered.

6. Many TA scripts use `weka status` parsed via grep/awk to extract fields like
   `hot_spare`, `stripe_data_drives`, `Buckets` count. The collector captures
   `weka status -J` which contains all these fields, so those are technically
   covered if the JSON is parsed offline.

7. The **highest priority** additions for offline analysis would be:
   - `/etc/fstab` and `mount` output (multiple TA scripts depend on these)
   - `getenforce` / SELinux state
   - `iptables-save` (complete firewall audit)
   - `/proc/cmdline` (IOMMU, boot params)
   - NVMe namespace details (`nvme id-ns`, `nvme list`)
   - Hugepages sysfs + numa_maps
   - Bonding info
   - `weka local resources net --stable -J` per container
   - `weka debug config show` for key config paths
   - `weka local status` (agent version + cgroup info)
