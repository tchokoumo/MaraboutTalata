use std::collections::{HashMap, HashSet, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sysinfo::{Disks, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind, Users};

use crate::agent_watcher::{
    self, AgentWatchConfig, AgentWatchSnapshot, AgentWatcher, ProcessSample,
};

#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;

const DISK_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const MAX_COMMAND_LENGTH: usize = 2_048;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemSnapshot {
    captured_at_ms: u128,
    cpu: CpuInfo,
    memory: MemoryInfo,
    swap: SwapInfo,
    disks: Vec<DiskInfo>,
    processes: Vec<ProcessInfo>,
    agents: AgentWatchSnapshot,
    system: SystemInfo,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CpuInfo {
    usage_percent: f32,
    cores: Vec<CpuCoreInfo>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CpuCoreInfo {
    name: String,
    usage_percent: f32,
    frequency_mhz: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MemoryInfo {
    total_bytes: u64,
    used_bytes: u64,
    available_bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SwapInfo {
    total_bytes: u64,
    used_bytes: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DiskInfo {
    name: String,
    mount_point: String,
    file_system: String,
    total_bytes: u64,
    used_bytes: u64,
    available_bytes: u64,
    removable: bool,
    technical: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessInfo {
    pid: usize,
    parent_pid: Option<usize>,
    name: String,
    user: String,
    cpu_percent: f32,
    memory_bytes: u64,
    run_time_seconds: u64,
    start_time_seconds: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessCommand {
    command: String,
    redacted: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemInfo {
    distribution: String,
    distribution_id: String,
    kernel: Option<String>,
    uptime_seconds: u64,
}

pub struct MonitorState {
    monitor: Mutex<Monitor>,
}

struct Monitor {
    system: System,
    disks: Disks,
    disk_info_cache: Vec<DiskInfo>,
    users: Users,
    process_metadata: HashMap<usize, CachedProcessMetadata>,
    agent_watcher: AgentWatcher,
    last_disk_refresh: Instant,
}

struct CachedProcessMetadata {
    signature: u64,
    name: String,
    user: String,
    command: String,
    command_redacted: bool,
}

impl MonitorState {
    pub fn new() -> Self {
        let mut system = System::new();
        system.refresh_cpu_all();
        system.refresh_memory();
        system.refresh_processes_specifics(ProcessesToUpdate::All, true, process_refresh_kind());
        let disks = Disks::new_with_refreshed_list();
        let disk_info_cache = collect_disk_info(&disks);

        Self {
            monitor: Mutex::new(Monitor {
                system,
                disks,
                disk_info_cache,
                users: Users::new_with_refreshed_list(),
                process_metadata: HashMap::new(),
                agent_watcher: AgentWatcher::new(),
                last_disk_refresh: Instant::now(),
            }),
        }
    }

    pub fn snapshot(&self) -> Result<SystemSnapshot, String> {
        let mut monitor = self.monitor.lock().map_err(|_| {
            "Le moniteur système est indisponible après une erreur interne.".to_owned()
        })?;

        monitor.system.refresh_cpu_usage();
        monitor.system.refresh_memory();
        monitor.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            process_refresh_kind(),
        );

        if monitor.last_disk_refresh.elapsed() >= DISK_REFRESH_INTERVAL {
            monitor.disks.refresh(true);
            monitor.disk_info_cache = collect_disk_info(&monitor.disks);
            monitor.last_disk_refresh = Instant::now();
        }

        let Monitor {
            system,
            disk_info_cache,
            users,
            process_metadata,
            agent_watcher,
            ..
        } = &mut *monitor;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or_default();

        let cpu = CpuInfo {
            usage_percent: percentage(system.global_cpu_usage()).clamp(0.0, 100.0),
            cores: system
                .cpus()
                .iter()
                .map(|cpu| CpuCoreInfo {
                    name: cpu.name().to_owned(),
                    usage_percent: percentage(cpu.cpu_usage()).clamp(0.0, 100.0),
                    frequency_mhz: cpu.frequency(),
                })
                .collect(),
        };

        let memory = MemoryInfo {
            total_bytes: system.total_memory(),
            used_bytes: system.used_memory(),
            available_bytes: system.available_memory(),
        };

        let swap = SwapInfo {
            total_bytes: system.total_swap(),
            used_bytes: system.used_swap(),
        };

        let disks = disk_info_cache.clone();

        let mut live_processes = HashSet::with_capacity(system.processes().len());
        let processes = {
            let metadata_cache = process_metadata;
            let mut processes = Vec::with_capacity(system.processes().len());
            let mut agent_processes = Vec::with_capacity(system.processes().len());

            for (pid, process) in system.processes() {
                let pid = pid.as_u32() as usize;
                live_processes.insert(pid);
                let name = process.name().to_string_lossy().into_owned();
                let argv_hint = agent_watcher::candidate_hint(
                    &name,
                    process.exe(),
                    process.cmd().iter().map(|part| part.as_os_str()),
                );
                let signature = process_signature(process, argv_hint);

                if !metadata_cache
                    .get(&pid)
                    .is_some_and(|metadata| metadata.signature == signature)
                {
                    let user = process
                        .user_id()
                        .map(|user_id| {
                            users
                                .get_user_by_id(user_id)
                                .map(|user| user.name().to_owned())
                                .unwrap_or_else(|| format!("{user_id:?}"))
                        })
                        .unwrap_or_else(|| "Inconnu".to_owned());

                    metadata_cache.insert(
                        pid,
                        cached_process_metadata(signature, name, user, process.cmd(), argv_hint),
                    );
                }

                let metadata = metadata_cache
                    .get(&pid)
                    .expect("process metadata is populated before use");
                agent_processes.push(ProcessSample {
                    pid,
                    parent_pid: process.parent().map(|parent| parent.as_u32() as usize),
                    name: metadata.name.clone(),
                    cpu_percent: percentage(process.cpu_usage()),
                    memory_bytes: process.memory(),
                    run_time_seconds: process.run_time(),
                    start_time_seconds: process.start_time(),
                    candidate_hint: argv_hint,
                });
                processes.push(ProcessInfo {
                    pid,
                    parent_pid: process.parent().map(|parent| parent.as_u32() as usize),
                    name: metadata.name.clone(),
                    user: metadata.user.clone(),
                    cpu_percent: percentage(process.cpu_usage()),
                    memory_bytes: process.memory(),
                    run_time_seconds: process.run_time(),
                    start_time_seconds: process.start_time(),
                });
            }

            metadata_cache.retain(|pid, _| live_processes.contains(pid));
            let agent_snapshot = agent_watcher.sample(&agent_processes, now as u64);
            (processes, agent_snapshot)
        };
        let (processes, agents) = processes;

        let distribution = System::long_os_version()
            .or_else(System::name)
            .unwrap_or_else(|| "Distribution inconnue".to_owned());

        Ok(SystemSnapshot {
            captured_at_ms: now,
            cpu,
            memory,
            swap,
            disks,
            processes,
            agents,
            system: SystemInfo {
                distribution,
                distribution_id: System::distribution_id(),
                kernel: System::kernel_version(),
                uptime_seconds: System::uptime(),
            },
        })
    }

    pub fn process_command(&self, pid: usize) -> Result<Option<ProcessCommand>, String> {
        let monitor = self.monitor.lock().map_err(|_| {
            "Le moniteur système est indisponible après une erreur interne.".to_owned()
        })?;
        Ok(monitor
            .process_metadata
            .get(&pid)
            .map(|metadata| ProcessCommand {
                command: metadata.command.clone(),
                redacted: metadata.command_redacted,
            }))
    }

    pub fn set_agent_watch_config(
        &self,
        config: AgentWatchConfig,
    ) -> Result<AgentWatchConfig, String> {
        let mut monitor = self.monitor.lock().map_err(|_| {
            "Le moniteur système est indisponible après une erreur interne.".to_owned()
        })?;
        monitor.agent_watcher.set_config(config)
    }
}

fn process_refresh_kind() -> ProcessRefreshKind {
    ProcessRefreshKind::nothing()
        .with_cpu()
        .with_memory()
        .with_user(UpdateKind::OnlyIfNotSet)
        .with_cmd(UpdateKind::OnlyIfNotSet)
        .without_tasks()
}

fn percentage(value: f32) -> f32 {
    if value.is_finite() {
        value.max(0.0)
    } else {
        0.0
    }
}

fn collect_disk_info(disks: &Disks) -> Vec<DiskInfo> {
    disks
        .list()
        .iter()
        .map(|disk| {
            let total_bytes = disk.total_space();
            let available_bytes = disk.available_space();
            let free_bytes = free_space_bytes(disk.mount_point()).unwrap_or(available_bytes);
            DiskInfo {
                name: disk.name().to_string_lossy().into_owned(),
                mount_point: disk.mount_point().to_string_lossy().into_owned(),
                file_system: disk.file_system().to_string_lossy().into_owned(),
                total_bytes,
                used_bytes: used_space(total_bytes, free_bytes),
                available_bytes,
                removable: disk.is_removable(),
                technical: is_technical_mount(
                    &disk.mount_point().to_string_lossy(),
                    &disk.file_system().to_string_lossy(),
                    &disk.name().to_string_lossy(),
                ),
            }
        })
        .collect()
}

fn used_space(total_bytes: u64, free_bytes: u64) -> u64 {
    total_bytes.saturating_sub(free_bytes)
}

#[cfg(target_os = "linux")]
fn free_space_bytes(mount_point: &Path) -> Option<u64> {
    let path = CString::new(mount_point.as_os_str().as_bytes()).ok()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return None;
    }

    let stat = unsafe { stat.assume_init() };
    let block_size = if stat.f_frsize == 0 {
        stat.f_bsize as u64
    } else {
        stat.f_frsize as u64
    };
    if block_size == 0 {
        return None;
    }
    Some(block_size.saturating_mul(stat.f_bfree as u64))
}

#[cfg(not(target_os = "linux"))]
fn free_space_bytes(_mount_point: &Path) -> Option<u64> {
    None
}

fn process_signature(process: &sysinfo::Process, agent_candidate: bool) -> u64 {
    let mut hasher = DefaultHasher::new();
    process.start_time().hash(&mut hasher);
    process.name().hash(&mut hasher);
    process.exe().hash(&mut hasher);
    process.user_id().hash(&mut hasher);
    agent_candidate.hash(&mut hasher);
    if !agent_candidate {
        process.cmd().hash(&mut hasher);
    }
    hasher.finish()
}

fn process_command(
    args: &[std::ffi::OsString],
    process_name: &str,
    agent_candidate: bool,
) -> (String, bool) {
    if agent_candidate {
        return redact_agent_command(args, process_name);
    }
    if args.is_empty() {
        return (process_name.to_owned(), false);
    }

    let args = args
        .iter()
        .map(|part| part.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    sanitize_command_args(&args, process_name)
}

fn cached_process_metadata(
    signature: u64,
    name: String,
    user: String,
    args: &[std::ffi::OsString],
    agent_candidate: bool,
) -> CachedProcessMetadata {
    let (command, command_redacted) = process_command(args, &name, agent_candidate);
    CachedProcessMetadata {
        signature,
        name,
        user,
        command,
        command_redacted,
    }
}

fn redact_agent_command(args: &[std::ffi::OsString], process_name: &str) -> (String, bool) {
    (process_name.to_owned(), !args.is_empty())
}

fn sanitize_command_args(args: &[String], process_name: &str) -> (String, bool) {
    let mut sanitized = Vec::with_capacity(args.len());
    let mut redact_next = false;
    let mut redacted = false;

    for value in args {
        if redact_next {
            sanitized.push(REDACTED.to_owned());
            redact_next = false;
            redacted = true;
            continue;
        }

        if let Some((key, _)) = value.split_once('=') {
            if is_sensitive_key(key) {
                sanitized.push(format!("{key}={REDACTED}"));
                redacted = true;
                continue;
            }
        }

        if value == "-p" || (value.starts_with('-') && is_sensitive_key(value)) {
            sanitized.push(value.to_owned());
            redact_next = true;
            continue;
        }

        let (value, value_redacted) = redact_embedded_secret(value);
        redacted |= value_redacted;
        sanitized.push(value);
    }

    let command = if sanitized.is_empty() {
        process_name.to_owned()
    } else {
        sanitized.join(" ")
    };
    (truncate_chars(command, MAX_COMMAND_LENGTH), redacted)
}

const REDACTED: &str = "[masqué]";

fn is_sensitive_key(value: &str) -> bool {
    let key = value
        .trim_start_matches('-')
        .split_once('=')
        .map_or(value.trim_start_matches('-'), |(key, _)| key);
    let normalized: String = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();

    [
        "password",
        "passwd",
        "token",
        "secret",
        "apikey",
        "accesskey",
        "privatekey",
        "clientsecret",
        "credential",
        "authorization",
        "bearer",
        "cookie",
        "sessionid",
        "databaseurl",
    ]
    .iter()
    .any(|sensitive| normalized.contains(sensitive))
}

fn redact_embedded_secret(value: &str) -> (String, bool) {
    let lowercase = value.to_ascii_lowercase();
    if let Some(position) = lowercase.find("bearer ") {
        return (
            format!("{}{}", &value[..position + "bearer ".len()], REDACTED),
            true,
        );
    }

    let mut sanitized = value.to_owned();
    let mut redacted = false;
    for header in [
        "cookie:",
        "set-cookie:",
        "authorization:",
        "proxy-authorization:",
    ] {
        if let Some(position) = lowercase.find(header) {
            let end = position + header.len();
            sanitized = format!("{} {}", &value[..end], REDACTED);
            redacted = true;
            break;
        }
    }

    if !redacted {
        if let Some((password_start, password_end)) = uri_password_range(value) {
            sanitized = format!(
                "{}{}{}",
                &value[..password_start],
                REDACTED,
                &value[password_end..]
            );
            redacted = true;
        }
    }

    let (sanitized, query_redacted) = redact_sensitive_query(&sanitized);
    (sanitized, redacted || query_redacted)
}

fn uri_password_range(value: &str) -> Option<(usize, usize)> {
    let scheme_end = value.find("://")?;
    let authority_start = scheme_end + 3;
    let authority_end = value[authority_start..]
        .find(['/', '?', '#'])
        .map_or(value.len(), |offset| authority_start + offset);
    let authority = &value[authority_start..authority_end];
    let at = authority.rfind('@')?;
    let user_info = &authority[..at];
    let password_separator = user_info.find(':')?;

    Some((
        authority_start + password_separator + 1,
        authority_start + at,
    ))
}

fn redact_sensitive_query(value: &str) -> (String, bool) {
    let mut sanitized = String::with_capacity(value.len());
    let mut rest = value;
    let mut redacted = false;

    while let Some(separator) = rest.find(['?', '&']) {
        sanitized.push_str(&rest[..=separator]);
        rest = &rest[separator + 1..];
        let pair_end = rest
            .find(|character| matches!(character, '&' | '#' | ' ' | '\t' | '"' | '\''))
            .unwrap_or(rest.len());
        let pair = &rest[..pair_end];
        if let Some((key, _)) = pair.split_once('=')
            && is_sensitive_key(key)
        {
            sanitized.push_str(key);
            sanitized.push('=');
            sanitized.push_str(REDACTED);
            redacted = true;
        } else {
            sanitized.push_str(pair);
        }
        rest = &rest[pair_end..];
    }

    sanitized.push_str(rest);
    (sanitized, redacted)
}

fn is_technical_mount(mount_point: &str, file_system: &str, source: &str) -> bool {
    let file_system = file_system.to_ascii_lowercase();
    let source = source.to_ascii_lowercase();
    let mount_point = Path::new(mount_point);

    const TECHNICAL_FILE_SYSTEMS: &[&str] = &[
        "autofs",
        "binfmt_misc",
        "bpf",
        "cgroup",
        "cgroup2",
        "configfs",
        "debugfs",
        "devpts",
        "devtmpfs",
        "efivarfs",
        "fusectl",
        "hugetlbfs",
        "mqueue",
        "nsfs",
        "overlay",
        "proc",
        "pstore",
        "ramfs",
        "rpc_pipefs",
        "securityfs",
        "squashfs",
        "sysfs",
        "tmpfs",
        "tracefs",
    ];

    if TECHNICAL_FILE_SYSTEMS.contains(&file_system.as_str())
        || file_system.contains("overlay")
        || source == "overlay"
        || source.starts_with("overlay:")
    {
        return true;
    }

    ["/proc", "/sys", "/dev", "/var/lib/docker/overlay2"]
        .iter()
        .any(|path| mount_point == Path::new(path) || mount_point.starts_with(path))
}

fn truncate_chars(value: String, max_chars: usize) -> String {
    let mut chars = value.chars();
    let shortened: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{shortened}…")
    } else {
        shortened
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MonitorState, cached_process_metadata, is_technical_mount, redact_agent_command,
        sanitize_command_args, truncate_chars,
    };
    use crate::agent_watcher;
    use std::ffi::OsString;

    #[test]
    fn classifies_virtual_and_docker_overlay_mounts_as_technical() {
        assert!(is_technical_mount("/proc", "proc", "proc"));
        assert!(is_technical_mount("/sys/fs/cgroup", "cgroup2", "cgroup"));
        assert!(is_technical_mount("/", "overlay", "overlay"));
        assert!(is_technical_mount(
            "/var/lib/docker/overlay2/abc123/merged",
            "ext4",
            "/dev/sda1"
        ));
    }

    #[test]
    fn keeps_real_filesystems_and_named_docker_volumes_visible() {
        assert!(!is_technical_mount("/", "ext4", "/dev/nvme0n1p2"));
        assert!(!is_technical_mount("/home", "xfs", "/dev/sdb1"));
        assert!(!is_technical_mount(
            "/var/lib/docker/volumes/app-data/_data",
            "ext4",
            "/dev/sda1"
        ));
    }

    #[test]
    fn disk_usage_excludes_reserved_free_blocks() {
        let total_bytes = 1_000;
        let free_bytes = 700;
        let available_bytes = 600;

        let used_bytes = super::used_space(total_bytes, free_bytes);
        assert_eq!(used_bytes, 300);
        assert_eq!(total_bytes - used_bytes - available_bytes, 100);
    }

    #[test]
    fn masks_common_secret_arguments_and_leaves_safe_arguments_intact() {
        let args = [
            "service".to_owned(),
            "--api-token".to_owned(),
            "secret-token-value".to_owned(),
            "DATABASE_URL=postgres://alice:db-secret@localhost/app".to_owned(),
            "--url=https://service.test/path?access_token=query-secret&safe=yes".to_owned(),
            "--config".to_owned(),
            "/etc/service/config.toml".to_owned(),
            "Authorization: Bearer access-token-value".to_owned(),
            "--header=Cookie: sessionid=cookie-secret".to_owned(),
        ];

        let (command, redacted) = sanitize_command_args(&args, "service");
        assert!(redacted);
        assert!(command.contains("--api-token [masqué]"));
        assert!(command.contains("DATABASE_URL=[masqué]"));
        assert!(command.contains("access_token=[masqué]&safe=yes"));
        assert!(command.contains("--config /etc/service/config.toml"));
        assert!(command.contains("Authorization: Bearer [masqué]"));
        assert!(command.contains("Cookie: [masqué]"));
        assert!(!command.contains("secret-token-value"));
        assert!(!command.contains("db-secret"));
        assert!(!command.contains("access-token-value"));
        assert!(!command.contains("query-secret"));
        assert!(!command.contains("cookie-secret"));
    }

    #[test]
    fn hides_all_arguments_for_agent_process_candidates() {
        let args = [
            OsString::from("claude"),
            OsString::from("--prompt"),
            OsString::from("private conversation text"),
        ];

        let (command, redacted) = redact_agent_command(&args, "claude");

        assert_eq!(command, "claude");
        assert!(redacted);
        assert!(!command.contains("private conversation text"));
    }

    #[test]
    fn agent_arguments_stay_private_through_cache_api_and_frontend_snapshot() {
        let monitor = MonitorState::new();
        let pid = std::process::id() as usize;
        let secret = "T002_PRIVATE_PROMPT_CONTENT_7b81";
        let args = [
            OsString::from("claude"),
            OsString::from("--prompt"),
            OsString::from(secret),
        ];
        let candidate =
            agent_watcher::candidate_hint("claude", None, args.iter().map(OsString::as_os_str));
        assert!(candidate);

        monitor
            .monitor
            .lock()
            .expect("monitor lock should be available")
            .process_metadata
            .insert(
                pid,
                cached_process_metadata(
                    1,
                    "claude".to_owned(),
                    "test-user".to_owned(),
                    &args,
                    candidate,
                ),
            );

        let detail = monitor
            .process_command(pid)
            .expect("Tauri process-command route should succeed")
            .expect("cached process details should exist");
        assert_eq!(detail.command, "claude");
        assert!(detail.redacted);
        let detail_json =
            serde_json::to_string(&detail).expect("detail should serialize for Tauri");
        assert!(!detail_json.contains(secret));

        let snapshot = monitor
            .snapshot()
            .expect("snapshot collection should succeed");
        let snapshot_json =
            serde_json::to_string(&snapshot).expect("snapshot should serialize for Tauri");
        assert!(!snapshot_json.contains(secret));
        assert!(snapshot_json.contains("\"agents\""));
        assert!(!snapshot_json.contains("\"command\""));
    }

    #[test]
    fn truncates_commands_by_characters_without_splitting_utf8() {
        assert_eq!(truncate_chars("aé🙂b".to_owned(), 3), "aé🙂…");
        assert_eq!(truncate_chars("court".to_owned(), 10), "court");
    }

    #[test]
    fn snapshot_contains_real_host_resources_and_processes() {
        let snapshot = MonitorState::new()
            .snapshot()
            .expect("snapshot should be readable");

        assert!(snapshot.captured_at_ms > 0);
        assert!(
            snapshot.memory.total_bytes > 0,
            "host RAM total should be available"
        );
        assert!(
            !snapshot.cpu.cores.is_empty(),
            "host CPU cores should be available"
        );
        assert!(snapshot.cpu.usage_percent.is_finite());
        assert!((0.0..=100.0).contains(&snapshot.cpu.usage_percent));
        assert!(
            snapshot
                .cpu
                .cores
                .iter()
                .all(|core| core.usage_percent.is_finite()
                    && (0.0..=100.0).contains(&core.usage_percent))
        );
        assert_eq!(
            snapshot.memory.used_bytes + snapshot.memory.available_bytes,
            snapshot.memory.total_bytes,
            "RAM used and available should reconcile to total"
        );
        assert!(snapshot.swap.used_bytes <= snapshot.swap.total_bytes);
        assert!(snapshot.disks.iter().all(|disk| {
            disk.available_bytes <= disk.total_bytes
                && disk.used_bytes <= disk.total_bytes - disk.available_bytes
        }));
        assert!(
            !snapshot.processes.is_empty(),
            "at least this test process should be visible"
        );
        assert!(
            snapshot
                .processes
                .iter()
                .all(|process| !process.user.is_empty() && process.cpu_percent.is_finite())
        );
        assert!(!snapshot.system.distribution.is_empty());
        assert!(snapshot.system.uptime_seconds > 0);
        let serialized =
            serde_json::to_value(&snapshot).expect("snapshot should serialize for Tauri");
        assert!(serialized["processes"][0].get("command").is_none());
    }

    #[test]
    fn cpu_readings_remain_valid_after_a_sample_interval() {
        let monitor = MonitorState::new();
        let first = monitor.snapshot().expect("first sample should be readable");
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        let second = monitor
            .snapshot()
            .expect("second sample should be readable");

        for sample in [first, second] {
            assert!(sample.cpu.usage_percent.is_finite());
            assert!((0.0..=100.0).contains(&sample.cpu.usage_percent));
        }
    }
}
