use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const MAX_CMDLINE_ARG_BYTES: usize = 4 * 1024;
const MAX_CMDLINE_READ_BYTES: usize = 2 * (MAX_CMDLINE_ARG_BYTES + 1);
const MAX_HISTORY_SAMPLES: usize = 240;
const MAX_TRACKED_PROCESSES: usize = 512;
const MAX_RETAINED_SESSIONS: usize = 64;
const RETAINED_SESSION_MS: u64 = 4 * 60 * 60 * 1_000;
const HISTORY_RETENTION_MS: u64 = 60 * 60 * 1_000;

#[derive(Clone, Debug)]
pub struct ProcessSample {
    pub pid: usize,
    pub parent_pid: Option<usize>,
    pub name: String,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub run_time_seconds: u64,
    pub start_time_seconds: u64,
    pub candidate_hint: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentWatchConfig {
    pub high_cpu_percent: f32,
    pub high_cpu_seconds: u64,
    pub high_memory_mib: u64,
    pub high_memory_seconds: u64,
    pub memory_growth_mib: u64,
    pub memory_growth_window_seconds: u64,
    pub long_runtime_hours: u64,
    pub rapid_children_count: usize,
    pub rapid_children_window_seconds: u64,
}

impl Default for AgentWatchConfig {
    fn default() -> Self {
        Self {
            high_cpu_percent: 85.0,
            high_cpu_seconds: 45,
            high_memory_mib: 1_536,
            high_memory_seconds: 120,
            memory_growth_mib: 256,
            memory_growth_window_seconds: 180,
            long_runtime_hours: 8,
            rapid_children_count: 12,
            rapid_children_window_seconds: 60,
        }
    }
}

impl AgentWatchConfig {
    pub fn validate(self) -> Result<Self, String> {
        let valid = self.high_cpu_percent.is_finite()
            && (10.0..=100.0).contains(&self.high_cpu_percent)
            && (10..=600).contains(&self.high_cpu_seconds)
            && (128..=32_768).contains(&self.high_memory_mib)
            && (30..=3_600).contains(&self.high_memory_seconds)
            && (32..=8_192).contains(&self.memory_growth_mib)
            && (30..=1_800).contains(&self.memory_growth_window_seconds)
            && (1..=168).contains(&self.long_runtime_hours)
            && (3..=200).contains(&self.rapid_children_count)
            && (15..=1_800).contains(&self.rapid_children_window_seconds);

        if valid {
            Ok(self)
        } else {
            Err("Un ou plusieurs seuils sont hors des limites autorisées.".to_owned())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    Codex,
    ClaudeCode,
}

impl AgentKind {
    fn display_name(self) -> &'static str {
        match self {
            Self::Codex => "Codex CLI",
            Self::ClaudeCode => "Claude Code",
        }
    }

    fn slug(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude_code",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentWatchSnapshot {
    pub sessions: Vec<AgentSession>,
    pub coverage: AgentCoverage,
    pub config: AgentWatchConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCoverage {
    pub candidate_processes: usize,
    pub detected_processes: usize,
    pub unreadable_candidates: usize,
    pub restricted: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSession {
    pub id: String,
    pub agent: AgentKind,
    pub agent_name: String,
    pub root_pid: usize,
    pub root_start_time_seconds: u64,
    pub confidence: Confidence,
    pub provenance: Vec<String>,
    pub classification_evidence: Vec<String>,
    pub project_name: String,
    pub project_path: Option<String>,
    pub process_count: usize,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub run_time_seconds: u64,
    pub process_group_id: Option<usize>,
    pub linux_session_id: Option<usize>,
    pub detached_processes: usize,
    pub history_ready: bool,
    pub tree: Vec<AgentProcessNode>,
    pub alerts: Vec<AgentAlert>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentProcessNode {
    pub identity: String,
    pub pid: usize,
    pub parent_pid: Option<usize>,
    pub start_time_seconds: u64,
    pub start_time_ticks: Option<u64>,
    pub name: String,
    pub process_type: String,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub run_time_seconds: u64,
    pub working_directory: Option<String>,
    pub state: Option<String>,
    pub process_group_id: Option<usize>,
    pub linux_session_id: Option<usize>,
    pub detached: bool,
    pub children: Vec<AgentProcessNode>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentAlert {
    pub id: String,
    pub pid: usize,
    pub process_name: String,
    pub classification: AlertClassification,
    pub category: String,
    pub title: String,
    pub message: String,
    pub evidence: Vec<String>,
    pub first_observed_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertClassification {
    Fact,
    Heuristic,
    Insufficient,
}

pub struct AgentWatcher {
    config: AgentWatchConfig,
    history: HashMap<ProcessIdentity, VecDeque<ResourceSample>>,
    attribution: HashMap<ProcessIdentity, HistoricalAttribution>,
    retained_sessions: HashMap<String, HistoricalSession>,
    previous_parent: HashMap<ProcessIdentity, Option<ProcessIdentity>>,
    previous_alerts: HashMap<AlertKey, AlertState>,
    first_seen: HashMap<ProcessIdentity, (String, u64)>,
}

impl AgentWatcher {
    pub fn new() -> Self {
        Self {
            config: AgentWatchConfig::default(),
            history: HashMap::new(),
            attribution: HashMap::new(),
            retained_sessions: HashMap::new(),
            previous_parent: HashMap::new(),
            previous_alerts: HashMap::new(),
            first_seen: HashMap::new(),
        }
    }

    pub fn set_config(&mut self, config: AgentWatchConfig) -> Result<AgentWatchConfig, String> {
        self.config = config.validate()?;
        Ok(self.config)
    }

    pub fn sample(
        &mut self,
        processes: &[ProcessSample],
        captured_at_ms: u64,
    ) -> AgentWatchSnapshot {
        #[cfg(target_os = "linux")]
        let mut proc_cache = HashMap::<usize, ProcMetadata>::new();
        #[cfg(target_os = "linux")]
        let mut candidate_processes = 0;
        #[cfg(target_os = "linux")]
        let mut unreadable_candidates = 0;
        #[cfg(target_os = "linux")]
        let mut detections = HashMap::<usize, Detection>::new();

        #[cfg(target_os = "linux")]
        for process in processes.iter().filter(|process| process.candidate_hint) {
            candidate_processes += 1;
            match read_proc_metadata(process.pid) {
                Some(metadata) => {
                    match read_and_detect_proc(process.pid, &process.name, &metadata) {
                        Ok(Some(detection)) => {
                            detections.insert(process.pid, detection);
                            if metadata.permissions_limited {
                                unreadable_candidates += 1;
                            }
                        }
                        Ok(None) => {
                            if metadata.permissions_limited {
                                unreadable_candidates += 1;
                            }
                        }
                        Err(ProcAccessError::PermissionDenied | ProcAccessError::Other) => {
                            unreadable_candidates += 1;
                        }
                        Err(ProcAccessError::Vanished) => {}
                    }
                    proc_cache.insert(process.pid, metadata);
                }
                None => unreadable_candidates += 1,
            }
        }

        #[cfg(not(target_os = "linux"))]
        let (candidate_processes, unreadable_candidates, detections) = (0, 0, HashMap::new());

        let process_by_pid: HashMap<usize, &ProcessSample> = processes
            .iter()
            .map(|process| (process.pid, process))
            .collect();
        let mut detected_roots = Vec::<DetectedRoot>::new();
        for (pid, detection) in detections.iter() {
            let Some(process) = process_by_pid.get(pid) else {
                continue;
            };
            let metadata = proc_cache.get(pid);
            let process_group_id = metadata.and_then(|value| value.stat.as_ref()?.process_group_id);
            let linux_session_id = metadata.and_then(|value| value.stat.as_ref()?.session_id);
            let mut provenance = detection.provenance.clone();
            provenance.push("T001 : instantané des processus sysinfo".to_owned());
            let mut evidence = detection.evidence.clone();
            evidence.push(format!(
                "Filiation observée : PID {} avec PPID {}.",
                process.pid,
                process
                    .parent_pid
                    .map_or_else(|| "inconnu".to_owned(), |pid| pid.to_string())
            ));
            if metadata
                .and_then(|value| value.working_directory.as_ref())
                .is_some()
            {
                provenance.push("/proc/<pid>/cwd".to_owned());
                evidence.push("Répertoire de travail Linux accessible.".to_owned());
            }
            if let Some(stat) = metadata.and_then(|value| value.stat.as_ref()) {
                provenance.push("/proc/<pid>/stat".to_owned());
                evidence.push(format!(
                    "Groupe de processus : {} ; session Linux : {}.",
                    stat.process_group_id
                        .map_or_else(|| "inconnue".to_owned(), |value| value.to_string()),
                    stat.session_id
                        .map_or_else(|| "inconnue".to_owned(), |value| value.to_string())
                ));
            }
            detected_roots.push(DetectedRoot {
                identity: ProcessIdentity::from_sample(
                    process,
                    metadata.and_then(|value| value.stat.as_ref()?.start_time_ticks),
                ),
                kind: detection.kind,
                confidence: detection.confidence,
                provenance,
                evidence,
                working_directory: metadata.and_then(|value| value.working_directory.clone()),
                process_group_id,
                linux_session_id,
            });
        }

        detected_roots.sort_by_key(|root| {
            (
                root.kind.slug(),
                root.identity.pid,
                root.identity.start_time_seconds,
            )
        });

        let mut session_roots = Vec::<SessionRoots>::new();
        for root in detected_roots {
            if let Some(existing) = session_roots.iter_mut().find(|session| {
                session.kind == root.kind
                    && root.process_group_id.is_some()
                    && root.linux_session_id.is_some()
                    && session.process_group_id == root.process_group_id
                    && session.linux_session_id == root.linux_session_id
            }) {
                existing.roots.push(root.identity.pid);
                existing.provenance.extend(root.provenance);
                existing.classification_evidence.extend(root.evidence);
                existing.confidence = max_confidence(existing.confidence, root.confidence);
                continue;
            }

            let id = format!(
                "{}:{}:{}",
                root.kind.slug(),
                root.identity.pid,
                root.identity.start_time_seconds
            );
            session_roots.push(SessionRoots {
                id,
                kind: root.kind,
                root_pid: root.identity.pid,
                root_start_time_seconds: root.identity.start_time_seconds,
                confidence: root.confidence,
                provenance: root.provenance,
                classification_evidence: root.evidence,
                roots: vec![root.identity.pid],
                root_working_directory: root.working_directory,
                process_group_id: root.process_group_id,
                linux_session_id: root.linux_session_id,
            });
        }

        let mut children_by_parent = HashMap::<usize, Vec<usize>>::new();
        for process in processes {
            if let Some(parent_pid) = process.parent_pid {
                children_by_parent
                    .entry(parent_pid)
                    .or_default()
                    .push(process.pid);
            }
        }
        for children in children_by_parent.values_mut() {
            children.sort_unstable();
        }

        let mut current_owner = HashMap::<usize, String>::new();
        for session in &session_roots {
            let mut visited = HashSet::new();
            for root_pid in &session.roots {
                collect_descendants(
                    *root_pid,
                    &children_by_parent,
                    &process_by_pid,
                    &mut visited,
                );
            }
            for pid in visited {
                current_owner
                    .entry(pid)
                    .or_insert_with(|| session.id.clone());
            }
        }

        let mut relevant_pids: HashSet<usize> = current_owner.keys().copied().collect();
        relevant_pids.extend(
            self.attribution
                .keys()
                .filter(|identity| {
                    process_by_pid.get(&identity.pid).is_some_and(|process| {
                        process.start_time_seconds == identity.start_time_seconds
                            && matches!(process.parent_pid, None | Some(0 | 1))
                    })
                })
                .map(|identity| identity.pid),
        );
        for pid in relevant_pids.iter().copied() {
            if !proc_cache.contains_key(&pid)
                && let Some(metadata) = read_proc_metadata(pid)
            {
                proc_cache.insert(pid, metadata);
            }
        }

        let identities_by_pid: HashMap<usize, ProcessIdentity> = processes
            .iter()
            .map(|process| {
                (
                    process.pid,
                    ProcessIdentity::from_sample(
                        process,
                        proc_cache
                            .get(&process.pid)
                            .and_then(|metadata| metadata.stat.as_ref()?.start_time_ticks),
                    ),
                )
            })
            .collect();
        let mut detached_roots = HashMap::<String, Vec<usize>>::new();
        for process in processes {
            if current_owner.contains_key(&process.pid) {
                continue;
            }
            let identity = identities_by_pid
                .get(&process.pid)
                .copied()
                .unwrap_or_else(|| ProcessIdentity::from_sample(process, None));
            let Some(previous_attribution) = self.attribution.get(&identity) else {
                continue;
            };
            let previous_parent = self.previous_parent.get(&identity).copied().flatten();
            let parent_was_lost = previous_parent.is_some_and(|parent_identity| {
                identities_by_pid
                    .get(&parent_identity.pid)
                    .is_none_or(|current_parent| *current_parent != parent_identity)
            });
            if parent_was_lost && matches!(process.parent_pid, None | Some(0 | 1)) {
                detached_roots
                    .entry(previous_attribution.session_id.clone())
                    .or_default()
                    .push(process.pid);
            }
        }

        for (session_id, roots) in &detached_roots {
            let mut visited = HashSet::new();
            for root_pid in roots {
                collect_descendants(
                    *root_pid,
                    &children_by_parent,
                    &process_by_pid,
                    &mut visited,
                );
            }
            for pid in visited {
                current_owner
                    .entry(pid)
                    .or_insert_with(|| session_id.clone());
            }
        }

        let now = captured_at_ms;
        for session in &session_roots {
            let root_identities: Vec<_> = session
                .roots
                .iter()
                .filter_map(|pid| identities_by_pid.get(pid).copied())
                .collect();
            let working_directory = session.root_working_directory.as_deref().or_else(|| {
                session.roots.iter().find_map(|pid| {
                    proc_cache
                        .get(pid)
                        .and_then(|metadata| metadata.working_directory.as_deref())
                })
            });
            let project = resolve_project(working_directory, &[]);
            let first_observed_at_ms = self
                .retained_sessions
                .get(&session.id)
                .map_or(now, |previous| previous.first_observed_at_ms);
            self.retained_sessions.insert(
                session.id.clone(),
                HistoricalSession {
                    id: session.id.clone(),
                    kind: session.kind,
                    root_pid: session.root_pid,
                    root_start_time_seconds: session.root_start_time_seconds,
                    confidence: session.confidence,
                    provenance: deduplicate(session.provenance.clone()),
                    classification_evidence: deduplicate(session.classification_evidence.clone()),
                    project_name: project.name,
                    project_path: project.path,
                    first_observed_at_ms,
                    process_group_id: session.process_group_id,
                    linux_session_id: session.linux_session_id,
                    last_seen_ms: now,
                },
            );
            for identity in root_identities {
                self.attribution.insert(
                    identity,
                    HistoricalAttribution {
                        session_id: session.id.clone(),
                    },
                );
            }
        }

        let mut current_identities = HashMap::<usize, ProcessIdentity>::new();
        let mut process_metadata = HashMap::<usize, ProcMetadata>::new();
        for pid in relevant_pids.iter().copied() {
            let Some(process) = process_by_pid.get(&pid) else {
                continue;
            };
            let identity = ProcessIdentity::from_sample(
                process,
                proc_cache
                    .get(&pid)
                    .and_then(|metadata| metadata.stat.as_ref()?.start_time_ticks),
            );
            current_identities.insert(pid, identity);
            if !proc_cache.contains_key(&pid) {
                if let Some(metadata) = read_proc_metadata(pid) {
                    proc_cache.insert(pid, metadata);
                }
            }
            if let Some(metadata) = proc_cache.get(&pid) {
                process_metadata.insert(pid, metadata.clone());
            }
        }

        for (session_id, session_metadata) in &mut self.retained_sessions {
            if session_metadata.project_path.is_some() {
                continue;
            }
            let root_cwd = session_roots
                .iter()
                .find(|session| &session.id == session_id)
                .and_then(|session| session.root_working_directory.as_deref());
            let project = project_for_session(
                root_cwd,
                process_metadata
                    .iter()
                    .filter(|(pid, _)| {
                        current_owner
                            .get(pid)
                            .is_some_and(|owner| owner == session_id)
                    })
                    .map(|(_, metadata)| metadata.working_directory.clone()),
            );
            if project.path.is_some() {
                session_metadata.project_name = project.name;
                session_metadata.project_path = project.path;
            }
        }

        for (pid, session_id) in &current_owner {
            let Some(process) = process_by_pid.get(pid) else {
                continue;
            };
            let identity = current_identities
                .get(pid)
                .copied()
                .unwrap_or_else(|| ProcessIdentity::from_sample(process, None));
            self.attribution.insert(
                identity,
                HistoricalAttribution {
                    session_id: session_id.clone(),
                },
            );
            let parent_identity = process
                .parent_pid
                .and_then(|parent_pid| identities_by_pid.get(&parent_pid).copied());
            let preserve_parent = process.parent_pid == Some(1)
                && self
                    .previous_parent
                    .get(&identity)
                    .copied()
                    .flatten()
                    .is_some_and(|parent| parent.pid != 1);
            if !preserve_parent {
                self.previous_parent.insert(identity, parent_identity);
            }
            record_resource_sample(
                &mut self.history,
                identity,
                ResourceSample {
                    at_ms: now,
                    cpu_percent: process.cpu_percent.max(0.0),
                    memory_bytes: process.memory_bytes,
                },
            );
            self.first_seen
                .entry(identity)
                .or_insert((session_id.clone(), now));
            if let Some(session) = self.retained_sessions.get_mut(session_id) {
                session.last_seen_ms = now;
            }
        }

        self.history.retain(|identity, samples| {
            current_identities
                .get(&identity.pid)
                .is_some_and(|current| *current == *identity)
                && samples
                    .back()
                    .is_some_and(|sample| now.saturating_sub(sample.at_ms) <= HISTORY_RETENTION_MS)
        });
        self.attribution.retain(|identity, attribution| {
            current_identities
                .get(&identity.pid)
                .is_some_and(|current| *current == *identity)
                || self
                    .retained_sessions
                    .get(&attribution.session_id)
                    .is_some_and(|session| {
                        now.saturating_sub(session.last_seen_ms) <= RETAINED_SESSION_MS
                    })
        });
        self.previous_parent
            .retain(|identity, _| self.attribution.contains_key(identity));
        self.first_seen
            .retain(|identity, _| self.attribution.contains_key(identity));
        self.previous_alerts
            .retain(|key, _| self.attribution.contains_key(&key.process));
        self.retained_sessions
            .retain(|_, session| now.saturating_sub(session.last_seen_ms) <= RETAINED_SESSION_MS);
        if self.retained_sessions.len() > MAX_RETAINED_SESSIONS {
            let mut retained: Vec<_> = self
                .retained_sessions
                .iter()
                .map(|(id, session)| (id.clone(), session.last_seen_ms))
                .collect();
            retained.sort_by_key(|(_, last_seen)| *last_seen);
            let excess = self.retained_sessions.len() - MAX_RETAINED_SESSIONS;
            for (id, _) in retained.into_iter().take(excess) {
                self.retained_sessions.remove(&id);
            }
        }
        if self.retained_sessions.len() > MAX_RETAINED_SESSIONS {
            let mut retained: Vec<_> = self
                .retained_sessions
                .iter()
                .map(|(id, session)| (id.clone(), session.last_seen_ms))
                .collect();
            retained.sort_by_key(|(_, last_seen)| *last_seen);
            for (id, _) in retained
                .into_iter()
                .take(self.retained_sessions.len() - MAX_RETAINED_SESSIONS)
            {
                self.retained_sessions.remove(&id);
            }
        }
        self.trim_process_cache();

        let mut visible_session_ids: HashSet<String> = session_roots
            .iter()
            .map(|session| session.id.clone())
            .collect();
        visible_session_ids.extend(detached_roots.keys().cloned());
        let mut sessions = Vec::new();
        for session_id in visible_session_ids {
            let Some(metadata) = self.retained_sessions.get(&session_id).cloned() else {
                continue;
            };
            let mut roots = session_roots
                .iter()
                .find(|session| session.id == session_id)
                .map(|session| session.roots.clone())
                .unwrap_or_default();
            let detached = detached_roots.get(&session_id).cloned().unwrap_or_default();
            roots.extend(detached.iter().copied());
            roots.sort_unstable();
            roots.dedup();
            if let Some(session) = build_session(
                metadata,
                &roots,
                &detached,
                &children_by_parent,
                &process_by_pid,
                &current_owner,
                &current_identities,
                &process_metadata,
                &self.history,
                &self.first_seen,
                &mut self.previous_alerts,
                self.config,
                now,
            ) {
                sessions.push(session);
            }
        }
        sessions.sort_by(|left, right| {
            left.agent_name
                .cmp(&right.agent_name)
                .then_with(|| left.project_name.cmp(&right.project_name))
                .then_with(|| left.root_pid.cmp(&right.root_pid))
        });

        AgentWatchSnapshot {
            sessions,
            coverage: AgentCoverage {
                candidate_processes,
                detected_processes: detections.len(),
                unreadable_candidates,
                restricted: unreadable_candidates > 0,
            },
            config: self.config,
        }
    }

    fn trim_process_cache(&mut self) {
        if self.attribution.len() <= MAX_TRACKED_PROCESSES {
            return;
        }
        let mut ranked: Vec<_> = self
            .attribution
            .iter()
            .map(|(identity, attribution)| {
                let at = self
                    .history
                    .get(identity)
                    .and_then(|samples| samples.back())
                    .map(|sample| sample.at_ms)
                    .unwrap_or_default();
                (at, *identity, attribution.session_id.clone())
            })
            .collect();
        ranked.sort_by_key(|entry| entry.0);
        let remove_count = ranked.len().saturating_sub(MAX_TRACKED_PROCESSES);
        for (_, identity, _) in ranked.into_iter().take(remove_count) {
            self.attribution.remove(&identity);
            self.history.remove(&identity);
            self.previous_parent.remove(&identity);
            self.first_seen.remove(&identity);
        }
    }
}

impl Default for AgentWatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ProcessIdentity {
    pid: usize,
    start_time_seconds: u64,
    start_time_ticks: Option<u64>,
}

impl ProcessIdentity {
    fn from_sample(process: &ProcessSample, start_time_ticks: Option<u64>) -> Self {
        Self {
            pid: process.pid,
            start_time_seconds: process.start_time_seconds,
            start_time_ticks,
        }
    }

    fn display(self) -> String {
        format!(
            "{}:{}:{}",
            self.pid,
            self.start_time_seconds,
            self.start_time_ticks
                .map_or_else(|| "?".to_owned(), |ticks| ticks.to_string())
        )
    }
}

#[derive(Clone, Debug)]
struct Detection {
    kind: AgentKind,
    confidence: Confidence,
    provenance: Vec<String>,
    evidence: Vec<String>,
}

#[derive(Clone, Debug)]
struct DetectedRoot {
    identity: ProcessIdentity,
    kind: AgentKind,
    confidence: Confidence,
    provenance: Vec<String>,
    evidence: Vec<String>,
    working_directory: Option<String>,
    process_group_id: Option<usize>,
    linux_session_id: Option<usize>,
}

#[derive(Clone, Debug)]
struct SessionRoots {
    id: String,
    kind: AgentKind,
    root_pid: usize,
    root_start_time_seconds: u64,
    confidence: Confidence,
    provenance: Vec<String>,
    classification_evidence: Vec<String>,
    roots: Vec<usize>,
    root_working_directory: Option<String>,
    process_group_id: Option<usize>,
    linux_session_id: Option<usize>,
}

#[derive(Clone, Debug)]
struct HistoricalAttribution {
    session_id: String,
}

#[derive(Clone, Debug)]
struct HistoricalSession {
    id: String,
    kind: AgentKind,
    root_pid: usize,
    root_start_time_seconds: u64,
    confidence: Confidence,
    provenance: Vec<String>,
    classification_evidence: Vec<String>,
    project_name: String,
    project_path: Option<String>,
    first_observed_at_ms: u64,
    process_group_id: Option<usize>,
    linux_session_id: Option<usize>,
    last_seen_ms: u64,
}

#[derive(Clone, Copy, Debug)]
struct ProcStat {
    state: char,
    process_group_id: Option<usize>,
    session_id: Option<usize>,
    start_time_ticks: Option<u64>,
}

#[derive(Clone, Debug, Default)]
struct ProcMetadata {
    executable_path: Option<PathBuf>,
    working_directory: Option<String>,
    stat: Option<ProcStat>,
    permissions_limited: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcAccessError {
    PermissionDenied,
    Vanished,
    Other,
}

fn classify_proc_access_error(error: &io::Error) -> ProcAccessError {
    match error.kind() {
        io::ErrorKind::PermissionDenied => ProcAccessError::PermissionDenied,
        io::ErrorKind::NotFound => ProcAccessError::Vanished,
        _ => ProcAccessError::Other,
    }
}

#[derive(Clone, Copy, Debug)]
struct ResourceSample {
    at_ms: u64,
    cpu_percent: f32,
    memory_bytes: u64,
}

fn record_resource_sample(
    history: &mut HashMap<ProcessIdentity, VecDeque<ResourceSample>>,
    identity: ProcessIdentity,
    sample: ResourceSample,
) {
    let samples = history.entry(identity).or_default();
    samples.push_back(sample);
    while samples.len() > MAX_HISTORY_SAMPLES {
        samples.pop_front();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum AlertKind {
    HighCpu,
    HighMemory,
    MemoryGrowth,
    LongRuntime,
    Detached,
    RapidChildren,
}

impl AlertKind {
    fn slug(self) -> &'static str {
        match self {
            Self::HighCpu => "high_cpu",
            Self::HighMemory => "high_memory",
            Self::MemoryGrowth => "memory_growth",
            Self::LongRuntime => "long_runtime",
            Self::Detached => "detached",
            Self::RapidChildren => "rapid_children",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct AlertKey {
    process: ProcessIdentity,
    kind: AlertKind,
}

#[derive(Clone, Copy, Debug, Default)]
struct AlertState {
    active: bool,
    clear_streak: u8,
    first_observed_at_ms: u64,
}

#[derive(Clone, Debug)]
struct ProjectEvidence {
    name: String,
    path: Option<String>,
}

fn max_confidence(left: Confidence, right: Confidence) -> Confidence {
    if left == Confidence::High || right == Confidence::High {
        Confidence::High
    } else {
        Confidence::Medium
    }
}

fn deduplicate(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn collect_descendants(
    root_pid: usize,
    children_by_parent: &HashMap<usize, Vec<usize>>,
    process_by_pid: &HashMap<usize, &ProcessSample>,
    visited: &mut HashSet<usize>,
) {
    let mut pending = vec![root_pid];
    while let Some(pid) = pending.pop() {
        if !process_by_pid.contains_key(&pid) || !visited.insert(pid) {
            continue;
        }
        if let Some(children) = children_by_parent.get(&pid) {
            pending.extend(children.iter().rev().copied());
        }
    }
}

fn build_session(
    metadata: HistoricalSession,
    roots: &[usize],
    detached_root_pids: &[usize],
    children_by_parent: &HashMap<usize, Vec<usize>>,
    process_by_pid: &HashMap<usize, &ProcessSample>,
    current_owner: &HashMap<usize, String>,
    identities_by_pid: &HashMap<usize, ProcessIdentity>,
    proc_metadata: &HashMap<usize, ProcMetadata>,
    history: &HashMap<ProcessIdentity, VecDeque<ResourceSample>>,
    first_seen: &HashMap<ProcessIdentity, (String, u64)>,
    alert_states: &mut HashMap<AlertKey, AlertState>,
    config: AgentWatchConfig,
    now: u64,
) -> Option<AgentSession> {
    let mut visited = HashSet::new();
    for root_pid in roots {
        collect_descendants(*root_pid, children_by_parent, process_by_pid, &mut visited);
    }
    visited.retain(|pid| {
        current_owner
            .get(pid)
            .is_some_and(|owner| owner == &metadata.id)
    });
    if visited.is_empty() {
        return None;
    }

    let mut children_by_session_parent = HashMap::<usize, Vec<usize>>::new();
    for pid in &visited {
        let process = process_by_pid.get(pid)?;
        if process
            .parent_pid
            .is_some_and(|parent| visited.contains(&parent))
        {
            children_by_session_parent
                .entry(process.parent_pid.expect("checked above"))
                .or_default()
                .push(*pid);
        }
    }
    for children in children_by_session_parent.values_mut() {
        children.sort_unstable();
    }
    let top_level = process_tree_roots(&visited, process_by_pid);

    let mut alerts = Vec::new();
    let mut total_cpu = 0.0;
    let mut total_memory = 0_u64;
    let mut max_runtime = 0_u64;
    let mut history_ready = true;
    let mut new_processes = Vec::new();
    for pid in &visited {
        let process = process_by_pid.get(pid)?;
        total_cpu += process.cpu_percent.max(0.0);
        total_memory = total_memory.saturating_add(process.memory_bytes);
        max_runtime = max_runtime.max(process.run_time_seconds);
        let identity = identities_by_pid.get(pid).copied()?;
        let samples = history.get(&identity).map(VecDeque::as_slices);
        let sample_count = samples.map_or(0, |(left, right)| left.len() + right.len());
        history_ready &= sample_count >= 2;
        if let Some((owner, first_seen_at)) = first_seen.get(&identity)
            && owner == &metadata.id
            && *first_seen_at > metadata.first_observed_at_ms.saturating_add(1_000)
            && now.saturating_sub(*first_seen_at)
                <= config.rapid_children_window_seconds.saturating_mul(1_000)
        {
            new_processes.push(*first_seen_at);
        }

        let process_history = history.get(&identity).cloned().unwrap_or_default();
        alerts.extend(classify_process_alerts(
            process,
            identity,
            &process_history,
            alert_states,
            config,
            now,
            detached_root_pids.contains(pid),
        ));
    }
    alerts.extend(classify_session_alerts(
        &metadata,
        &visited,
        &new_processes,
        alert_states,
        config,
        now,
    ));
    if !history_ready {
        alerts.push(AgentAlert {
            id: format!("{}:insufficient-history", metadata.id),
            pid: metadata.root_pid,
            process_name: metadata.kind.display_name().to_owned(),
            classification: AlertClassification::Insufficient,
            category: "insufficient_history".to_owned(),
            title: "Historique en construction".to_owned(),
            message: "Les tendances CPU et mémoire demandent plusieurs échantillons.".to_owned(),
            evidence: vec!["Les données instantanées restent disponibles.".to_owned()],
            first_observed_at_ms: now,
        });
    }
    alerts.sort_by(|left, right| {
        left.classification
            .cmp(&right.classification)
            .then_with(|| left.title.cmp(&right.title))
            .then_with(|| left.pid.cmp(&right.pid))
    });

    let detached_root_pids: HashSet<usize> = detached_root_pids.iter().copied().collect();
    let detached_root_pids: HashSet<usize> = detached_root_pids.iter().copied().collect();
    let agent_root_pids: HashSet<usize> = roots.iter().copied().collect();
    let tree = top_level
        .into_iter()
        .filter_map(|pid| {
            build_process_node(
                pid,
                &children_by_session_parent,
                process_by_pid,
                proc_metadata,
                identities_by_pid,
                &mut HashSet::new(),
                detached_root_pids.contains(&pid),
                agent_root_pids.contains(&pid),
            )
        })
        .collect::<Vec<_>>();
    let detached_processes = tree.iter().map(count_detached).sum::<usize>();
    let session_runtime = roots
        .iter()
        .filter_map(|pid| {
            process_by_pid
                .get(pid)
                .map(|process| process.run_time_seconds)
        })
        .max()
        .unwrap_or(max_runtime);

    Some(AgentSession {
        id: metadata.id,
        agent: metadata.kind,
        agent_name: metadata.kind.display_name().to_owned(),
        root_pid: metadata.root_pid,
        root_start_time_seconds: metadata.root_start_time_seconds,
        confidence: metadata.confidence,
        provenance: metadata.provenance,
        classification_evidence: metadata.classification_evidence,
        project_name: metadata.project_name,
        project_path: metadata.project_path,
        process_count: visited.len(),
        cpu_percent: total_cpu,
        memory_bytes: total_memory,
        run_time_seconds: session_runtime,
        process_group_id: metadata.process_group_id,
        linux_session_id: metadata.linux_session_id,
        detached_processes,
        history_ready,
        tree,
        alerts,
    })
}

impl PartialOrd for AlertClassification {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AlertClassification {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let order = |value| match value {
            Self::Heuristic => 0,
            Self::Insufficient => 1,
            Self::Fact => 2,
        };
        order(*self).cmp(&order(*other))
    }
}

fn count_detached(node: &AgentProcessNode) -> usize {
    usize::from(node.detached) + node.children.iter().map(count_detached).sum::<usize>()
}

fn process_tree_roots(
    visited: &HashSet<usize>,
    process_by_pid: &HashMap<usize, &ProcessSample>,
) -> Vec<usize> {
    let mut roots: Vec<_> = visited
        .iter()
        .filter(|pid| {
            process_by_pid.get(pid).is_some_and(|process| {
                process
                    .parent_pid
                    .is_none_or(|parent| !visited.contains(&parent))
            })
        })
        .copied()
        .collect();
    if roots.is_empty()
        && let Some(root) = visited.iter().min()
    {
        roots.push(*root);
    }
    roots.sort_unstable();
    roots
}

fn build_process_node(
    pid: usize,
    children_by_parent: &HashMap<usize, Vec<usize>>,
    process_by_pid: &HashMap<usize, &ProcessSample>,
    proc_metadata: &HashMap<usize, ProcMetadata>,
    identities_by_pid: &HashMap<usize, ProcessIdentity>,
    visited: &mut HashSet<usize>,
    detached: bool,
    agent_root: bool,
) -> Option<AgentProcessNode> {
    let process = process_by_pid.get(&pid)?;
    if !visited.insert(pid) {
        return None;
    }
    let metadata = proc_metadata.get(&pid);
    let stat = metadata.and_then(|value| value.stat.as_ref());
    let children = children_by_parent
        .get(&pid)
        .into_iter()
        .flatten()
        .filter_map(|child| {
            build_process_node(
                *child,
                children_by_parent,
                process_by_pid,
                proc_metadata,
                identities_by_pid,
                visited,
                false,
                false,
            )
        })
        .collect();
    let identity = identities_by_pid.get(&pid).copied()?;
    Some(AgentProcessNode {
        identity: identity.display(),
        pid,
        parent_pid: process.parent_pid,
        start_time_seconds: process.start_time_seconds,
        start_time_ticks: stat.and_then(|value| value.start_time_ticks),
        name: bounded_text(&process.name, 256),
        process_type: if agent_root {
            "Agent IA".to_owned()
        } else {
            classify_process_type(
                &process.name,
                metadata.and_then(|v| v.executable_path.as_deref()),
            )
        },
        cpu_percent: finite_nonnegative(process.cpu_percent),
        memory_bytes: process.memory_bytes,
        run_time_seconds: process.run_time_seconds,
        working_directory: metadata.and_then(|value| value.working_directory.clone()),
        state: stat.map(|value| process_state_name(value.state).to_owned()),
        process_group_id: stat.and_then(|value| value.process_group_id),
        linux_session_id: stat.and_then(|value| value.session_id),
        detached,
        children,
    })
}

fn classify_process_type(name: &str, executable_path: Option<&Path>) -> String {
    let executable = executable_path
        .and_then(Path::file_name)
        .and_then(|value| value.to_str())
        .unwrap_or(name)
        .to_ascii_lowercase();
    let normalized = executable.trim_start_matches('-');
    if matches!(normalized, "codex" | "claude" | "claude-code") {
        "Agent IA".to_owned()
    } else if matches!(normalized, "node" | "nodejs" | "bun" | "deno") {
        "Runtime JavaScript".to_owned()
    } else if matches!(normalized, "python" | "python3" | "python3.12" | "uv") {
        "Runtime Python".to_owned()
    } else if matches!(normalized, "bash" | "sh" | "zsh" | "fish") {
        "Shell".to_owned()
    } else if matches!(normalized, "git" | "ssh" | "scp") {
        "Outil système".to_owned()
    } else {
        "Processus enfant".to_owned()
    }
}

fn finite_nonnegative(value: f32) -> f32 {
    if value.is_finite() {
        value.max(0.0)
    } else {
        0.0
    }
}

fn bounded_text(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let result: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{result}…")
    } else {
        result
    }
}

fn process_state_name(state: char) -> &'static str {
    match state {
        'R' => "En cours d’exécution",
        'S' => "En sommeil interruptible",
        'D' => "En attente non interruptible",
        'T' | 't' => "Arrêté ou tracé",
        'Z' => "Zombie",
        'I' => "Inactif",
        _ => "État inconnu",
    }
}

fn classify_process_alerts(
    process: &ProcessSample,
    identity: ProcessIdentity,
    history: &VecDeque<ResourceSample>,
    alert_states: &mut HashMap<AlertKey, AlertState>,
    config: AgentWatchConfig,
    now: u64,
    detached: bool,
) -> Vec<AgentAlert> {
    let mut result = Vec::new();
    let latest_cpu = history
        .back()
        .map_or(process.cpu_percent, |value| value.cpu_percent);
    let cpu_window = samples_covering(history, config.high_cpu_seconds.saturating_mul(1_000), now);
    let cpu_sustained = cpu_window.len() >= 2
        && cpu_window.first().is_some_and(|sample| {
            now.saturating_sub(sample.at_ms) >= config.high_cpu_seconds.saturating_mul(1_000)
        })
        && cpu_window
            .iter()
            .all(|sample| sample.cpu_percent >= config.high_cpu_percent);
    push_alert_if_active(
        &mut result,
        alert_states,
        AlertKey {
            process: identity,
            kind: AlertKind::HighCpu,
        },
        cpu_sustained,
        latest_cpu < config.high_cpu_percent * 0.9,
        process,
        AlertClassification::Heuristic,
        "CPU élevé durablement",
        format!(
            "Le CPU est resté au-dessus de {:.0} % pendant au moins {} s.",
            config.high_cpu_percent, config.high_cpu_seconds
        ),
        vec![
            format!("Dernière mesure : {:.1} % CPU.", latest_cpu),
            format!("Fenêtre observée : {} s.", config.high_cpu_seconds),
        ],
        now,
    );

    let memory_threshold = config.high_memory_mib.saturating_mul(1024 * 1024);
    let memory_window = samples_covering(
        history,
        config.high_memory_seconds.saturating_mul(1_000),
        now,
    );
    let memory_sustained = memory_window.len() >= 2
        && memory_window.first().is_some_and(|sample| {
            now.saturating_sub(sample.at_ms) >= config.high_memory_seconds.saturating_mul(1_000)
        })
        && memory_window
            .iter()
            .all(|sample| sample.memory_bytes >= memory_threshold);
    let latest_memory = history
        .back()
        .map_or(process.memory_bytes, |value| value.memory_bytes);
    push_alert_if_active(
        &mut result,
        alert_states,
        AlertKey {
            process: identity,
            kind: AlertKind::HighMemory,
        },
        memory_sustained,
        latest_memory < memory_threshold.saturating_mul(9) / 10,
        process,
        AlertClassification::Heuristic,
        "Mémoire élevée durablement",
        format!(
            "La mémoire est restée au-dessus de {} Mio pendant au moins {} s.",
            config.high_memory_mib, config.high_memory_seconds
        ),
        vec![
            format!("Dernière mesure : {} Mio.", latest_memory / (1024 * 1024)),
            format!("Seuil configuré : {} Mio.", config.high_memory_mib),
        ],
        now,
    );

    let growth_window_ms = config.memory_growth_window_seconds.saturating_mul(1_000);
    let growth_window = samples_covering(history, growth_window_ms, now);
    let growth_threshold = config.memory_growth_mib.saturating_mul(1024 * 1024);
    let baseline = growth_window
        .first()
        .map(|sample| sample.memory_bytes)
        .unwrap_or(latest_memory);
    let growth = latest_memory.saturating_sub(baseline);
    let monotonic_growth = growth_window.len() >= 4
        && growth_window
            .first()
            .is_some_and(|sample| now.saturating_sub(sample.at_ms) >= growth_window_ms)
        && growth_window
            .windows(2)
            .all(|pair| pair[1].memory_bytes >= pair[0].memory_bytes)
        && growth >= growth_threshold;
    push_alert_if_active(
        &mut result,
        alert_states,
        AlertKey {
            process: identity,
            kind: AlertKind::MemoryGrowth,
        },
        monotonic_growth,
        growth < growth_threshold / 2,
        process,
        AlertClassification::Heuristic,
        "Croissance continue de la mémoire",
        format!(
            "La mémoire a augmenté de façon monotone d’au moins {} Mio sur {} s.",
            config.memory_growth_mib, config.memory_growth_window_seconds
        ),
        vec![
            format!("Variation mesurée : {} Mio.", growth / (1024 * 1024)),
            format!("Échantillons de la fenêtre : {}.", growth_window.len()),
        ],
        now,
    );

    let runtime_threshold = config.long_runtime_hours.saturating_mul(3_600);
    push_alert_if_active(
        &mut result,
        alert_states,
        AlertKey {
            process: identity,
            kind: AlertKind::LongRuntime,
        },
        process.run_time_seconds >= runtime_threshold,
        process.run_time_seconds < runtime_threshold.saturating_mul(9) / 10,
        process,
        AlertClassification::Heuristic,
        "Exécution de longue durée",
        format!(
            "Le processus est actif depuis au moins {} h.",
            config.long_runtime_hours
        ),
        vec![format!("Durée observée : {} s.", process.run_time_seconds)],
        now,
    );

    push_alert_if_active(
        &mut result,
        alert_states,
        AlertKey {
            process: identity,
            kind: AlertKind::Detached,
        },
        detached,
        !detached,
        process,
        AlertClassification::Heuristic,
        "Processus potentiellement détaché",
        "Le parent observé auparavant a disparu et le processus a été réattribué par le système."
            .to_owned(),
        vec![
            "Lien avec l’agent conservé dans l’historique de cette exécution.".to_owned(),
            format!(
                "PPID actuel : {}.",
                process
                    .parent_pid
                    .map_or_else(|| "inconnu".to_owned(), |pid| pid.to_string())
            ),
        ],
        now,
    );
    if detached {
        result.push(AgentAlert {
            id: format!("{}:{}:detached-fact", identity.display(), now),
            pid: process.pid,
            process_name: bounded_text(&process.name, 256),
            classification: AlertClassification::Fact,
            category: "parent_disappeared".to_owned(),
            title: "Lien d’ascendance conservé".to_owned(),
            message: "Le parent enregistré lors d’un échantillon précédent n’est plus présent."
                .to_owned(),
            evidence: vec![
                format!(
                    "PPID observé actuellement : {}.",
                    process
                        .parent_pid
                        .map_or_else(|| "inconnu".to_owned(), |pid| pid.to_string())
                ),
                "Cette association utilise l’historique de la session en cours.".to_owned(),
            ],
            first_observed_at_ms: now,
        });
    }

    result
}

fn classify_session_alerts(
    session: &HistoricalSession,
    process_ids: &HashSet<usize>,
    new_processes: &[u64],
    alert_states: &mut HashMap<AlertKey, AlertState>,
    config: AgentWatchConfig,
    now: u64,
) -> Vec<AgentAlert> {
    let session_identity = ProcessIdentity {
        pid: session.root_pid,
        start_time_seconds: session.root_start_time_seconds,
        start_time_ticks: None,
    };
    let burst_threshold = config.rapid_children_count;
    let recent_count = new_processes.len();
    let pseudo_process = ProcessSample {
        pid: session.root_pid,
        parent_pid: None,
        name: session.kind.display_name().to_owned(),
        cpu_percent: 0.0,
        memory_bytes: 0,
        run_time_seconds: 0,
        start_time_seconds: session.root_start_time_seconds,
        candidate_hint: false,
    };
    let session_warmup_complete = now.saturating_sub(session.first_observed_at_ms) >= 2_000;
    let condition = session_warmup_complete
        && recent_count >= burst_threshold
        && process_ids.len() >= burst_threshold;
    let clear_condition = recent_count < burst_threshold.saturating_mul(4) / 5;
    let mut result = Vec::new();
    push_alert_if_active(
        &mut result,
        alert_states,
        AlertKey {
            process: session_identity,
            kind: AlertKind::RapidChildren,
        },
        condition,
        clear_condition,
        &pseudo_process,
        AlertClassification::Heuristic,
        "Multiplication rapide de descendants",
        format!(
            "Au moins {burst_threshold} nouveaux processus ont été observés dans la fenêtre configurée."
        ),
        vec![
            format!("Nouveaux processus suivis : {recent_count}."),
            format!("Fenêtre : {} s.", config.rapid_children_window_seconds),
            "Cette observation ne conclut pas à une boucle infinie.".to_owned(),
        ],
        now,
    );
    result
}

fn samples_covering<'a>(
    history: &'a VecDeque<ResourceSample>,
    window_ms: u64,
    now: u64,
) -> Vec<&'a ResourceSample> {
    history
        .iter()
        .filter(|sample| now.saturating_sub(sample.at_ms) <= window_ms)
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn push_alert_if_active(
    output: &mut Vec<AgentAlert>,
    states: &mut HashMap<AlertKey, AlertState>,
    key: AlertKey,
    condition: bool,
    clear_condition: bool,
    process: &ProcessSample,
    classification: AlertClassification,
    title: &str,
    message: String,
    evidence: Vec<String>,
    now: u64,
) {
    let state = states.entry(key).or_default();
    if condition {
        if !state.active {
            state.active = true;
            state.first_observed_at_ms = now;
        }
        state.clear_streak = 0;
    } else if state.active && clear_condition {
        state.clear_streak = state.clear_streak.saturating_add(1);
        if state.clear_streak >= 2 {
            state.active = false;
            state.clear_streak = 0;
        }
    } else if state.active {
        state.clear_streak = 0;
    }

    if state.active {
        output.push(AgentAlert {
            id: format!(
                "{}:{}:{}",
                key.process.display(),
                key.kind.slug(),
                state.first_observed_at_ms
            ),
            pid: process.pid,
            process_name: bounded_text(&process.name, 256),
            classification,
            category: key.kind.slug().to_owned(),
            title: title.to_owned(),
            message,
            evidence,
            first_observed_at_ms: state.first_observed_at_ms,
        });
    }
}

#[cfg(target_os = "linux")]
fn read_proc_metadata(pid: usize) -> Option<ProcMetadata> {
    let process_path = PathBuf::from(format!("/proc/{pid}"));
    let stat_result = fs::read_to_string(process_path.join("stat"));
    let executable_result = fs::read_link(process_path.join("exe"));
    let working_directory_result = fs::read_link(process_path.join("cwd"));
    let permissions_limited = [
        stat_result.as_ref().err(),
        executable_result.as_ref().err(),
        working_directory_result.as_ref().err(),
    ]
    .into_iter()
    .flatten()
    .any(|error| error.kind() == io::ErrorKind::PermissionDenied);
    let stat = stat_result.ok().and_then(|value| parse_proc_stat(&value));
    let executable_path = executable_result.ok();
    let working_directory = working_directory_result
        .ok()
        .map(|value| value.to_string_lossy().into_owned());
    Some(ProcMetadata {
        executable_path,
        working_directory,
        stat,
        permissions_limited,
    })
}

#[cfg(not(target_os = "linux"))]
fn read_proc_metadata(_pid: usize) -> Option<ProcMetadata> {
    None
}

fn parse_proc_stat(value: &str) -> Option<ProcStat> {
    let close = value.rfind(')')?;
    let rest = value.get(close + 1..)?.trim_start();
    let fields: Vec<_> = rest.split_whitespace().collect();
    Some(ProcStat {
        state: fields.first()?.chars().next()?,
        process_group_id: fields.get(2)?.parse().ok(),
        session_id: fields.get(3)?.parse().ok(),
        start_time_ticks: fields.get(19)?.parse().ok(),
    })
}

fn resolve_project(
    working_directory: Option<&str>,
    fallback: &[Option<String>],
) -> ProjectEvidence {
    let candidates = std::iter::once(working_directory)
        .chain(fallback.iter().map(Option::as_deref))
        .flatten();
    for candidate in candidates {
        let path = Path::new(candidate);
        if !path.is_absolute() {
            continue;
        }
        if let Some(project_path) = find_project_root(path) {
            let name = project_path
                .file_name()
                .and_then(|value| value.to_str())
                .map(|value| bounded_text(value, 96))
                .unwrap_or_else(|| "Projet local".to_owned());
            return ProjectEvidence {
                name,
                path: Some(project_path.to_string_lossy().into_owned()),
            };
        }
    }
    ProjectEvidence {
        name: "Projet inconnu".to_owned(),
        path: None,
    }
}

fn find_project_root(working_directory: &Path) -> Option<PathBuf> {
    let mut current = working_directory.to_path_buf();
    for _ in 0..=4 {
        if [
            ".git",
            "Cargo.toml",
            "package.json",
            "pyproject.toml",
            "go.mod",
        ]
        .iter()
        .any(|marker| current.join(marker).exists())
        {
            return Some(current);
        }
        if !current.pop() {
            break;
        }
    }
    None
}

fn candidate_path_marker(path: &str) -> Option<AgentKind> {
    let mut segments = path.split('/');
    while let Some(segment) = segments.next() {
        if segment == "@openai" {
            let mut tail = segments.clone();
            if tail.next() == Some("codex") && tail.any(|part| matches!(part, "codex.js" | "codex"))
            {
                return Some(AgentKind::Codex);
            }
        }
        if segment == "@anthropic-ai" {
            let mut tail = segments.clone();
            if tail.next() == Some("claude-code")
                && tail.any(|part| matches!(part, "cli.js" | "claude" | "claude-code"))
            {
                return Some(AgentKind::ClaudeCode);
            }
        }
    }
    None
}

pub fn candidate_hint<'a>(
    name: &str,
    executable: Option<&Path>,
    argv: impl Iterator<Item = &'a std::ffi::OsStr>,
) -> bool {
    let executable_name = executable
        .and_then(Path::file_name)
        .and_then(|value| value.to_str());
    if is_exact_cli_name(name) || executable_name.is_some_and(is_exact_cli_name) {
        return true;
    }
    argv.take(2).enumerate().any(|(index, value)| {
        let Some(value) = value.to_str() else {
            return false;
        };
        if index == 0
            && is_exact_cli_name(
                Path::new(value)
                    .file_name()
                    .and_then(|item| item.to_str())
                    .unwrap_or_default(),
            )
        {
            return true;
        }
        candidate_path_marker(value).is_some()
    })
}

fn is_exact_cli_name(value: &str) -> bool {
    matches!(
        value.trim_start_matches('-'),
        "codex" | "claude" | "claude-code"
    )
}

fn is_known_package_entry(value: &str, kind: AgentKind) -> bool {
    candidate_path_marker(value) == Some(kind)
}

fn basename_matches(path: &Path, kind: AgentKind) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|value| match kind {
            AgentKind::Codex => value == "codex",
            AgentKind::ClaudeCode => matches!(value, "claude" | "claude-code"),
        })
}

fn is_known_launcher_path(value: &str, kind: AgentKind) -> bool {
    let path = Path::new(value);
    path.is_absolute()
        && basename_matches(path, kind)
        && path
            .parent()
            .and_then(Path::file_name)
            .and_then(|part| part.to_str())
            == Some("bin")
        && path.components().any(|component| {
            matches!(
                component.as_os_str().to_str(),
                Some(
                    ".local"
                        | ".npm"
                        | ".npm-global"
                        | ".bun"
                        | ".volta"
                        | "usr"
                        | "opt"
                        | "node_modules"
                )
            )
        })
}

fn is_versioned_claude_native_executable(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }

    let components: Vec<_> = path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect();
    if components.len() < 5 {
        return false;
    }

    let suffix_start = components.len() - 3;
    components[suffix_start] == "claude"
        && components[suffix_start + 1] == "versions"
        && is_semver_version(components[suffix_start + 2])
}

fn is_native_codex_cli_executable(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }

    let components: Vec<_> = path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect();
    if components.len() < 6 {
        return false;
    }

    let suffix_start = components.len() - 6;
    components[suffix_start..suffix_start + 3] == ["packages", "standalone", "releases"]
        && is_codex_release_directory(components[suffix_start + 3])
        && components[suffix_start + 4..] == ["bin", "codex"]
}

fn is_codex_release_directory(value: &str) -> bool {
    [
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-musl",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
        "aarch64-pc-windows-msvc",
    ]
    .into_iter()
    .any(|target| {
        value
            .strip_suffix(target)
            .and_then(|prefix| prefix.strip_suffix('-'))
            .is_some_and(is_semver_version)
    })
}

fn is_semver_version(value: &str) -> bool {
    fn valid_identifiers(value: &str) -> bool {
        !value.is_empty()
            && value.split('.').all(|identifier| {
                !identifier.is_empty()
                    && identifier
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
    }

    let (without_build, build) = value
        .split_once('+')
        .map_or((value, None), |(version, metadata)| {
            (version, Some(metadata))
        });
    if build.is_some_and(|metadata| !valid_identifiers(metadata)) {
        return false;
    }

    let (release, prerelease) = without_build
        .split_once('-')
        .map_or((without_build, None), |(version, suffix)| {
            (version, Some(suffix))
        });
    if prerelease.is_some_and(|suffix| !valid_identifiers(suffix)) {
        return false;
    }

    let components: Vec<_> = release.split('.').collect();
    components.len() == 3
        && components.iter().all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn read_bounded_cmdline(reader: &mut impl Read) -> io::Result<SensitiveBytes> {
    let mut bytes = SensitiveBytes(Vec::with_capacity(MAX_CMDLINE_READ_BYTES));
    (&mut *reader)
        .take(MAX_CMDLINE_READ_BYTES as u64)
        .read_to_end(&mut bytes.0)?;
    Ok(bytes)
}

fn is_javascript_runtime_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|value| matches!(value, "node" | "nodejs" | "bun" | "deno"))
}

trait AgentDetector {
    fn kind(&self) -> AgentKind;
    fn classify(
        &self,
        process_name: &str,
        executable: Option<&Path>,
        argv: &[&str],
    ) -> Option<Detection>;
}

struct KnownCliDetector(AgentKind);

impl AgentDetector for KnownCliDetector {
    fn kind(&self) -> AgentKind {
        self.0
    }

    fn classify(
        &self,
        process_name: &str,
        executable: Option<&Path>,
        argv: &[&str],
    ) -> Option<Detection> {
        let kind = self.kind();
        let native_codex_match = kind == AgentKind::Codex
            && process_name == "codex"
            && executable.is_some_and(is_native_codex_cli_executable);
        let native_claude_match = kind == AgentKind::ClaudeCode
            && process_name == "claude"
            && executable.is_some_and(is_versioned_claude_native_executable);
        let argv0_match = argv
            .first()
            .is_some_and(|value| is_known_launcher_path(value, kind));
        let runtime_match = executable.is_some_and(is_javascript_runtime_path)
            || argv
                .first()
                .is_some_and(|value| is_javascript_runtime_path(Path::new(value)));
        let package_match = runtime_match
            && argv
                .get(1)
                .is_some_and(|value| is_known_package_entry(value, kind));
        if native_codex_match || native_claude_match || package_match || argv0_match {
            let mut provenance = Vec::new();
            let mut evidence = Vec::new();
            if native_codex_match {
                provenance.push("/proc/<pid>/exe".to_owned());
                provenance.push("instantané sysinfo : nom du processus".to_owned());
                evidence.push("Nom de processus exact « codex ».".to_owned());
                evidence.push(
                    "Exécutable dans le répertoire natif Codex packages/standalone/releases/<version>/bin/codex."
                        .to_owned(),
                );
            }
            if native_claude_match {
                provenance.push("/proc/<pid>/exe".to_owned());
                provenance.push("instantané sysinfo : nom du processus".to_owned());
                evidence.push("Nom de processus exact « claude ».".to_owned());
                evidence.push(
                    "Exécutable dans le répertoire natif Claude Code versions/<version>."
                        .to_owned(),
                );
            }
            if package_match {
                provenance.push("/proc/<pid>/cmdline: entrée de paquet connue".to_owned());
                evidence.push("Argument d’entrée correspondant au paquet CLI officiel.".to_owned());
            }
            if argv0_match {
                provenance.push("/proc/<pid>/cmdline: argv[0]".to_owned());
                evidence.push("Nom de commande exact dans argv[0].".to_owned());
            }
            return Some(Detection {
                kind,
                confidence: if native_codex_match || native_claude_match || package_match {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                provenance,
                evidence,
            });
        }
        None
    }
}

fn detector_registry() -> [KnownCliDetector; 2] {
    [
        KnownCliDetector(AgentKind::Codex),
        KnownCliDetector(AgentKind::ClaudeCode),
    ]
}

fn classify_evidence(
    process_name: &str,
    executable: Option<&Path>,
    argv: &[&str],
) -> Option<Detection> {
    detector_registry()
        .iter()
        .find_map(|detector| detector.classify(process_name, executable, argv))
}

#[cfg(target_os = "linux")]
fn read_and_detect_proc(
    pid: usize,
    process_name: &str,
    metadata: &ProcMetadata,
) -> Result<Option<Detection>, ProcAccessError> {
    if (process_name == "codex"
        && metadata
            .executable_path
            .as_deref()
            .is_some_and(is_native_codex_cli_executable))
        || (process_name == "claude"
            && metadata
                .executable_path
                .as_deref()
                .is_some_and(is_versioned_claude_native_executable))
    {
        return Ok(classify_evidence(
            process_name,
            metadata.executable_path.as_deref(),
            &[],
        ));
    }
    let mut file = File::open(format!("/proc/{pid}/cmdline"))
        .map_err(|error| classify_proc_access_error(&error))?;
    let bytes =
        read_bounded_cmdline(&mut file).map_err(|error| classify_proc_access_error(&error))?;
    let (argument_ranges, truncated) = first_two_argument_ranges(&bytes.0);
    // Only complete arguments before a truncation can contribute classification evidence.
    if truncated {
        debug_assert!(argument_ranges.len() < 2);
    }
    let argv: Vec<&str> = argument_ranges
        .into_iter()
        .filter_map(|range| std::str::from_utf8(&bytes.0[range]).ok())
        .collect();
    let detection = classify_evidence(process_name, metadata.executable_path.as_deref(), &argv);
    drop(argv);
    Ok(detection)
}

struct SensitiveBytes(Vec<u8>);

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            // Keep the temporary cmdline bytes from being optimized away before deallocation.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

fn first_two_argument_ranges(bytes: &[u8]) -> (Vec<std::ops::Range<usize>>, bool) {
    let mut ranges = Vec::with_capacity(2);
    let mut start = 0;
    let mut truncated = false;

    for _ in 0..2 {
        if start >= bytes.len() {
            break;
        }
        let end = start
            .saturating_add(MAX_CMDLINE_ARG_BYTES + 1)
            .min(bytes.len());
        let argument = &bytes[start..end];
        match argument.iter().position(|byte| *byte == 0) {
            Some(nul) if nul <= MAX_CMDLINE_ARG_BYTES => {
                ranges.push(start..start + nul);
                start += nul + 1;
            }
            Some(_) | None => {
                truncated = true;
                break;
            }
        }
    }

    (ranges, truncated)
}

#[cfg(not(target_os = "linux"))]
fn read_and_detect_proc(
    _pid: usize,
    _process_name: &str,
    _metadata: &ProcMetadata,
) -> Result<Option<Detection>, ProcAccessError> {
    Ok(None)
}

fn project_for_session(
    working_directory: Option<&str>,
    process_working_directories: impl Iterator<Item = Option<String>>,
) -> ProjectEvidence {
    let fallback: Vec<_> = process_working_directories.take(8).collect();
    resolve_project(working_directory, &fallback)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    fn process(pid: usize, parent_pid: Option<usize>, start: u64) -> ProcessSample {
        ProcessSample {
            pid,
            parent_pid,
            name: format!("proc-{pid}"),
            cpu_percent: 0.0,
            memory_bytes: 8 * 1024 * 1024,
            run_time_seconds: 60,
            start_time_seconds: start,
            candidate_hint: false,
        }
    }

    #[test]
    fn recognizes_codex_package_entry_and_keeps_proofs_secret_free() {
        let argv = [
            "/usr/bin/node",
            "/home/maya/.npm-global/lib/node_modules/@openai/codex/bin/codex.js",
            "--api-key=private-token-value",
            "--prompt",
            "private conversation text",
        ];
        let detection = classify_evidence("node", Some(Path::new("/usr/bin/node")), &argv)
            .expect("Codex package entry should be recognized");
        assert_eq!(detection.kind, AgentKind::Codex);
        assert_eq!(detection.confidence, Confidence::High);
        let public_proof = serde_json::to_string(&(detection.provenance, detection.evidence))
            .expect("proofs should serialize");
        assert!(!public_proof.contains("private-token-value"));
        assert!(!public_proof.contains("private conversation text"));
    }

    #[test]
    fn recognizes_supported_native_codex_cli_install_layouts_directly() {
        let standalone = Path::new(
            "/home/maya/.codex/packages/standalone/releases/0.164.0-x86_64-unknown-linux-musl/bin/codex",
        );
        let detection = classify_evidence("codex", Some(standalone), &[])
            .expect("standalone Codex CLI executable should be recognized directly");
        assert_eq!(detection.kind, AgentKind::Codex);
        assert_eq!(detection.confidence, Confidence::High);
        assert!(
            detection
                .provenance
                .iter()
                .any(|item| item == "/proc/<pid>/exe")
        );
        assert!(
            detection
                .evidence
                .iter()
                .any(|item| item.contains("packages/standalone/releases"))
        );

        let custom_codex_home = Path::new(
            "/srv/codex-home/packages/standalone/releases/0.164.0-aarch64-unknown-linux-musl/bin/codex",
        );
        assert!(classify_evidence("codex", Some(custom_codex_home), &[]).is_some());

        let launcher = ["/home/maya/.local/bin/codex"];
        let launcher_detection = classify_evidence("bash", Some(Path::new("/bin/bash")), &launcher)
            .expect("the official visible Codex launcher should be recognized");
        assert_eq!(launcher_detection.kind, AgentKind::Codex);
        assert_eq!(launcher_detection.confidence, Confidence::Medium);
    }

    #[test]
    fn rejects_codex_named_executables_outside_supported_cli_layouts() {
        assert!(classify_evidence("codex", Some(Path::new("/tmp/codex")), &[]).is_none());
        assert!(classify_evidence(
            "codex",
            Some(Path::new(
                "/home/maya/.codex/packages/app-server-daemon/releases/0.164.0-x86_64-unknown-linux-musl/bin/codex"
            )),
            &[]
        )
        .is_none());
        assert!(classify_evidence(
            "unrelated-process",
            Some(Path::new(
                "/home/maya/.codex/packages/standalone/releases/0.164.0-x86_64-unknown-linux-musl/bin/codex"
            )),
            &[]
        )
        .is_none());
        assert!(
            classify_evidence(
                "codex",
                Some(Path::new(
                    "/home/maya/.codex/packages/standalone/releases/current/bin/codex"
                )),
                &[]
            )
            .is_none()
        );
    }

    #[test]
    fn recognizes_claude_code_package_entry() {
        let argv = [
            "/usr/bin/node",
            "/home/maya/.local/share/npm/node_modules/@anthropic-ai/claude-code/cli.js",
        ];
        let detection = classify_evidence("node", Some(Path::new("/usr/bin/node")), &argv)
            .expect("Claude Code package entry should be recognized");
        assert_eq!(detection.kind, AgentKind::ClaudeCode);
        assert_eq!(detection.confidence, Confidence::High);
        assert!(
            detection
                .provenance
                .iter()
                .any(|source| source.contains("cmdline"))
        );
    }

    #[test]
    fn recognizes_native_versioned_claude_code_and_keeps_proofs_secret_free() {
        let executable = Path::new("/home/maya/.local/share/claude/versions/9.8.7");
        let argv = [
            "/home/maya/.local/share/claude/versions/9.8.7",
            "--prompt",
            "private conversation text",
        ];
        let detection = classify_evidence("claude", Some(executable), &argv)
            .expect("native Claude Code executable should be recognized");

        assert_eq!(detection.kind, AgentKind::ClaudeCode);
        assert_eq!(detection.confidence, Confidence::High);
        assert!(
            detection
                .evidence
                .iter()
                .any(|item| item.contains("Nom de processus exact"))
        );
        assert!(
            detection
                .evidence
                .iter()
                .any(|item| item.contains("versions/<version>"))
        );

        let public_proof = serde_json::to_string(&(detection.provenance, detection.evidence))
            .expect("proofs should serialize");
        assert!(!public_proof.contains("private conversation text"));
        assert!(!public_proof.contains("/home/maya"));
        assert!(!public_proof.contains("9.8.7"));
    }

    #[test]
    fn recognizes_native_claude_code_with_a_custom_xdg_data_home() {
        let executable = Path::new("/mnt/agent-xdg-data/claude/versions/2.1.310");
        let detection = classify_evidence("claude", Some(executable), &[])
            .expect("custom XDG native Claude Code layout should be recognized");

        assert_eq!(detection.kind, AgentKind::ClaudeCode);
        assert_eq!(detection.confidence, Confidence::High);
        assert!(
            detection
                .provenance
                .contains(&"instantané sysinfo : nom du processus".to_owned())
        );
        assert!(detection.provenance.contains(&"/proc/<pid>/exe".to_owned()));
        assert!(
            detection
                .evidence
                .iter()
                .any(|item| item.contains("Nom de processus exact"))
        );
    }

    #[test]
    fn rejects_native_claude_paths_without_the_expected_name_and_versioned_layout() {
        let valid_native_path = Path::new("/home/maya/.local/share/claude/versions/2.1.310");

        assert!(classify_evidence("bash", Some(valid_native_path), &[]).is_none());
        assert!(classify_evidence("claude-helper", Some(valid_native_path), &[]).is_none());
        assert!(
            classify_evidence("claude", Some(Path::new("/tmp/arbitrary-executable")), &[])
                .is_none()
        );
        assert!(
            classify_evidence("claude", Some(Path::new("/usr/local/bin/claude")), &[]).is_none()
        );
        assert!(
            classify_evidence(
                "claude",
                Some(Path::new("/home/maya/.local/share/claude/versions/current")),
                &[]
            )
            .is_none()
        );
        assert!(
            classify_evidence(
                "claude",
                Some(Path::new("/home/maya/projects/claude/bin/claude")),
                &[]
            )
            .is_none()
        );
    }

    #[test]
    fn bounded_cmdline_read_stops_after_the_fixed_prefix_for_a_long_argument() {
        let mut input = std::io::Cursor::new(vec![b'x'; 2 * 1024 * 1024]);
        let bytes = read_bounded_cmdline(&mut input).expect("bounded read should succeed");
        assert_eq!(input.position(), MAX_CMDLINE_READ_BYTES as u64);
        assert_eq!(bytes.0.len(), MAX_CMDLINE_READ_BYTES);

        let (arguments, truncated) = first_two_argument_ranges(&bytes.0);
        assert!(arguments.is_empty());
        assert!(truncated);
    }

    #[test]
    fn malformed_cmdline_data_is_ignored_without_panicking_or_using_prefixes() {
        let malformed_utf8 = SensitiveBytes(vec![0xff, 0, 0xfe, 0]);
        let (ranges, truncated) = first_two_argument_ranges(&malformed_utf8.0);
        assert!(!truncated);
        let argv: Vec<_> = ranges
            .into_iter()
            .filter_map(|range| std::str::from_utf8(&malformed_utf8.0[range]).ok())
            .collect();
        assert!(classify_evidence("node", Some(Path::new("/usr/bin/node")), &argv).is_none());

        let mut unterminated = b"/usr/bin/node\0".to_vec();
        unterminated.extend(std::iter::repeat_n(b'x', MAX_CMDLINE_ARG_BYTES + 32));
        let (ranges, truncated) = first_two_argument_ranges(&unterminated);
        assert!(truncated);
        let argv: Vec<_> = ranges
            .into_iter()
            .filter_map(|range| std::str::from_utf8(&unterminated[range]).ok())
            .collect();
        assert_eq!(argv, ["/usr/bin/node"]);
        assert!(classify_evidence("node", Some(Path::new("/usr/bin/node")), &argv).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "smoke test requiring MARABOUTTALATA_LIVE_CLAUDE_PID for an active native session"]
    fn detects_the_configured_live_native_claude_session() {
        let pid = std::env::var("MARABOUTTALATA_LIVE_CLAUDE_PID")
            .expect("set MARABOUTTALATA_LIVE_CLAUDE_PID to the live Claude Code PID")
            .parse::<usize>()
            .expect("the configured PID should be numeric");
        let process_name = fs::read_to_string(format!("/proc/{pid}/comm"))
            .expect("the live process name should be readable")
            .trim()
            .to_owned();
        let metadata = read_proc_metadata(pid).expect("the live process metadata should exist");
        let executable = metadata
            .executable_path
            .as_deref()
            .expect("the live executable path should be readable");

        assert_eq!(process_name, "claude");
        assert!(is_versioned_claude_native_executable(executable));

        let process = ProcessSample {
            pid,
            parent_pid: None,
            name: process_name.clone(),
            cpu_percent: 0.0,
            memory_bytes: 0,
            run_time_seconds: 0,
            start_time_seconds: 0,
            candidate_hint: candidate_hint(&process_name, Some(executable), std::iter::empty()),
        };
        let snapshot = AgentWatcher::new().sample(&[process], 1);
        let session = snapshot
            .sessions
            .iter()
            .find(|session| session.root_pid == pid)
            .expect("the live native process should be detected as a session");

        assert_eq!(session.agent, AgentKind::ClaudeCode);
        assert_eq!(session.confidence, Confidence::High);
        let public_proof = serde_json::to_string(&(
            session.provenance.clone(),
            session.classification_evidence.clone(),
        ))
        .expect("the live proof should serialize");
        assert!(!public_proof.contains(&executable.to_string_lossy().to_string()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "smoke test requiring MARABOUTTALATA_LIVE_CODEX_PIDS for active native sessions"]
    fn detects_the_configured_live_native_codex_cli_session() {
        let pids: Vec<_> = std::env::var("MARABOUTTALATA_LIVE_CODEX_PIDS")
            .expect("set MARABOUTTALATA_LIVE_CODEX_PIDS to active Codex CLI PIDs")
            .split(',')
            .map(|pid| {
                pid.parse::<usize>()
                    .expect("each configured PID should be numeric")
            })
            .collect();
        assert!(!pids.is_empty());

        for pid in pids {
            let process_name = fs::read_to_string(format!("/proc/{pid}/comm"))
                .expect("the live process name should be readable")
                .trim()
                .to_owned();
            let metadata = read_proc_metadata(pid).expect("the live process metadata should exist");
            let executable = metadata
                .executable_path
                .as_deref()
                .expect("the live executable path should be readable");

            assert_eq!(process_name, "codex");
            assert!(is_native_codex_cli_executable(executable));

            let process = ProcessSample {
                pid,
                parent_pid: None,
                name: process_name.clone(),
                cpu_percent: 0.0,
                memory_bytes: 0,
                run_time_seconds: 0,
                start_time_seconds: 0,
                candidate_hint: candidate_hint(&process_name, Some(executable), std::iter::empty()),
            };
            let snapshot = AgentWatcher::new().sample(&[process], 1);
            let session = snapshot
                .sessions
                .iter()
                .find(|session| session.root_pid == pid)
                .expect("the live native process should be detected as a session");

            assert_eq!(session.agent, AgentKind::Codex);
            assert_eq!(session.confidence, Confidence::High);
        }
    }

    #[test]
    fn rejects_editor_browser_and_arbitrary_files_named_after_an_agent() {
        let editor = [
            "/usr/share/code/code",
            "--extension=claude-helper",
            "codex.ts",
        ];
        let browser = [
            "/usr/lib/firefox/firefox",
            "file:///home/maya/node_modules/@anthropic-ai/claude-code/cli.js",
        ];
        let arbitrary_file = ["/usr/bin/cat", "/home/maya/project/bin/codex"];
        assert!(classify_evidence("code", Some(Path::new(editor[0])), &editor).is_none());
        assert!(classify_evidence("firefox", Some(Path::new(browser[0])), &browser).is_none());
        assert!(
            classify_evidence("cat", Some(Path::new(arbitrary_file[0])), &arbitrary_file).is_none()
        );

        let arbitrary_launcher = ["/home/maya/project/bin/claude"];
        assert!(
            classify_evidence("bash", Some(Path::new("/bin/bash")), &arbitrary_launcher).is_none()
        );
    }

    #[test]
    fn candidate_hint_uses_executable_and_known_entry_shapes() {
        assert!(candidate_hint(
            "node",
            Some(Path::new("/usr/bin/node")),
            [
                OsStr::new("node"),
                OsStr::new("/node_modules/@openai/codex/bin/codex.js")
            ]
            .into_iter()
        ));
        assert!(!candidate_hint(
            "code",
            Some(Path::new("/usr/share/code/code")),
            [OsStr::new("code"), OsStr::new("/home/user/codex.ts")].into_iter()
        ));
    }

    #[test]
    fn process_tree_traversal_deduplicates_overlapping_roots_and_breaks_cycles() {
        let values = [
            process(10, Some(12), 1),
            process(11, Some(10), 2),
            process(12, Some(10), 3),
        ];
        let by_pid: HashMap<_, _> = values.iter().map(|value| (value.pid, value)).collect();
        let children = HashMap::from([(10, vec![11, 12]), (12, vec![10])]);
        let mut visited = HashSet::new();
        collect_descendants(10, &children, &by_pid, &mut visited);
        collect_descendants(12, &children, &by_pid, &mut visited);
        assert_eq!(visited, HashSet::from([10, 11, 12]));
        assert_eq!(process_tree_roots(&visited, &by_pid), vec![10]);
    }

    #[test]
    fn process_that_disappears_mid_collection_is_omitted_safely() {
        let values = [process(20, None, 1)];
        let by_pid: HashMap<_, _> = values.iter().map(|value| (value.pid, value)).collect();
        let children = HashMap::from([(20, vec![21]), (21, vec![22])]);
        let mut visited = HashSet::new();
        collect_descendants(20, &children, &by_pid, &mut visited);
        assert_eq!(visited, HashSet::from([20]));
    }

    #[test]
    fn pid_reuse_creates_a_distinct_process_identity() {
        let original = ProcessIdentity {
            pid: 123,
            start_time_seconds: 1_700_000_000,
            start_time_ticks: Some(400),
        };
        let reused = ProcessIdentity {
            pid: 123,
            start_time_seconds: 1_700_000_000,
            start_time_ticks: Some(900),
        };
        let later_start = ProcessIdentity {
            pid: 123,
            start_time_seconds: 1_700_000_001,
            start_time_ticks: None,
        };
        assert_ne!(original, reused);
        assert_ne!(original, later_start);
    }

    #[test]
    fn missing_proc_paths_remain_unknown_and_do_not_block_tree_details() {
        let root = process(30, None, 1);
        let by_pid = HashMap::from([(30, &root)]);
        let identities = HashMap::from([(
            30,
            ProcessIdentity {
                pid: 30,
                start_time_seconds: 1,
                start_time_ticks: None,
            },
        )]);
        let node = build_process_node(
            30,
            &HashMap::new(),
            &by_pid,
            &HashMap::new(),
            &identities,
            &mut HashSet::new(),
            false,
            true,
        )
        .expect("accessible process metrics should still form a node");
        assert_eq!(node.working_directory, None);
        assert_eq!(node.state, None);
        assert_eq!(node.process_type, "Agent IA");
        assert_eq!(resolve_project(None, &[]).name, "Projet inconnu");
        assert_eq!(resolve_project(None, &[]).path, None);
        assert!(!ProcMetadata::default().permissions_limited);
        assert_eq!(
            classify_proc_access_error(&io::Error::from(io::ErrorKind::NotFound)),
            ProcAccessError::Vanished
        );
        assert_eq!(
            classify_proc_access_error(&io::Error::from(io::ErrorKind::PermissionDenied)),
            ProcAccessError::PermissionDenied
        );
    }

    #[test]
    fn sustained_cpu_alert_is_heuristic_and_uses_clear_hysteresis() {
        let process = ProcessSample {
            pid: 40,
            parent_pid: Some(1),
            name: "node".to_owned(),
            cpu_percent: 90.0,
            memory_bytes: 100 * 1024 * 1024,
            run_time_seconds: 120,
            start_time_seconds: 1,
            candidate_hint: true,
        };
        let identity = ProcessIdentity::from_sample(&process, Some(80));
        let config = AgentWatchConfig::default();
        let mut history = VecDeque::from([
            ResourceSample {
                at_ms: 55_000,
                cpu_percent: 90.0,
                memory_bytes: process.memory_bytes,
            },
            ResourceSample {
                at_ms: 100_000,
                cpu_percent: 90.0,
                memory_bytes: process.memory_bytes,
            },
        ]);
        let mut states = HashMap::new();
        let high = classify_process_alerts(
            &process,
            identity,
            &history,
            &mut states,
            config,
            100_000,
            false,
        );
        assert!(high.iter().any(|alert| {
            alert.category == "high_cpu" && alert.classification == AlertClassification::Heuristic
        }));

        history.push_back(ResourceSample {
            at_ms: 103_000,
            cpu_percent: 70.0,
            memory_bytes: process.memory_bytes,
        });
        let first_clear = classify_process_alerts(
            &process,
            identity,
            &history,
            &mut states,
            config,
            103_000,
            false,
        );
        assert!(first_clear.iter().any(|alert| alert.category == "high_cpu"));
        history.push_back(ResourceSample {
            at_ms: 106_000,
            cpu_percent: 70.0,
            memory_bytes: process.memory_bytes,
        });
        let second_clear = classify_process_alerts(
            &process,
            identity,
            &history,
            &mut states,
            config,
            106_000,
            false,
        );
        assert!(
            !second_clear
                .iter()
                .any(|alert| alert.category == "high_cpu")
        );
    }

    #[test]
    fn rapid_descendant_alert_is_heuristic_and_never_calls_it_an_infinite_loop() {
        let session = HistoricalSession {
            id: "codex:50:1".to_owned(),
            kind: AgentKind::Codex,
            root_pid: 50,
            root_start_time_seconds: 1,
            confidence: Confidence::High,
            provenance: vec![],
            classification_evidence: vec![],
            project_name: "Projet inconnu".to_owned(),
            project_path: None,
            first_observed_at_ms: 0,
            process_group_id: None,
            linux_session_id: None,
            last_seen_ms: 0,
        };
        let mut config = AgentWatchConfig::default();
        config.rapid_children_count = 3;
        let mut states = HashMap::new();
        let alerts = classify_session_alerts(
            &session,
            &HashSet::from([50, 51, 52, 53]),
            &[3_000, 4_000, 5_000],
            &mut states,
            config,
            5_000,
        );
        let alert = alerts
            .first()
            .expect("rapid descendant alert should be emitted");
        assert_eq!(alert.classification, AlertClassification::Heuristic);
        assert!(
            alert
                .evidence
                .iter()
                .any(|item| item.contains("ne conclut pas à une boucle infinie"))
        );
    }

    #[test]
    fn sustained_memory_and_detachment_are_classified_separately() {
        let process = ProcessSample {
            pid: 45,
            parent_pid: Some(1),
            name: "codex-child".to_owned(),
            cpu_percent: 0.0,
            memory_bytes: 2_100 * 1024 * 1024,
            run_time_seconds: 120,
            start_time_seconds: 2,
            candidate_hint: false,
        };
        let identity = ProcessIdentity::from_sample(&process, Some(120));
        let history = VecDeque::from([
            ResourceSample {
                at_ms: 0,
                cpu_percent: 0.0,
                memory_bytes: 1_700 * 1024 * 1024,
            },
            ResourceSample {
                at_ms: 60_000,
                cpu_percent: 0.0,
                memory_bytes: 1_800 * 1024 * 1024,
            },
            ResourceSample {
                at_ms: 120_000,
                cpu_percent: 0.0,
                memory_bytes: 1_900 * 1024 * 1024,
            },
            ResourceSample {
                at_ms: 180_000,
                cpu_percent: 0.0,
                memory_bytes: process.memory_bytes,
            },
        ]);
        let mut states = HashMap::new();
        let alerts = classify_process_alerts(
            &process,
            identity,
            &history,
            &mut states,
            AgentWatchConfig::default(),
            180_000,
            true,
        );
        assert!(alerts.iter().any(|alert| {
            alert.category == "high_memory"
                && alert.classification == AlertClassification::Heuristic
        }));
        assert!(alerts.iter().any(|alert| {
            alert.category == "memory_growth"
                && alert.classification == AlertClassification::Heuristic
        }));
        assert!(alerts.iter().any(|alert| {
            alert.category == "detached" && alert.classification == AlertClassification::Heuristic
        }));
        assert!(alerts.iter().any(|alert| {
            alert.category == "parent_disappeared"
                && alert.classification == AlertClassification::Fact
        }));
    }

    #[test]
    fn process_history_is_bounded() {
        let identity = ProcessIdentity {
            pid: 60,
            start_time_seconds: 1,
            start_time_ticks: Some(2),
        };
        let mut history = HashMap::new();
        for at_ms in 0..(MAX_HISTORY_SAMPLES as u64 + 25) {
            record_resource_sample(
                &mut history,
                identity,
                ResourceSample {
                    at_ms,
                    cpu_percent: 1.0,
                    memory_bytes: at_ms,
                },
            );
        }
        let values = history.get(&identity).expect("history should be retained");
        assert_eq!(values.len(), MAX_HISTORY_SAMPLES);
        assert_eq!(values.front().map(|sample| sample.at_ms), Some(25));
        assert_eq!(values.back().map(|sample| sample.at_ms), Some(264));
    }

    #[test]
    fn no_agent_sessions_are_invented_without_a_live_candidate() {
        let mut watcher = AgentWatcher::new();
        let result = watcher.sample(&[process(70, None, 1)], 10_000);
        assert!(result.sessions.is_empty());
        assert_eq!(result.coverage.detected_processes, 0);
    }

    #[test]
    fn invalid_thresholds_are_rejected() {
        let mut watcher = AgentWatcher::new();
        let invalid = AgentWatchConfig {
            high_cpu_percent: 101.0,
            ..AgentWatchConfig::default()
        };
        assert!(watcher.set_config(invalid).is_err());
        assert_eq!(
            watcher.set_config(AgentWatchConfig::default()).unwrap(),
            AgentWatchConfig::default()
        );
    }
}
