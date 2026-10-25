export interface CpuCoreInfo {
  name: string;
  usagePercent: number;
  frequencyMhz: number;
}

export interface CpuInfo {
  usagePercent: number;
  cores: CpuCoreInfo[];
}

export interface MemoryInfo {
  totalBytes: number;
  usedBytes: number;
  availableBytes: number;
}

export interface SwapInfo {
  totalBytes: number;
  usedBytes: number;
}

export interface DiskInfo {
  name: string;
  mountPoint: string;
  fileSystem: string;
  totalBytes: number;
  usedBytes: number;
  availableBytes: number;
  removable: boolean;
  technical: boolean;
}

export interface ProcessInfo {
  pid: number;
  parentPid: number | null;
  name: string;
  user: string;
  cpuPercent: number;
  memoryBytes: number;
  runTimeSeconds: number;
  startTimeSeconds: number;
}

export type AgentKind = "codex" | "claude_code";
export type AgentConfidence = "high" | "medium";
export type AlertClassification = "fact" | "heuristic" | "insufficient";

export interface AgentWatchConfig {
  highCpuPercent: number;
  highCpuSeconds: number;
  highMemoryMib: number;
  highMemorySeconds: number;
  memoryGrowthMib: number;
  memoryGrowthWindowSeconds: number;
  longRuntimeHours: number;
  rapidChildrenCount: number;
  rapidChildrenWindowSeconds: number;
}

export interface AgentCoverage {
  candidateProcesses: number;
  detectedProcesses: number;
  unreadableCandidates: number;
  restricted: boolean;
}

export interface AgentAlert {
  id: string;
  pid: number;
  processName: string;
  classification: AlertClassification;
  category: string;
  title: string;
  message: string;
  evidence: string[];
  firstObservedAtMs: number;
}

export interface AgentProcessNode {
  identity: string;
  pid: number;
  parentPid: number | null;
  startTimeSeconds: number;
  startTimeTicks: number | null;
  name: string;
  processType: string;
  cpuPercent: number;
  memoryBytes: number;
  runTimeSeconds: number;
  workingDirectory: string | null;
  state: string | null;
  processGroupId: number | null;
  linuxSessionId: number | null;
  detached: boolean;
  children: AgentProcessNode[];
}

export interface AgentSession {
  id: string;
  agent: AgentKind;
  agentName: string;
  rootPid: number;
  rootStartTimeSeconds: number;
  confidence: AgentConfidence;
  provenance: string[];
  classificationEvidence: string[];
  projectName: string;
  projectPath: string | null;
  processCount: number;
  cpuPercent: number;
  memoryBytes: number;
  runTimeSeconds: number;
  processGroupId: number | null;
  linuxSessionId: number | null;
  detachedProcesses: number;
  historyReady: boolean;
  tree: AgentProcessNode[];
  alerts: AgentAlert[];
}

export interface AgentWatchSnapshot {
  sessions: AgentSession[];
  coverage: AgentCoverage;
  config: AgentWatchConfig;
}

export interface ProcessCommand {
  command: string;
  redacted: boolean;
}

export interface SystemInfo {
  distribution: string;
  distributionId: string;
  kernel: string | null;
  uptimeSeconds: number;
}

export interface SystemSnapshot {
  capturedAtMs: number;
  cpu: CpuInfo;
  memory: MemoryInfo;
  swap: SwapInfo;
  disks: DiskInfo[];
  processes: ProcessInfo[];
  agents: AgentWatchSnapshot;
  system: SystemInfo;
}

export type ProcessSortKey = "name" | "pid" | "user" | "cpuPercent" | "memoryBytes" | "runTimeSeconds";
export type SortDirection = "asc" | "desc";
