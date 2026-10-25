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
  system: SystemInfo;
}

export type ProcessSortKey = "name" | "pid" | "user" | "cpuPercent" | "memoryBytes" | "runTimeSeconds";
export type SortDirection = "asc" | "desc";
