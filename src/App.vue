<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, shallowRef, watch } from "vue";
import { invoke, isTauri } from "@tauri-apps/api/core";
import AppIcon from "./components/AppIcon.vue";
import AgentWatcherPage from "./components/AgentWatcherPage.vue";
import ProcessTable from "./components/ProcessTable.vue";
import type { DiskInfo, ProcessCommand, ProcessInfo, ProcessSortKey, SortDirection, SystemSnapshot } from "./types/monitor";

type View = "overview" | "processes" | "storage" | "agents";
type Theme = "dark" | "light";
type MetricKey = "cpu" | "memory" | "swap" | "storage";
interface HistoryPoint {
  cpu: number;
  memory: number;
  swap: number;
  storage: number;
}

const HISTORY_LIMIT = 40;
const activeView = ref<View>("overview");
const theme = ref<Theme>("dark");
const snapshot = shallowRef<SystemSnapshot | null>(null);
const loading = ref(true);
const refreshing = ref(false);
const error = ref("");
const autoRefresh = ref(true);
const showTechnicalMounts = ref(false);
const refreshInterval = ref(3);
const processSearch = ref("");
const processSort = ref<ProcessSortKey>("cpuPercent");
const processSortDirection = ref<SortDirection>("desc");
const selectedProcess = ref<ProcessInfo | null>(null);
const selectedCommand = ref("");
const selectedCommandRedacted = ref(false);
const selectedCommandLoading = ref(false);
const history = ref<HistoryPoint[]>([]);
let refreshTimer: number | null = null;
let requestInFlight = false;

const displayDisks = computed(() => {
  const disks = (snapshot.value?.disks ?? [])
    .filter((disk) => showTechnicalMounts.value || !disk.technical);
  return [...disks].sort((a, b) => {
    if (a.mountPoint === "/") return -1;
    if (b.mountPoint === "/") return 1;
    return a.mountPoint.localeCompare(b.mountPoint, "fr", { sensitivity: "base" });
  });
});

const dashboardDisks = computed(() => displayDisks.value.slice(0, 4));

function primaryDisk(disks: DiskInfo[]): DiskInfo | null {
  const volumes = disks.filter((disk) => !disk.technical);
  return volumes.find((disk) => disk.mountPoint === "/")
    ?? [...volumes].sort((a, b) => b.totalBytes - a.totalBytes)[0]
    ?? null;
}

const rootDisk = computed<DiskInfo | null>(() => {
  return primaryDisk(displayDisks.value);
});

const diskUsagePercent = computed(() => rootDisk.value?.totalBytes
  ? (rootDisk.value.usedBytes / rootDisk.value.totalBytes) * 100
  : 0);

const memoryUsagePercent = computed(() => snapshot.value?.memory.totalBytes
  ? (snapshot.value.memory.usedBytes / snapshot.value.memory.totalBytes) * 100
  : 0);

const swapUsagePercent = computed(() => snapshot.value?.swap.totalBytes
  ? (snapshot.value.swap.usedBytes / snapshot.value.swap.totalBytes) * 100
  : 0);

const sortedProcesses = computed(() => {
  const query = processSearch.value.trim().toLocaleLowerCase("fr");
  const processes = (snapshot.value?.processes ?? []).filter((process) => {
    if (!query) return true;
    return [process.name, process.user, String(process.pid)]
      .some((value) => value.toLocaleLowerCase("fr").includes(query));
  });

  return processes.sort((a, b) => {
    const first = a[processSort.value];
    const second = b[processSort.value];
    const comparison = typeof first === "string" && typeof second === "string"
      ? first.localeCompare(second, "fr", { sensitivity: "base" })
      : Number(first) - Number(second);
    return processSortDirection.value === "asc" ? comparison : -comparison;
  });
});

const dashboardProcesses = computed(() => [...(snapshot.value?.processes ?? [])]
  .sort((a, b) => b.cpuPercent - a.cpuPercent)
  .slice(0, 6));

const viewTitle = computed(() => ({
  overview: "Vue d’ensemble",
  processes: "Processus",
  storage: "Stockage",
  agents: "Agents IA",
})[activeView.value]);

const updateTime = computed(() => snapshot.value
  ? new Intl.DateTimeFormat("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" })
    .format(new Date(snapshot.value.capturedAtMs))
  : "—");

function ratio(used: number, total: number): number {
  return total > 0 ? Math.min((used / total) * 100, 100) : 0;
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 1) return "0 o";
  const units = ["o", "Ko", "Mo", "Go", "To", "Po"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / (1024 ** index);
  return `${new Intl.NumberFormat("fr-FR", { maximumFractionDigits: index > 1 ? 1 : 0 }).format(value)} ${units[index]}`;
}

function formatPercent(value: number): string {
  return `${new Intl.NumberFormat("fr-FR", { maximumFractionDigits: 1 }).format(value)} %`;
}

function formatDuration(seconds: number): string {
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  if (days > 0) return `${days} j ${hours} h`;
  if (hours > 0) return `${hours} h ${minutes} min`;
  return `${minutes} min ${seconds % 60} s`;
}

function addHistoryPoint(data: SystemSnapshot): void {
  const root = primaryDisk(data.disks);
  history.value = [...history.value, {
    cpu: data.cpu.usagePercent,
    memory: ratio(data.memory.usedBytes, data.memory.totalBytes),
    swap: ratio(data.swap.usedBytes, data.swap.totalBytes),
    storage: root ? ratio(root.usedBytes, root.totalBytes) : 0,
  }].slice(-HISTORY_LIMIT);
}

async function refreshSnapshot(): Promise<void> {
  if (requestInFlight) return;
  if (!isTauri()) {
    error.value = "L’accès au moniteur système nécessite de lancer MaraboutTalata avec npm run tauri dev.";
    loading.value = false;
    return;
  }

  requestInFlight = true;
  refreshing.value = true;
  if (!snapshot.value) loading.value = true;

  try {
    const data = await invoke<SystemSnapshot>("get_system_snapshot");
    snapshot.value = data;
    addHistoryPoint(data);
    error.value = "";
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause);
  } finally {
    requestInFlight = false;
    refreshing.value = false;
    loading.value = false;
  }
}

function scheduleRefresh(): void {
  if (refreshTimer !== null) {
    window.clearInterval(refreshTimer);
    refreshTimer = null;
  }
  if (autoRefresh.value && isTauri()) {
    refreshTimer = window.setInterval(() => void refreshSnapshot(), refreshInterval.value * 1_000);
  }
}

function setSort(key: ProcessSortKey): void {
  if (processSort.value === key) {
    processSortDirection.value = processSortDirection.value === "asc" ? "desc" : "asc";
  } else {
    processSort.value = key;
    processSortDirection.value = key === "name" || key === "user" ? "asc" : "desc";
  }
}

function selectProcess(process: ProcessInfo): void {
  selectedProcess.value = process;
}

watch(() => selectedProcess.value?.pid, (pid) => {
  selectedCommand.value = "";
  selectedCommandRedacted.value = false;
  selectedCommandLoading.value = pid !== undefined;
  if (pid === undefined) return;

  void invoke<ProcessCommand | null>("get_process_command", { pid })
    .then((details) => {
      if (selectedProcess.value?.pid !== pid) return;
      selectedCommand.value = details?.command ?? "";
      selectedCommandRedacted.value = details?.redacted ?? false;
    })
    .catch(() => {
      if (selectedProcess.value?.pid === pid) selectedCommand.value = "";
    })
    .finally(() => {
      if (selectedProcess.value?.pid === pid) selectedCommandLoading.value = false;
    });
});

function chartLine(key: MetricKey): string {
  const points = history.value.map((point, index) => {
    const x = history.value.length < 2 ? 300 : (index / (history.value.length - 1)) * 300;
    const y = 58 - (Math.min(Math.max(point[key], 0), 100) / 100) * 52;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  return points.length ? `M ${points.join(" L ")}` : "";
}

function chartArea(key: MetricKey): string {
  const line = chartLine(key);
  return line ? `${line} L 300,62 L 0,62 Z` : "";
}

function changeTheme(): void {
  theme.value = theme.value === "dark" ? "light" : "dark";
}

watch([autoRefresh, refreshInterval], scheduleRefresh);
watch(theme, (value) => {
  try {
    localStorage.setItem("sentinel-theme", value);
  } catch {
    // Preferences remain available for this session when storage is unavailable.
  }
});
watch(snapshot, (data) => {
  if (!data || !selectedProcess.value) return;
  selectedProcess.value = data.processes.find((process) => process.pid === selectedProcess.value?.pid) ?? null;
});

onMounted(() => {
  try {
    const savedTheme = localStorage.getItem("sentinel-theme");
    if (savedTheme === "light" || savedTheme === "dark") theme.value = savedTheme;
    const savedInterval = Number(localStorage.getItem("sentinel-refresh-interval"));
    if ([3, 5, 10].includes(savedInterval)) refreshInterval.value = savedInterval;
    const savedAutoRefresh = localStorage.getItem("sentinel-auto-refresh");
    if (savedAutoRefresh === "false") autoRefresh.value = false;
    showTechnicalMounts.value = localStorage.getItem("sentinel-show-technical-mounts") === "true";
  } catch {
    // Use the defaults when persistent storage is unavailable.
  }
  void refreshSnapshot();
  scheduleRefresh();
});

watch(refreshInterval, (value) => {
  try {
    localStorage.setItem("sentinel-refresh-interval", String(value));
  } catch {
    // The selected interval still applies until the app closes.
  }
});
watch(autoRefresh, (value) => {
  try {
    localStorage.setItem("sentinel-auto-refresh", String(value));
  } catch {
    // The selected state still applies until the app closes.
  }
});
watch(showTechnicalMounts, (value) => {
  try {
    localStorage.setItem("sentinel-show-technical-mounts", String(value));
  } catch {
    // The selected state still applies until the app closes.
  }
});

onUnmounted(() => {
  if (refreshTimer !== null) window.clearInterval(refreshTimer);
});
</script>

<template>
  <div class="app-shell" :class="`theme-${theme}`">
    <aside class="sidebar">
      <div class="brand-lockup">
        <div class="brand-mark"><AppIcon name="shield" :size="22" /></div>
        <div class="brand-name">MaraboutTalata<span>V1</span></div>
      </div>

      <div class="sidebar-label">Supervision</div>
      <nav class="primary-nav" aria-label="Navigation principale">
        <button class="nav-item" :class="{ active: activeView === 'overview' }" @click="activeView = 'overview'">
          <AppIcon name="overview" />
          <span>Vue d’ensemble</span>
          <span v-if="activeView === 'overview'" class="active-mark" />
        </button>
        <button class="nav-item" :class="{ active: activeView === 'processes' }" @click="activeView = 'processes'">
          <AppIcon name="process" />
          <span>Processus</span>
          <span class="nav-count">{{ snapshot?.processes.length ?? "—" }}</span>
        </button>
        <button class="nav-item" :class="{ active: activeView === 'agents' }" @click="activeView = 'agents'">
          <AppIcon name="terminal" />
          <span>Agents IA</span>
          <span class="nav-count">{{ snapshot?.agents.sessions.length ?? "—" }}</span>
          <span v-if="activeView === 'agents'" class="active-mark" />
        </button>
        <button class="nav-item" :class="{ active: activeView === 'storage' }" @click="activeView = 'storage'">
          <AppIcon name="storage" />
          <span>Stockage</span>
        </button>
      </nav>

      <div class="sidebar-label secondary-label">À venir</div>
      <nav class="primary-nav" aria-label="Modules à venir">
        <button class="nav-item unavailable" disabled title="Ce module n’est pas encore disponible">
          <AppIcon name="network" />
          <span>Réseau</span>
          <span class="soon-mark">Bientôt</span>
        </button>
        <button class="nav-item unavailable" disabled title="Ce module n’est pas encore disponible">
          <AppIcon name="gauge" />
          <span>Capteurs</span>
          <span class="soon-mark">Bientôt</span>
        </button>
      </nav>

      <div class="sidebar-bottom">
        <div class="system-status">
          <span class="status-led" :class="{ online: !!snapshot && !error }" />
          <span>{{ snapshot ? (error ? 'Données en cache' : 'Système surveillé') : 'Connexion au système' }}</span>
        </div>
        <button class="theme-toggle" @click="changeTheme">
          <AppIcon :name="theme === 'dark' ? 'sun' : 'moon'" :size="17" />
          <span>Thème {{ theme === 'dark' ? 'clair' : 'sombre' }}</span>
        </button>
        <div class="sidebar-version"><span class="version-dot" /> MaraboutTalata · V1</div>
      </div>
    </aside>

    <main class="main-content">
      <header class="topbar">
        <div class="breadcrumbs"><span>Système</span><AppIcon name="chevron" :size="13" /><strong>{{ viewTitle }}</strong></div>
        <div class="topbar-right">
          <div class="system-chip" v-if="snapshot">
            <span class="status-led online" />
            <span>{{ snapshot.system.distribution }}</span>
          </div>
          <span class="topbar-divider" />
          <button class="icon-button refresh-button" :class="{ spinning: refreshing }" aria-label="Actualiser maintenant" title="Actualiser maintenant" :disabled="refreshing" @click="refreshSnapshot">
            <AppIcon name="refresh" :size="17" />
          </button>
          <div class="updated-at"><span>Mis à jour</span><strong>{{ updateTime }}</strong></div>
        </div>
      </header>

      <div class="page-content">
        <section class="page-heading">
          <div>
            <p class="eyebrow">CENTRE DE CONTRÔLE</p>
            <h1>{{ viewTitle }}</h1>
            <p class="page-subtitle">
              <template v-if="activeView === 'overview'">Les performances de votre machine, en temps réel.</template>
              <template v-else-if="activeView === 'processes'">Consultez et explorez les processus actifs.</template>
              <template v-else-if="activeView === 'storage'">Volumes montés et espace disponible sur vos disques.</template>
              <template v-else>Détection locale et analyse des processus Codex CLI et Claude Code.</template>
            </p>
          </div>
          <div class="heading-controls">
            <label class="interval-picker">
              <AppIcon name="clock" :size="15" />
              <span>Intervalle</span>
              <select v-model.number="refreshInterval" aria-label="Intervalle d’actualisation">
                <option :value="3">3 s</option>
                <option :value="5">5 s</option>
                <option :value="10">10 s</option>
              </select>
            </label>
            <button class="auto-toggle" :class="{ enabled: autoRefresh }" :aria-pressed="autoRefresh" @click="autoRefresh = !autoRefresh">
              <span class="toggle-track"><i /></span>
              <span>Actualisation auto</span>
            </button>
          </div>
        </section>

        <div v-if="error" class="error-banner" role="alert">
          <span class="error-icon">!</span>
          <div><strong>Collecte indisponible</strong><span>{{ error }}<template v-if="snapshot"> Les dernières données reçues restent affichées.</template></span></div>
          <button class="retry-button" @click="refreshSnapshot">Réessayer</button>
        </div>

        <div v-if="loading && !snapshot" class="loading-state" aria-live="polite">
          <div class="loader-orbit"><span /></div>
          <strong>Connexion au moniteur système</strong>
          <span>Lecture des ressources de la machine…</span>
        </div>

        <template v-else-if="snapshot">
          <template v-if="activeView === 'overview'">
            <section class="metric-grid" aria-label="Ressources du système">
              <article class="metric-card accent-cyan">
                <div class="metric-top"><div class="metric-icon"><AppIcon name="cpu" :size="18" /></div><span class="metric-kicker">PROCESSEUR</span><span class="metric-live"><i /> LIVE</span></div>
                <div class="metric-value">{{ formatPercent(snapshot.cpu.usagePercent) }}</div>
                <div class="metric-description">Charge globale <span>·</span> {{ snapshot.cpu.cores.length }} cœurs logiques</div>
                <div class="chart-wrap"><svg viewBox="0 0 300 64" preserveAspectRatio="none" role="img" aria-label="Historique réel de l’utilisation du processeur"><path class="chart-area" d="M 0,62 L 0,62 L 300,62 Z" :class="`fill-${'cpu'}`" /><path class="chart-area" :d="chartArea('cpu')" /><path class="chart-line" :d="chartLine('cpu')" /></svg></div>
                <div class="metric-foot"><span>0 %</span><span>Échantillons récents</span><span>100 %</span></div>
              </article>

              <article class="metric-card accent-violet">
                <div class="metric-top"><div class="metric-icon"><AppIcon name="memory" :size="18" /></div><span class="metric-kicker">MÉMOIRE RAM</span><span class="metric-live"><i /> LIVE</span></div>
                <div class="metric-value">{{ formatBytes(snapshot.memory.usedBytes) }}<small> / {{ formatBytes(snapshot.memory.totalBytes) }}</small></div>
                <div class="metric-description">{{ formatPercent(memoryUsagePercent) }} utilisés <span>·</span> {{ formatBytes(snapshot.memory.availableBytes) }} disponibles</div>
                <div class="chart-wrap"><svg viewBox="0 0 300 64" preserveAspectRatio="none" role="img" aria-label="Historique réel de l’utilisation de la mémoire vive"><path class="chart-area" :d="chartArea('memory')" /><path class="chart-line" :d="chartLine('memory')" /></svg></div>
                <div class="metric-foot"><span>0 %</span><span>Échantillons récents</span><span>100 %</span></div>
              </article>

              <article class="metric-card accent-amber">
                <div class="metric-top"><div class="metric-icon"><AppIcon name="memory" :size="18" /></div><span class="metric-kicker">SWAP</span><span class="metric-live"><i /> LIVE</span></div>
                <div v-if="snapshot.swap.totalBytes" class="metric-value">{{ formatBytes(snapshot.swap.usedBytes) }}<small> / {{ formatBytes(snapshot.swap.totalBytes) }}</small></div>
                <div v-else class="metric-value metric-unavailable">Non configurée</div>
                <div class="metric-description">{{ snapshot.swap.totalBytes ? `${formatPercent(swapUsagePercent)} utilisés` : 'Aucune partition swap détectée' }}</div>
                <div class="chart-wrap"><svg viewBox="0 0 300 64" preserveAspectRatio="none" role="img" aria-label="Historique réel de l’utilisation de la mémoire swap"><path class="chart-area" :d="chartArea('swap')" /><path class="chart-line" :d="chartLine('swap')" /></svg></div>
                <div class="metric-foot"><span>0 %</span><span>Échantillons récents</span><span>100 %</span></div>
              </article>

              <article class="metric-card accent-green">
                <div class="metric-top"><div class="metric-icon"><AppIcon name="drive" :size="18" /></div><span class="metric-kicker">STOCKAGE</span><span class="metric-live"><i /> LIVE</span></div>
                <div v-if="rootDisk" class="metric-value">{{ formatBytes(rootDisk.usedBytes) }}<small> / {{ formatBytes(rootDisk.totalBytes) }}</small></div>
                <div v-else class="metric-value metric-unavailable">Aucun disque détecté</div>
                <div class="metric-description">{{ rootDisk ? `${rootDisk.mountPoint} · ${formatPercent(diskUsagePercent)} utilisés` : 'Les volumes seront affichés ici' }}</div>
                <div class="chart-wrap"><svg viewBox="0 0 300 64" preserveAspectRatio="none" role="img" aria-label="Historique réel de l’espace occupé sur le volume principal"><path class="chart-area" :d="chartArea('storage')" /><path class="chart-line" :d="chartLine('storage')" /></svg></div>
                <div class="metric-foot"><span>0 %</span><span>Échantillons récents</span><span>100 %</span></div>
              </article>
            </section>

            <section class="dashboard-grid">
              <article class="panel cores-panel">
                <div class="panel-heading"><div><h2>Charge par cœur</h2><p>Utilisation instantanée des cœurs logiques</p></div><span class="panel-badge">{{ snapshot.cpu.cores.length }} cœurs</span></div>
                <div v-if="snapshot.cpu.cores.length" class="core-list">
                  <div v-for="(core, index) in snapshot.cpu.cores" :key="`${core.name}-${index}`" class="core-row">
                    <span class="core-name">{{ core.name || `Cœur ${index + 1}` }}</span>
                    <div class="core-track"><i :style="{ width: `${Math.min(core.usagePercent, 100)}%` }" /></div>
                    <span class="core-value">{{ formatPercent(core.usagePercent) }}</span>
                    <span class="core-frequency">{{ core.frequencyMhz ? `${core.frequencyMhz} MHz` : '—' }}</span>
                  </div>
                </div>
                <div v-else class="panel-empty">Aucune information CPU disponible.</div>
              </article>

              <article class="panel disk-panel">
                <div class="panel-heading"><div><h2>Volumes principaux</h2><p>Capacité et espace restant</p></div><button class="text-link" @click="activeView = 'storage'">Tous les disques <AppIcon name="chevron" :size="14" /></button></div>
                <div v-if="dashboardDisks.length" class="disk-list">
                  <div v-for="disk in dashboardDisks" :key="`${disk.mountPoint}-${disk.name}`" class="disk-row">
                    <div class="disk-row-title"><span class="disk-symbol"><AppIcon name="drive" :size="15" /></span><div><strong>{{ disk.mountPoint }}</strong><small>{{ disk.name || disk.fileSystem }}</small></div><span class="disk-free">{{ formatBytes(disk.availableBytes) }} libres</span></div>
                    <div class="disk-track"><i :style="{ width: `${ratio(disk.usedBytes, disk.totalBytes)}%` }" /></div>
                    <div class="disk-row-foot"><span>{{ formatBytes(disk.usedBytes) }} utilisés</span><span>{{ formatBytes(disk.totalBytes) }} au total</span></div>
                  </div>
                </div>
                <div v-else class="panel-empty">Aucun volume monté détecté.</div>
              </article>
            </section>

            <section class="panel process-panel">
              <div class="panel-heading process-panel-heading"><div><h2>Processus les plus actifs</h2><p>Triés selon leur consommation CPU</p></div><button class="text-link" @click="activeView = 'processes'">Tous les processus <AppIcon name="chevron" :size="14" /></button></div>
              <ProcessTable :processes="dashboardProcesses" :sort-by="processSort" :sort-direction="processSortDirection" compact :selected-pid="selectedProcess?.pid" @select="selectProcess" @sort="setSort" />
            </section>

            <section class="system-footer panel">
              <div class="system-footer-main"><div class="os-mark"><AppIcon name="shield" :size="20" /></div><div><span class="footer-label">SYSTÈME D’EXPLOITATION</span><strong>{{ snapshot.system.distribution }}</strong></div></div>
              <div class="footer-stat"><span class="footer-label">NOYAU LINUX</span><strong>{{ snapshot.system.kernel ?? 'Indisponible' }}</strong></div>
              <div class="footer-stat"><span class="footer-label">TEMPS DE FONCTIONNEMENT</span><strong>{{ formatDuration(snapshot.system.uptimeSeconds) }}</strong></div>
              <div class="footer-stat"><span class="footer-label">PROCESSUS ACTIFS</span><strong>{{ snapshot.processes.length }}</strong></div>
            </section>
          </template>

          <template v-else-if="activeView === 'processes'">
            <section class="panel process-page-panel">
              <div class="process-toolbar">
                <div class="process-total"><span class="total-pulse" />{{ snapshot.processes.length }} processus actifs</div>
                <label class="search-field"><AppIcon name="search" :size="17" /><input v-model="processSearch" type="search" placeholder="Rechercher par nom, PID ou utilisateur…" aria-label="Filtrer les processus" /></label>
              </div>
              <ProcessTable :processes="sortedProcesses" :sort-by="processSort" :sort-direction="processSortDirection" :selected-pid="selectedProcess?.pid" @select="selectProcess" @sort="setSort" />
              <div class="table-footer"><span>{{ sortedProcesses.length }} résultat{{ sortedProcesses.length > 1 ? 's' : '' }}</span><span>Les données CPU et mémoire sont collectées localement</span></div>
            </section>
          </template>

          <template v-else-if="activeView === 'storage'">
            <section class="storage-summary-grid">
              <article class="panel storage-summary"><div class="metric-icon accent-icon-green"><AppIcon name="drive" :size="18" /></div><div><span class="footer-label">VOLUMES AFFICHÉS</span><strong>{{ displayDisks.length }}</strong></div></article>
              <article class="panel storage-summary"><div class="metric-icon accent-icon-cyan"><AppIcon name="memory" :size="18" /></div><div><span class="footer-label">VOLUME PRINCIPAL</span><strong>{{ rootDisk?.mountPoint ?? 'Indisponible' }}</strong></div></article>
              <article class="panel storage-summary"><div class="metric-icon accent-icon-violet"><AppIcon name="storage" :size="18" /></div><div><span class="footer-label">ESPACE DU VOLUME PRINCIPAL</span><strong>{{ rootDisk ? formatBytes(rootDisk.availableBytes) : '—' }}</strong></div></article>
            </section>
            <section class="panel storage-panel">
              <div class="panel-heading storage-panel-heading"><div><h2>Volumes montés</h2><p>Capacités par montage, non additionnées · actualisées toutes les 30 secondes.</p></div><label class="mount-filter"><input v-model="showTechnicalMounts" type="checkbox" /><span>Afficher les montages techniques</span></label></div>
              <div class="table-scroll">
                <table class="storage-table">
                  <thead><tr><th>Point de montage</th><th>Nom du volume</th><th>Système de fichiers</th><th>Utilisation</th><th class="align-right">Disponible</th></tr></thead>
                  <tbody>
                    <tr v-for="disk in displayDisks" :key="`${disk.mountPoint}-${disk.name}`">
                      <td><div class="mount-cell"><span class="disk-symbol"><AppIcon name="drive" :size="15" /></span><strong :title="disk.mountPoint">{{ disk.mountPoint }}</strong><span v-if="disk.technical" class="technical-tag">Technique</span><span v-if="disk.removable" class="removable-tag">Amovible</span></div></td>
                      <td class="muted-cell">{{ disk.name || '—' }}</td>
                      <td><span class="filesystem-tag">{{ disk.fileSystem || '—' }}</span></td>
                      <td class="storage-usage-cell"><div class="storage-usage-line"><div class="disk-track"><i :style="{ width: `${ratio(disk.usedBytes, disk.totalBytes)}%` }" /></div><span>{{ formatPercent(ratio(disk.usedBytes, disk.totalBytes)) }}</span></div><small>{{ formatBytes(disk.usedBytes) }} sur {{ formatBytes(disk.totalBytes) }}</small></td>
                      <td class="align-right numeric-cell">{{ formatBytes(disk.availableBytes) }}</td>
                    </tr>
                    <tr v-if="!displayDisks.length"><td colspan="5" class="empty-row">Aucun volume n’a été signalé par le système.</td></tr>
                  </tbody>
                </table>
              </div>
            </section>
          </template>

          <template v-else>
            <AgentWatcherPage :watcher="snapshot.agents" />
          </template>
        </template>

        <div v-else-if="!loading" class="fatal-error panel">
          <div class="fatal-icon"><AppIcon name="gauge" :size="22" /></div>
          <h2>Impossible de lire les données système</h2>
          <p>{{ error || 'Le moniteur natif n’a renvoyé aucun résultat.' }}</p>
          <button class="primary-button" @click="refreshSnapshot"><AppIcon name="refresh" :size="16" /> Réessayer</button>
        </div>

        <footer class="page-footer"><span><AppIcon name="shield" :size="13" /> Collecte locale en lecture seule</span><span>{{ autoRefresh ? `Actualisation toutes les ${refreshInterval} secondes` : 'Actualisation automatique en pause' }}</span></footer>
      </div>
    </main>

    <div v-if="selectedProcess" class="modal-backdrop" @click.self="selectedProcess = null" @keydown.esc="selectedProcess = null">
      <aside class="process-detail panel" role="dialog" aria-modal="true" aria-labelledby="process-detail-title">
        <div class="detail-topline"><span class="detail-eyebrow">DÉTAIL DU PROCESSUS</span><button class="icon-button" aria-label="Fermer" @click="selectedProcess = null"><AppIcon name="close" :size="18" /></button></div>
        <div class="detail-process-heading"><span class="detail-process-icon"><AppIcon name="terminal" :size="21" /></span><div><h2 id="process-detail-title">{{ selectedProcess.name || 'Processus sans nom' }}</h2><span>PID {{ selectedProcess.pid }}</span></div></div>
        <div class="detail-metrics"><div><span>CPU</span><strong>{{ formatPercent(selectedProcess.cpuPercent) }}</strong></div><div><span>Mémoire RAM</span><strong>{{ formatBytes(selectedProcess.memoryBytes) }}</strong></div></div>
        <div class="detail-section"><span class="detail-label">IDENTITÉ</span><div class="detail-row"><span>Utilisateur</span><strong>{{ selectedProcess.user }}</strong></div><div class="detail-row"><span>PID parent</span><strong>{{ selectedProcess.parentPid ?? '—' }}</strong></div><div class="detail-row"><span>Durée d’exécution</span><strong>{{ formatDuration(selectedProcess.runTimeSeconds) }}</strong></div></div>
        <div class="detail-section command-section"><span class="detail-label">COMMANDE</span><code>{{ selectedCommandLoading ? 'Chargement…' : selectedCommand || 'Commande indisponible' }}</code><small v-if="selectedCommandRedacted" class="command-note">Les valeurs reconnues comme sensibles sont masquées.</small></div>
        <div class="detail-readonly"><AppIcon name="shield" :size="15" /> Informations système en lecture seule</div>
      </aside>
    </div>
  </div>
</template>

<style>
@import "./style.css";
</style>
