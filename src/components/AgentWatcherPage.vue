<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { invoke, isTauri } from "@tauri-apps/api/core";
import AgentProcessTree from "./AgentProcessTree.vue";
import type {
  AgentAlert,
  AgentKind,
  AgentProcessNode,
  AgentSession,
  AgentWatchConfig,
  AgentWatchSnapshot,
} from "../types/monitor";

const props = defineProps<{ watcher: AgentWatchSnapshot }>();
type AgentFilter = "all" | AgentKind;
type ContentTab = "sessions" | "alerts";

const filterAgent = ref<AgentFilter>("all");
const search = ref("");
const activeTab = ref<ContentTab>("sessions");
const selectedSessionId = ref("");
const selectedNode = ref<AgentProcessNode | null>(null);
const configDraft = ref<AgentWatchConfig>({ ...props.watcher.config });
const savingConfig = ref(false);
const configError = ref("");
const configSaved = ref(false);

watch(() => JSON.stringify(props.watcher.config), () => {
  const config = props.watcher.config;
  configDraft.value = { ...config };
});
watch(() => props.watcher.sessions, (currentSessions) => {
  if (!currentSessions.some((session) => session.id === selectedSessionId.value)) {
    selectedSessionId.value = currentSessions[0]?.id ?? "";
  }
  const session = currentSessions.find((candidate) => candidate.id === selectedSessionId.value);
  const currentNode = selectedNode.value
    ? findProcessNode(session?.tree ?? [], selectedNode.value.identity)
    : null;
  if (currentNode) {
    selectedNode.value = currentNode;
  } else {
    selectedNode.value = session?.tree[0] ?? null;
  }
}, { immediate: true });

const sessions = computed(() => props.watcher.sessions);
const filteredSessions = computed(() => {
  const query = search.value.trim().toLocaleLowerCase("fr");
  return sessions.value.filter((session) => {
    if (filterAgent.value !== "all" && session.agent !== filterAgent.value) return false;
    if (!query) return true;
    return [session.agentName, session.projectName, session.projectPath ?? "", String(session.rootPid)]
      .some((value) => value.toLocaleLowerCase("fr").includes(query));
  });
});
const allAlerts = computed(() => sessions.value.flatMap((session) => session.alerts.map((alert) => ({ session, alert }))));
const filteredAlerts = computed(() => {
  const query = search.value.trim().toLocaleLowerCase("fr");
  return allAlerts.value.filter(({ session, alert }) => {
    if (filterAgent.value !== "all" && session.agent !== filterAgent.value) return false;
    if (!query) return true;
    return [session.agentName, session.projectName, alert.title, alert.message, String(alert.pid)]
      .some((value) => value.toLocaleLowerCase("fr").includes(query));
  });
});
const agentCounts = computed(() => ({
  codex: sessions.value.filter((session) => session.agent === "codex").length,
  claude: sessions.value.filter((session) => session.agent === "claude_code").length,
}));
const alertCount = computed(() => allAlerts.value.filter(({ alert }) => alert.classification !== "insufficient").length);

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 1) return "0 o";
  const units = ["o", "Ko", "Mo", "Go", "To"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / (1024 ** index)).toLocaleString("fr-FR", { maximumFractionDigits: index > 1 ? 1 : 0 })} ${units[index]}`;
}

function formatDuration(seconds: number): string {
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  if (days) return `${days} j ${hours} h`;
  if (hours) return `${hours} h ${minutes} min`;
  return `${minutes} min ${seconds % 60} s`;
}

function formatStartTime(seconds: number): string {
  if (!seconds) return "Inconnu";
  return new Intl.DateTimeFormat("fr-FR", { dateStyle: "medium", timeStyle: "medium" })
    .format(new Date(seconds * 1_000));
}

function percent(value: number): string {
  return `${value.toLocaleString("fr-FR", { maximumFractionDigits: 1 })} %`;
}

function findProcessNode(nodes: AgentProcessNode[], identity: string): AgentProcessNode | null {
  for (const node of nodes) {
    if (node.identity === identity) return node;
    const child = findProcessNode(node.children, identity);
    if (child) return child;
  }
  return null;
}

function selectSession(session: AgentSession): void {
  selectedSessionId.value = session.id;
  selectedNode.value = session.tree[0] ?? null;
}

function classificationLabel(classification: AgentAlert["classification"]): string {
  return {
    fact: "Observation factuelle",
    heuristic: "Alerte heuristique",
    insufficient: "Information insuffisante",
  }[classification];
}

async function saveConfig(): Promise<void> {
  if (!isTauri()) {
    configError.value = "La configuration doit être appliquée dans l’application Tauri.";
    return;
  }
  savingConfig.value = true;
  configError.value = "";
  configSaved.value = false;
  try {
    configDraft.value = await invoke<AgentWatchConfig>("set_agent_watch_config", { config: configDraft.value });
    configSaved.value = true;
  } catch (cause) {
    configError.value = cause instanceof Error ? cause.message : String(cause);
  } finally {
    savingConfig.value = false;
  }
}
</script>

<template>
  <section class="agent-watcher-page">
    <div v-if="watcher.coverage.restricted" class="agent-coverage-warning" role="status">
      <strong>Accès partiel à /proc</strong>
      <span>{{ watcher.coverage.unreadableCandidates }} processus candidats n’ont pas pu être lus. La détection peut être incomplète avec les permissions actuelles.</span>
    </div>

    <section class="agent-summary-grid" aria-label="Résumé des agents détectés">
      <article class="panel agent-summary-card codex-summary">
        <div><span class="agent-summary-kicker">CODEX CLI</span><strong>{{ agentCounts.codex }}</strong><small>session{{ agentCounts.codex > 1 ? 's' : '' }} détectée{{ agentCounts.codex > 1 ? 's' : '' }}</small></div>
        <span class="agent-summary-mark">C</span>
      </article>
      <article class="panel agent-summary-card claude-summary">
        <div><span class="agent-summary-kicker">CLAUDE CODE</span><strong>{{ agentCounts.claude }}</strong><small>session{{ agentCounts.claude > 1 ? 's' : '' }} détectée{{ agentCounts.claude > 1 ? 's' : '' }}</small></div>
        <span class="agent-summary-mark">A</span>
      </article>
      <article class="panel agent-summary-card alert-summary">
        <div><span class="agent-summary-kicker">ALERTES ACTIVES</span><strong>{{ alertCount }}</strong><small>{{ watcher.coverage.detectedProcesses }} processus classifiés</small></div>
        <span class="agent-summary-mark">!</span>
      </article>
    </section>

    <section class="panel agent-controls">
      <div class="agent-tabs" role="tablist" aria-label="Vue des agents">
        <button role="tab" :aria-selected="activeTab === 'sessions'" :class="{ active: activeTab === 'sessions' }" @click="activeTab = 'sessions'">Sessions <span>{{ sessions.length }}</span></button>
        <button role="tab" :aria-selected="activeTab === 'alerts'" :class="{ active: activeTab === 'alerts' }" @click="activeTab = 'alerts'">Alertes <span>{{ alertCount }}</span></button>
      </div>
      <div class="agent-filter-row">
        <label class="agent-search"><span aria-hidden="true">⌕</span><input v-model="search" type="search" placeholder="Projet, PID ou alerte…" aria-label="Rechercher les sessions et alertes" /></label>
        <label class="agent-select-label"><span>Agent</span><select v-model="filterAgent" aria-label="Filtrer par agent"><option value="all">Tous</option><option value="codex">Codex CLI</option><option value="claude_code">Claude Code</option></select></label>
      </div>
    </section>

    <section v-if="activeTab === 'sessions'" class="agent-session-list">
      <div v-if="!filteredSessions.length" class="panel agent-empty-state">
        <div class="agent-empty-glyph"><span>⌘</span></div>
        <h2>{{ sessions.length ? 'Aucune session correspondante' : 'Aucune session IA détectée' }}</h2>
        <p v-if="sessions.length">Modifiez la recherche ou le filtre pour afficher les sessions déjà observées.</p>
        <p v-else-if="watcher.coverage.restricted">Les processus candidats existent, mais les permissions de lecture de /proc empêchent de confirmer une session.</p>
        <p v-else>Les processus Codex CLI et Claude Code apparaîtront ici lorsqu’une session active sera confirmée sur cette machine.</p>
        <small>Les données sont lues sur le système local. Aucune session fictive n’est affichée.</small>
      </div>

      <article
        v-for="session in filteredSessions"
        :key="session.id"
        class="panel agent-session-card"
        :class="[{ selected: selectedSessionId === session.id }, `agent-${session.agent}`]"
      >
        <header class="agent-session-head">
          <button class="agent-session-title" @click="selectSession(session)">
            <span class="agent-session-icon"><span>{{ session.agent === 'codex' ? 'C' : 'A' }}</span></span>
            <span><strong>{{ session.agentName }}</strong><small>PID racine {{ session.rootPid }} · Démarré {{ formatStartTime(session.rootStartTimeSeconds) }}</small></span>
          </button>
          <div class="agent-confidence" :class="`confidence-${session.confidence}`"><span />Confiance {{ session.confidence === 'high' ? 'élevée' : 'moyenne' }}</div>
        </header>

        <div class="agent-session-project">
          <span class="project-mark">⌂</span>
          <div><strong>{{ session.projectName }}</strong><small>{{ session.projectPath ?? 'Répertoire de projet inconnu' }}</small></div>
          <span class="session-process-count">{{ session.processCount }} processus</span>
        </div>

        <div class="agent-session-metrics">
          <div><span>CPU</span><strong>{{ percent(session.cpuPercent) }}</strong></div>
          <div><span>Mémoire RAM</span><strong>{{ formatBytes(session.memoryBytes) }}</strong></div>
          <div><span>Durée</span><strong>{{ formatDuration(session.runTimeSeconds) }}</strong></div>
          <div><span>Groupe / session</span><strong>{{ session.processGroupId ?? '—' }} / {{ session.linuxSessionId ?? '—' }}</strong></div>
        </div>

        <div v-if="!session.historyReady" class="agent-info-note"><span>i</span>Historique insuffisant pour les tendances. L’analyse se complète aux prochains échantillons.</div>
        <div v-if="session.detachedProcesses" class="agent-detached-note">{{ session.detachedProcesses }} processus lié{{ session.detachedProcesses > 1 ? 's' : '' }} par l’historique de cette session après disparition du parent.</div>

        <div class="agent-session-body">
          <section class="agent-tree-section">
            <div class="agent-section-heading"><div><h3>Arbre des processus</h3><p>Filiation active observée dans Linux</p></div><span>{{ session.processCount }} nœuds</span></div>
            <ul class="agent-process-tree">
              <AgentProcessTree
                v-for="node in session.tree"
                :key="node.identity"
                :node="node"
                :selected-identity="selectedNode?.identity"
                @select="selectedNode = $event; selectedSessionId = session.id"
              />
            </ul>
          </section>

          <aside class="agent-node-detail">
            <template v-if="selectedSessionId === session.id && selectedNode">
              <span class="detail-label">PROCESSUS SÉLECTIONNÉ</span>
              <h3>{{ selectedNode.name }}</h3>
              <div class="agent-detail-grid"><span>PID / PPID</span><strong>{{ selectedNode.pid }} / {{ selectedNode.parentPid ?? '—' }}</strong><span>Identité</span><strong>{{ selectedNode.identity }}</strong><span>Début</span><strong>{{ formatStartTime(selectedNode.startTimeSeconds) }}</strong><span>État observé</span><strong>{{ selectedNode.state ?? 'Inconnu' }}</strong><span>Type</span><strong>{{ selectedNode.processType }}</strong><span>Groupe / session</span><strong>{{ selectedNode.processGroupId ?? '—' }} / {{ selectedNode.linuxSessionId ?? '—' }}</strong><span>Répertoire courant</span><strong class="path-value">{{ selectedNode.workingDirectory ?? 'Inconnu' }}</strong></div>
            </template>
            <div v-else class="agent-node-placeholder">Sélectionnez un processus pour consulter ses détails.</div>
          </aside>
        </div>

        <details class="agent-proof-details">
          <summary>Preuves de classification <span>{{ session.provenance.length }} sources</span></summary>
          <div class="agent-proof-columns">
            <div><strong>Éléments observés</strong><ul><li v-for="proof in session.classificationEvidence" :key="proof">{{ proof }}</li><li v-if="!session.classificationEvidence.length">Aucune preuve complémentaire disponible.</li></ul></div>
            <div><strong>Provenance des données</strong><ul><li v-for="source in session.provenance" :key="source">{{ source }}</li></ul></div>
          </div>
        </details>
      </article>
    </section>

    <section v-else class="agent-alert-list">
      <article v-for="({ session, alert }) in filteredAlerts" :key="`${session.id}-${alert.id}`" class="panel agent-alert-card" :class="`classification-${alert.classification}`">
        <div class="alert-classification"><span>{{ alert.classification === 'fact' ? '●' : alert.classification === 'heuristic' ? '!' : 'i' }}</span>{{ classificationLabel(alert.classification) }}</div>
        <div class="alert-main"><div class="alert-topline"><strong>{{ alert.title }}</strong><span>{{ session.agentName }} · {{ session.projectName }}</span></div><p>{{ alert.message }}</p><div class="alert-evidence"><span v-for="evidence in alert.evidence" :key="evidence">{{ evidence }}</span></div></div>
        <div class="alert-process">PID {{ alert.pid }}<small>{{ alert.processName }}</small></div>
      </article>
      <div v-if="!filteredAlerts.length" class="panel agent-empty-state compact-empty">
        <h2>{{ allAlerts.length ? 'Aucune alerte correspondante' : 'Aucune alerte active' }}</h2>
        <p>{{ allAlerts.length ? 'Ajustez les filtres pour consulter les alertes actives.' : 'Les observations factuelles, alertes heuristiques et informations insuffisantes seront listées ici.' }}</p>
      </div>
    </section>

    <details class="panel agent-config-panel">
      <summary><span><strong>Seuils d’analyse</strong><small>Hystérésis appliquée à l’ouverture et à la fermeture des alertes</small></span><span class="config-edit-label">Configurer</span></summary>
      <form class="agent-config-form" @submit.prevent="saveConfig">
        <label><span>CPU élevé (%)</span><input v-model.number="configDraft.highCpuPercent" type="number" min="10" max="100" step="1" /></label>
        <label><span>Durée CPU (secondes)</span><input v-model.number="configDraft.highCpuSeconds" type="number" min="10" max="600" step="5" /></label>
        <label><span>Mémoire élevée (Mio)</span><input v-model.number="configDraft.highMemoryMib" type="number" min="128" max="32768" step="128" /></label>
        <label><span>Durée mémoire (secondes)</span><input v-model.number="configDraft.highMemorySeconds" type="number" min="30" max="3600" step="15" /></label>
        <label><span>Croissance mémoire (Mio)</span><input v-model.number="configDraft.memoryGrowthMib" type="number" min="32" max="8192" step="32" /></label>
        <label><span>Fenêtre de croissance (secondes)</span><input v-model.number="configDraft.memoryGrowthWindowSeconds" type="number" min="30" max="1800" step="15" /></label>
        <label><span>Longue durée (heures)</span><input v-model.number="configDraft.longRuntimeHours" type="number" min="1" max="168" step="1" /></label>
        <label><span>Nouveaux descendants</span><input v-model.number="configDraft.rapidChildrenCount" type="number" min="3" max="200" step="1" /></label>
        <label><span>Fenêtre descendants (secondes)</span><input v-model.number="configDraft.rapidChildrenWindowSeconds" type="number" min="15" max="1800" step="15" /></label>
        <div class="agent-config-footer"><span>Configuration en mémoire jusqu’à la fermeture de l’application.</span><span v-if="configError" class="config-error" role="alert">{{ configError }}</span><span v-else-if="configSaved" class="config-saved" role="status">Seuils appliqués.</span><button class="primary-button" type="submit" :disabled="savingConfig">{{ savingConfig ? 'Application…' : 'Appliquer les seuils' }}</button></div>
      </form>
    </details>

    <footer class="agent-readonly-note"><span>⛨</span> Lecture seule · aucune commande, conversation ou valeur d’argument d’agent n’est collectée pour cette page.</footer>
  </section>
</template>
