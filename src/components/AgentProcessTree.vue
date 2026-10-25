<script setup lang="ts">
import { ref } from "vue";
import type { AgentProcessNode } from "../types/monitor";

defineOptions({ name: "AgentProcessTree" });

const props = defineProps<{
  node: AgentProcessNode;
  depth?: number;
  selectedIdentity?: string;
}>();
const emit = defineEmits<{ select: [node: AgentProcessNode] }>();
const expanded = ref((props.depth ?? 0) < 2);
</script>

<template>
  <li class="agent-tree-item">
    <div class="agent-tree-row" :style="{ '--tree-depth': depth ?? 0 }">
      <button
        class="tree-toggle"
        :disabled="!node.children.length"
        :aria-label="expanded ? 'Réduire les processus enfants' : 'Développer les processus enfants'"
        :aria-expanded="node.children.length ? expanded : undefined"
        @click="expanded = !expanded"
      >
        <span v-if="node.children.length">{{ expanded ? '−' : '+' }}</span>
        <span v-else class="tree-leaf">·</span>
      </button>
      <button
        class="tree-process-button"
        :class="{ selected: selectedIdentity === node.identity, detached: node.detached }"
        @click="emit('select', node)"
      >
        <span class="tree-process-main">
          <strong>{{ node.name || 'Processus sans nom' }}</strong>
          <small>{{ node.processType }} · PID {{ node.pid }} · PPID {{ node.parentPid ?? '—' }}</small>
        </span>
        <span class="tree-process-metric">{{ node.cpuPercent.toLocaleString('fr-FR', { maximumFractionDigits: 1 }) }} % CPU</span>
        <span class="tree-process-metric">{{ (node.memoryBytes / 1_048_576).toLocaleString('fr-FR', { maximumFractionDigits: 0 }) }} Mio</span>
        <span v-if="node.detached" class="detached-tag">Détaché</span>
      </button>
    </div>
    <ul v-if="expanded && node.children.length" class="agent-tree-children">
      <AgentProcessTree
        v-for="child in node.children"
        :key="child.identity"
        :node="child"
        :depth="(depth ?? 0) + 1"
        :selected-identity="selectedIdentity"
        @select="emit('select', $event)"
      />
    </ul>
  </li>
</template>
