<script setup lang="ts">
import AppIcon from "./AppIcon.vue";
import type { ProcessInfo, ProcessSortKey, SortDirection } from "../types/monitor";

const props = withDefaults(defineProps<{
  processes: ProcessInfo[];
  sortBy: ProcessSortKey;
  sortDirection: SortDirection;
  compact?: boolean;
  selectedPid?: number | null;
}>(), { compact: false, selectedPid: null });

const emit = defineEmits<{
  select: [process: ProcessInfo];
  sort: [key: ProcessSortKey];
}>();

const sortLabel = (key: ProcessSortKey) => props.sortBy === key
  ? (props.sortDirection === "asc" ? "↑" : "↓")
  : "↕";

const formatBytes = (bytes: number) => {
  if (bytes < 1) return "0 o";
  const units = ["o", "Ko", "Mo", "Go", "To"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / (1024 ** index);
  return `${new Intl.NumberFormat("fr-FR", { maximumFractionDigits: index > 1 ? 1 : 0 }).format(value)} ${units[index]}`;
};

const formatPercent = (value: number) => `${new Intl.NumberFormat("fr-FR", { maximumFractionDigits: 1 }).format(value)} %`;
</script>

<template>
  <div class="table-scroll">
    <table class="process-table" :class="{ compact }">
      <thead>
        <tr>
          <th v-if="!compact"><button class="sort-button" @click="emit('sort', 'pid')">PID <span>{{ sortLabel('pid') }}</span></button></th>
          <th><button class="sort-button" @click="emit('sort', 'name')">Processus <span>{{ sortLabel('name') }}</span></button></th>
          <th v-if="!compact"><button class="sort-button" @click="emit('sort', 'user')">Utilisateur <span>{{ sortLabel('user') }}</span></button></th>
          <th class="align-right"><button class="sort-button" @click="emit('sort', 'cpuPercent')">CPU <span>{{ sortLabel('cpuPercent') }}</span></button></th>
          <th class="align-right"><button class="sort-button" @click="emit('sort', 'memoryBytes')">Mémoire <span>{{ sortLabel('memoryBytes') }}</span></button></th>
          <th v-if="!compact" class="align-right"><button class="sort-button" @click="emit('sort', 'runTimeSeconds')">Durée <span>{{ sortLabel('runTimeSeconds') }}</span></button></th>
          <th class="row-action"><span class="sr-only">Détails</span></th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="process in processes"
          :key="process.pid"
          :class="{ selected: process.pid === selectedPid }"
          tabindex="0"
          @click="emit('select', process)"
          @keydown.enter="emit('select', process)"
          @keydown.space.prevent="emit('select', process)"
        >
          <td v-if="!compact" class="pid-cell">{{ process.pid }}</td>
          <td>
            <div class="process-name-cell">
              <span class="process-glyph"><AppIcon name="terminal" :size="15" /></span>
              <span class="process-name-text">
                <strong>{{ process.name || 'Processus sans nom' }}</strong>
                <small v-if="compact">{{ process.user }} · {{ process.pid }}</small>
              </span>
            </div>
          </td>
          <td v-if="!compact" class="muted-cell">{{ process.user }}</td>
          <td class="align-right numeric-cell">
            <span>{{ formatPercent(process.cpuPercent) }}</span>
            <span class="mini-meter"><i :style="{ width: `${Math.min(process.cpuPercent, 100)}%` }" /></span>
          </td>
          <td class="align-right numeric-cell">{{ formatBytes(process.memoryBytes) }}</td>
          <td v-if="!compact" class="align-right muted-cell">{{ Math.floor(process.runTimeSeconds / 3600) }} h {{ Math.floor((process.runTimeSeconds % 3600) / 60) }} min</td>
          <td class="row-action"><AppIcon name="chevron" :size="15" /></td>
        </tr>
        <tr v-if="processes.length === 0">
          <td :colspan="compact ? 4 : 7" class="empty-row">Aucun processus ne correspond à cette recherche.</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
