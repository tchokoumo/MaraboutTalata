<script setup lang="ts">
withDefaults(defineProps<{ name: string; size?: number }>(), { size: 18 });

const icons: Record<string, string[]> = {
  shield: ["M12 3 20 6v5c0 5-3.4 8.5-8 10-4.6-1.5-8-5-8-10V6l8-3Z", "m9 12 2 2 4-4"],
  overview: ["M3 3h8v8H3z", "M13 3h8v5h-8z", "M13 10h8v11h-8z", "M3 13h8v8H3z"],
  process: ["M4 5h16", "M4 12h16", "M4 19h16", "M8 5h.01", "M8 12h.01", "M8 19h.01"],
  storage: ["M4 5h16v14H4z", "M4 10h16", "M8 15h.01", "M12 15h.01"],
  network: ["M5 12.5a10 10 0 0 1 14 0", "M8 15.5a6 6 0 0 1 8 0", "M11 18.5a2 2 0 0 1 2 0", "M12 21h.01"],
  gauge: ["M4 19a9 9 0 1 1 16 0", "M12 13l4-4", "M7 19h10"],
  settings: ["M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z", "m19.4 15 .1.1a1.7 1.7 0 0 1-2.4 2.4l-.1-.1a1.7 1.7 0 0 0-2.9 1.2v.2a1.7 1.7 0 0 1-3.4 0v-.2a1.7 1.7 0 0 0-2.9-1.2l-.1.1a1.7 1.7 0 0 1-2.4-2.4l.1-.1A1.7 1.7 0 0 0 4.2 12h-.2a1.7 1.7 0 0 1 0-3.4h.2a1.7 1.7 0 0 0 1.2-2.9l-.1-.1a1.7 1.7 0 0 1 2.4-2.4l.1.1a1.7 1.7 0 0 0 2.9-1.2v-.2a1.7 1.7 0 0 1 3.4 0v.2a1.7 1.7 0 0 0 2.9 1.2l.1-.1a1.7 1.7 0 0 1 2.4 2.4l-.1.1a1.7 1.7 0 0 0 1.2 2.9h.2a1.7 1.7 0 0 1 0 3.4h-.2a1.7 1.7 0 0 0-1.2 2.9Z"],
  sun: ["M12 4V2", "M12 22v-2", "M4.93 4.93 3.5 3.5", "M20.5 20.5l-1.43-1.43", "M4 12H2", "M22 12h-2", "M4.93 19.07 3.5 20.5", "M20.5 3.5l-1.43 1.43", "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z"],
  moon: ["M20.9 13A9 9 0 0 1 11 3.1 9 9 0 1 0 20.9 13Z"],
  search: ["M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16Z", "m21 21-4.35-4.35"],
  refresh: ["M20 7v5h-5", "M4 17v-5h5", "M5.6 9A7 7 0 0 1 18 6l2 2", "M4 16l2 2a7 7 0 0 0 12.4-3"],
  chevron: ["m9 18 6-6-6-6"],
  close: ["m18 6-12 12", "m6 6 12 12"],
  cpu: ["M5 5h14v14H5z", "M9 9h6v6H9z", "M9 1v4", "M15 1v4", "M9 19v4", "M15 19v4", "M1 9h4", "M1 15h4", "M19 9h4", "M19 15h4"],
  memory: ["M5 7h14v10H5z", "M8 10h2v4H8z", "M13 10h3v4h-3z", "M8 3v4", "M12 3v4", "M16 3v4", "M8 17v4", "M12 17v4", "M16 17v4"],
  drive: ["M4 6h16v12H4z", "M4 10h16", "M8 14h.01", "M12 14h.01"],
  clock: ["M12 8v4l3 2", "M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z"],
  user: ["M20 21a8 8 0 0 0-16 0", "M12 13a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z"],
  terminal: ["m4 17 6-6-6-6", "M12 19h8"],
  check: ["m5 12 4 4L19 6"],
};

const pathsFor = (name: string) => icons[name] ?? icons.gauge;
</script>

<template>
  <svg
    :width="size"
    :height="size"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    stroke-width="1.7"
    stroke-linecap="round"
    stroke-linejoin="round"
    aria-hidden="true"
  >
    <path v-for="path in pathsFor(name)" :key="path" :d="path" />
  </svg>
</template>
