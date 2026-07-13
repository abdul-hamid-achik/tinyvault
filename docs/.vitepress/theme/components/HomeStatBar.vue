<script setup lang="ts">
/**
 * Trust strip — the one-glance "why this is interesting" numbers.
 * Rendered right under the hero so first-time visitors get the scale
 * before the feature grid.
 */
const stats = [
  { value: '1', label: 'Binary', sub: 'CLI + MCP + TUI' },
  { value: '0', label: 'Servers', sub: 'no backend, no cloud' },
  { value: '49', label: 'MCP tools', sub: 'value-free by default' },
  { value: 'AES-256', label: 'GCM', sub: 'Argon2id KEK' },
]
</script>

<template>
  <div class="tv-statbar">
    <div
      v-for="s in stats"
      :key="s.label"
      class="tv-stat"
    >
      <span class="tv-stat__value">{{ s.value }}</span>
      <span class="tv-stat__label">{{ s.label }}</span>
      <span class="tv-stat__sub">{{ s.sub }}</span>
    </div>
  </div>
</template>