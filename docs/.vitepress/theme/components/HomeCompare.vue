<script setup lang="ts">
/**
 * Honest comparison table — the "is this the right tool?" decision aid.
 * Mirrors the table in /guide/what-is-tinyvault so the landing page
 * doesn't contradict the docs.
 */
const rows = [
  { label: 'Single binary, no account', us: true, op1: false, pass: true, vault: false, doppler: false },
  { label: 'Local-only by default', us: true, op1: false, pass: true, vault: 'config', doppler: false },
  { label: 'Per-project key isolation', us: true, op1: 'vaults', pass: false, vault: true, doppler: true },
  { label: 'First-class MCP for agents', us: true, op1: false, pass: false, vault: false, doppler: false },
  { label: 'Redaction-safe agent exec', us: true, op1: false, pass: false, vault: false, doppler: false },
  { label: 'Commit-safe encrypted .env', us: true, op1: false, pass: 'GPG', vault: false, doppler: false },
  { label: 'Versioned secrets + rollback', us: true, op1: false, pass: 'git', vault: true, doppler: true },
  { label: 'Team sync between people', us: false, op1: true, pass: 'git/GPG', vault: true, doppler: true },
  { label: 'Passphrase / account recovery', us: false, op1: true, pass: 'GPG', vault: 'shards', doppler: true },
  { label: 'Dynamic / short-lived secrets', us: false, op1: false, pass: false, vault: true, doppler: 'limited' },
]

const cols = [
  { key: 'us', name: 'TinyVault', brand: true },
  { key: 'op1', name: '1Password CLI' },
  { key: 'pass', name: 'pass' },
  { key: 'vault', name: 'HashiCorp Vault' },
  { key: 'doppler', name: 'Doppler' },
] as const

type Cell = boolean | string
const render = (c: Cell) => {
  if (c === true) return '✓'
  if (c === false) return '—'
  return String(c)
}
</script>

<template>
  <section class="tv-cmp">
    <header class="tv-section__head">
      <h2 class="tv-section__title">An honest comparison</h2>
      <p class="tv-section__sub">TinyVault is the local-first, agent-first complement — not a production Vault replacement. Pick the tool that fits the job.</p>
    </header>
    <div class="tv-cmp__scroll">
      <table class="tv-cmp__table">
        <thead>
          <tr>
            <th class="tv-cmp__rowhead" />
            <th
              v-for="c in cols"
              :key="c.key"
              :class="['tv-cmp__col', { 'tv-cmp__col--brand': c.brand }]"
            >
              {{ c.name }}
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in rows" :key="r.label">
            <th class="tv-cmp__rowhead">{{ r.label }}</th>
            <td
              v-for="c in cols"
              :key="c.key"
              :class="['tv-cmp__cell', { 'tv-cmp__cell--brand': c.brand, 'tv-cmp__cell--yes': r[c.key] === true, 'tv-cmp__cell--no': r[c.key] === false }]"
            >
              {{ render(r[c.key] as Cell) }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <p class="tv-cmp__note">
      Full breakdown, including threat-model trade-offs, in
      <a href="/guide/what-is-tinyvault#how-it-compares">What is TinyVault?</a>
    </p>
  </section>
</template>