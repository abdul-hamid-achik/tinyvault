<script setup lang="ts">
/**
 * Three-step "how it works" — the minimum viable mental model.
 * Each step links deeper into the guide.
 */
const steps = [
  {
    n: '01',
    title: 'Init a vault',
    body: 'One command creates a single encrypted bbolt file. Argon2id derives your KEK; per-project DEKs wrap every value. No account, no server, no network.',
    link: '/guide/getting-started',
    cta: 'Getting Started',
  },
  {
    n: '02',
    title: 'Store & inject',
    body: '`tvault set` writes a value; `tvault run --` execs your app with secrets injected as env vars — plaintext never sits in a `.env` file. Versioned, searchable, recoverable.',
    link: '/guide/run-and-env',
    cta: 'Run & Environment',
  },
  {
    n: '03',
    title: 'Hand it to an agent',
    body: 'Point an MCP client at `tvault mcp`. 49 tools, value-free by default: inject, seal to a recipient, write a redacted env file. The model never sees the secret.',
    link: '/mcp/',
    cta: 'MCP overview',
  },
]
</script>

<template>
  <section class="tv-how">
    <header class="tv-section__head">
      <h2 class="tv-section__title">From zero to sealed in three steps</h2>
      <p class="tv-section__sub">No YAML manifests, no Helm charts, no cloud project. Just a binary and a passphrase.</p>
    </header>
    <div class="tv-how__grid">
      <a
        v-for="s in steps"
        :key="s.n"
        :href="s.link"
        class="tv-how__step"
      >
        <span class="tv-how__num">{{ s.n }}</span>
        <h3 class="tv-how__title">{{ s.title }}</h3>
        <p class="tv-how__body">{{ s.body }}</p>
        <span class="tv-how__cta">{{ s.cta }} →</span>
      </a>
    </div>
  </section>
</template>