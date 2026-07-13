<script setup lang="ts">
/**
 * Use-case cards — who TinyVault is for. Each links to the relevant guide.
 */
const cases = [
  {
    icon: '🧑‍💻',
    title: 'For developers',
    body: 'Kill `.env` sprawl on your laptop. One encrypted file, per-project isolation, two-way dotenv sync, and a `tvault run` that injects secrets without leaving plaintext behind.',
    points: ['Per-project DEKs', 'Two-way .env sync', 'Versioned & rollback', 'Interactive studio'],
    link: '/guide/what-is-tinyvault',
    cta: 'What is TinyVault?',
  },
  {
    icon: '🤖',
    title: 'For AI agents',
    body: 'A 49-tool MCP server where values stay out of the model context by design. Inject into a subprocess, seal to a recipient, or write a redacted env file — gated by a YAML access policy, not by the model.',
    points: ['Value-free by default', 'Output redaction', 'YAML access policy', 'Sealed recipients'],
    link: '/guide/for-ai-agents',
    cta: 'For AI Agents',
  },
  {
    icon: '🔁',
    title: 'For CI / CD',
    body: 'Passphrase-free, identity-based decrypt in CI. Commit-safe `.env.encrypted` (v2) survives rotation; `git-filter` keeps ciphertext in history and plaintext in your working tree. No vault server to reach over the network.',
    points: ['X25519 identity decrypt', 'Commit-safe v2 format', 'Transparent git filters', 'K8s SealedSecret'],
    link: '/guide/ci-cd',
    cta: 'CI/CD guide',
  },
]
</script>

<template>
  <section class="tv-use">
    <header class="tv-section__head">
      <h2 class="tv-section__title">Built for the people who touch secrets</h2>
      <p class="tv-section__sub">One vault, three surfaces — the CLI for humans, the studio for browsing, the MCP server for agents.</p>
    </header>
    <div class="tv-use__grid">
      <article
        v-for="c in cases"
        :key="c.title"
        class="tv-use__card"
      >
        <span class="tv-use__icon">{{ c.icon }}</span>
        <h3 class="tv-use__title">{{ c.title }}</h3>
        <p class="tv-use__body">{{ c.body }}</p>
        <ul class="tv-use__points">
          <li v-for="p in c.points" :key="p">{{ p }}</li>
        </ul>
        <a :href="c.link" class="tv-use__cta">{{ c.cta }} →</a>
      </article>
    </div>
  </section>
</template>