<script setup lang="ts">
/**
 * Final call-to-action band — the "go install it" closer.
 */
const ctas = [
  { text: 'Get Started', link: '/guide/getting-started', primary: true },
  { text: 'Read the threat model', link: '/reference/security', primary: false },
  { text: 'Star on GitHub', link: 'https://github.com/abdul-hamid-achik/tinyvault', primary: false },
]
</script>

<template>
  <section class="tv-cta">
    <div class="tv-cta__glow" />
    <div class="tv-cta__inner">
      <h2 class="tv-cta__title">Stop leaking secrets in <code>.env</code> files.</h2>
      <p class="tv-cta__sub">One binary. One encrypted file. Zero servers. Install in 10 seconds — keep your secrets, your machine, and your model context clean.</p>
      <div class="tv-cta__actions">
        <a
          v-for="c in ctas"
          :key="c.text"
          :href="c.link"
          :class="['tv-cta__btn', { 'tv-cta__btn--primary': c.primary }]"
        >
          {{ c.text }}
        </a>
      </div>
      <pre class="tv-cta__install"><span class="tv-cmd">brew install abdul-hamid-achik/tap/tvault</span></pre>
    </div>
  </section>
</template>