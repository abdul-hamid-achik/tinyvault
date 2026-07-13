<script setup lang="ts">
/**
 * Animated terminal showcase — a fake `tvault` session that sells the
 * one-binary loop without being a video. Pure CSS, no JS runtime cost
 * beyond the blink caret.
 */
</script>

<template>
  <div class="tv-term">
    <div class="tv-term__bar">
      <span class="tv-term__dot tv-term__dot--red" />
      <span class="tv-term__dot tv-term__dot--amber" />
      <span class="tv-term__dot tv-term__dot--green" />
      <span class="tv-term__title">tvault — zsh</span>
    </div>
    <pre class="tv-term__body"><span class="tv-prompt">$</span> brew install abdul-hamid-achik/tap/tvault
<span class="tv-ok">✓</span> tvault poured, no servers started
<span class="tv-prompt">$</span> tvault init
<span class="tv-dim">  ✔ created ~/.tvault/vault.db  (AES-256-GCM + Argon2id)</span>
<span class="tv-prompt">$</span> tvault set DATABASE_URL <span class="tv-str">"postgres://app@localhost/db"</span>
<span class="tv-prompt">$</span> tvault set API_KEY <span class="tv-str">"sk-live-…"</span>
<span class="tv-prompt">$</span> tvault run -- npm start
<span class="tv-dim">  injecting 2 secrets into: node ./server.js</span>
<span class="tv-dim">  ✔ DATABASE_URL, API_KEY never touched a .env file</span>
<span class="tv-prompt">$</span> tvault mcp<span class="tv-caret"> </span></pre>
  </div>
</template>