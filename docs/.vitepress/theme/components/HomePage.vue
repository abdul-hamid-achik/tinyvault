<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref } from 'vue'

const installCommand = 'brew install abdul-hamid-achik/tap/tvault'
const activeFlow = ref<'developer' | 'agent'>('developer')
const copied = ref(false)
let copyTimer: ReturnType<typeof setTimeout> | undefined

const flows = {
  developer: {
    label: 'Developer flow',
    lines: [
      { lead: '$', body: 'tvault init', tone: 'command' },
      { lead: '✓', body: 'created ~/.tvault/vault.db', tone: 'success' },
      { lead: '$', body: 'tvault set STRIPE_KEY --from-env .env', tone: 'command' },
      { lead: '✓', body: "Secret 'STRIPE_KEY' set successfully", tone: 'success' },
      { lead: '$', body: 'tvault run -- npm run deploy', tone: 'command' },
      { lead: '↳', body: 'secret injected into the child, not the parent shell', tone: 'muted' },
    ],
  },
  agent: {
    label: 'Agent flow',
    lines: [
      { lead: '→', body: 'vault_search_secrets  name_like="STRIPE_*"', tone: 'command' },
      { lead: '←', body: 'STRIPE_KEY · metadata only', tone: 'muted' },
      { lead: '→', body: 'vault_run_with_secrets  command="npm test"', tone: 'command' },
      { lead: '←', body: 'exit_code: 0 · stdout: "tests passed"', tone: 'success' },
      { lead: '✓', body: 'no dedicated plaintext field in this flow', tone: 'accent' },
    ],
  },
} as const
const flowOrder: Array<keyof typeof flows> = ['developer', 'agent']

const currentFlow = computed(() => flows[activeFlow.value])

async function copyInstall() {
  try {
    await navigator.clipboard.writeText(installCommand)
    copied.value = true
    if (copyTimer) clearTimeout(copyTimer)
    copyTimer = setTimeout(() => {
      copied.value = false
    }, 1800)
  } catch {
    copied.value = false
  }
}

async function handleFlowKeydown(event: KeyboardEvent) {
  const currentIndex = flowOrder.indexOf(activeFlow.value)
  let nextIndex: number | undefined

  if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
    nextIndex = (currentIndex + 1) % flowOrder.length
  } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
    nextIndex = (currentIndex - 1 + flowOrder.length) % flowOrder.length
  } else if (event.key === 'Home') {
    nextIndex = 0
  } else if (event.key === 'End') {
    nextIndex = flowOrder.length - 1
  }

  if (nextIndex === undefined) return

  event.preventDefault()
  activeFlow.value = flowOrder[nextIndex]
  await nextTick()
  document.getElementById(`tv-tab-${activeFlow.value}`)?.focus()
}

onBeforeUnmount(() => {
  if (copyTimer) clearTimeout(copyTimer)
})
</script>

<template>
  <main class="tv-home">
    <section class="tv-hero" aria-labelledby="tv-hero-title">
      <div class="tv-hero__copy">
        <p class="tv-eyebrow">
          <span class="tv-eyebrow__mark" aria-hidden="true" />
          Local-first secrets for developers and agents
        </p>

        <h1 id="tv-hero-title">
          Your vault stays local.
          <span>Your agents stay useful.</span>
        </h1>

        <p class="tv-hero__lede">
          TinyVault is one Go binary that encrypts developer secrets in a local
          vault and lets tools use them without routinely exposing values to the
          model. No account, hosted service, or control plane.
        </p>

        <div class="tv-hero__actions">
          <a class="tv-button tv-button--primary" href="/guide/getting-started">
            Start in five minutes
            <svg viewBox="0 0 20 20" aria-hidden="true">
              <path d="M4 10h11M11 6l4 4-4 4" />
            </svg>
          </a>
          <a class="tv-button tv-button--secondary" href="/mcp/">
            Connect an agent
          </a>
        </div>

        <button
          class="tv-install"
          type="button"
          :aria-label="copied ? 'Install command copied' : 'Copy Homebrew install command'"
          @click="copyInstall"
        >
          <span class="tv-install__prompt" aria-hidden="true">$</span>
          <code>{{ installCommand }}</code>
          <span class="tv-install__copy" aria-hidden="true">
            <svg v-if="!copied" viewBox="0 0 20 20">
              <rect x="7" y="7" width="9" height="9" rx="2" />
              <path d="M13 7V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h2" />
            </svg>
            <svg v-else viewBox="0 0 20 20">
              <path d="m4 10 4 4 8-9" />
            </svg>
          </span>
          <span class="sr-only" aria-live="polite">{{ copied ? 'Copied' : '' }}</span>
        </button>

        <dl class="tv-hero__proof" aria-label="TinyVault at a glance">
          <div>
            <dt>1</dt>
            <dd>Go binary</dd>
          </div>
          <div>
            <dt>1</dt>
            <dd>local vault database</dd>
          </div>
          <div>
            <dt>MCP</dt>
            <dd>agent tool surface</dd>
          </div>
          <div>
            <dt>0</dt>
            <dd>hosted backends</dd>
          </div>
        </dl>
      </div>

      <div class="tv-console" aria-label="TinyVault command examples">
        <div class="tv-console__topbar">
          <div class="tv-console__brand">
            <img src="/logo.svg" alt="" width="24" height="24">
            <span>tinyvault</span>
          </div>
          <span class="tv-console__status">
            <span aria-hidden="true" /> local
          </span>
        </div>

        <div class="tv-console__tabs" role="tablist" aria-label="Example workflow">
          <button
            v-for="(flow, key) in flows"
            :id="`tv-tab-${key}`"
            :key="key"
            type="button"
            role="tab"
            :aria-selected="activeFlow === key"
            aria-controls="tv-flow-panel"
            :tabindex="activeFlow === key ? 0 : -1"
            :class="{ 'is-active': activeFlow === key }"
            @click="activeFlow = key"
            @keydown="handleFlowKeydown"
          >
            {{ flow.label }}
          </button>
        </div>

        <div
          id="tv-flow-panel"
          class="tv-console__body"
          role="tabpanel"
          :aria-labelledby="`tv-tab-${activeFlow}`"
          tabindex="0"
        >
          <div
            v-for="(line, index) in currentFlow.lines"
            :key="`${activeFlow}-${index}`"
            :class="['tv-console__line', `is-${line.tone}`]"
          >
            <span class="tv-console__lead" aria-hidden="true">{{ line.lead }}</span>
            <span>{{ line.body }}</span>
          </div>
        </div>

        <div class="tv-console__footer">
          <span>
            <svg viewBox="0 0 20 20" aria-hidden="true">
              <path d="M10 2 4 4.5v4.4c0 4 2.5 7.1 6 8.6 3.5-1.5 6-4.6 6-8.6V4.5L10 2Z" />
              <path d="m7.5 9.8 1.7 1.7 3.5-4" />
            </svg>
            Values encrypted at rest
          </span>
          <span>AES-256-GCM · Argon2id</span>
        </div>
      </div>
    </section>

    <section class="tv-boundary" aria-labelledby="tv-boundary-title">
      <div class="tv-section-intro">
        <p class="tv-kicker">A smaller trust boundary</p>
        <h2 id="tv-boundary-title">Let the secret reach the process—not the conversation.</h2>
        <p>
          TinyVault’s agent tools are shaped around outcomes. Search returns
          metadata. Generation returns non-secret metadata. Export returns a file
          path. Execution injects values into a child process and can redact literal
          values in captured output when policy enables it. A raw read exists, but
          it is the explicit exception.
        </p>
      </div>

      <div class="tv-boundary__diagram" role="img" aria-label="A local vault database sends selected values to a child process while an AI agent receives metadata and command results">
        <div class="tv-boundary__source">
          <span class="tv-boundary__icon">
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <rect x="3" y="5" width="18" height="16" rx="3" />
              <circle cx="11" cy="13" r="4" />
              <path d="M11 9V6m0 11v3m4-7h3M7 13H4m15 0h2" />
            </svg>
          </span>
          <strong>Local vault database</strong>
          <small>encrypted values · readable metadata</small>
        </div>

        <div class="tv-boundary__rail" aria-hidden="true">
          <span>policy + audit</span>
        </div>

        <div class="tv-boundary__destinations">
          <div class="tv-boundary__node tv-boundary__node--process">
            <span>Child process</span>
            <strong>Receives selected values as environment variables</strong>
          </div>
          <div class="tv-boundary__node">
            <span>Typical agent response</span>
            <strong>Receives metadata, paths, ciphertext, or command output; raw reads remain an explicit exception</strong>
          </div>
        </div>
      </div>

      <p class="tv-boundary__note">
        Redaction reduces accidental leaks; it is not a sandbox. The
        <a href="/reference/security">threat model</a> explains the boundary in full.
      </p>
    </section>

    <section class="tv-surfaces" aria-labelledby="tv-surfaces-title">
      <div class="tv-section-intro tv-section-intro--split">
        <div>
          <p class="tv-kicker">One vault, three surfaces</p>
          <h2 id="tv-surfaces-title">Use the interface that fits the caller.</h2>
        </div>
        <p>
          The CLI, terminal studio, and MCP server all use the same storage,
          encryption, project boundaries, and audit trail. There is no sync layer
          to drift and no second database to secure.
        </p>
      </div>

      <div class="tv-surface-list">
        <a class="tv-surface" href="/guide/getting-started">
          <span class="tv-surface__number">01</span>
          <div>
            <p class="tv-surface__label">Humans + scripts</p>
            <h3>CLI</h3>
          </div>
          <p>Store, search, inject, sync, seal, share, rotate, and roll back from one composable command.</p>
          <code>tvault run -- npm start</code>
          <span class="tv-surface__arrow" aria-hidden="true">↗</span>
        </a>

        <a class="tv-surface" href="/guide/studio">
          <span class="tv-surface__number">02</span>
          <div>
            <p class="tv-surface__label">Humans + terminals</p>
            <h3>Studio</h3>
          </div>
          <p>Browse projects, metadata, versions, and audit history in a read-only-by-default terminal UI.</p>
          <code>tvault studio</code>
          <span class="tv-surface__arrow" aria-hidden="true">↗</span>
        </a>

        <a class="tv-surface" href="/mcp/">
          <span class="tv-surface__number">03</span>
          <div>
            <p class="tv-surface__label">Agents + automations</p>
            <h3>MCP</h3>
          </div>
          <p>Give an agent task-shaped tools, a disk-loaded policy, and value-minimizing defaults over stdio.</p>
          <code>tvault mcp</code>
          <span class="tv-surface__arrow" aria-hidden="true">↗</span>
        </a>
      </div>
    </section>

    <section class="tv-capabilities" aria-labelledby="tv-capabilities-title">
      <div class="tv-capabilities__heading">
        <p class="tv-kicker">Beyond set and get</p>
        <h2 id="tv-capabilities-title">A complete local secrets workflow.</h2>
        <p>
          Replace the loose collection of plaintext files, one-off scripts, and
          copied credentials with one inspectable tool.
        </p>
        <a class="tv-text-link" href="/guide/">
          Explore the guides
          <span aria-hidden="true">→</span>
        </a>
      </div>

      <div class="tv-capability-list">
        <article>
          <span>01</span>
          <div>
            <h3>Tame <code>.env</code> sprawl</h3>
            <p>Import without shell expansion, detect drift, sync in either direction, or keep commit-safe placeholders in the repo.</p>
            <a href="/guide/dotenv">Dotenv workflows →</a>
          </div>
        </article>
        <article>
          <span>02</span>
          <div>
            <h3>Share without sharing a passphrase</h3>
            <p>Wrap a project key to X25519 recipients. Removing one re-keys the updated live vault; retained snapshots remain readable.</p>
            <a href="/guide/sharing">Recipient sharing →</a>
          </div>
        </article>
        <article>
          <span>03</span>
          <div>
            <h3>Commit ciphertext, not credentials</h3>
            <p>Use standalone encrypted env files, Kubernetes-shaped sealed manifests, or transparent Git clean/smudge filters.</p>
            <a href="/guide/committable-secrets">Committable secrets →</a>
          </div>
        </article>
        <article>
          <span>04</span>
          <div>
            <h3>Recover from a bad rotation</h3>
            <p>Every overwrite archives the prior encrypted value. Inspect metadata and roll back non-destructively to a new version.</p>
            <a href="/guide/versioning">Versioning and rollback →</a>
          </div>
        </article>
        <article>
          <span>05</span>
          <div>
            <h3>Model environments explicitly</h3>
            <p>Group development, staging, and production projects; compare drift, inherit defaults, pin overrides, and promote deliberately.</p>
            <a href="/guide/env-groups">Environment groups →</a>
          </div>
        </article>
      </div>
    </section>

    <section class="tv-crypto" aria-labelledby="tv-crypto-title">
      <div class="tv-crypto__copy">
        <p class="tv-kicker">Inspectable security</p>
        <h2 id="tv-crypto-title">No mystery service between you and your keys.</h2>
        <p>
          The encryption path is compact enough to audit: Argon2id derives a
          key-encryption key, each project gets its own data-encryption key, and
          AES-256-GCM authenticates every encrypted value.
        </p>
        <a class="tv-text-link" href="/reference/architecture">
          Read the architecture
          <span aria-hidden="true">→</span>
        </a>
      </div>

      <div class="tv-keychain" aria-label="TinyVault key hierarchy">
        <div class="tv-keychain__step">
          <span>01</span>
          <div>
            <small>You remember</small>
            <strong>Passphrase</strong>
          </div>
        </div>
        <div class="tv-keychain__connector">
          <span>Argon2id</span>
        </div>
        <div class="tv-keychain__step">
          <span>02</span>
          <div>
            <small>Held in memory</small>
            <strong>KEK</strong>
          </div>
        </div>
        <div class="tv-keychain__connector">
          <span>AES-GCM wrap</span>
        </div>
        <div class="tv-keychain__step">
          <span>03</span>
          <div>
            <small>One per project</small>
            <strong>DEK</strong>
          </div>
        </div>
        <div class="tv-keychain__connector">
          <span>AES-GCM encrypt</span>
        </div>
        <div class="tv-keychain__step tv-keychain__step--final">
          <span>04</span>
          <div>
            <small>Authenticated ciphertext</small>
            <strong>Secret values</strong>
          </div>
        </div>
      </div>
    </section>

    <section class="tv-fit" aria-labelledby="tv-fit-title">
      <div class="tv-section-intro">
        <p class="tv-kicker">An intentionally narrow product</p>
        <h2 id="tv-fit-title">Know when TinyVault fits—and when it does not.</h2>
      </div>

      <div class="tv-fit__grid">
        <div class="tv-fit__column tv-fit__column--yes">
          <p class="tv-fit__label">Use TinyVault when</p>
          <ul>
            <li>You want local development secrets without a hosted account.</li>
            <li>You need to inject values into any process that reads environment variables.</li>
            <li>You want an agent to act on secrets while minimizing value exposure.</li>
            <li>You prefer one portable binary and one local database with encrypted secret values.</li>
          </ul>
        </div>
        <div class="tv-fit__column">
          <p class="tv-fit__label">Choose another tool when</p>
          <ul>
            <li>You need managed team sync, centralized RBAC, or an admin console.</li>
            <li>You require dynamic credentials, cloud KMS, HSMs, or high availability.</li>
            <li>You need account recovery or escrow if the passphrase is lost.</li>
            <li>You need isolation from another malicious process running as the same OS user.</li>
          </ul>
        </div>
      </div>
      <a class="tv-fit__security" href="/reference/security">
        Read the full threat model before trusting TinyVault with anything important
        <span aria-hidden="true">→</span>
      </a>
    </section>

    <section class="tv-final" aria-labelledby="tv-final-title">
      <div>
        <p class="tv-kicker">Local by default</p>
        <h2 id="tv-final-title">Build with secrets.<br>Keep the values out of the way.</h2>
      </div>
      <div class="tv-final__action">
        <p>Install the binary, create a vault, and inject your first secret in a few minutes.</p>
        <a class="tv-button tv-button--primary" href="/guide/getting-started">
          Open the quickstart
          <svg viewBox="0 0 20 20" aria-hidden="true">
            <path d="M4 10h11M11 6l4 4-4 4" />
          </svg>
        </a>
      </div>
    </section>
  </main>
</template>
