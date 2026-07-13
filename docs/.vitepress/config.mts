import { defineConfig } from 'vitepress'

// Primary serving host (Vercel redirects the apex tinyvault.dev -> www).
// Keep this in sync with the canonical host configured in Vercel → Domains.
const SITE_URL = 'https://www.tinyvault.dev'
const SITE_TITLE = 'TinyVault'
const SITE_TAGLINE = 'Local secrets. Agent-ready workflows.'
const SITE_DESC =
  'TinyVault is one Go binary for local secrets management. Encrypt values per project, ' +
  'inject them into any process, and give MCP agents value-minimizing tools without an account ' +
  'or hosted backend.'

const GH = 'https://github.com/abdul-hamid-achik/tinyvault'

export default defineConfig({
  lang: 'en-US',
  title: SITE_TITLE,
  titleTemplate: ':title · TinyVault',
  description: SITE_DESC,

  markdown: {
    // Code blocks use a dark terminal surface in both site themes, so keep
    // syntax tokens on the matching high-contrast palette as well.
    theme: {
      light: 'github-dark',
      dark: 'github-dark',
    },
  },

  cleanUrls: true,
  ignoreDeadLinks: false,
  lastUpdated: true,

  sitemap: {
    hostname: SITE_URL,
    // Vercel (cleanUrls) serves dir indexes at slash-free, .html-free paths,
    // so emit canonical-matching URLs (strip the trailing slash on /cli/, /mcp/).
    transformItems: (items) =>
      items.map((item) => ({
        ...item,
        url: item.url.length > 1 ? item.url.replace(/\/$/, '') : item.url,
      })),
  },

  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/logo.svg' }],
    ['meta', { name: 'theme-color', content: '#fbfaf6', media: '(prefers-color-scheme: light)' }],
    ['meta', { name: 'theme-color', content: '#11120f', media: '(prefers-color-scheme: dark)' }],
    ['meta', { name: 'author', content: 'Abdul Hamid Achik' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:site_name', content: SITE_TITLE }],
    ['meta', { property: 'og:title', content: `${SITE_TITLE} — ${SITE_TAGLINE}` }],
    ['meta', { property: 'og:description', content: SITE_DESC }],
    ['meta', { property: 'og:url', content: SITE_URL }],
    ['meta', { property: 'og:image', content: `${SITE_URL}/og.png` }],
    ['meta', { property: 'og:locale', content: 'en_US' }],
    ['meta', { property: 'og:image:width', content: '1200' }],
    ['meta', { property: 'og:image:height', content: '630' }],
    ['meta', { property: 'og:image:alt', content: 'TinyVault — local-first secrets for developers and AI agents' }],
    ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
    ['meta', { name: 'twitter:title', content: `${SITE_TITLE} — ${SITE_TAGLINE}` }],
    ['meta', { name: 'twitter:description', content: SITE_DESC }],
    ['meta', { name: 'twitter:image', content: `${SITE_URL}/og.png` }],
    ['meta', { name: 'twitter:image:alt', content: 'TinyVault — local-first secrets for developers and AI agents' }],
    ['script', { type: 'application/ld+json' }, JSON.stringify({
      '@context': 'https://schema.org',
      '@graph': [
        {
          '@type': 'SoftwareApplication',
          name: 'TinyVault',
          applicationCategory: 'DeveloperApplication',
          operatingSystem: 'Linux, macOS, Windows (amd64, arm64)',
          url: SITE_URL,
          downloadUrl: `${GH}/releases`,
          description: SITE_DESC,
          offers: {
            '@type': 'Offer',
            price: '0',
            priceCurrency: 'USD',
            availability: 'https://schema.org/InStock',
          },
          featureList: [
            'Per-project AES-256-GCM encryption with Argon2id passphrase derivation',
            'MCP tools designed to minimize secret-value exposure',
            'Dotenv import, synchronization, drift detection, and encrypted files',
            'X25519 recipient sharing with project re-keying',
            'Transparent git filters for commit-safe secrets',
            'Versioned secrets with rollback',
            'Interactive terminal studio (TUI)',
          ],
        },
        {
          '@type': 'Organization',
          name: 'TinyVault',
          url: SITE_URL,
          logo: `${SITE_URL}/logo.svg`,
        },
        {
          '@type': 'WebSite',
          name: 'TinyVault',
          url: SITE_URL,
          inLanguage: 'en-US',
          publisher: { '@type': 'Organization', name: 'TinyVault' },
        },
      ],
    })],
  ],

  // Per-page <link rel="canonical"> — head config alone can't be page-aware.
  // Produce the clean URL Vercel actually serves: no .html, no trailing slash
  // (except the site root).
  transformPageData(pageData) {
    const path = pageData.relativePath
      .replace(/(^|\/)index\.md$/, '$1') // 'cli/index.md' -> 'cli/', 'index.md' -> ''
      .replace(/\.md$/, '') // 'guide/x.md' -> 'guide/x'
      .replace(/\/$/, '') // 'cli/' -> 'cli'
    const canonical = path ? `${SITE_URL}/${path}` : `${SITE_URL}/`
    pageData.frontmatter.head ??= []
    pageData.frontmatter.head.push(['link', { rel: 'canonical', href: canonical }])
  },

  themeConfig: {
    logo: '/logo.svg',
    siteTitle: 'TinyVault',

    nav: [
      { text: 'Quickstart', link: '/guide/getting-started' },
      { text: 'Guides', link: '/guide/', activeMatch: '^/guide/(?!getting-started$)' },
      { text: 'CLI', link: '/cli/', activeMatch: '/cli/' },
      { text: 'MCP', link: '/mcp/', activeMatch: '/mcp/' },
      { text: 'Security', link: '/reference/security' },
      {
        text: 'Reference',
        activeMatch: '^/reference/(?!security$)',
        items: [
          { text: 'Architecture', link: '/reference/architecture' },
          { text: 'Configuration', link: '/reference/configuration' },
          { text: 'Environment variables', link: '/reference/environment-variables' },
          { text: 'Troubleshooting', link: '/reference/troubleshooting' },
          { text: 'Changelog', link: '/changelog' },
          { text: 'Releases', link: `${GH}/releases` },
        ],
      },
    ],

    sidebar: {
      '/guide/': [
        {
          text: 'Start Here',
          collapsed: false,
          items: [
            { text: 'Guides overview', link: '/guide/' },
            { text: 'What is TinyVault?', link: '/guide/what-is-tinyvault' },
            { text: 'Install & quickstart', link: '/guide/getting-started' },
            { text: 'Core Concepts', link: '/guide/concepts' },
          ],
        },
        {
          text: 'Everyday Workflows',
          collapsed: false,
          items: [
            { text: 'Store & find secrets', link: '/guide/secrets' },
            { text: 'Run apps with secrets', link: '/guide/run-and-env' },
            { text: 'Projects', link: '/guide/projects' },
            { text: 'Environment Groups', link: '/guide/env-groups' },
            { text: 'Import & sync .env', link: '/guide/dotenv' },
            { text: 'Versioning & Rollback', link: '/guide/versioning' },
          ],
        },
        {
          text: 'Share & Deploy',
          collapsed: false,
          items: [
            { text: 'Identities & sharing', link: '/guide/sharing' },
            { text: 'Committable Secrets', link: '/guide/committable-secrets' },
            { text: 'Git Filter', link: '/guide/git-filter' },
            { text: 'CI/CD', link: '/guide/ci-cd' },
          ],
        },
        {
          text: 'Interfaces',
          collapsed: false,
          items: [
            { text: 'Interactive Studio', link: '/guide/studio' },
            { text: 'Local Agent', link: '/guide/agent' },
            { text: 'For AI Agents', link: '/guide/for-ai-agents' },
          ],
        },
        {
          text: 'Operations',
          collapsed: true,
          items: [
            { text: 'Backup, restore & rotate', link: '/guide/key-management' },
            { text: 'Configuration', link: '/reference/configuration' },
            { text: 'Troubleshooting', link: '/reference/troubleshooting' },
          ],
        },
        {
          text: 'Integrations',
          collapsed: true,
          items: [
            { text: 'Pulumi & IaC', link: '/guide/pulumi' },
            { text: 'DigitalOcean & SSH', link: '/guide/digitalocean' },
            { text: 'Codemap integration', link: '/guide/codemap' },
          ],
        },
      ],
      '/mcp/': [
        {
          text: 'AI Agents (MCP)',
          collapsed: false,
          items: [
            { text: 'Overview & Setup', link: '/mcp/' },
            { text: 'Safe agent workflow', link: '/guide/for-ai-agents' },
            { text: 'Access Policy', link: '/mcp/access-policy' },
            { text: 'Recipes', link: '/mcp/recipes' },
            { text: 'Tools Reference', link: '/mcp/tools' },
          ],
        },
      ],
      '/cli/': [
        {
          text: 'Reference',
          collapsed: false,
          items: [{ text: 'CLI Reference', link: '/cli/' }],
        },
      ],
      '/reference/': [
        {
          text: 'Reference',
          collapsed: false,
          items: [
            { text: 'Security & Threat Model', link: '/reference/security' },
            { text: 'Architecture', link: '/reference/architecture' },
            { text: 'Configuration', link: '/reference/configuration' },
            { text: 'Environment Variables', link: '/reference/environment-variables' },
            { text: 'Troubleshooting & FAQ', link: '/reference/troubleshooting' },
          ],
        },
      ],
    },

    socialLinks: [{ icon: 'github', link: GH }],

    search: {
      provider: 'local',
    },

    editLink: {
      pattern: `${GH}/edit/main/docs/:path`,
      text: 'Edit this page on GitHub',
    },

    outline: { level: [2, 3], label: 'On this page' },

    footer: {
      message: 'Released under the MIT License.',
      copyright: `Copyright © ${new Date().getFullYear()} Abdul Hamid Achik`,
    },
  },
})
