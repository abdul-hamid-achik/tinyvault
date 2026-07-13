import { defineConfig } from 'vitepress'

// Primary serving host (Vercel redirects the apex tinyvault.dev -> www).
// Keep this in sync with the canonical host configured in Vercel → Domains.
const SITE_URL = 'https://www.tinyvault.dev'
const SITE_TITLE = 'TinyVault'
const SITE_TAGLINE = 'Local-first secrets for developers & AI agents'
// SEO: keyword-targeted description. Covers the high-intent terms a developer
// or AI engineer searches for ("secrets manager", "MCP server", "local secrets",
// "secrets CLI", ".env", "AI agent secrets") while staying a natural sentence.
const SITE_DESC =
  'TinyVault is a local-first secrets manager and MCP server for developers and AI agents. ' +
  'A single Go binary (tvault) stores secrets encrypted with AES-256-GCM + Argon2id, ' +
  'ships a full .env toolkit, X25519 sharing, versioned secrets, and a 49-tool MCP server — ' +
  'no servers, no accounts, no cloud.'

const GH = 'https://github.com/abdul-hamid-achik/tinyvault'

export default defineConfig({
  lang: 'en-US',
  title: SITE_TITLE,
  titleTemplate: ':title · TinyVault',
  description: SITE_DESC,

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
    ['meta', { name: 'theme-color', content: '#f5a623' }],
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
    // Structured data: helps Google classify this as a developer tool and
    // powers rich results (software application, organization, website).
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
          softwareVersion: '0.17.0',
          datePublished: '2026-05-01',
          dateModified: '2026-07-11',
          description: SITE_DESC,
          offers: {
            '@type': 'Offer',
            price: '0',
            priceCurrency: 'USD',
            availability: 'https://schema.org/InStock',
          },
          featureList: [
            'AES-256-GCM encryption with two-tier key hierarchy',
            'Argon2id passphrase key derivation',
            '49-tool MCP server for AI agents (value-free by default)',
            'Full .env toolkit: parser, sync, drift diff, encrypted .env',
            'X25519 recipient sharing with revocation',
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
      { text: 'Guide', link: '/guide/what-is-tinyvault', activeMatch: '/guide/' },
      { text: 'CLI', link: '/cli/', activeMatch: '/cli/' },
      { text: 'MCP', link: '/mcp/', activeMatch: '/mcp/' },
      { text: 'AI Agents', link: '/guide/for-ai-agents' },
      {
        text: 'Reference',
        activeMatch: '/reference/',
        items: [
          { text: 'Configuration', link: '/reference/configuration' },
          { text: 'Environment Variables', link: '/reference/environment-variables' },
          { text: 'Architecture', link: '/reference/architecture' },
          { text: 'Security & Threat Model', link: '/reference/security' },
          { text: 'Troubleshooting & FAQ', link: '/reference/troubleshooting' },
        ],
      },
      { text: 'Changelog', link: '/changelog' },
      { text: 'Releases', link: `${GH}/releases` },
    ],

    sidebar: {
      '/guide/': [
        {
          text: 'Introduction',
          collapsed: false,
          items: [
            { text: 'What is TinyVault?', link: '/guide/what-is-tinyvault' },
            { text: 'Getting Started', link: '/guide/getting-started' },
            { text: 'Core Concepts', link: '/guide/concepts' },
            { text: 'For AI Agents', link: '/guide/for-ai-agents' },
          ],
        },
        {
          text: 'Working with Secrets',
          collapsed: false,
          items: [
            { text: 'Secrets & Search', link: '/guide/secrets' },
            { text: 'Projects', link: '/guide/projects' },
            { text: 'Environment Groups', link: '/guide/env-groups' },
            { text: 'Run & Environment', link: '/guide/run-and-env' },
            { text: '.env Files', link: '/guide/dotenv' },
            { text: 'Versioning & Rollback', link: '/guide/versioning' },
            { text: 'Key Management', link: '/guide/key-management' },
          ],
        },
        {
          text: 'Sharing & Committing',
          collapsed: false,
          items: [
            { text: 'Sharing Secrets', link: '/guide/sharing' },
            { text: 'Committable Secrets', link: '/guide/committable-secrets' },
            { text: 'Git Filter', link: '/guide/git-filter' },
            { text: 'CI/CD', link: '/guide/ci-cd' },
          ],
        },
        {
          text: 'Deploying',
          collapsed: false,
          items: [
            { text: 'Pulumi & IaC', link: '/guide/pulumi' },
            { text: 'DigitalOcean & SSH', link: '/guide/digitalocean' },
          ],
        },
        {
          text: 'Interfaces',
          collapsed: false,
          items: [
            { text: 'Interactive Studio', link: '/guide/studio' },
            { text: 'Local Agent', link: '/guide/agent' },
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
            { text: 'Tools Reference', link: '/mcp/tools' },
            { text: 'Recipes', link: '/mcp/recipes' },
            { text: 'Access Policy', link: '/mcp/access-policy' },
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
            { text: 'Configuration', link: '/reference/configuration' },
            { text: 'Environment Variables', link: '/reference/environment-variables' },
            { text: 'Architecture', link: '/reference/architecture' },
            { text: 'Security & Threat Model', link: '/reference/security' },
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
