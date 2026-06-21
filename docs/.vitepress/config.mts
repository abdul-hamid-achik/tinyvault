import { defineConfig } from 'vitepress'

// Primary serving host (Vercel redirects the apex tinyvault.dev -> www).
// Keep this in sync with the canonical host configured in Vercel → Domains.
const SITE_URL = 'https://www.tinyvault.dev'
const SITE_TITLE = 'TinyVault'
const SITE_TAGLINE = 'Local-first secrets for developers & AI agents'
const SITE_DESC =
  'TinyVault is a single-binary, local-first secrets manager (tvault) and MCP server. ' +
  'AES-256-GCM + Argon2id, .env tooling, X25519 sharing, versioned secrets — no servers, no accounts, no cloud.'

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
    ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
    ['meta', { name: 'twitter:title', content: `${SITE_TITLE} — ${SITE_TAGLINE}` }],
    ['meta', { name: 'twitter:description', content: SITE_DESC }],
    ['meta', { name: 'twitter:image', content: `${SITE_URL}/og.png` }],
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
          ],
        },
        {
          text: 'Interfaces',
          collapsed: false,
          items: [
            { text: 'Interactive Studio', link: '/guide/studio' },
            { text: 'Local Agent', link: '/guide/agent' },
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
