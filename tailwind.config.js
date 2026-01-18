/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./internal/views/**/*.templ",
    "./internal/views/**/*_templ.go",
    "./web/static/**/*.html",
  ],
  theme: {
    extend: {
      colors: {
        // Nord Polar Night (dark backgrounds)
        nord0: '#2E3440',
        nord1: '#3B4252',
        nord2: '#434C5E',
        nord3: '#4C566A',
        // Nord Snow Storm (light backgrounds/text)
        nord4: '#D8DEE9',
        nord5: '#E5E9F0',
        nord6: '#ECEFF4',
        // Nord Frost (accent colors)
        nord7: '#8FBCBB',
        nord8: '#88C0D0',
        nord9: '#81A1C1',
        nord10: '#5E81AC',
        // Nord Aurora (semantic colors)
        nord11: '#BF616A', // red
        nord12: '#D08770', // orange
        nord13: '#EBCB8B', // yellow
        nord14: '#A3BE8C', // green
        nord15: '#B48EAD', // purple
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Menlo', 'Monaco', 'monospace'],
      },
    },
  },
  plugins: [],
}
