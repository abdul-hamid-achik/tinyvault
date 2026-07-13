import type { Theme } from 'vitepress'
import DefaultTheme from 'vitepress/theme-without-fonts'
import '@fontsource-variable/geist'
import './custom.css'

import HomePage from './components/HomePage.vue'
import ThemeLayout from './components/ThemeLayout.vue'

export default {
  extends: DefaultTheme,
  Layout: ThemeLayout,
  enhanceApp({ app }) {
    app.component('HomePage', HomePage)
  },
} satisfies Theme
