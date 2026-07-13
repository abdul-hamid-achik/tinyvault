import type { Theme } from 'vitepress'
import DefaultTheme from 'vitepress/theme'
import './custom.css'

import HomeStatBar from './components/HomeStatBar.vue'
import HomeTerminal from './components/HomeTerminal.vue'
import HomeHowItWorks from './components/HomeHowItWorks.vue'
import HomeUseCases from './components/HomeUseCases.vue'
import HomeCompare from './components/HomeCompare.vue'
import HomeCTA from './components/HomeCTA.vue'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('HomeStatBar', HomeStatBar)
    app.component('HomeTerminal', HomeTerminal)
    app.component('HomeHowItWorks', HomeHowItWorks)
    app.component('HomeUseCases', HomeUseCases)
    app.component('HomeCompare', HomeCompare)
    app.component('HomeCTA', HomeCTA)
  },
} satisfies Theme