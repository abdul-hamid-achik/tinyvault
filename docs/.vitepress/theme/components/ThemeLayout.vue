<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, watch } from 'vue'
import { useRoute } from 'vitepress'
import DefaultTheme from 'vitepress/theme-without-fonts'

const route = useRoute()
const DefaultLayout = DefaultTheme.Layout
let navObserver: MutationObserver | undefined

function normalizePath(path: string) {
  const normalized = path.replace(/(?:index)?\.html$/, '').replace(/\/$/, '')
  return normalized || '/'
}

function syncCurrentPageLinks() {
  if (typeof window === 'undefined') return

  const currentPath = normalizePath(new URL(route.path, window.location.origin).pathname)
  const links = document.querySelectorAll<HTMLAnchorElement>(
    '.VPNavBarMenuLink[href], .VPMenuLink a[href], .VPNavScreen a[href]',
  )

  links.forEach((link) => {
    let isCurrent = false

    try {
      const target = new URL(link.href, window.location.origin)
      isCurrent = target.origin === window.location.origin
        && normalizePath(target.pathname) === currentPath
    } catch {
      isCurrent = false
    }

    if (isCurrent) link.setAttribute('aria-current', 'page')
    else link.removeAttribute('aria-current')
  })
}

async function scheduleCurrentPageSync() {
  await nextTick()
  window.requestAnimationFrame(syncCurrentPageLinks)
}

watch(() => route.path, scheduleCurrentPageSync, { flush: 'post' })

onMounted(() => {
  syncCurrentPageLinks()
  navObserver = new MutationObserver(syncCurrentPageLinks)
  navObserver.observe(document.body, { childList: true, subtree: true })
})

onBeforeUnmount(() => navObserver?.disconnect())
</script>

<template>
  <DefaultLayout />
</template>
