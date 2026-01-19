// TinyVault main JavaScript - handles UI interactions
(function() {
  'use strict';

  // ==========================================================================
  // CSRF Protection
  // ==========================================================================

  // Get CSRF token from cookie (handles base64 tokens with = padding)
  function getCSRFToken() {
    const cookie = document.cookie.split('; ').find(function(row) {
      return row.startsWith('csrf_token=');
    });
    return cookie ? cookie.substring('csrf_token='.length) : null;
  }

  // Configure HTMX to include CSRF token in all requests
  document.addEventListener('htmx:configRequest', function(e) {
    var token = getCSRFToken();
    if (token) {
      e.detail.headers['X-CSRF-Token'] = token;
    }
  });

  // Inject CSRF token into regular form submissions
  document.addEventListener('submit', function(e) {
    var form = e.target;
    if (form.tagName === 'FORM' && form.method.toUpperCase() === 'POST') {
      var csrfInput = form.querySelector('input[name="csrf_token"]');
      if (!csrfInput) {
        csrfInput = document.createElement('input');
        csrfInput.type = 'hidden';
        csrfInput.name = 'csrf_token';
        form.appendChild(csrfInput);
      }
      var token = getCSRFToken();
      if (token) {
        csrfInput.value = token;
      }
    }
  });

  // ==========================================================================
  // UI Interactions
  // ==========================================================================

  // Icon SVGs
  const icons = {
    check: '<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>',
    copy: '<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>',
    eye: '<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>',
    spinner: '<svg class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>'
  };

  // Initialize all event handlers
  function init() {
    initMobileMenu();
    initModalClose();
    initCliDemoCopy();
    initToastClose();
    initSecretHandlers();
  }

  // Modal close handler (replaces hx-on:click which requires eval)
  function initModalClose() {
    document.addEventListener('click', function(e) {
      var closeBtn = e.target.closest('[data-close-modal]');
      if (closeBtn) {
        var modalContainer = document.getElementById('modal-container');
        if (modalContainer) {
          modalContainer.innerHTML = '';
        }
      }
    });
  }

  // Mobile menu toggle
  function initMobileMenu() {
    document.addEventListener('click', function(e) {
      const btn = e.target.closest('[data-toggle-menu]');
      if (btn) {
        const menuId = btn.getAttribute('data-toggle-menu');
        const menu = document.getElementById(menuId);
        if (menu) {
          menu.classList.toggle('hidden');
        }
      }
    });
  }

  // CLI demo copy button
  function initCliDemoCopy() {
    document.addEventListener('click', function(e) {
      const btn = e.target.closest('[data-copy-cli]');
      if (btn) {
        const commands = [
          'brew install tinyvault/tap/tvault',
          'tvault login',
          'tvault projects create my-app',
          'tvault use my-app',
          'tvault set DATABASE_URL "postgres://..."',
          'tvault set STRIPE_KEY "sk_live_..."',
          'tvault run npm start'
        ].join('\n');

        navigator.clipboard.writeText(commands);
        if (window.showToast) window.showToast('Commands copied to clipboard', 'success');

        const originalHTML = btn.innerHTML;
        btn.innerHTML = icons.check;
        setTimeout(function() {
          btn.innerHTML = originalHTML;
        }, 2000);
      }
    });
  }

  // Toast close button
  function initToastClose() {
    document.addEventListener('click', function(e) {
      const btn = e.target.closest('.toast-close');
      if (btn) {
        const toast = btn.closest('.toast');
        if (toast) {
          toast.remove();
        }
      }
    });
  }

  // Secret value copy and hide handlers
  function initSecretHandlers() {
    document.addEventListener('click', function(e) {
      // Copy secret button
      const copyBtn = e.target.closest('.copy-secret-btn');
      if (copyBtn) {
        const container = copyBtn.closest('.secret-value-container');
        if (container) {
          const valueEl = container.querySelector('.secret-value');
          if (valueEl) {
            navigator.clipboard.writeText(valueEl.textContent);
            if (window.showToast) window.showToast('Copied to clipboard', 'success');
          }
        }
        return;
      }

      // Hide secret button
      const hideBtn = e.target.closest('.hide-secret-btn');
      if (hideBtn) {
        const container = hideBtn.closest('.secret-value-container');
        if (container) {
          const projectId = container.dataset.projectId;
          const key = container.dataset.key;
          const td = container.closest('td');

          if (td && projectId && key) {
            td.innerHTML = '<div class="flex items-center gap-2">' +
              '<span class="secret-hidden">••••••••••••</span>' +
              '<button type="button" class="text-nord4 hover:text-nord8 htmx-btn" ' +
                'hx-get="/projects/' + projectId + '/secrets/' + key + '/reveal" ' +
                'hx-target="closest td" hx-swap="innerHTML">' +
                '<span class="htmx-indicator">' + icons.spinner + '</span>' +
                '<span class="htmx-hide-on-request">' + icons.eye + '</span>' +
              '</button>' +
            '</div>';
            htmx.process(td);
          }
        }
      }
    });
  }

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Re-initialize after HTMX swaps (for dynamically loaded content)
  document.body.addEventListener('htmx:afterSwap', function() {
    // Event delegation handles this automatically
  });
})();
