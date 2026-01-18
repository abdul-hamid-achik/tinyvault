// Toast notification system for TinyVault
(function() {
  'use strict';

  const TOAST_DURATION = 4000; // 4 seconds

  // Create a toast notification
  function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
      <div class="flex items-center gap-3">
        ${getIcon(type)}
        <span>${escapeHtml(message)}</span>
      </div>
      <button type="button" class="toast-close">
        <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
        </svg>
      </button>
    `;

    // Add animation class
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    container.appendChild(toast);

    // Trigger animation
    requestAnimationFrame(() => {
      toast.style.transition = 'all 0.3s ease-out';
      toast.style.opacity = '1';
      toast.style.transform = 'translateX(0)';
    });

    // Auto-remove after duration
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      setTimeout(() => toast.remove(), 300);
    }, TOAST_DURATION);
  }

  // Get icon SVG based on type
  function getIcon(type) {
    switch (type) {
      case 'success':
        return `<svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
        </svg>`;
      case 'error':
        return `<svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
        </svg>`;
      case 'warning':
        return `<svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
        </svg>`;
      default:
        return `<svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
        </svg>`;
    }
  }

  // Escape HTML to prevent XSS
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // Listen for HTMX events to show toasts
  document.addEventListener('htmx:afterRequest', function(event) {
    const xhr = event.detail.xhr;
    if (!xhr) return;

    // Check for toast header from server
    const toastMessage = xhr.getResponseHeader('X-Toast-Message');
    const toastType = xhr.getResponseHeader('X-Toast-Type') || 'info';

    if (toastMessage) {
      showToast(toastMessage, toastType);
    }
  });

  // Listen for custom showToast events (for HX-Trigger)
  document.body.addEventListener('showToast', function(event) {
    const { message, type } = event.detail || {};
    if (message) {
      showToast(message, type || 'info');
    }
  });

  // Expose globally for manual use
  window.showToast = showToast;
})();
