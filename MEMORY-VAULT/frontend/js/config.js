/**
 * MEMORY VAULT – Frontend Configuration
 *
 * LOCAL XAMPP SETUP:
 *   Keep API_BASE_URL as '../backend/api' when serving from:
 *   http://localhost/MEMORY-VAULT/frontend/index.html
 *
 * VERCEL FRONTEND + TUNNELED XAMPP BACKEND:
 *   Replace API_BASE_URL with your HTTPS tunnel URL, e.g.:
 *   'https://your-subdomain.trycloudflare.com/MEMORY-VAULT/backend/api'
 */

(function () {
  const isPreviewHost =
    typeof window !== 'undefined' &&
    /\.run\.app$/i.test(window.location.hostname || '');

  window.MV_CONFIG = {
    APP_NAME: 'Memory Vault',
    // On XAMPP (http://localhost/MEMORY-VAULT/frontend/...) this uses '../backend/api' (.php endpoints).
    // Inside AI Studio's HTTPS preview proxy (*.run.app), it uses '/api' so nginx never blocks POST *.php requests.
    API_BASE_URL: isPreviewHost ? '/api' : '../backend/api',
    USE_PHP_EXTENSION: !isPreviewHost,
    CRON_BASE_URL: isPreviewHost ? '/api/cron' : '../backend/cron',
    WISH_LABELS: {
      preserve_account: 'Preserve the account',
      preserve_memories: 'Preserve selected memories',
      share_information: 'Share selected information',
      request_memorialization: 'Request memorialization',
      request_deletion: 'Request deletion or cancellation through official provider process'
    }
  };
})();
