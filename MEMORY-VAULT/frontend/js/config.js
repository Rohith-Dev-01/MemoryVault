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
  const host = typeof window !== 'undefined' ? window.location.hostname || '' : '';
  const port = typeof window !== 'undefined' ? window.location.port || '' : '';
  const pathname = typeof window !== 'undefined' ? window.location.pathname || '' : '';
  // Use PHP backend only when served locally via XAMPP Apache (http://localhost/MEMORY-VAULT/frontend/...)
  const isLocalXampp =
    /^(localhost|127\.0\.0\.1)$/i.test(host) &&
    (port === '' || port === '80') &&
    pathname.includes('/MEMORY-VAULT/frontend/');
  const useNodeApi = !isLocalXampp;

  window.MV_CONFIG = {
    APP_NAME: 'Memory Vault',
    // On XAMPP (http://localhost/MEMORY-VAULT/frontend/...) this uses '../backend/api' (.php endpoints).
    // On Vercel (*.vercel.app / custom domain), AI Studio (*.run.app), and local Node (port 3000), it uses '/api'.
    API_BASE_URL: useNodeApi ? '/api' : '../backend/api',
    USE_PHP_EXTENSION: !useNodeApi,
    CRON_BASE_URL: useNodeApi ? '/api/cron' : '../backend/cron',
    WISH_LABELS: {
      preserve_account: 'Preserve the account',
      preserve_memories: 'Preserve selected memories',
      share_information: 'Share selected information',
      request_memorialization: 'Request memorialization',
      request_deletion: 'Request deletion or cancellation through official provider process'
    }
  };
})();
