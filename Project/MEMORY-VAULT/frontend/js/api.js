/**
 * MEMORY VAULT – Fetch API Client (Sessions + CSRF Token Handling)
 */

window.MV_API = (function () {
  let csrfToken = '';

  function setCsrfToken(token) {
    if (token && typeof token === 'string') {
      csrfToken = token;
    }
  }

  function getCsrfToken() {
    return csrfToken;
  }

  /**
   * Fetch current session & CSRF token from auth.php?action=me
   */
  async function initSession() {
    const res = await request('auth.php?action=me', { method: 'GET' });
    if (res && res.csrf_token) {
      setCsrfToken(res.csrf_token);
    }
    return res;
  }

  function resolveEndpoint(endpoint) {
    if (endpoint.startsWith('http')) return endpoint;
    const usePhp = window.MV_CONFIG.USE_PHP_EXTENSION !== false;
    const normalized = usePhp ? endpoint : endpoint.replace(/\.php(?=\?|$)/i, '');
    return `${window.MV_CONFIG.API_BASE_URL}/${normalized}`;
  }

  /**
   * Core Fetch wrapper with credentialed cookies and automatic CSRF header injection.
   */
  async function request(endpoint, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    const isMutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);

    // Ensure CSRF token is loaded before any mutating request
    if (isMutating && !csrfToken && !endpoint.startsWith('auth.php?action=me')) {
      const boot = await fetch(resolveEndpoint('auth.php?action=me'), {
        method: 'GET',
        credentials: 'include',
        headers: { 'Accept': 'application/json' }
      });
      const bootJson = await boot.json().catch(() => ({}));
      if (bootJson.csrf_token) {
        setCsrfToken(bootJson.csrf_token);
      }
    }

    const headers = {
      'Accept': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      ...(options.headers || {})
    };

    if (isMutating) {
      headers['Content-Type'] = 'application/json';
      if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
      }
    }

    const url = resolveEndpoint(endpoint);

    const response = await fetch(url, {
      method,
      credentials: 'include',
      headers,
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined
    });

    const data = await response.json().catch(() => ({
      success: false,
      error: `Unexpected response format from server (HTTP ${response.status}).`
    }));

    if (data && data.csrf_token) {
      setCsrfToken(data.csrf_token);
    }

    if (!response.ok || data.success === false) {
      const err = new Error(data.error || `Request failed (${response.status})`);
      err.status = response.status;
      err.data = data;
      throw err;
    }

    return data;
  }

  return {
    initSession,
    request,
    setCsrfToken,
    getCsrfToken
  };
})();
