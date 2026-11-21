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
   * Normalize flat or nested server error payloads (e.g., { error: { code, message } })
   * into a human-readable string so UI never renders "[object Object]".
   */
  function extractErrorMessage(payload, fallback) {
    if (!payload) return fallback;
    if (typeof payload === 'string') return payload;
    if (payload instanceof Error) {
      return extractErrorMessage(payload.message, fallback);
    }
    if (typeof payload === 'object') {
      if (typeof payload.message === 'string' && payload.message.trim()) {
        return payload.message.trim();
      }
      if (payload.error !== undefined && payload.error !== null) {
        return extractErrorMessage(payload.error, fallback);
      }
      if (typeof payload.code === 'string' && payload.code.trim()) {
        return payload.code.trim();
      }
      try {
        return JSON.stringify(payload);
      } catch (_e) {
        return fallback;
      }
    }
    return String(payload);
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
      const fallbackMsg = `Request failed (${response.status})`;
      const message = extractErrorMessage(data, fallbackMsg);
      const err = new Error(message);
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
    getCsrfToken,
    extractErrorMessage
  };
})();
