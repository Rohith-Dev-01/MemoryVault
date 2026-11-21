/**
 * MEMORY VAULT – Fetch API Client (Stateless Sessions + Double-Submit CSRF Handling)
 */

window.MV_API = (function () {
  let csrfToken = '';

  function readCsrfCookie() {
    if (typeof document === 'undefined' || !document.cookie) return '';
    const parts = document.cookie.split(';');
    for (const part of parts) {
      const idx = part.indexOf('=');
      if (idx === -1) continue;
      const key = part.slice(0, idx).trim();
      if (key === 'MV_CSRF') {
        const raw = part.slice(idx + 1).trim();
        try {
          return decodeURIComponent(raw);
        } catch (_e) {
          return raw;
        }
      }
    }
    return '';
  }

  function setCsrfToken(token) {
    if (token && typeof token === 'string') {
      csrfToken = token.trim();
    }
  }

  function getCsrfToken() {
    return readCsrfCookie() || csrfToken;
  }

  function syncTokenFromPayload(payload) {
    if (!payload || typeof payload !== 'object') return;
    const token = payload.csrf_token || payload.csrfToken;
    if (token && typeof token === 'string') {
      setCsrfToken(token);
    }
  }

  function resolveEndpoint(endpoint) {
    if (endpoint.startsWith('http')) return endpoint;
    const usePhp = window.MV_CONFIG.USE_PHP_EXTENSION !== false;
    const normalized = usePhp ? endpoint : endpoint.replace(/\.php(?=\?|$)/i, '');
    return `${window.MV_CONFIG.API_BASE_URL}/${normalized}`;
  }

  /**
   * Fetch current session & fresh CSRF token from auth?action=me with credentials included.
   */
  async function fetchFreshCsrfToken() {
    const boot = await fetch(resolveEndpoint('auth.php?action=me'), {
      method: 'GET',
      credentials: 'include',
      headers: { Accept: 'application/json' }
    });
    const bootJson = await boot.json().catch(() => ({}));
    syncTokenFromPayload(bootJson);
    if (!csrfToken) {
      const cookieVal = readCsrfCookie();
      if (cookieVal) setCsrfToken(cookieVal);
    }
    return bootJson;
  }

  async function initSession() {
    const res = await request('auth.php?action=me', { method: 'GET' });
    syncTokenFromPayload(res);
    return res;
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
  async function request(endpoint, options = {}, _retriedCsrf = false) {
    const method = (options.method || 'GET').toUpperCase();
    const isMutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);

    // Ensure CSRF token is present before any mutating request
    if (isMutating && !endpoint.startsWith('auth.php?action=me')) {
      if (!getCsrfToken()) {
        await fetchFreshCsrfToken();
      }
    }

    const headers = {
      Accept: 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      ...(options.headers || {})
    };

    if (isMutating) {
      headers['Content-Type'] = 'application/json';
      const activeToken = getCsrfToken();
      if (activeToken) {
        headers['X-CSRF-Token'] = activeToken;
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

    syncTokenFromPayload(data);

    // If a stale token triggered CSRF_INVALID (e.g., expired tab), refresh token once and retry cleanly
    if (
      isMutating &&
      !_retriedCsrf &&
      response.status === 401 &&
      data &&
      data.code === 'CSRF_INVALID'
    ) {
      csrfToken = '';
      await fetchFreshCsrfToken();
      return request(endpoint, options, true);
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
