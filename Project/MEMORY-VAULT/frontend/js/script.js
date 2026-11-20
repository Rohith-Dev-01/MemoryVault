/**
 * MEMORY VAULT – Shared UI Helpers, Strict Role Route Guards & Sidebars
 */

window.MV_UI = (function () {
  /**
   * Escape untrusted strings before inserting into HTML templates (XSS defense).
   */
  function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  /**
   * Format ISO timestamps cleanly for editorial display.
   */
  function formatDate(isoStr, includeTime = false) {
    if (!isoStr) return '—';
    const d = new Date(isoStr);
    if (Number.isNaN(d.getTime())) return escapeHtml(isoStr);
    const opts = includeTime
      ? { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }
      : { year: 'numeric', month: 'long', day: 'numeric' };
    return d.toLocaleDateString(undefined, opts);
  }

  /**
   * Display a subtle editorial toast notification.
   */
  function toast(message, type = 'success') {
    let container = document.getElementById('mv-toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'mv-toast-container';
      container.className = 'toast-container';
      document.body.appendChild(container);
    }

    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    el.setAttribute('role', 'status');
    el.innerHTML = `<span>${escapeHtml(message)}</span>`;
    container.appendChild(el);

    setTimeout(() => {
      el.style.opacity = '0';
      el.style.transform = 'translateY(8px)';
      el.style.transition = 'opacity 180ms ease, transform 180ms ease';
      setTimeout(() => el.remove(), 200);
    }, 4200);
  }

  /**
   * Wire up mobile navigation drawer toggle.
   */
  function initMobileMenu() {
    const btn = document.getElementById('mobile-menu-btn');
    const nav = document.getElementById('primary-nav');
    if (btn && nav) {
      btn.addEventListener('click', () => {
        nav.classList.toggle('open');
      });
    }
  }

  /**
   * Strict Vault User route guard (dashboard, assets, wishes, contacts, memories, summary).
   * - Authenticated Admin -> automatically redirected to admin.html
   * - Unauthenticated -> redirected to login.html
   */
  async function requireAuth() {
    try {
      const session = await window.MV_API.initSession();
      if (session.role === 'admin' || session.admin_authenticated) {
        window.location.replace('admin.html');
        return null;
      }
      if (session.role !== 'user' || !session.authenticated || !session.user) {
        window.location.replace('login.html');
        return null;
      }
      populateSidebarUser(session.user);
      wireLogoutButtons('login.html');
      return session.user;
    } catch (err) {
      window.location.replace('login.html');
      return null;
    }
  }

  /**
   * Strict Administrator route guard (admin.html).
   * - Authenticated Vault User -> automatically redirected to dashboard.html
   * - Unauthenticated -> redirected to login.html?role=admin
   */
  async function requireAdminAuth() {
    try {
      const session = await window.MV_API.initSession();
      if (session.role === 'user' || session.authenticated) {
        window.location.replace('dashboard.html');
        return null;
      }
      if (session.role !== 'admin' || !session.admin_authenticated || !session.admin) {
        window.location.replace('login.html?role=admin');
        return null;
      }
      populateAdminSidebarUser(session.admin);
      wireLogoutButtons('login.html?role=admin');
      return session.admin;
    } catch (err) {
      window.location.replace('login.html?role=admin');
      return null;
    }
  }

  function populateSidebarUser(user) {
    const nameEl = document.getElementById('sidebar-user-name');
    const emailEl = document.getElementById('sidebar-user-email');
    if (nameEl) nameEl.textContent = user.full_name || 'Vault Owner';
    if (emailEl) emailEl.textContent = `${user.email} · @${user.user_handle}`;
  }

  function populateAdminSidebarUser(admin) {
    const nameEl = document.getElementById('admin-sidebar-name');
    const emailEl = document.getElementById('admin-sidebar-email');
    if (nameEl) nameEl.textContent = admin.full_name || 'Administrator';
    if (emailEl) emailEl.textContent = `${admin.email} · Administrator`;
  }

  function wireLogoutButtons(redirectUrl = 'login.html') {
    document.querySelectorAll('[data-logout-btn]').forEach((btn) => {
      if (btn.dataset.logoutBound === 'true') return;
      btn.dataset.logoutBound = 'true';
      btn.addEventListener('click', async () => {
        try {
          await window.MV_API.request('auth.php?action=logout', { method: 'POST', body: {} });
          toast('Signed out safely.');
          setTimeout(() => {
            window.location.replace(redirectUrl);
          }, 250);
        } catch (err) {
          toast(err.message || 'Sign out failed.', 'error');
        }
      });
    });
  }

  function statusClass(status) {
    const s = String(status || '').toLowerCase();
    if (['accepted', 'approved', 'active', 'success'].includes(s)) return 'status-success';
    if (['pending', 'warning'].includes(s)) return 'status-warning';
    if (['declined', 'rejected', 'error'].includes(s)) return 'status-error';
    return 'status-neutral';
  }

  function wishLabel(actionType) {
    return window.MV_CONFIG.WISH_LABELS[actionType] || actionType || 'Not assigned yet';
  }

  /**
   * Shared Vault User workspace sidebar (strictly user vault modules only).
   */
  function renderSidebar(activePage) {
    const host = document.getElementById('vault-sidebar');
    if (!host) return;

    const links = [
      { key: 'dashboard', href: 'dashboard.html', label: 'Dashboard', icon: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/>' },
      { key: 'assets', href: 'assets.html', label: 'Digital Assets', icon: '<path d="M4 7V5a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v2"/><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M12 11v6"/><path d="M9 14h6"/>' },
      { key: 'wishes', href: 'wishes.html', label: 'Final Wishes', icon: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>' },
      { key: 'contacts', href: 'contacts.html', label: 'Trusted Contacts', icon: '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>' },
      { key: 'memories', href: 'memories.html', label: 'Memories & Letters', icon: '<path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/>' },
      { key: 'summary', href: 'summary.html', label: 'Legacy Summary', icon: '<polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/>' }
    ];

    host.innerHTML = `
      <div class="sidebar-user">
        <div id="sidebar-user-name" class="sidebar-user-name">Loading vault…</div>
        <div id="sidebar-user-email" class="sidebar-user-email"></div>
      </div>
      <nav class="sidebar-nav" aria-label="Vault navigation">
        ${links.map((item) => `
          <a href="${item.href}" class="${activePage === item.key ? 'active' : ''}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${item.icon}</svg>
            <span>${item.label}</span>
          </a>
        `).join('')}
      </nav>
      <div class="sidebar-footer">
        <button type="button" class="btn btn-outline btn-sm" style="width:100%" data-logout-btn>
          Sign Out
        </button>
      </div>
    `;
  }

  /**
   * Dedicated Administrator Dashboard sidebar (strictly admin governance sections only).
   */
  function renderAdminSidebar(activeSection, onSelectSection) {
    const host = document.getElementById('admin-sidebar');
    if (!host) return;

    const items = [
      { key: 'pending', label: 'Pending Requests', icon: '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>' },
      { key: 'history', label: 'Approved / Rejected', icon: '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>' },
      { key: 'audit', label: 'Audit Action Logs', icon: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>' },
      { key: 'notifications', label: 'System Notices', icon: '<path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/>' }
    ];

    host.innerHTML = `
      <div class="sidebar-user">
        <div id="admin-sidebar-name" class="sidebar-user-name">Loading console…</div>
        <div id="admin-sidebar-email" class="sidebar-user-email"></div>
      </div>
      <nav class="sidebar-nav" aria-label="Administrator navigation">
        ${items.map((item) => `
          <a href="#${item.key}" data-admin-section="${item.key}" class="${activeSection === item.key ? 'active' : ''}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${item.icon}</svg>
            <span>${item.label}</span>
          </a>
        `).join('')}
      </nav>
      <div class="sidebar-footer">
        <button type="button" class="btn btn-outline btn-sm" style="width:100%" data-logout-btn>
          Sign Out
        </button>
      </div>
    `;

    host.querySelectorAll('[data-admin-section]').forEach((link) => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const key = link.dataset.adminSection;
        host.querySelectorAll('[data-admin-section]').forEach((a) => a.classList.remove('active'));
        link.classList.add('active');
        if (typeof onSelectSection === 'function') {
          onSelectSection(key);
        }
      });
    });
  }

  document.addEventListener('DOMContentLoaded', initMobileMenu);

  return {
    escapeHtml,
    formatDate,
    toast,
    requireAuth,
    requireAdminAuth,
    statusClass,
    wishLabel,
    renderSidebar,
    renderAdminSidebar
  };
})();
