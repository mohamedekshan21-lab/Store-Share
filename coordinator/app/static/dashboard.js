/**
 * Expo Integrated Multi-Role Application Portal (Phase 10F)
 * Unified Vanilla JavaScript frontend providing:
 * - Consumer File Manager (upload, download, delete, quota tracking, empty & loading states)
 * - Provider Portal (node health, telemetry, metrics, charts, onboarding, drain controls)
 * - Admin Console (account status, node lifecycle, system stats, reconciliation, audit log)
 * - Session status, CSRF defense, and XSS sanitization throughout.
 */

(function () {
  'use strict';

  // State
  let currentCsrfToken = null;
  let currentPrincipal = null;
  let currentAccount = null;
  let currentActiveView = 'landing'; // 'landing' | 'consumer' | 'provider' | 'admin'

  // Header Nav Elements
  const navLandingBtn = document.getElementById('nav-landing-btn');
  const navConsumerBtn = document.getElementById('nav-consumer-btn');
  const navProviderBtn = document.getElementById('nav-provider-btn');
  const navAdminBtn = document.getElementById('nav-admin-btn');
  const windowSelectorContainer = document.getElementById('window-selector-container');
  const windowSelect = document.getElementById('window-select');
  const refreshBtn = document.getElementById('refresh-btn');
  const retryBtn = document.getElementById('retry-btn');
  const authBtn = document.getElementById('auth-btn');
  const providerIdLabel = document.getElementById('current-provider-id');
  const currentUserRoleBadge = document.getElementById('current-user-role');
  const authVerificationBadge = document.getElementById('auth-verification-badge');

  // Views & Landing Elements
  const landingView = document.getElementById('landing-view');
  const consumerView = document.getElementById('consumer-view');
  const providerView = document.getElementById('provider-view');
  const adminView = document.getElementById('admin-view');
  const loadingContainer = document.getElementById('loading-container');
  const errorContainer = document.getElementById('error-container');
  const errorMessage = document.getElementById('error-message');
  const dashboardContent = document.getElementById('dashboard-content');
  const staleBanner = document.getElementById('stale-alert-banner');
  const emailVerificationBanner = document.getElementById('email-verification-banner');
  const providerOnboardBanner = document.getElementById('provider-onboard-banner');
  const bannerOnboardBtn = document.getElementById('banner-onboard-btn');

  // Landing Interactive Buttons
  const landingLaunchBtn = document.getElementById('landing-launch-btn');
  const landingSigninBtn = document.getElementById('landing-signin-btn');
  const landingRegisterBtn = document.getElementById('landing-register-btn');
  const ctaConsumerActionBtn = document.getElementById('cta-consumer-action-btn');
  const ctaProviderActionBtn = document.getElementById('cta-provider-action-btn');
  const demoSigninBtn = document.getElementById('demo-signin-btn');
  const portalToast = document.getElementById('portal-toast');
  const toastMsg = document.getElementById('toast-msg');
  const toastIcon = document.getElementById('toast-icon');

  function showToast(msg, icon = '⚠️', durationMs = 3500) {
    if (!portalToast || !toastMsg) return;
    toastMsg.textContent = msg;
    if (toastIcon) toastIcon.textContent = icon;
    portalToast.style.display = 'flex';
    clearTimeout(portalToast._timeout);
    portalToast._timeout = setTimeout(() => {
      portalToast.style.display = 'none';
    }, durationMs);
  }

  function setupPasswordToggle(btnId, inputId) {
    const btn = document.getElementById(btnId);
    const input = document.getElementById(inputId);
    if (!btn || !input) return;
    btn.addEventListener('click', () => {
      const isPassword = input.type === 'password';
      input.type = isPassword ? 'text' : 'password';
      btn.textContent = isPassword ? '👁️‍🗨️' : '👁️';
    });
  }

  // Consumer View Elements
  const consumerUsedBytesEl = document.getElementById('consumer-used-bytes');
  const consumerTotalQuotaEl = document.getElementById('consumer-total-quota');
  const consumerAvailBytesEl = document.getElementById('consumer-avail-bytes');
  const consumerProgressFill = document.getElementById('consumer-progress-fill');
  const consumerFilesCountEl = document.getElementById('consumer-files-count');
  const consumerFileInput = document.getElementById('consumer-file-input');
  const consumerUploadBtn = document.getElementById('consumer-upload-btn');
  const consumerUploadStatus = document.getElementById('consumer-upload-status');
  const consumerFilesSubtitle = document.getElementById('consumer-files-subtitle');
  const consumerSearchInput = document.getElementById('consumer-search-input');
  const consumerEmptyFiles = document.getElementById('consumer-empty-files');
  const consumerFilesTbody = document.getElementById('consumer-files-tbody');
  const dropzone = document.getElementById('dropzone');
  const selectedFileNameEl = document.getElementById('selected-file-name');

  // Provider View Elements
  const verifiedStoredBytesEl = document.getElementById('verified-stored-bytes');
  const configuredQuotaBytesEl = document.getElementById('configured-quota-bytes');
  const remainingQuotaBytesEl = document.getElementById('remaining-quota-bytes');
  const storageProgressFill = document.getElementById('storage-progress-fill');
  const physicalDiskStatsEl = document.getElementById('physical-disk-stats');
  const totalTrafficBytesEl = document.getElementById('total-traffic-bytes');
  const totalIngressBytesEl = document.getElementById('total-ingress-bytes');
  const totalEgressBytesEl = document.getElementById('total-egress-bytes');
  const trafficRatioTextEl = document.getElementById('traffic-ratio-text');
  const trafficWindowBadge = document.getElementById('traffic-window-badge');
  const totalCreditsBalanceEl = document.getElementById('total-credits-balance');
  const totalLifetimeEarnedEl = document.getElementById('total-lifetime-earned');
  const totalLifetimeReversedEl = document.getElementById('total-lifetime-reversed');
  const averageReputationScoreEl = document.getElementById('average-reputation-score');
  const reputationConfidenceBadge = document.getElementById('reputation-confidence-badge');
  const recentSuccRepairsEl = document.getElementById('recent-succ-repairs');
  const recentFailRepairsEl = document.getElementById('recent-fail-repairs');
  const storageChartContainer = document.getElementById('storage-chart-container');
  const trafficChartContainer = document.getElementById('traffic-chart-container');
  const nodesTableBody = document.getElementById('nodes-table-body');
  const emptyNodesContainer = document.getElementById('empty-nodes-container');
  const nodesCountSubtitle = document.getElementById('nodes-count-subtitle');
  const nodeSearchInput = document.getElementById('node-search-input');
  const activityStreamList = document.getElementById('activity-stream-list');
  const registerNodeOpenBtn = document.getElementById('register-node-open-btn');

  // Admin View Elements
  const adminTotalAccountsEl = document.getElementById('admin-total-accounts');
  const adminRolesSplitEl = document.getElementById('admin-roles-split');
  const adminSuspendedAccountsEl = document.getElementById('admin-suspended-accounts');
  const adminTotalNodesEl = document.getElementById('admin-total-nodes');
  const adminOnlineNodesEl = document.getElementById('admin-online-nodes');
  const adminProbationNodesEl = document.getElementById('admin-probation-nodes');
  const adminTotalCapacityEl = document.getElementById('admin-total-capacity');
  const adminUsedCapacityEl = document.getElementById('admin-used-capacity');
  const adminTotalFilesEl = document.getElementById('admin-total-files');
  const adminPendingDeletionsEl = document.getElementById('admin-pending-deletions');
  const adminFailedRepairsEl = document.getElementById('admin-failed-repairs');
  const adminActiveReservationsEl = document.getElementById('admin-active-reservations');
  const adminAccountSearch = document.getElementById('admin-account-search');
  const adminAccountRoleFilter = document.getElementById('admin-account-role-filter');
  const adminAccountStatusFilter = document.getElementById('admin-account-status-filter');
  const adminAccountsTbody = document.getElementById('admin-accounts-tbody');
  const adminNodesTbody = document.getElementById('admin-nodes-tbody');
  const adminAuditTbody = document.getElementById('admin-audit-tbody');
  const adminReconcileBtn = document.getElementById('admin-reconcile-btn');
  const adminReconcileDryRun = document.getElementById('admin-reconcile-dryrun');
  const adminReconcileResults = document.getElementById('admin-reconcile-results');

  // Modals
  const nodeModal = document.getElementById('node-modal');
  const modalNodeTitle = document.getElementById('modal-node-title');
  const modalNodeEndpoint = document.getElementById('modal-node-endpoint');
  const modalBodyContent = document.getElementById('modal-body-content');
  const modalCloseBtn = document.getElementById('modal-close-btn');
  const modalDismissBtn = document.getElementById('modal-dismiss-btn');
  const modalDrainBtn = document.getElementById('modal-drain-btn');

  const nodeRegisterModal = document.getElementById('node-register-modal');
  const nodeRegCloseBtn = document.getElementById('node-reg-close-btn');
  const nodeRegForm = document.getElementById('node-reg-form');
  const nodeRegId = document.getElementById('node-reg-id');
  const nodeRegHost = document.getElementById('node-reg-host');
  const nodeRegPort = document.getElementById('node-reg-port');
  const nodeRegCapacity = document.getElementById('node-reg-capacity');
  const nodeRegStatus = document.getElementById('node-reg-status');

  const providerOnboardModal = document.getElementById('provider-onboard-modal');
  const onboardCloseBtn = document.getElementById('onboard-close-btn');
  const onboardForm = document.getElementById('onboard-form');
  const onboardProviderId = document.getElementById('onboard-provider-id');
  const onboardAcceptTerms = document.getElementById('onboard-accept-terms');
  const onboardStatusMsg = document.getElementById('onboard-status-msg');

  const loginModal = document.getElementById('login-modal');
  const loginForm = document.getElementById('login-form');
  const loginProviderId = document.getElementById('login-provider-id');
  const loginSecret = document.getElementById('login-secret');
  const loginErrorMsg = document.getElementById('login-error-msg');
  const loginCloseBtn = document.getElementById('login-close-btn');

  let currentActiveNodeId = null;
  let cachedNodes = [];
  let cachedConsumerFiles = [];
  let cachedAdminAccounts = [];

  // =========================================================================
  // Utilities
  // =========================================================================

  function formatBytes(bytes) {
    if (bytes === null || bytes === undefined || isNaN(bytes)) return 'N/A';
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    const val = (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 2);
    return `${val} ${units[i]}`;
  }

  function formatCredits(val) {
    if (val === null || val === undefined || isNaN(val)) return '0.0000 ECC';
    return `${Number(val).toFixed(4)} ECC`;
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function formatDate(isoStr) {
    if (!isoStr) return '—';
    try {
      const d = new Date(isoStr);
      return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch (_) {
      return isoStr;
    }
  }

  function getStatusBadge(statusStr, isSchedulable) {
    const s = (statusStr || 'offline').toLowerCase();
    if (s === 'drain_blocked') {
      return '<span class="badge badge-rose"><span class="status-dot"></span> Drain Blocked</span>';
    }
    if (s === 'drained') {
      return '<span class="badge badge-gray"><span class="status-dot"></span> Drained</span>';
    }
    if (s === 'draining') {
      return '<span class="badge badge-amber"><span class="status-dot"></span> Draining</span>';
    }
    if (s === 'disabled' || isSchedulable === false) {
      return '<span class="badge badge-gray">Disabled</span>';
    }
    if (s === 'online') {
      return '<span class="badge badge-emerald"><span class="status-dot pulse-green"></span> Online</span>';
    }
    if (s === 'probation') {
      return '<span class="badge badge-amber"><span class="status-dot"></span> Probation</span>';
    }
    if (s === 'unhealthy') {
      return '<span class="badge badge-rose"><span class="status-dot"></span> Unhealthy</span>';
    }
    return '<span class="badge badge-rose">Offline</span>';
  }

  // API Call Wrapper: Session Cookie + CSRF Defense (No hardcoded secrets)
  async function fetchApi(endpoint, options = {}) {
    const defaultHeaders = {
      'Accept': 'application/json',
    };

    const method = (options.method || 'GET').toUpperCase();
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
      if (!currentCsrfToken) {
        try {
          const csrfRes = await fetch('/auth/csrf', { credentials: 'same-origin' });
          if (csrfRes.ok) {
            const csrfData = await csrfRes.json();
            currentCsrfToken = csrfData.csrf_token;
          }
        } catch (_) {}
      }
      if (currentCsrfToken) {
        defaultHeaders['X-CSRF-Token'] = currentCsrfToken;
      }
    }

    const res = await fetch(endpoint, {
      ...options,
      credentials: 'same-origin',
      headers: { ...defaultHeaders, ...(options.headers || {}) },
    });

    if (res.status === 401) {
      currentPrincipal = null;
      currentAccount = null;
      updateAuthUI(false, null);
      openLoginModal();
      throw new Error('Authentication required. Please sign in.');
    }

    if (!res.ok) {
      const errText = await res.text();
      let errJson;
      try { errJson = JSON.parse(errText); } catch (_) {}
      let msg;
      if (Array.isArray(errJson?.detail)) {
        msg = errJson.detail.map(e => (e.loc ? `${e.loc.join('.')}: ` : '') + (e.msg || JSON.stringify(e))).join(' | ');
      } else if (typeof errJson?.detail === 'string') {
        msg = errJson.detail;
      } else if (errJson?.detail) {
        msg = JSON.stringify(errJson.detail);
      } else {
        msg = `HTTP ${res.status}: ${res.statusText}`;
      }
      throw new Error(msg);
    }
    return res.json();
  }

  // =========================================================================
  // View Navigation & Hash Routing
  // =========================================================================

  function switchMainView(viewName, updateHash = true) {
    if (viewName === 'files') viewName = 'consumer';
    if (!['landing', 'consumer', 'provider', 'admin'].includes(viewName)) {
      viewName = 'landing';
    }

    // Security check: Only verified administrators can view the Admin Console
    if (viewName === 'admin') {
      if (!currentAccount || (!currentAccount.is_admin && currentAccount.role !== 'admin')) {
        showToast('Access Denied: Server-verified administrator role required.', '🛡️', 4000);
        const fallback = currentAccount ? (currentAccount.role === 'provider' ? 'provider' : 'consumer') : 'landing';
        return switchMainView(fallback, true);
      }
    }

    currentActiveView = viewName;
    if (updateHash) {
      const targetHash = (viewName === 'landing') ? '#landing' : '#' + viewName;
      if (window.location.hash !== targetHash) {
        window.location.hash = targetHash;
      }
    }

    if (navLandingBtn) navLandingBtn.classList.toggle('active', viewName === 'landing');
    if (navConsumerBtn) navConsumerBtn.classList.toggle('active', viewName === 'consumer');
    if (navProviderBtn) navProviderBtn.classList.toggle('active', viewName === 'provider');
    if (navAdminBtn) navAdminBtn.classList.toggle('active', viewName === 'admin');

    if (landingView) landingView.style.display = (viewName === 'landing') ? 'flex' : 'none';
    if (consumerView) consumerView.style.display = (viewName === 'consumer') ? 'flex' : 'none';
    if (providerView) providerView.style.display = (viewName === 'provider') ? 'flex' : 'none';
    if (adminView) adminView.style.display = (viewName === 'admin') ? 'flex' : 'none';

    if (windowSelectorContainer) {
      windowSelectorContainer.style.display = (viewName === 'provider') ? 'flex' : 'none';
    }

    if (viewName === 'landing') {
      if (dashboardContent) dashboardContent.style.display = 'block';
      if (loadingContainer) loadingContainer.style.display = 'none';
      if (errorContainer) errorContainer.style.display = 'none';
    } else if (viewName === 'consumer') {
      loadConsumerFiles();
    } else if (viewName === 'provider') {
      loadProviderDashboard();
    } else if (viewName === 'admin') {
      loadAdminData();
    }
  }

  window.addEventListener('hashchange', () => {
    let h = window.location.hash.replace(/^#\/?/, '').toLowerCase();
    if (!h || h === 'landing') h = 'landing';
    if (h === 'files') h = 'consumer';
    if (['landing', 'consumer', 'provider', 'admin'].includes(h) && h !== currentActiveView) {
      switchMainView(h, false);
    }
  });

  if (navLandingBtn) navLandingBtn.addEventListener('click', () => switchMainView('landing'));
  if (navConsumerBtn) navConsumerBtn.addEventListener('click', () => switchMainView('consumer'));
  if (navProviderBtn) navProviderBtn.addEventListener('click', () => switchMainView('provider'));
  if (navAdminBtn) navAdminBtn.addEventListener('click', () => switchMainView('admin'));

  // Landing CTAs
  if (landingLaunchBtn) {
    landingLaunchBtn.addEventListener('click', () => {
      if (currentAccount) {
        const role = (currentAccount.role || 'consumer').toLowerCase();
        switchMainView(role === 'admin' ? 'admin' : (role === 'provider' ? 'provider' : 'consumer'));
      } else {
        switchMainView('consumer');
      }
    });
  }
  if (landingSigninBtn) {
    landingSigninBtn.addEventListener('click', () => {
      openLoginModal();
      switchAuthTab('login');
    });
  }
  if (landingRegisterBtn) {
    landingRegisterBtn.addEventListener('click', () => {
      openLoginModal();
      switchAuthTab('register');
    });
  }
  if (ctaConsumerActionBtn) {
    ctaConsumerActionBtn.addEventListener('click', () => switchMainView('consumer'));
  }
  if (ctaProviderActionBtn) {
    ctaProviderActionBtn.addEventListener('click', () => switchMainView('provider'));
  }
  if (demoSigninBtn) {
    demoSigninBtn.addEventListener('click', () => {
      openLoginModal();
      switchAuthTab('login');
    });
  }

  // Pre-fill demo accounts on click
  document.querySelectorAll('.demo-account-box').forEach(box => {
    box.addEventListener('click', () => {
      const email = box.getAttribute('data-email');
      openLoginModal();
      switchAuthTab('login');
      if (loginProviderId && email) {
        loginProviderId.value = email;
        if (loginSecret) loginSecret.focus();
      }
    });
  });

  // =========================================================================
  // CONSUMER FILE MANAGER (Phase 10F)
  // =========================================================================

  async function loadConsumerFiles() {
    loadingContainer.style.display = 'block';
    errorContainer.style.display = 'none';

    if (!currentPrincipal) {
      loadingContainer.style.display = 'none';
      dashboardContent.style.display = 'block';
      consumerEmptyFiles.style.display = 'block';
      consumerFilesSubtitle.textContent = 'Sign in to store and manage your distributed files';
      consumerUsedBytesEl.textContent = '0 B';
      consumerTotalQuotaEl.textContent = '10.00 GB';
      consumerAvailBytesEl.textContent = '10.00 GB';
      consumerProgressFill.style.width = '0%';
      renderConsumerFilesTable([]);
      return;
    }

    try {
      const data = await fetchApi('/consumer/files');
      cachedConsumerFiles = data.files || [];

      // Update Quota Summary
      consumerUsedBytesEl.textContent = formatBytes(data.used_bytes);
      consumerTotalQuotaEl.textContent = formatBytes(data.quota_bytes);
      consumerAvailBytesEl.textContent = formatBytes(data.available_bytes);
      consumerFilesCountEl.textContent = `${data.total_files} file${data.total_files === 1 ? '' : 's'}`;

      let pct = 0;
      if (data.quota_bytes > 0) {
        pct = Math.min(100, Math.round((data.used_bytes / data.quota_bytes) * 100));
      }
      consumerProgressFill.style.width = `${pct}%`;
      if (pct > 90) {
        consumerProgressFill.className = 'progress-bar-fill rose-fill';
      } else if (pct > 75) {
        consumerProgressFill.className = 'progress-bar-fill amber-fill';
      } else {
        consumerProgressFill.className = 'progress-bar-fill cyan-fill';
      }

      renderConsumerFilesTable(cachedConsumerFiles);
      loadingContainer.style.display = 'none';
      dashboardContent.style.display = 'block';
    } catch (err) {
      loadingContainer.style.display = 'none';
      errorMessage.textContent = err.message || 'Failed to load consumer files.';
      errorContainer.style.display = 'block';
    }
  }

  function renderConsumerFilesTable(files) {
    consumerFilesSubtitle.textContent = `${files.length} file${files.length === 1 ? '' : 's'} registered`;
    consumerFilesTbody.innerHTML = '';

    if (files.length === 0) {
      consumerEmptyFiles.style.display = 'block';
      return;
    }
    consumerEmptyFiles.style.display = 'none';

    files.forEach(f => {
      const tr = document.createElement('tr');
      const safeFilename = escapeHtml(f.original_filename);
      const safeId = escapeHtml(f.file_id);
      const statusBadge = (f.status === 'active')
        ? '<span class="badge badge-emerald">Active</span>'
        : `<span class="badge badge-amber">${escapeHtml(f.status)}</span>`;

      tr.innerHTML = `
        <td>
          <div style="font-weight: 600; color: var(--text-main);">${safeFilename}</div>
          <div style="font-size: 0.75rem; color: var(--text-dim);">${safeId}</div>
        </td>
        <td>${formatBytes(f.original_size)}</td>
        <td><span class="badge badge-cyan">${escapeHtml(f.redundancy_mode)}</span></td>
        <td>${f.chunk_count} chunk${f.chunk_count === 1 ? '' : 's'}</td>
        <td>${statusBadge}</td>
        <td>${formatDate(f.created_at)}</td>
        <td>
          <div style="display: flex; gap: 0.4rem;">
            <button class="btn btn-outline btn-sm download-file-btn" data-id="${safeId}" data-name="${safeFilename}" title="Download file">
              ⬇ Download
            </button>
            <button class="btn btn-danger btn-sm delete-file-btn" data-id="${safeId}" data-name="${safeFilename}" title="Delete file">
              🗑 Delete
            </button>
          </div>
        </td>
      `;
      consumerFilesTbody.appendChild(tr);
    });

    // Attach row action listeners
    consumerFilesTbody.querySelectorAll('.download-file-btn').forEach(btn => {
      btn.addEventListener('click', () => handleDownloadFile(btn.dataset.id, btn.dataset.name, btn));
    });
    consumerFilesTbody.querySelectorAll('.delete-file-btn').forEach(btn => {
      btn.addEventListener('click', () => handleDeleteFile(btn.dataset.id, btn.dataset.name));
    });
  }

  // Consumer File Upload
  if (consumerFileInput) {
    consumerFileInput.addEventListener('change', () => {
      if (consumerFileInput.files.length > 0) {
        selectedFileNameEl.textContent = `Selected: ${consumerFileInput.files[0].name} (${formatBytes(consumerFileInput.files[0].size)})`;
        selectedFileNameEl.style.display = 'block';
      }
    });
  }

  if (consumerUploadBtn) {
    consumerUploadBtn.addEventListener('click', async (e) => {
      e.stopPropagation();
      if (!consumerFileInput.files || consumerFileInput.files.length === 0) {
        consumerFileInput.click();
        return;
      }

      const file = consumerFileInput.files[0];
      const formData = new FormData();
      formData.append('file', file);

      consumerUploadStatus.textContent = `Uploading '${file.name}' to distributed storage...`;
      consumerUploadStatus.style.color = 'var(--accent-cyan)';
      consumerUploadStatus.style.display = 'block';
      consumerUploadBtn.disabled = true;

      try {
        const res = await fetch('/consumer/files/upload', {
          method: 'POST',
          credentials: 'same-origin',
          headers: currentCsrfToken ? { 'X-CSRF-Token': currentCsrfToken } : {},
          body: formData,
        });

        const data = await res.json();
        if (res.ok) {
          consumerUploadStatus.textContent = `✅ Successfully uploaded '${file.name}' (${formatBytes(file.size)})!`;
          consumerUploadStatus.style.color = 'var(--accent-emerald)';
          consumerFileInput.value = '';
          selectedFileNameEl.style.display = 'none';
          await loadConsumerFiles();
        } else {
          consumerUploadStatus.textContent = `❌ Upload failed: ${data.detail || 'Server error'}`;
          consumerUploadStatus.style.color = 'var(--accent-rose)';
        }
      } catch (err) {
        consumerUploadStatus.textContent = `❌ Upload network error: ${err.message}`;
        consumerUploadStatus.style.color = 'var(--accent-rose)';
      } finally {
        consumerUploadBtn.disabled = false;
      }
    });
  }

  // Drag and Drop
  if (dropzone) {
    ['dragenter', 'dragover'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        dropzone.classList.add('dragover');
      }, false);
    });
    ['dragleave', 'drop'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
      }, false);
    });
    dropzone.addEventListener('drop', (e) => {
      if (e.dataTransfer.files.length > 0) {
        consumerFileInput.files = e.dataTransfer.files;
        selectedFileNameEl.textContent = `Selected: ${consumerFileInput.files[0].name} (${formatBytes(consumerFileInput.files[0].size)})`;
        selectedFileNameEl.style.display = 'block';
      }
    });
  }

  // Consumer File Download
  async function handleDownloadFile(fileId, filename, triggerBtn) {
    if (triggerBtn) {
      triggerBtn.disabled = true;
      triggerBtn.textContent = '⏳ Decrypting...';
    }
    try {
      const res = await fetch(`/consumer/files/${encodeURIComponent(fileId)}/download`, {
        credentials: 'same-origin',
      });
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        let msg = errJson.detail;
        if (Array.isArray(msg)) msg = msg.map(e => e.msg || JSON.stringify(e)).join('; ');
        throw new Error(msg || `Download failed with HTTP ${res.status}`);
      }
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename || `${fileId}.bin`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();
    } catch (err) {
      alert(`Download Error: ${err.message}`);
    } finally {
      if (triggerBtn) {
        triggerBtn.disabled = false;
        triggerBtn.textContent = '⬇ Download';
      }
    }
  }

  // Consumer File Deletion
  async function handleDeleteFile(fileId, filename) {
    if (!confirm(`Are you sure you want to delete '${filename}'? Chunks will be deleted from storage nodes.`)) {
      return;
    }
    try {
      await fetchApi(`/consumer/files/${encodeURIComponent(fileId)}`, {
        method: 'DELETE',
      });
      await loadConsumerFiles();
    } catch (err) {
      alert(`Deletion Error: ${err.message}`);
    }
  }

  if (consumerSearchInput) {
    consumerSearchInput.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase().trim();
      const filtered = cachedConsumerFiles.filter(f =>
        f.original_filename.toLowerCase().includes(q) || f.file_id.toLowerCase().includes(q)
      );
      renderConsumerFilesTable(filtered);
    });
  }

  // =========================================================================
  // PROVIDER PORTAL (Storage Node Telemetry & Lifecycle)
  // =========================================================================

  async function loadProviderDashboard() {
    const windowHours = parseFloat(windowSelect.value) || 24.0;
    trafficWindowBadge.textContent = `${windowHours}h Window`;

    loadingContainer.style.display = 'block';
    errorContainer.style.display = 'none';
    staleBanner.style.display = 'none';

    if (!currentPrincipal) {
      loadingContainer.style.display = 'none';
      dashboardContent.style.display = 'block';
      if (providerOnboardBanner) providerOnboardBanner.style.display = 'none';
      emptyNodesContainer.style.display = 'block';
      nodesCountSubtitle.textContent = 'Sign in as a provider to register and manage nodes';
      nodesTableBody.innerHTML = '';
      return;
    }

    try {
      // Check onboarding consent status
      fetchApi('/provider/onboarding')
        .then(() => {
          if (providerOnboardBanner) providerOnboardBanner.style.display = 'none';
        })
        .catch(() => {
          if (providerOnboardBanner) providerOnboardBanner.style.display = 'flex';
        });

      const data = await fetchApi(`/provider/overview?window_hours=${windowHours}`);
      renderProviderOverview(data);
      cachedNodes = data.nodes || [];
      renderNodesTable(cachedNodes);
      renderCharts(data);
      await loadCombinedActivity(cachedNodes);

      loadingContainer.style.display = 'none';
      dashboardContent.style.display = 'block';
    } catch (err) {
      loadingContainer.style.display = 'none';
      errorMessage.textContent = err.message || 'Failed to fetch provider overview.';
      errorContainer.style.display = 'block';
    }
  }

  function renderProviderOverview(data) {
    providerIdLabel.textContent = data.provider_id || 'default_provider';

    verifiedStoredBytesEl.textContent = formatBytes(data.total_verified_stored_bytes);
    configuredQuotaBytesEl.textContent = formatBytes(data.total_configured_quota_bytes);
    remainingQuotaBytesEl.textContent = formatBytes(data.total_remaining_quota_bytes);

    let progressPct = 0;
    if (data.total_configured_quota_bytes > 0) {
      progressPct = Math.min(100, (data.total_verified_stored_bytes / data.total_configured_quota_bytes) * 100);
    }
    storageProgressFill.style.width = `${progressPct.toFixed(1)}%`;

    if (data.physical_host_disk) {
      const d = data.physical_host_disk;
      physicalDiskStatsEl.textContent = `${formatBytes(d.used_bytes)} / ${formatBytes(d.total_bytes)} (${d.usage_percent.toFixed(1)}% used)`;
    } else {
      physicalDiskStatsEl.textContent = 'Not reported by provider';
    }

    totalTrafficBytesEl.textContent = formatBytes(data.bandwidth_stats.total_traffic_bytes);
    totalIngressBytesEl.textContent = formatBytes(data.bandwidth_stats.total_ingress_bytes);
    totalEgressBytesEl.textContent = formatBytes(data.bandwidth_stats.total_egress_bytes);
    trafficRatioTextEl.textContent = `Egress / Ingress = ${data.bandwidth_stats.transfer_ratio.toFixed(2)}`;

    totalCreditsBalanceEl.textContent = formatCredits(data.credits_summary.total_balance_ecc);
    totalLifetimeEarnedEl.textContent = formatCredits(data.credits_summary.total_lifetime_earned_ecc);
    totalLifetimeReversedEl.textContent = formatCredits(data.credits_summary.total_lifetime_reversed_ecc);

    averageReputationScoreEl.textContent = data.reputation_summary.average_score.toFixed(1);
    reputationConfidenceBadge.textContent = `${data.reputation_summary.confidence_rating} Confidence`;
    recentSuccRepairsEl.textContent = data.reputation_summary.recent_successful_repairs;
    recentFailRepairsEl.textContent = data.reputation_summary.recent_failed_repairs;

    if (data.stale_heartbeat_nodes_count > 0) {
      staleBanner.style.display = 'flex';
    } else {
      staleBanner.style.display = 'none';
    }
  }

  function renderNodesTable(nodes) {
    nodesCountSubtitle.textContent = `${nodes.length} node${nodes.length === 1 ? '' : 's'} registered`;
    nodesTableBody.innerHTML = '';

    if (nodes.length === 0) {
      emptyNodesContainer.style.display = 'block';
      return;
    }
    emptyNodesContainer.style.display = 'none';

    nodes.forEach(node => {
      const tr = document.createElement('tr');
      const safeId = escapeHtml(node.node_id);
      const safeEndpoint = escapeHtml(node.endpoint || '');
      const schedText = node.is_schedulable ? 'Schedulable' : 'Suspended';
      const schedBadge = node.is_schedulable ? 'badge-emerald' : 'badge-gray';

      tr.innerHTML = `
        <td>
          <a href="#" class="node-id-link" data-node-id="${safeId}">${safeId}</a>
          <span style="display: block; font-size: 0.75rem; color: var(--text-dim);">${safeEndpoint}</span>
        </td>
        <td>${getStatusBadge(node.status, node.is_schedulable)}</td>
        <td><span class="badge badge-cyan">${escapeHtml(node.connectivity_mode)}</span></td>
        <td>
          <div style="font-size: 0.85rem;">${formatBytes(node.verified_stored_bytes)} / ${formatBytes(node.total_capacity_bytes)}</div>
          <div style="font-size: 0.7rem; color: var(--text-dim);">${formatBytes(node.available_capacity_bytes)} free</div>
        </td>
        <td>${(node.availability_ratio * 100).toFixed(1)}%</td>
        <td><span class="amber-text font-bold">${node.reputation_score.toFixed(1)}</span></td>
        <td><span class="emerald-text font-bold">${formatCredits(node.credit_balance_ecc)}</span></td>
        <td><span class="badge ${schedBadge}">${schedText}</span></td>
        <td>
          <div style="display: flex; gap: 0.4rem;">
            <button class="btn btn-outline btn-sm node-diag-btn" data-node-id="${safeId}" title="Diagnostics">
              Inspect
            </button>
            <button class="btn btn-danger btn-sm node-drain-trigger-btn" data-node-id="${safeId}" title="Drain Node">
              Drain
            </button>
          </div>
        </td>
      `;
      nodesTableBody.appendChild(tr);
    });

    nodesTableBody.querySelectorAll('.node-id-link, .node-diag-btn').forEach(el => {
      el.addEventListener('click', (e) => {
        e.preventDefault();
        openNodeModal(el.dataset.nodeId);
      });
    });

    nodesTableBody.querySelectorAll('.node-drain-trigger-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const nid = btn.dataset.nodeId;
        if (!confirm(`Initiate graceful drain for node '${nid}'?`)) return;
        try {
          await fetchApi(`/provider/nodes/${encodeURIComponent(nid)}/drain`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reason: 'Provider drain from UI' }),
          });
          await loadProviderDashboard();
        } catch (err) {
          alert(`Drain Error: ${err.message}`);
        }
      });
    });
  }

  // Node Search
  if (nodeSearchInput) {
    nodeSearchInput.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase().trim();
      const filtered = cachedNodes.filter(n =>
        n.node_id.toLowerCase().includes(q) || n.host.toLowerCase().includes(q)
      );
      renderNodesTable(filtered);
    });
  }

  // SVG Charts
  function renderCharts(data) {
    if (storageChartContainer) {
      const verified = data.total_verified_stored_bytes || 0;
      const quota = data.total_configured_quota_bytes || 1;
      const pct = Math.min(100, (verified / quota) * 100);

      storageChartContainer.innerHTML = `
        <svg viewBox="0 0 400 120" style="width: 100%; height: 100%;">
          <rect x="20" y="30" width="360" height="30" rx="15" fill="rgba(255,255,255,0.05)" />
          <rect x="20" y="30" width="${Math.max(10, (360 * pct) / 100)}" height="30" rx="15" fill="url(#cyan-grad)" />
          <defs>
            <linearGradient id="cyan-grad" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stop-color="#06b6d4" />
              <stop offset="100%" stop-color="#3b82f6" />
            </linearGradient>
          </defs>
          <text x="20" y="85" fill="#94a3b8" font-size="12">Stored: ${formatBytes(verified)} (${pct.toFixed(1)}%)</text>
          <text x="380" y="85" text-anchor="end" fill="#94a3b8" font-size="12">Quota: ${formatBytes(quota)}</text>
        </svg>
      `;
    }

    if (trafficChartContainer) {
      const ing = data.bandwidth_stats.total_ingress_bytes || 0;
      const eg = data.bandwidth_stats.total_egress_bytes || 0;
      const total = ing + eg || 1;
      const ingPct = (ing / total) * 100;
      const egPct = (eg / total) * 100;

      trafficChartContainer.innerHTML = `
        <svg viewBox="0 0 400 120" style="width: 100%; height: 100%;">
          <rect x="20" y="30" width="360" height="30" rx="15" fill="rgba(255,255,255,0.05)" />
          <rect x="20" y="30" width="${(360 * ingPct) / 100}" height="30" rx="15" fill="#06b6d4" />
          <rect x="${20 + (360 * ingPct) / 100}" y="30" width="${(360 * egPct) / 100}" height="30" rx="15" fill="#8b5cf6" />
          <text x="20" y="85" fill="#06b6d4" font-size="12">Ingress: ${formatBytes(ing)}</text>
          <text x="380" y="85" text-anchor="end" fill="#8b5cf6" font-size="12">Egress: ${formatBytes(eg)}</text>
        </svg>
      `;
    }
  }

  async function loadCombinedActivity(nodes) {
    if (!activityStreamList) return;
    activityStreamList.innerHTML = '<p style="color: var(--text-dim); padding: 1rem;">Loading activity stream...</p>';

    const allEvents = [];
    for (const node of nodes.slice(0, 5)) {
      try {
        const events = await fetchApi(`/provider/nodes/${encodeURIComponent(node.node_id)}/ledger/events?limit=3`);
        events.forEach(e => allEvents.push({ ...e, node_id: node.node_id }));
      } catch (_) {}
    }

    if (allEvents.length === 0) {
      activityStreamList.innerHTML = '<p style="color: var(--text-dim); padding: 1rem;">No recent ledger activity recorded.</p>';
      return;
    }

    allEvents.sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
    activityStreamList.innerHTML = '';
    allEvents.slice(0, 8).forEach(e => {
      const item = document.createElement('div');
      item.className = 'activity-item';
      item.style.padding = '0.75rem';
      item.style.borderBottom = '1px solid var(--border-subtle)';
      item.innerHTML = `
        <div style="display: flex; justify-content: space-between; font-size: 0.85rem;">
          <span style="font-weight: 600; color: var(--accent-cyan);">${escapeHtml(e.event_type || 'Ledger Accrual')}</span>
          <span style="color: var(--text-dim);">${formatDate(e.created_at)}</span>
        </div>
        <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.2rem;">
          Node: <strong>${escapeHtml(e.node_id)}</strong> &bull; Amount: <strong>${formatCredits(e.amount_ecc)}</strong>
        </div>
      `;
      activityStreamList.appendChild(item);
    });
  }

  // Node Modal
  async function openNodeModal(nodeId) {
    currentActiveNodeId = nodeId;
    modalNodeTitle.textContent = `Node Diagnostics: ${nodeId}`;
    modalBodyContent.innerHTML = '<p style="padding: 1.5rem; color: var(--text-muted);">Loading diagnostics...</p>';
    nodeModal.style.display = 'flex';

    try {
      const diag = await fetchApi(`/provider/nodes/${encodeURIComponent(nodeId)}/diagnostics`);
      modalNodeEndpoint.textContent = diag.endpoint || '';
      modalBodyContent.innerHTML = `
        <div class="diag-grid">
          <div class="diag-item"><span class="diag-label">Lifecycle State</span><span class="diag-value">${escapeHtml(diag.lifecycle_state || 'registered')}</span></div>
          <div class="diag-item"><span class="diag-label">Reliability Score</span><span class="diag-value font-bold amber-text">${Number(diag.reliability_score || 0).toFixed(1)} / 100</span></div>
          <div class="diag-item"><span class="diag-label">Successful Health Checks</span><span class="diag-value emerald-text">${diag.health_check_success_count || 0}</span></div>
          <div class="diag-item"><span class="diag-label">Failed Health Checks</span><span class="diag-value rose-text">${diag.health_check_fail_count || 0}</span></div>
          <div class="diag-item"><span class="diag-label">Consecutive Failures</span><span class="diag-value">${diag.consecutive_failures || 0}</span></div>
          <div class="diag-item"><span class="diag-label">Drain Status</span><span class="diag-value">${escapeHtml(diag.drain_status || 'none')}</span></div>
        </div>
        <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 1rem;">
          <span style="font-size: 0.85rem; color: var(--text-muted);">Run instant non-destructive health validation:</span>
          <button id="modal-run-check-btn" class="btn btn-outline btn-sm">Run Health Check</button>
        </div>
        <div id="modal-check-result" style="margin-top: 0.75rem; font-size: 0.85rem; display: none;"></div>
      `;

      const runCheckBtn = document.getElementById('modal-run-check-btn');
      const checkResultEl = document.getElementById('modal-check-result');
      if (runCheckBtn) {
        runCheckBtn.addEventListener('click', async () => {
          runCheckBtn.disabled = true;
          checkResultEl.textContent = 'Running validation checks...';
          checkResultEl.style.display = 'block';
          checkResultEl.style.color = 'var(--accent-cyan)';
          try {
            const v = await fetchApi(`/provider/nodes/${encodeURIComponent(nodeId)}/validate`, { method: 'POST' });
            checkResultEl.textContent = `✅ Validation complete: ${v.status} (score: ${v.reliability_score?.toFixed(1)})`;
            checkResultEl.style.color = 'var(--accent-emerald)';
          } catch (err) {
            checkResultEl.textContent = `❌ Validation failed: ${err.message}`;
            checkResultEl.style.color = 'var(--accent-rose)';
          } finally {
            runCheckBtn.disabled = false;
          }
        });
      }
    } catch (err) {
      modalBodyContent.innerHTML = `<p style="padding: 1.5rem; color: var(--accent-rose);">Failed to load diagnostics: ${err.message}</p>`;
    }
  }

  function closeNodeModal() {
    nodeModal.style.display = 'none';
  }

  if (modalCloseBtn) modalCloseBtn.addEventListener('click', closeNodeModal);
  if (modalDismissBtn) modalDismissBtn.addEventListener('click', closeNodeModal);
  if (nodeModal) {
    nodeModal.addEventListener('click', (e) => {
      if (e.target === nodeModal) closeNodeModal();
    });
  }

  if (modalDrainBtn) {
    modalDrainBtn.addEventListener('click', async () => {
      if (!currentActiveNodeId) return;
      if (!confirm(`Are you sure you want to drain node '${currentActiveNodeId}'?`)) return;
      try {
        await fetchApi(`/provider/nodes/${encodeURIComponent(currentActiveNodeId)}/drain`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ reason: 'Modal drain' }),
        });
        closeNodeModal();
        await loadProviderDashboard();
      } catch (err) {
        alert(`Drain Error: ${err.message}`);
      }
    });
  }

  // =========================================================================
  // ADMIN CONSOLE (Phase 10F)
  // =========================================================================

  async function loadAdminData() {
    loadingContainer.style.display = 'block';
    errorContainer.style.display = 'none';

    if (!currentAccount || (!currentAccount.is_admin && currentAccount.role !== 'admin')) {
      loadingContainer.style.display = 'none';
      errorMessage.textContent = 'Administrative privileges required. Please sign in with an administrator account to view the Admin Console.';
      errorContainer.style.display = 'block';
      return;
    }

    try {
      // 1. Stats Overview
      const stats = await fetchApi('/admin/stats/overview');
      adminTotalAccountsEl.textContent = stats.accounts.total;
      adminRolesSplitEl.textContent = `${stats.accounts.active} active &bull; ${stats.accounts.providers} prov`;
      adminSuspendedAccountsEl.textContent = stats.accounts.suspended;

      adminTotalNodesEl.textContent = stats.nodes.total;
      adminOnlineNodesEl.textContent = `${stats.nodes.online} Online`;
      adminProbationNodesEl.textContent = `${stats.nodes.probation} prob &bull; ${stats.nodes.unhealthy} unh`;

      adminTotalCapacityEl.textContent = formatBytes(stats.storage.total_capacity_bytes);
      adminUsedCapacityEl.textContent = formatBytes(stats.storage.used_capacity_bytes);
      adminTotalFilesEl.textContent = `${stats.storage.total_files} files (${formatBytes(stats.storage.total_file_bytes)})`;

      adminPendingDeletionsEl.textContent = stats.jobs.pending_deletions;
      adminFailedRepairsEl.textContent = stats.jobs.failed_repairs;
      adminActiveReservationsEl.textContent = stats.jobs.active_reservations;

      // 2. Accounts List
      const accData = await fetchApi('/admin/accounts?limit=50');
      cachedAdminAccounts = accData.accounts || [];
      renderAdminAccountsTable(cachedAdminAccounts);

      // 3. Nodes List
      const nodeData = await fetchApi('/admin/nodes?limit=50');
      renderAdminNodesTable(nodeData.nodes || []);

      // 4. Audit Logs
      const auditData = await fetchApi('/admin/audit-logs?limit=50');
      renderAdminAuditTable(auditData.logs || []);

      loadingContainer.style.display = 'none';
      dashboardContent.style.display = 'block';
    } catch (err) {
      loadingContainer.style.display = 'none';
      errorMessage.textContent = err.message || 'Failed to load administrative console.';
      errorContainer.style.display = 'block';
    }
  }

  function renderAdminAccountsTable(accounts) {
    adminAccountsTbody.innerHTML = '';
    accounts.forEach(acc => {
      const tr = document.createElement('tr');
      const safeId = escapeHtml(acc.account_id);
      const safeEmail = escapeHtml(acc.email);
      const isSuspended = acc.status === 'suspended' || acc.status === 'disabled';
      const statusBadge = isSuspended
        ? '<span class="badge badge-rose">Suspended</span>'
        : '<span class="badge badge-emerald">Active</span>';
      const actionBtnText = isSuspended ? 'Restore' : 'Suspend';
      const actionBtnClass = isSuspended ? 'btn-success' : 'btn-danger';
      const newStatus = isSuspended ? 'active' : 'suspended';

      tr.innerHTML = `
        <td><span style="font-family: monospace; font-size: 0.8rem;">${safeId}</span></td>
        <td><strong>${safeEmail}</strong></td>
        <td><span class="badge badge-cyan">${escapeHtml(acc.role)}</span></td>
        <td>${statusBadge}</td>
        <td>${acc.email_verified ? '✅ Verified' : '⚠️ No'}</td>
        <td>${formatBytes(acc.quota_bytes || 0)}</td>
        <td>${formatDate(acc.created_at)}</td>
        <td>
          <button class="btn ${actionBtnClass} btn-sm admin-toggle-status-btn" data-id="${safeId}" data-status="${newStatus}" title="${actionBtnText} account">
            ${actionBtnText}
          </button>
        </td>
      `;
      adminAccountsTbody.appendChild(tr);
    });

    adminAccountsTbody.querySelectorAll('.admin-toggle-status-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const accId = btn.dataset.id;
        const targetStatus = btn.dataset.status;
        const reason = prompt(`Enter justification for changing account status to '${targetStatus}':`, 'Admin portal update');
        if (!reason || !reason.trim()) return;

        try {
          await fetchApi(`/admin/accounts/${encodeURIComponent(accId)}/status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: targetStatus, reason: reason.trim() }),
          });
          await loadAdminData();
        } catch (err) {
          alert(`Account Status Update Error: ${err.message}`);
        }
      });
    });
  }

  function renderAdminNodesTable(nodes) {
    adminNodesTbody.innerHTML = '';
    nodes.forEach(n => {
      const tr = document.createElement('tr');
      const safeId = escapeHtml(n.node_id);
      const safeProv = escapeHtml(n.provider_id || 'default');

      tr.innerHTML = `
        <td><strong>${safeId}</strong></td>
        <td>${safeProv}</td>
        <td>${getStatusBadge(n.status, n.is_schedulable)}</td>
        <td><span class="badge badge-cyan">${escapeHtml(n.lifecycle_state || 'registered')}</span></td>
        <td><span class="amber-text font-bold">${Number(n.reliability_score || 0).toFixed(1)}</span></td>
        <td>${n.consecutive_failures || 0}</td>
        <td>${formatBytes(n.used_capacity_bytes || 0)} / ${formatBytes(n.total_capacity_bytes || 0)}</td>
        <td>
          <button class="btn btn-danger btn-sm admin-node-drain-btn" data-id="${safeId}">
            Drain
          </button>
        </td>
      `;
      adminNodesTbody.appendChild(tr);
    });

    adminNodesTbody.querySelectorAll('.admin-node-drain-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const nid = btn.dataset.id;
        const reason = prompt(`Reason for administrative drain of node '${nid}':`, 'Administrative maintenance');
        if (!reason || !reason.trim()) return;

        try {
          await fetchApi(`/admin/nodes/${encodeURIComponent(nid)}/drain`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reason: reason.trim() }),
          });
          await loadAdminData();
        } catch (err) {
          alert(`Node Drain Error: ${err.message}`);
        }
      });
    });
  }

  function renderAdminAuditTable(logs) {
    adminAuditTbody.innerHTML = '';
    logs.forEach(l => {
      const tr = document.createElement('tr');
      const detailsStr = l.details ? JSON.stringify(l.details) : '—';
      tr.innerHTML = `
        <td>${formatDate(l.timestamp)}</td>
        <td>${escapeHtml(l.admin_email)}</td>
        <td><span class="badge badge-violet">${escapeHtml(l.action)}</span></td>
        <td>${escapeHtml(l.target_type)}</td>
        <td><span style="font-family: monospace; font-size: 0.8rem;">${escapeHtml(l.target_id)}</span></td>
        <td>${escapeHtml(l.ip_address || '—')}</td>
        <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(detailsStr)}">
          ${escapeHtml(detailsStr)}
        </td>
      `;
      adminAuditTbody.appendChild(tr);
    });
  }

  // Admin Account Search & Filters
  if (adminAccountSearch) {
    adminAccountSearch.addEventListener('input', applyAdminAccountFilters);
  }
  if (adminAccountRoleFilter) {
    adminAccountRoleFilter.addEventListener('change', applyAdminAccountFilters);
  }
  if (adminAccountStatusFilter) {
    adminAccountStatusFilter.addEventListener('change', applyAdminAccountFilters);
  }

  function applyAdminAccountFilters() {
    const q = (adminAccountSearch?.value || '').toLowerCase().trim();
    const r = (adminAccountRoleFilter?.value || '').toLowerCase().trim();
    const s = (adminAccountStatusFilter?.value || '').toLowerCase().trim();

    const filtered = cachedAdminAccounts.filter(acc => {
      const matchQ = !q || acc.email.toLowerCase().includes(q) || acc.account_id.toLowerCase().includes(q);
      const matchR = !r || (acc.role || '').toLowerCase() === r;
      const matchS = !s || (acc.status || '').toLowerCase() === s;
      return matchQ && matchR && matchS;
    });
    renderAdminAccountsTable(filtered);
  }

  // Reconciliation Trigger
  if (adminReconcileBtn) {
    adminReconcileBtn.addEventListener('click', async () => {
      const dryRun = adminReconcileDryRun ? adminReconcileDryRun.checked : true;
      adminReconcileBtn.disabled = true;
      adminReconcileResults.style.display = 'block';
      adminReconcileResults.textContent = 'Running catalog reconciliation...';
      adminReconcileResults.style.color = 'var(--accent-cyan)';

      try {
        const res = await fetchApi(`/admin/operations/reconcile?dry_run=${dryRun}`, { method: 'POST' });
        const orphaned = res.orphaned_objects_detected ?? res.orphaned_objects_found ?? 0;
        const missing = res.missing_objects_detected ?? res.missing_objects_found ?? 0;
        const stalled = res.stalled_deletions_resumed ?? res.stalled_deletions_processed ?? 0;
        adminReconcileResults.innerHTML = `
          <strong>Reconciliation Results (${res.status === 'dry_run' ? 'Dry Run' : 'Executed'}):</strong><br>
          &bull; Orphaned Objects: ${orphaned}<br>
          &bull; Missing Objects: ${missing}<br>
          &bull; Stalled Deletions Resumed: ${stalled}
        `;
        adminReconcileResults.style.color = 'var(--accent-emerald)';
        await loadAdminData();
      } catch (err) {
        adminReconcileResults.textContent = `❌ Reconciliation Error: ${err.message}`;
        adminReconcileResults.style.color = 'var(--accent-rose)';
      } finally {
        adminReconcileBtn.disabled = false;
      }
    });
  }

  // =========================================================================
  // NODE REGISTRATION & PROVIDER ONBOARDING MODALS (Phase 10F)
  // =========================================================================

  if (registerNodeOpenBtn) {
    registerNodeOpenBtn.addEventListener('click', () => {
      nodeRegisterModal.style.display = 'flex';
      nodeRegStatus.style.display = 'none';
    });
  }
  if (nodeRegCloseBtn) {
    nodeRegCloseBtn.addEventListener('click', () => {
      nodeRegisterModal.style.display = 'none';
    });
  }

  if (nodeRegForm) {
    nodeRegForm.addEventListener('submit', async () => {
      const nid = nodeRegId.value.trim();
      const host = nodeRegHost.value.trim();
      const port = parseInt(nodeRegPort.value, 10);
      const capGb = parseFloat(nodeRegCapacity.value);

      if (!nid || !host || isNaN(port) || isNaN(capGb)) {
        nodeRegStatus.textContent = 'Please fill out all fields with valid values.';
        nodeRegStatus.style.color = 'var(--accent-rose)';
        nodeRegStatus.style.display = 'block';
        return;
      }

      const submitBtn = document.getElementById('node-reg-submit-btn');
      if (submitBtn) submitBtn.disabled = true;

      nodeRegStatus.textContent = 'Registering node...';
      nodeRegStatus.style.color = 'var(--accent-cyan)';
      nodeRegStatus.style.display = 'block';

      try {
        await fetchApi('/nodes/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            node_id: nid,
            host: host,
            port: port,
            endpoint: `http://${host}:${port}`,
            advertised_endpoint: `http://${host}:${port}`,
            total_capacity_bytes: Math.round(capGb * 1024 * 1024 * 1024),
            connectivity_mode: 'LAN',
            status: 'online',
          }),
        });

        nodeRegStatus.textContent = '✅ Node successfully registered!';
        nodeRegStatus.style.color = 'var(--accent-emerald)';
        setTimeout(() => {
          nodeRegisterModal.style.display = 'none';
          loadProviderDashboard();
        }, 800);
      } catch (err) {
        nodeRegStatus.textContent = `❌ Registration failed: ${err.message}`;
        nodeRegStatus.style.color = 'var(--accent-rose)';
      } finally {
        if (submitBtn) submitBtn.disabled = false;
      }
    });
  }

  // Provider Onboarding
  if (bannerOnboardBtn) {
    bannerOnboardBtn.addEventListener('click', () => {
      providerOnboardModal.style.display = 'flex';
      onboardStatusMsg.style.display = 'none';
    });
  }
  if (onboardCloseBtn) {
    onboardCloseBtn.addEventListener('click', () => {
      providerOnboardModal.style.display = 'none';
    });
  }

  if (onboardForm) {
    onboardForm.addEventListener('submit', async () => {
      if (!onboardAcceptTerms.checked) {
        onboardStatusMsg.textContent = 'You must agree to the terms of service.';
        onboardStatusMsg.style.color = 'var(--accent-rose)';
        onboardStatusMsg.style.display = 'block';
        return;
      }

      const submitBtn = document.getElementById('onboard-submit-btn');
      if (submitBtn) submitBtn.disabled = true;

      onboardStatusMsg.textContent = 'Submitting onboarding acceptance...';
      onboardStatusMsg.style.color = 'var(--accent-cyan)';
      onboardStatusMsg.style.display = 'block';

      try {
        const provId = onboardProviderId.value.trim() || undefined;
        await fetchApi('/provider/onboard', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            accept_terms: true,
            provider_id: provId,
            terms_version: '1.0',
          }),
        });

        onboardStatusMsg.textContent = '✅ Provider onboarding complete!';
        onboardStatusMsg.style.color = 'var(--accent-emerald)';
        if (providerOnboardBanner) providerOnboardBanner.style.display = 'none';
        setTimeout(() => {
          providerOnboardModal.style.display = 'none';
          loadProviderDashboard();
        }, 800);
      } catch (err) {
        onboardStatusMsg.textContent = `❌ Onboarding failed: ${err.message}`;
        onboardStatusMsg.style.color = 'var(--accent-rose)';
      } finally {
        if (submitBtn) submitBtn.disabled = false;
      }
    });
  }

  // =========================================================================
  // AUTHENTICATION, REGISTRATION & RECOVERY (Phase 10E & 10F)
  // =========================================================================

  function openLoginModal() {
    loginModal.style.display = 'flex';
    if (loginErrorMsg) loginErrorMsg.style.display = 'none';
  }

  function closeLoginModal() {
    loginModal.style.display = 'none';
  }

  function switchAuthTab(tabName) {
    const tabs = {
      login: { btn: document.getElementById('tab-login'), form: document.getElementById('login-form') },
      register: { btn: document.getElementById('tab-register'), form: document.getElementById('register-form') },
      verify: { btn: document.getElementById('tab-verify'), form: document.getElementById('verify-form') },
      forgot: { btn: document.getElementById('tab-forgot'), form: document.getElementById('forgot-form') },
      reset: { btn: null, form: document.getElementById('reset-form') },
      sms: { btn: document.getElementById('tab-sms'), form: document.getElementById('sms-form') },
    };

    Object.keys(tabs).forEach(k => {
      const t = tabs[k];
      if (t.btn) {
        if (k === tabName) {
          t.btn.style.borderBottom = '2px solid var(--accent-cyan)';
          t.btn.style.color = 'var(--accent-cyan)';
        } else {
          t.btn.style.borderBottom = '2px solid transparent';
          t.btn.style.color = 'var(--text-muted)';
        }
      }
      if (t.form) {
        t.form.style.display = (k === tabName) ? 'flex' : 'none';
      }
    });
  }

  const tabLogin = document.getElementById('tab-login');
  const tabRegister = document.getElementById('tab-register');
  const tabVerify = document.getElementById('tab-verify');
  const tabForgot = document.getElementById('tab-forgot');
  const tabSms = document.getElementById('tab-sms');

  if (tabLogin) tabLogin.addEventListener('click', () => switchAuthTab('login'));
  if (tabRegister) tabRegister.addEventListener('click', () => switchAuthTab('register'));
  if (tabVerify) tabVerify.addEventListener('click', () => switchAuthTab('verify'));
  if (tabForgot) tabForgot.addEventListener('click', () => switchAuthTab('forgot'));
  if (tabSms) tabSms.addEventListener('click', () => switchAuthTab('sms'));

  // Sign In Handler
  async function handleLogin(e) {
    e.preventDefault();
    const ident = loginProviderId.value.trim().toLowerCase();
    const secret = loginSecret.value;
    if (!ident || !secret) {
      if (loginErrorMsg) {
        loginErrorMsg.textContent = 'Please enter both email and password.';
        loginErrorMsg.style.display = 'block';
      }
      return;
    }

    const submitBtn = document.getElementById('login-submit-btn');
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = 'Authenticating...';
    }
    if (loginErrorMsg) loginErrorMsg.style.display = 'none';

    try {
      const resp = await fetch('/auth/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: ident, password: secret }),
      });

      const data = await resp.json();
      if (!resp.ok) {
        let msg = data.detail;
        if (Array.isArray(msg)) msg = msg.map(m => m.msg || JSON.stringify(m)).join('; ');
        throw new Error(msg || 'Invalid email or password.');
      }

      currentCsrfToken = data.csrf_token;
      currentAccount = data.account;
      currentPrincipal = data.account?.account_id || data.account_id || data.token;
      
      // Update UI state
      updateAuthUI(true, currentAccount.email || currentAccount.account_id);
      closeLoginModal();
      loginSecret.value = '';

      // Server-Verified Role-Based Dashboard Routing
      const role = (currentAccount?.role || 'consumer').toLowerCase();
      if (role === 'admin' || currentAccount?.is_admin) {
        switchMainView('admin', true);
        showToast(`Welcome, Administrator! Authenticated as ${currentAccount.email}`, '🛡️', 3500);
      } else if (role === 'provider') {
        switchMainView('provider', true);
        showToast(`Welcome, Storage Provider! Authenticated as ${currentAccount.email}`, '🖥️', 3500);
      } else {
        switchMainView('consumer', true);
        showToast(`Welcome! Authenticated as ${currentAccount.email}`, '📁', 3500);
      }
    } catch (err) {
      if (loginErrorMsg) {
        loginErrorMsg.textContent = err.message || 'Invalid email or password.';
        loginErrorMsg.style.display = 'block';
      }
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Authenticate';
      }
    }
  }

  // Register New Account Handler (Phase 10 UI)
  const registerForm = document.getElementById('register-form');
  const registerEmailInput = document.getElementById('register-email-input');
  const registerPasswordInput = document.getElementById('register-password-input');
  const registerStatusMsg = document.getElementById('register-status-msg');

  if (registerForm) {
    registerForm.addEventListener('submit', async () => {
      const email = registerEmailInput.value.trim().toLowerCase();
      const pw = registerPasswordInput.value;

      if (!email || !pw || pw.length < 8) {
        registerStatusMsg.textContent = 'Please enter a valid email and password (minimum 8 characters).';
        registerStatusMsg.style.color = 'var(--accent-rose)';
        registerStatusMsg.style.display = 'block';
        return;
      }

      const submitBtn = document.getElementById('register-submit-btn');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Creating Account...';
      }

      registerStatusMsg.textContent = 'Creating account...';
      registerStatusMsg.style.color = 'var(--accent-cyan)';
      registerStatusMsg.style.display = 'block';

      try {
        const res = await fetch('/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: email, password: pw, role: 'consumer' }),
        });

        const data = await res.json();
        if (res.ok) {
          registerStatusMsg.textContent = '✅ Account created! Signing in...';
          registerStatusMsg.style.color = 'var(--accent-emerald)';

          // Auto-login
          const loginRes = await fetch('/auth/login', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: email, password: pw }),
          });
          if (loginRes.ok) {
            const loginData = await loginRes.json();
            currentCsrfToken = loginData.csrf_token;
            currentAccount = loginData.account;
            currentPrincipal = loginData.account?.account_id || loginData.account_id || loginData.token;
            updateAuthUI(true, currentAccount.email || currentAccount.account_id);
            closeLoginModal();
            registerPasswordInput.value = '';
            switchMainView('consumer', true);
            showToast('Account created successfully! Welcome to Expo.', '✅', 3500);
          } else {
            switchAuthTab('login');
          }
        } else {
          let msg = data.detail;
          if (Array.isArray(msg)) msg = msg.map(m => m.msg || JSON.stringify(m)).join('; ');
          registerStatusMsg.textContent = `❌ ${msg || 'Registration failed.'}`;
          registerStatusMsg.style.color = 'var(--accent-rose)';
        }
      } catch (err) {
        registerStatusMsg.textContent = `❌ Network error: ${err.message}`;
        registerStatusMsg.style.color = 'var(--accent-rose)';
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Create Account';
        }
      }
    });
  }

  // Logout Handler
  async function handleLogout() {
    try {
      await fetchApi('/auth/logout', { method: 'POST' });
    } catch (_) {}
    currentCsrfToken = null;
    currentPrincipal = null;
    currentAccount = null;
    updateAuthUI(false, null);
    if (navAdminBtn) navAdminBtn.style.display = 'none';
    switchMainView('landing', true);
    showToast('Signed out successfully. Session ended.', '👋', 3000);
  }

  // Email Verification Handlers
  const verifySubmitBtn = document.getElementById('verify-submit-btn');
  const verifyResendBtn = document.getElementById('verify-resend-btn');
  const verifyTokenInput = document.getElementById('verify-token-input');
  const verifyStatusMsg = document.getElementById('verify-status-msg');
  const bannerResendBtn = document.getElementById('banner-resend-btn');

  if (verifySubmitBtn) {
    verifySubmitBtn.addEventListener('click', async () => {
      const tok = verifyTokenInput.value.trim();
      if (!tok) {
        verifyStatusMsg.textContent = 'Please paste or enter verification token.';
        verifyStatusMsg.style.color = 'var(--accent-rose)';
        verifyStatusMsg.style.display = 'block';
        return;
      }
      try {
        const res = await fetch('/auth/verify-email', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: tok }),
        });
        const data = await res.json();
        if (res.ok) {
          verifyStatusMsg.textContent = '✅ ' + (data.detail || 'Email verified successfully!');
          verifyStatusMsg.style.color = 'var(--accent-emerald)';
          verifyStatusMsg.style.display = 'block';
          checkAccountVerificationStatus();
        } else {
          verifyStatusMsg.textContent = '❌ ' + (data.detail || 'Verification failed.');
          verifyStatusMsg.style.color = 'var(--accent-rose)';
          verifyStatusMsg.style.display = 'block';
        }
      } catch (_) {
        verifyStatusMsg.textContent = '❌ Network error during verification.';
        verifyStatusMsg.style.color = 'var(--accent-rose)';
        verifyStatusMsg.style.display = 'block';
      }
    });
  }

  async function triggerResendEmail(email) {
    if (!email) {
      email = prompt('Enter your account email address:');
    }
    if (!email || !email.trim()) return;

    try {
      const res = await fetch('/auth/resend-verification', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim() }),
      });
      const data = await res.json();
      alert(data.detail || 'Verification link re-issued.');
    } catch (_) {
      alert('Network error requesting verification resend.');
    }
  }

  if (verifyResendBtn) {
    verifyResendBtn.addEventListener('click', () => triggerResendEmail(currentAccount?.email));
  }
  if (bannerResendBtn) {
    bannerResendBtn.addEventListener('click', () => triggerResendEmail(currentAccount?.email));
  }

  // Forgot Password Handler
  const forgotSubmitBtn = document.getElementById('forgot-submit-btn');
  const forgotEmailInput = document.getElementById('forgot-email-input');
  const forgotStatusMsg = document.getElementById('forgot-status-msg');

  if (forgotSubmitBtn) {
    forgotSubmitBtn.addEventListener('click', async () => {
      const email = forgotEmailInput.value.trim();
      if (!email) {
        forgotStatusMsg.textContent = 'Please enter your account email address.';
        forgotStatusMsg.style.color = 'var(--accent-rose)';
        forgotStatusMsg.style.display = 'block';
        return;
      }
      try {
        const res = await fetch('/auth/forgot-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: email }),
        });
        const data = await res.json();
        forgotStatusMsg.textContent = '✅ ' + (data.detail || 'Instructions sent if account exists.');
        forgotStatusMsg.style.color = 'var(--accent-emerald)';
        forgotStatusMsg.style.display = 'block';
      } catch (_) {
        forgotStatusMsg.textContent = '❌ Network error requesting password reset.';
        forgotStatusMsg.style.color = 'var(--accent-rose)';
        forgotStatusMsg.style.display = 'block';
      }
    });
  }

  // Reset Password Handler
  const resetSubmitBtn = document.getElementById('reset-submit-btn');
  const resetTokenInput = document.getElementById('reset-token-input');
  const resetNewPassword = document.getElementById('reset-new-password');
  const resetStatusMsg = document.getElementById('reset-status-msg');

  if (resetSubmitBtn) {
    resetSubmitBtn.addEventListener('click', async () => {
      const tok = resetTokenInput.value.trim();
      const pw = resetNewPassword.value.trim();
      if (!tok || !pw || pw.length < 8) {
        resetStatusMsg.textContent = 'Please enter valid token and password (min 8 chars).';
        resetStatusMsg.style.color = 'var(--accent-rose)';
        resetStatusMsg.style.display = 'block';
        return;
      }
      try {
        const res = await fetch('/auth/reset-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: tok, new_password: pw }),
        });
        const data = await res.json();
        if (res.ok) {
          resetStatusMsg.textContent = '✅ ' + (data.detail || 'Password updated successfully!');
          resetStatusMsg.style.color = 'var(--accent-emerald)';
          resetStatusMsg.style.display = 'block';
        } else {
          resetStatusMsg.textContent = '❌ ' + (data.detail || 'Failed to reset password.');
          resetStatusMsg.style.color = 'var(--accent-rose)';
          resetStatusMsg.style.display = 'block';
        }
      } catch (_) {
        resetStatusMsg.textContent = '❌ Network error during password reset.';
        resetStatusMsg.style.color = 'var(--accent-rose)';
        resetStatusMsg.style.display = 'block';
      }
    });
  }

  // SMS Verification Handlers
  const smsSendBtn = document.getElementById('sms-send-btn');
  const smsVerifyBtn = document.getElementById('sms-verify-btn');
  const smsPhoneInput = document.getElementById('sms-phone-input');
  const smsCodeInput = document.getElementById('sms-code-input');
  const smsStatusMsg = document.getElementById('sms-status-msg');

  if (smsSendBtn) {
    smsSendBtn.addEventListener('click', async () => {
      const phone = smsPhoneInput.value.trim();
      if (!phone) {
        smsStatusMsg.textContent = 'Please enter a valid phone number.';
        smsStatusMsg.style.color = 'var(--accent-rose)';
        smsStatusMsg.style.display = 'block';
        return;
      }
      try {
        const res = await fetch('/auth/sms/send-code', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', ...(currentCsrfToken ? { 'X-CSRF-Token': currentCsrfToken } : {}) },
          body: JSON.stringify({ phone_number: phone }),
        });
        const data = await res.json();
        if (res.ok) {
          smsStatusMsg.textContent = '✅ ' + (data.detail || 'Verification code sent!');
          smsStatusMsg.style.color = 'var(--accent-emerald)';
        } else {
          smsStatusMsg.textContent = '❌ ' + (data.detail || 'Failed to send SMS code.');
          smsStatusMsg.style.color = 'var(--accent-rose)';
        }
        smsStatusMsg.style.display = 'block';
      } catch (_) {
        smsStatusMsg.textContent = '❌ Network error sending SMS code.';
        smsStatusMsg.style.color = 'var(--accent-rose)';
        smsStatusMsg.style.display = 'block';
      }
    });
  }

  if (smsVerifyBtn) {
    smsVerifyBtn.addEventListener('click', async () => {
      const phone = smsPhoneInput.value.trim();
      const code = smsCodeInput.value.trim();
      if (!phone || !code || code.length !== 6) {
        smsStatusMsg.textContent = 'Please enter phone number and 6-digit verification code.';
        smsStatusMsg.style.color = 'var(--accent-rose)';
        smsStatusMsg.style.display = 'block';
        return;
      }
      try {
        const res = await fetch('/auth/sms/verify-code', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', ...(currentCsrfToken ? { 'X-CSRF-Token': currentCsrfToken } : {}) },
          body: JSON.stringify({ phone_number: phone, code: code }),
        });
        const data = await res.json();
        if (res.ok) {
          smsStatusMsg.textContent = '✅ ' + (data.detail || 'Phone verified successfully!');
          smsStatusMsg.style.color = 'var(--accent-emerald)';
          checkAccountVerificationStatus();
        } else {
          smsStatusMsg.textContent = '❌ ' + (data.detail || 'Failed to verify code.');
          smsStatusMsg.style.color = 'var(--accent-rose)';
        }
        smsStatusMsg.style.display = 'block';
      } catch (_) {
        smsStatusMsg.textContent = '❌ Network error verifying SMS code.';
        smsStatusMsg.style.color = 'var(--accent-rose)';
        smsStatusMsg.style.display = 'block';
      }
    });
  }

  // Account Verification & Profile Resolution
  async function checkAccountVerificationStatus() {
    try {
      const res = await fetch('/auth/me', { credentials: 'same-origin' });
      if (res.ok) {
        currentAccount = await res.json();
        currentUserRoleBadge.textContent = (currentAccount.role || 'consumer').toUpperCase();
        if (authVerificationBadge) {
          authVerificationBadge.style.display = 'inline-block';
          if (currentAccount.email_verified) {
            authVerificationBadge.className = 'badge badge-emerald';
            authVerificationBadge.textContent = 'Verified';
            authVerificationBadge.title = 'Account email address verified';
            if (emailVerificationBanner) emailVerificationBanner.style.display = 'none';
          } else {
            authVerificationBadge.className = 'badge badge-rose';
            authVerificationBadge.textContent = 'Unverified ⚠️';
            authVerificationBadge.title = 'Account email unverified. Click to verify.';
            authVerificationBadge.style.cursor = 'pointer';
            authVerificationBadge.onclick = () => {
              openLoginModal();
              switchAuthTab('verify');
            };
            if (emailVerificationBanner) emailVerificationBanner.style.display = 'flex';
          }
        }

        // Show Admin Nav Tab if user is administrator
        if (currentAccount.is_admin || currentAccount.role === 'admin') {
          navAdminBtn.style.display = 'flex';
        } else {
          navAdminBtn.style.display = 'none';
        }
      } else {
        if (authVerificationBadge) authVerificationBadge.style.display = 'none';
        if (emailVerificationBanner) emailVerificationBanner.style.display = 'none';
        navAdminBtn.style.display = 'none';
      }
    } catch (_) {
      if (authVerificationBadge) authVerificationBadge.style.display = 'none';
      if (emailVerificationBanner) emailVerificationBanner.style.display = 'none';
      navAdminBtn.style.display = 'none';
    }
  }

  function updateAuthUI(authenticated, accountId) {
    if (authBtn) {
      authBtn.textContent = authenticated ? 'Sign Out' : 'Sign In';
    }
    if (providerIdLabel && accountId) {
      providerIdLabel.textContent = accountId;
    }
    checkAccountVerificationStatus();
  }

  // Boot Application & Check Session
  async function initAuth() {
    try {
      const res = await fetch('/auth/me', { credentials: 'same-origin' });
      if (res.ok) {
        currentAccount = await res.json();
        currentPrincipal = currentAccount.account_id;
        updateAuthUI(true, currentAccount.email || currentAccount.account_id);

        // Check CSRF token from /auth/csrf
        try {
          const csrfRes = await fetch('/auth/csrf', { credentials: 'same-origin' });
          if (csrfRes.ok) {
            const csrfData = await csrfRes.json();
            currentCsrfToken = csrfData.csrf_token;
          }
        } catch (_) {}

        // Route to hash view if specified, otherwise default to role-appropriate view
        const currentHash = window.location.hash.toLowerCase().replace(/^#\/?/, '');
        if ((currentHash === 'admin' || currentHash === '/admin') && (currentAccount.role === 'admin' || currentAccount.is_admin)) {
          switchMainView('admin', false);
        } else if (currentHash === 'provider' || currentHash === '/provider') {
          switchMainView('provider', false);
        } else if (currentHash === 'consumer' || currentHash === '/consumer' || currentHash === 'files') {
          switchMainView('consumer', false);
        } else if (currentHash === 'landing' || currentHash === '/landing') {
          switchMainView('landing', false);
        } else {
          // If no specific hash requested, route to role-appropriate dashboard
          const role = (currentAccount.role || 'consumer').toLowerCase();
          if (role === 'admin' || currentAccount.is_admin) {
            switchMainView('admin', false);
          } else if (role === 'provider') {
            switchMainView('provider', false);
          } else {
            switchMainView('consumer', false);
          }
        }
        return;
      }
    } catch (_) {}

    // Guest fallback
    updateAuthUI(false, null);
    const guestHash = window.location.hash.toLowerCase().replace(/^#\/?/, '');
    if (guestHash === 'provider' || guestHash === '/provider') {
      switchMainView('provider', false);
    } else if (guestHash === 'consumer' || guestHash === '/consumer' || guestHash === 'files') {
      switchMainView('consumer', false);
    } else {
      switchMainView('landing', false);
    }
  }

  // Setup password visibility toggles
  setupPasswordToggle('toggle-login-password', 'login-secret');
  setupPasswordToggle('toggle-register-password', 'register-password-input');

  // Check URL parameters for direct verification or reset token
  try {
    const urlParams = new URLSearchParams(window.location.search);
    const tokenParam = urlParams.get('token');
    if (tokenParam) {
      openLoginModal();
      if (window.location.pathname.includes('reset') || window.location.hash.includes('reset')) {
        switchAuthTab('reset');
        if (resetTokenInput) resetTokenInput.value = tokenParam;
      } else {
        switchAuthTab('verify');
        if (verifyTokenInput) verifyTokenInput.value = tokenParam;
      }
    }
  } catch (_) {}

  // Event Listeners
  refreshBtn.addEventListener('click', () => {
    if (currentActiveView === 'consumer') loadConsumerFiles();
    else if (currentActiveView === 'provider') loadProviderDashboard();
    else if (currentActiveView === 'admin') loadAdminData();
  });

  retryBtn.addEventListener('click', () => {
    if (currentActiveView === 'consumer') loadConsumerFiles();
    else if (currentActiveView === 'provider') loadProviderDashboard();
    else if (currentActiveView === 'admin') loadAdminData();
  });

  windowSelect.addEventListener('change', loadProviderDashboard);

  if (authBtn) {
    authBtn.addEventListener('click', () => {
      if (currentPrincipal) {
        handleLogout();
      } else {
        openLoginModal();
      }
    });
  }

  if (loginForm) loginForm.addEventListener('submit', handleLogin);
  if (loginCloseBtn) loginCloseBtn.addEventListener('click', closeLoginModal);
  if (loginModal) {
    loginModal.addEventListener('click', (e) => {
      if (e.target === loginModal) closeLoginModal();
    });
  }

  // Backwards compatibility alias
  const loadDashboard = loadProviderDashboard;
  window.loadDashboard = loadDashboard;

  // Start Application
  initAuth();
})();
