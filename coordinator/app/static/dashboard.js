/**
 * Expo Provider Monitoring & Management Dashboard (Phase 8A)
 * Vanilla JavaScript application with live metrics, SVG charts, scheduling toggles,
 * graceful drain controls, and diagnostics drilldown.
 */

(function () {
  'use strict';

  // DOM Elements
  const windowSelect = document.getElementById('window-select');
  const refreshBtn = document.getElementById('refresh-btn');
  const retryBtn = document.getElementById('retry-btn');
  const authBtn = document.getElementById('auth-btn');
  const providerIdLabel = document.getElementById('current-provider-id');
  const loadingContainer = document.getElementById('loading-container');
  const errorContainer = document.getElementById('error-container');
  const errorMessage = document.getElementById('error-message');
  const dashboardContent = document.getElementById('dashboard-content');
  const staleBanner = document.getElementById('stale-alert-banner');
  const staleDesc = document.getElementById('stale-alert-desc');

  // Login Modal Elements
  const loginModal = document.getElementById('login-modal');
  const loginForm = document.getElementById('login-form');
  const loginProviderId = document.getElementById('login-provider-id');
  const loginSecret = document.getElementById('login-secret');
  const loginErrorMsg = document.getElementById('login-error-msg');
  const loginCloseBtn = document.getElementById('login-close-btn');

  let currentCsrfToken = null;
  let currentPrincipal = null;

  // Hero Card Elements
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

  // Charts
  const storageChartContainer = document.getElementById('storage-chart-container');
  const trafficChartContainer = document.getElementById('traffic-chart-container');

  // Table
  const nodesTableBody = document.getElementById('nodes-table-body');
  const emptyNodesContainer = document.getElementById('empty-nodes-container');
  const nodesCountSubtitle = document.getElementById('nodes-count-subtitle');
  const nodeSearchInput = document.getElementById('node-search-input');

  // Activity Stream
  const activityStreamList = document.getElementById('activity-stream-list');

  // Modal
  const nodeModal = document.getElementById('node-modal');
  const modalNodeTitle = document.getElementById('modal-node-title');
  const modalNodeEndpoint = document.getElementById('modal-node-endpoint');
  const modalBodyContent = document.getElementById('modal-body-content');
  const modalCloseBtn = document.getElementById('modal-close-btn');
  const modalDismissBtn = document.getElementById('modal-dismiss-btn');
  const modalDrainBtn = document.getElementById('modal-drain-btn');

  let currentActiveNodeId = null;
  let cachedNodes = [];

  // Utilities
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
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
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
    if (s === 'disabled' || !isSchedulable) {
      return '<span class="badge badge-gray">Disabled</span>';
    }
    if (s === 'online') {
      return '<span class="badge badge-emerald"><span class="status-dot pulse-green"></span> Online</span>';
    }
    if (s === 'degraded') {
      return '<span class="badge badge-amber">Degraded</span>';
    }
    return '<span class="badge badge-rose">Offline</span>';
  }

  // API Call Wrapper: Session Cookie + CSRF Defense (No hardcoded secrets)
  async function fetchApi(endpoint, options = {}) {
    const defaultHeaders = {
      'Accept': 'application/json',
    };

    // Attach CSRF token on state-changing browser requests
    const method = (options.method || 'GET').toUpperCase();
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method) && currentCsrfToken) {
      defaultHeaders['X-CSRF-Token'] = currentCsrfToken;
    }

    const res = await fetch(endpoint, {
      ...options,
      credentials: 'same-origin',
      headers: { ...defaultHeaders, ...(options.headers || {}) },
    });

    if (res.status === 401) {
      openLoginModal();
      throw new Error('Authentication required. Please sign in to the Provider Portal.');
    }

    if (!res.ok) {
      const errText = await res.text();
      let errJson;
      try { errJson = JSON.parse(errText); } catch (_) {}
      const msg = errJson?.detail || `HTTP ${res.status}: ${res.statusText}`;
      throw new Error(msg);
    }
    return res.json();
  }

  // Load Dashboard Data
  async function loadDashboard() {
    const windowHours = parseFloat(windowSelect.value) || 24.0;
    trafficWindowBadge.textContent = `${windowHours}h Window`;

    loadingContainer.style.display = 'block';
    errorContainer.style.display = 'none';
    dashboardContent.style.display = 'none';
    staleBanner.style.display = 'none';

    try {
      const data = await fetchApi(`/provider/overview?window_hours=${windowHours}`);
      renderOverview(data);
      cachedNodes = data.nodes || [];
      renderNodesTable(cachedNodes);
      renderCharts(data);
      await loadCombinedActivity(cachedNodes);

      loadingContainer.style.display = 'none';
      dashboardContent.style.display = 'block';
    } catch (err) {
      loadingContainer.style.display = 'none';
      errorMessage.textContent = err.message || 'Failed to fetch provider overview from Coordinator.';
      errorContainer.style.display = 'block';
    }
  }

  // Render Overview
  function renderOverview(data) {
    providerIdLabel.textContent = data.provider_id || 'default_provider';

    // 1. Storage
    verifiedStoredBytesEl.textContent = formatBytes(data.total_verified_stored_bytes);
    configuredQuotaBytesEl.textContent = formatBytes(data.total_configured_quota_bytes);
    remainingQuotaBytesEl.textContent = formatBytes(data.total_remaining_quota_bytes);

    let progressPct = 0;
    if (data.total_configured_quota_bytes > 0) {
      progressPct = Math.min(100, (data.total_verified_stored_bytes / data.total_configured_quota_bytes) * 100);
    }
    storageProgressFill.style.width = `${progressPct.toFixed(1)}%`;

    if (data.total_physical_disk_bytes !== null && data.total_physical_disk_bytes > 0) {
      const pFree = data.total_physical_free_bytes !== null ? formatBytes(data.total_physical_free_bytes) : 'N/A';
      physicalDiskStatsEl.textContent = `${formatBytes(data.total_physical_disk_bytes)} total (${pFree} free)`;
    } else {
      physicalDiskStatsEl.textContent = 'Not reported by provider hosts';
    }

    // 2. Traffic
    totalTrafficBytesEl.textContent = formatBytes(data.total_traffic_bytes);
    totalIngressBytesEl.textContent = formatBytes(data.total_ingress_bytes);
    totalEgressBytesEl.textContent = formatBytes(data.total_egress_bytes);

    if (data.total_traffic_bytes > 0) {
      const inPct = ((data.total_ingress_bytes / data.total_traffic_bytes) * 100).toFixed(0);
      const outPct = (100 - inPct).toFixed(0);
      trafficRatioTextEl.textContent = `${inPct}% Ingress / ${outPct}% Egress`;
    } else {
      trafficRatioTextEl.textContent = '0 transfers in window';
    }

    // 3. Credits
    totalCreditsBalanceEl.textContent = formatCredits(data.total_credit_balance);
    const earnedSum = (data.nodes || []).reduce((acc, n) => acc + (n.credit_balance > 0 ? n.credit_balance : 0), 0);
    totalLifetimeEarnedEl.textContent = formatCredits(earnedSum);
    totalLifetimeReversedEl.textContent = '0.0000 ECC';

    // 4. Reputation
    averageReputationScoreEl.textContent = (data.average_reputation_score !== undefined) ? `${data.average_reputation_score.toFixed(1)} / 100` : '50.0 / 100';
    recentSuccRepairsEl.textContent = `${data.recent_successful_repairs} completed`;
    recentFailRepairsEl.textContent = `${data.recent_failed_repairs} failed`;

    // Check confidence across nodes
    const highConf = (data.nodes || []).filter(n => n.data_sufficiency_status === 'sufficient').length;
    if (highConf === (data.nodes || []).length && (data.nodes || []).length > 0) {
      reputationConfidenceBadge.className = 'badge badge-emerald';
      reputationConfidenceBadge.textContent = 'Sufficient Evidence';
    } else if ((data.nodes || []).some(n => n.data_sufficiency_status === 'provisional')) {
      reputationConfidenceBadge.className = 'badge badge-amber';
      reputationConfidenceBadge.textContent = 'Provisional (Evaluating)';
    } else {
      reputationConfidenceBadge.className = 'badge badge-gray';
      reputationConfidenceBadge.textContent = 'Insufficient Evidence';
    }

    // Check for stale heartbeats (> 30s)
    const staleNodes = (data.nodes || []).filter(n => n.last_heartbeat_elapsed_seconds > 30);
    if (staleNodes.length > 0) {
      staleDesc.textContent = `${staleNodes.length} node(s) have overdue heartbeats (>30s): ${staleNodes.map(n => n.node_id).join(', ')}.`;
      staleBanner.style.display = 'flex';
    }
  }

  // Render Nodes Table
  function renderNodesTable(nodes) {
    nodesTableBody.innerHTML = '';
    nodesCountSubtitle.textContent = `${nodes.length} storage node(s) registered`;

    if (!nodes || nodes.length === 0) {
      emptyNodesContainer.style.display = 'block';
      return;
    }
    emptyNodesContainer.style.display = 'none';

    nodes.forEach(node => {
      const tr = document.createElement('tr');

      const modeBadge = `<span class="badge badge-cyan">${escapeHtml(node.connectivity_mode)}</span>`;
      const repBadge = `<span class="badge badge-amber">${node.reputation_score.toFixed(1)}</span>`;

      tr.innerHTML = `
        <td>
          <div class="node-title-cell">
            <span class="node-id-text">${escapeHtml(node.node_id)}</span>
            <span class="node-host-text">${escapeHtml(node.host)}:${node.port}</span>
          </div>
        </td>
        <td>${getStatusBadge(node.status, node.is_schedulable)}</td>
        <td>${modeBadge}</td>
        <td>
          <div><strong>${formatBytes(node.verified_stored_bytes)}</strong> / ${formatBytes(node.total_configured_quota_bytes)}</div>
        </td>
        <td>${node.observed_availability_percentage.toFixed(1)}%</td>
        <td>${repBadge}</td>
        <td><strong>${formatCredits(node.credit_balance)}</strong></td>
        <td>
          <label class="switch" title="Toggle allocation scheduling">
            <input type="checkbox" class="schedule-toggle" data-node-id="${escapeHtml(node.node_id)}" ${node.is_schedulable ? 'checked' : ''}>
            <span class="slider"></span>
          </label>
        </td>
        <td>
          <button class="btn btn-outline btn-sm view-detail-btn" data-node-id="${escapeHtml(node.node_id)}">Diagnostics</button>
        </td>
      `;
      nodesTableBody.appendChild(tr);
    });

    // Wire up scheduling toggles
    document.querySelectorAll('.schedule-toggle').forEach(chk => {
      chk.addEventListener('change', async (e) => {
        const nodeId = e.target.getAttribute('data-node-id');
        const enabled = e.target.checked;
        try {
          await fetchApi(`/provider/nodes/${encodeURIComponent(nodeId)}/scheduling`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: enabled, reason: `Toggled via Provider UI` }),
          });
          await loadDashboard();
        } catch (err) {
          alert(`Failed to update scheduling for ${nodeId}: ${err.message}`);
          e.target.checked = !enabled; // Revert
        }
      });
    });

    // Wire up detail buttons
    document.querySelectorAll('.view-detail-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const nodeId = e.target.getAttribute('data-node-id');
        openNodeDetailModal(nodeId);
      });
    });
  }

  // Render Charts using pure SVG
  function renderCharts(data) {
    const verified = data.total_verified_stored_bytes || 0;
    const remaining = data.total_remaining_quota_bytes || 0;
    const totalQuota = verified + remaining;

    // 1. Storage Bar Chart (SVG)
    const vPct = totalQuota > 0 ? (verified / totalQuota) * 100 : 0;
    const rPct = totalQuota > 0 ? (remaining / totalQuota) * 100 : 100;

    storageChartContainer.innerHTML = `
      <svg width="100%" height="160" viewBox="0 0 400 160" preserveAspectRatio="none" style="overflow: visible;">
        <defs>
          <linearGradient id="cyanGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#06b6d4" stop-opacity="0.9"/>
            <stop offset="100%" stop-color="#0284c7" stop-opacity="0.4"/>
          </linearGradient>
          <linearGradient id="purpleGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#8b5cf6" stop-opacity="0.8"/>
            <stop offset="100%" stop-color="#6d28d9" stop-opacity="0.2"/>
          </linearGradient>
        </defs>
        <!-- Background Track -->
        <rect x="20" y="30" width="360" height="40" rx="8" fill="rgba(255,255,255,0.05)" stroke="rgba(255,255,255,0.1)" stroke-width="1"/>
        <!-- Verified Stored Slice -->
        <rect x="20" y="30" width="${(vPct * 3.6).toFixed(1)}" height="40" rx="8" fill="url(#cyanGrad)"/>
        <!-- Labels -->
        <text x="20" y="95" fill="#06b6d4" font-size="12" font-weight="600">■ Verified: ${formatBytes(verified)} (${vPct.toFixed(1)}%)</text>
        <text x="220" y="95" fill="#94a3b8" font-size="12" font-weight="600">■ Available: ${formatBytes(remaining)} (${rPct.toFixed(1)}%)</text>
        <text x="20" y="125" fill="#64748b" font-size="11">Total Configured Quota: ${formatBytes(totalQuota)}</text>
      </svg>
    `;

    // 2. Traffic Ingress vs Egress Chart (SVG)
    const ingress = data.total_ingress_bytes || 0;
    const egress = data.total_egress_bytes || 0;
    const maxTraffic = Math.max(1, ingress, egress);
    const inH = Math.max(4, (ingress / maxTraffic) * 90);
    const outH = Math.max(4, (egress / maxTraffic) * 90);

    trafficChartContainer.innerHTML = `
      <svg width="100%" height="160" viewBox="0 0 400 160" style="overflow: visible;">
        <defs>
          <linearGradient id="inGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#06b6d4"/>
            <stop offset="100%" stop-color="#0e7490"/>
          </linearGradient>
          <linearGradient id="outGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#8b5cf6"/>
            <stop offset="100%" stop-color="#581c87"/>
          </linearGradient>
        </defs>
        <!-- Ingress Bar -->
        <rect x="100" y="${120 - inH}" width="60" height="${inH}" rx="6" fill="url(#inGrad)"/>
        <text x="130" y="140" fill="#94a3b8" font-size="12" font-weight="600" text-anchor="middle">Ingress (Up)</text>
        <text x="130" y="${110 - inH}" fill="#06b6d4" font-size="11" font-weight="700" text-anchor="middle">${formatBytes(ingress)}</text>

        <!-- Egress Bar -->
        <rect x="240" y="${120 - outH}" width="60" height="${outH}" rx="6" fill="url(#outGrad)"/>
        <text x="270" y="140" fill="#94a3b8" font-size="12" font-weight="600" text-anchor="middle">Egress (Down)</text>
        <text x="270" y="${110 - outH}" fill="#8b5cf6" font-size="11" font-weight="700" text-anchor="middle">${formatBytes(egress)}</text>
      </svg>
    `;
  }

  // Load Activity Stream
  async function loadCombinedActivity(nodes) {
    activityStreamList.innerHTML = '';
    if (!nodes || nodes.length === 0) {
      activityStreamList.innerHTML = '<p class="loading-text" style="padding: 1rem 0;">No active nodes to stream activity from.</p>';
      return;
    }

    try {
      // Pick first node or fetch details to gather recent entries
      const firstNode = nodes[0];
      const detail = await fetchApi(`/provider/nodes/${encodeURIComponent(firstNode.node_id)}/detail`);
      const items = detail.recent_activity || [];

      if (items.length === 0) {
        activityStreamList.innerHTML = '<p class="loading-text" style="padding: 1rem 0;">No operational events recorded yet.</p>';
        return;
      }

      items.slice(0, 8).forEach(item => {
        const div = document.createElement('div');
        div.className = 'activity-item';

        let tagClass = 'badge-cyan';
        if (item.type === 'operation') tagClass = 'badge-violet';
        if (item.type === 'credit') tagClass = 'badge-emerald';

        div.innerHTML = `
          <div class="activity-left">
            <span class="activity-tag ${tagClass}">${escapeHtml(item.type)}</span>
            <span>${escapeHtml(item.summary)}</span>
          </div>
          <span class="activity-time">${escapeHtml(item.timestamp.slice(0, 19).replace('T', ' '))}</span>
        `;
        activityStreamList.appendChild(div);
      });
    } catch (_) {
      activityStreamList.innerHTML = '<p class="loading-text">Activity stream idle.</p>';
    }
  }

  // Node Detail Modal
  async function openNodeDetailModal(nodeId) {
    currentActiveNodeId = nodeId;
    modalNodeTitle.textContent = `Node Diagnostics: ${nodeId}`;
    modalNodeEndpoint.textContent = 'Loading diagnostics...';
    modalBodyContent.innerHTML = '<div class="spinner" style="margin: 2rem auto;"></div>';
    nodeModal.style.display = 'flex';

    try {
      const d = await fetchApi(`/provider/nodes/${encodeURIComponent(nodeId)}/detail`);
      modalNodeEndpoint.textContent = `${d.endpoint} (Advertised: ${d.endpoint})`;

      const physDisk = (d.physical_disk_total_bytes !== null)
        ? `${formatBytes(d.physical_disk_total_bytes)} (${formatBytes(d.physical_disk_free_bytes)} free)`
        : 'Not reported by node host';

      modalBodyContent.innerHTML = `
        <div class="diag-grid">
          <div class="diag-item">
            <span class="diag-label">Node Status & Mode</span>
            <span class="diag-value">${getStatusBadge(d.status, d.is_schedulable)} &bull; ${escapeHtml(d.connectivity_mode)}</span>
          </div>
          <div class="diag-item">
            <span class="diag-label">Configured Quota vs Stored</span>
            <span class="diag-value">${formatBytes(d.verified_stored_bytes)} / ${formatBytes(d.total_configured_quota_bytes)}</span>
          </div>
          <div class="diag-item">
            <span class="diag-label">Host Physical Disk</span>
            <span class="diag-value">${physDisk}</span>
          </div>
          <div class="diag-item">
            <span class="diag-label">Uptime Availability</span>
            <span class="diag-value">${d.observed_availability_percentage.toFixed(1)}% (${(d.observed_online_seconds / 3600).toFixed(1)}h online)</span>
          </div>
          <div class="diag-item">
            <span class="diag-label">Reputation & Confidence</span>
            <span class="diag-value">${d.reputation_score.toFixed(1)} / 100 (${d.data_sufficiency_status})</span>
          </div>
          <div class="diag-item">
            <span class="diag-label">ECC Credit Balance</span>
            <span class="diag-value emerald-text">${formatCredits(d.credit_balance)}</span>
          </div>
        </div>

        <h3 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 0.5rem;">Recent Capacity Snapshots</h3>
        <div class="table-responsive" style="max-height: 140px; overflow-y: auto; margin-bottom: 1.5rem;">
          <table class="nodes-table" style="font-size: 0.8rem;">
            <thead>
              <tr><th>Timestamp</th><th>Used Bytes</th><th>Total Quota</th><th>Source</th></tr>
            </thead>
            <tbody>
              ${(d.recent_snapshots || []).map(s => `
                <tr>
                  <td>${escapeHtml(s.timestamp.slice(0, 19).replace('T', ' '))}</td>
                  <td><strong>${formatBytes(s.used_bytes)}</strong></td>
                  <td>${formatBytes(s.total_quota_bytes)}</td>
                  <td><span class="badge badge-gray">${escapeHtml(s.source)}</span></td>
                </tr>
              `).join('') || '<tr><td colspan="4">No historical snapshots recorded yet.</td></tr>'}
            </tbody>
          </table>
        </div>
      `;
    } catch (err) {
      modalBodyContent.innerHTML = `<div class="error-desc" style="color: var(--accent-rose);">Failed to load diagnostics: ${err.message}</div>`;
    }
  }

  function closeModal() {
    nodeModal.style.display = 'none';
    currentActiveNodeId = null;
  }

  function openLoginModal() {
    if (loginErrorMsg) loginErrorMsg.style.display = 'none';
    if (loginModal) loginModal.style.display = 'flex';
  }

  function closeLoginModal() {
    if (loginModal) loginModal.style.display = 'none';
  }

  async function handleLogin(e) {
    e.preventDefault();
    const providerId = loginProviderId.value.trim();
    const secret = loginSecret.value.trim();

    if (!providerId || !secret) {
      if (loginErrorMsg) {
        loginErrorMsg.textContent = 'Please provide both Provider ID and Secret/Token.';
        loginErrorMsg.style.display = 'block';
      }
      return;
    }

    try {
      const res = await fetch('/provider/session/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider_id: providerId, secret_or_token: secret }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || 'Authentication failed');
      }

      const data = await res.json();
      currentCsrfToken = data.csrf_token;
      currentPrincipal = data.provider_id;
      closeLoginModal();
      updateAuthUI(true, data.provider_id);
      await loadDashboard();
    } catch (err) {
      if (loginErrorMsg) {
        loginErrorMsg.textContent = err.message || 'Login failed.';
        loginErrorMsg.style.display = 'block';
      }
    }
  }

  async function handleLogout() {
    try {
      await fetchApi('/provider/session/logout', { method: 'POST' });
    } catch (_) {}
    currentCsrfToken = null;
    currentPrincipal = null;
    updateAuthUI(false, null);
    openLoginModal();
  }

  function updateAuthUI(authenticated, providerId) {
    if (authBtn) {
      authBtn.textContent = authenticated ? 'Sign Out' : 'Sign In';
    }
    if (providerIdLabel && providerId) {
      providerIdLabel.textContent = providerId;
    }
  }

  // Check current session status on boot
  async function initAuth() {
    try {
      const res = await fetch('/provider/session/status', { credentials: 'same-origin' });
      if (res.ok) {
        const status = await res.json();
        if (status.authenticated) {
          currentCsrfToken = status.csrf_token;
          currentPrincipal = status.provider_id;
          updateAuthUI(true, status.provider_id);
          await loadDashboard();
          return;
        }
      }
    } catch (_) {}
    // If not authenticated, prompt login
    updateAuthUI(false, null);
    openLoginModal();
  }

  // Graceful Drain/Shutdown Button
  modalDrainBtn.addEventListener('click', async () => {
    if (!currentActiveNodeId) return;
    if (!confirm(`Are you sure you want to initiate a graceful drain and shutdown of node '${currentActiveNodeId}'? Future chunk placements will be disabled immediately.`)) {
      return;
    }

    try {
      const resp = await fetchApi(`/provider/nodes/${encodeURIComponent(currentActiveNodeId)}/drain`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'Provider graceful drain initiated from UI' }),
      });
      alert(`Node '${currentActiveNodeId}' drain initiated. Status: ${resp.status}`);
      closeModal();
      await loadDashboard();
    } catch (err) {
      alert(`Drain failed: ${err.message}`);
    }
  });

  // Search filter
  nodeSearchInput.addEventListener('input', (e) => {
    const q = e.target.value.toLowerCase().trim();
    const filtered = cachedNodes.filter(n =>
      n.node_id.toLowerCase().includes(q) || n.host.toLowerCase().includes(q)
    );
    renderNodesTable(filtered);
  });

  // Event Listeners
  refreshBtn.addEventListener('click', loadDashboard);
  retryBtn.addEventListener('click', loadDashboard);
  windowSelect.addEventListener('change', loadDashboard);
  modalCloseBtn.addEventListener('click', closeModal);
  modalDismissBtn.addEventListener('click', closeModal);
  nodeModal.addEventListener('click', (e) => {
    if (e.target === nodeModal) closeModal();
  });

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

  // Boot Application
  initAuth();
})();
