/**
 * Store-Share Distributed Storage Network API Client & Simulation Engine
 * Supports both Live Coordinator FastAPI communication and High-Fidelity Local Simulation.
 */

// Local Storage Keys
const STORAGE_KEY_URL = 'expo_coordinator_url';
const STORAGE_KEY_TOKEN = 'expo_coordinator_token';
const STORAGE_KEY_AUTH_TOKEN = 'expo_access_token';
const STORAGE_KEY_SIMULATION = 'expo_simulation_mode';

export function getCoordinatorUrl() {
  return localStorage.getItem(STORAGE_KEY_URL) || 'http://127.0.0.1:9000';
}

export function setCoordinatorUrl(url) {
  localStorage.setItem(STORAGE_KEY_URL, url);
}

export function getCoordinatorToken() {
  return localStorage.getItem(STORAGE_KEY_TOKEN) || 'secret_provider_token';
}

export function setCoordinatorToken(token) {
  localStorage.setItem(STORAGE_KEY_TOKEN, token);
}

export function getAuthToken() {
  return sessionStorage.getItem(STORAGE_KEY_AUTH_TOKEN) || localStorage.getItem(STORAGE_KEY_AUTH_TOKEN) || '';
}

export function setAuthToken(token) {
  sessionStorage.setItem(STORAGE_KEY_AUTH_TOKEN, token);
}

export function removeAuthToken() {
  sessionStorage.removeItem(STORAGE_KEY_AUTH_TOKEN);
  localStorage.removeItem(STORAGE_KEY_AUTH_TOKEN);
}

export function isSimulationMode() {
  const val = localStorage.getItem(STORAGE_KEY_SIMULATION);
  return val === null ? true : val === 'true'; // Default to demo simulation if first run
}

export function setSimulationMode(enabled) {
  localStorage.setItem(STORAGE_KEY_SIMULATION, enabled ? 'true' : 'false');
}

// -------------------------------------------------------------
// High-Fidelity Mock Cluster State (Phase 1-9A spec accurate)
// -------------------------------------------------------------
const INITIAL_NODES = [
  {
    node_id: "NODE-8a7f1d2c-90b1",
    endpoint: "http://127.0.0.1:9001",
    advertised_endpoint: "http://192.168.1.101:9001",
    status: "online",
    connectivity_mode: "LAN",
    total_capacity_bytes: 53687091200, // 50 GB
    used_capacity_bytes: 14680064000,  // 13.67 GB
    available_capacity_bytes: 39007027200,
    is_schedulable: 1,
    provider_id: "provider-primary-alpha",
    last_seen: new Date().toISOString(),
    chunks_stored: 48,
    reputation: 99.4,
    latency_ms: 12,
  },
  {
    node_id: "NODE-4e2b9c3f-71a2",
    endpoint: "http://127.0.0.1:9002",
    advertised_endpoint: "http://192.168.1.102:9002",
    status: "online",
    connectivity_mode: "DIRECT",
    total_capacity_bytes: 107374182400, // 100 GB
    used_capacity_bytes: 32212254720,  // 30 GB
    available_capacity_bytes: 75161927680,
    is_schedulable: 1,
    provider_id: "provider-primary-alpha",
    last_seen: new Date(Date.now() - 15000).toISOString(),
    chunks_stored: 92,
    reputation: 98.8,
    latency_ms: 24,
  },
  {
    node_id: "NODE-1f9e8a7b-33c4",
    endpoint: "http://127.0.0.1:9003",
    advertised_endpoint: "relay://ws.expo.net/node-3",
    status: "online",
    connectivity_mode: "RELAY",
    total_capacity_bytes: 26843545600, // 25 GB
    used_capacity_bytes: 8589934592,   // 8 GB
    available_capacity_bytes: 18253611008,
    is_schedulable: 1,
    provider_id: "provider-community-beta",
    last_seen: new Date(Date.now() - 4000).toISOString(),
    chunks_stored: 34,
    reputation: 96.5,
    latency_ms: 68,
  },
  {
    node_id: "NODE-c73d5a1e-88f5",
    endpoint: "http://127.0.0.1:9004",
    advertised_endpoint: "http://192.168.1.104:9004",
    status: "online",
    connectivity_mode: "DIRECT",
    total_capacity_bytes: 64424509440, // 60 GB
    used_capacity_bytes: 21474836480,  // 20 GB
    available_capacity_bytes: 42949672960,
    is_schedulable: 1,
    provider_id: "provider-community-gamma",
    last_seen: new Date(Date.now() - 8000).toISOString(),
    chunks_stored: 60,
    reputation: 99.1,
    latency_ms: 18,
  },
  {
    node_id: "NODE-d31e9a2b-65c8",
    endpoint: "http://127.0.0.1:9005",
    advertised_endpoint: "http://192.168.1.105:9005",
    status: "offline",
    connectivity_mode: "LAN",
    total_capacity_bytes: 42949672960, // 40 GB
    used_capacity_bytes: 12884901888,  // 12 GB
    available_capacity_bytes: 30064771072,
    is_schedulable: 0,
    provider_id: "provider-edge-delta",
    last_seen: new Date(Date.now() - 180000).toISOString(),
    chunks_stored: 22,
    reputation: 84.2,
    latency_ms: 0,
  }
];

const INITIAL_FILES = [
  {
    file_id: "FILE-7e12c98d-a410",
    filename: "satellite_telemetry_2026.dat",
    original_size_bytes: 25165824, // 24 MB
    encrypted_size_bytes: 25165852,
    chunk_size_bytes: 4194304, // 4 MB
    chunk_count: 6,
    replication_factor: 2,
    erasure_coding: "None (Full Replica)",
    encryption_algorithm: "AES-256-GCM",
    owner_id: "default_user",
    created_at: new Date(Date.now() - 3600000 * 5).toISOString(),
    status: "active",
    sha256_checksum: "a3b942cf891d0e123456789abcdef0123456789abcdef0123456789abcdef012",
    chunks: [
      {
        index: 0,
        chunk_id: "CHUNK-7e12c-0",
        size_bytes: 4194304,
        sha256: "b10a241f6c4c9e88d1f2a3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4",
        placements: [
          { node_id: "NODE-8a7f1d2c-90b1", endpoint: "http://127.0.0.1:9001", role: "PRIMARY", status: "HEALTHY" },
          { node_id: "NODE-4e2b9c3f-71a2", endpoint: "http://127.0.0.1:9002", role: "REPLICA", status: "HEALTHY" }
        ]
      },
      {
        index: 1,
        chunk_id: "CHUNK-7e12c-1",
        size_bytes: 4194304,
        sha256: "c21b352f7d5d0f99e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",
        placements: [
          { node_id: "NODE-4e2b9c3f-71a2", endpoint: "http://127.0.0.1:9002", role: "PRIMARY", status: "HEALTHY" },
          { node_id: "NODE-c73d5a1e-88f5", endpoint: "http://127.0.0.1:9004", role: "REPLICA", status: "HEALTHY" }
        ]
      },
      {
        index: 2,
        chunk_id: "CHUNK-7e12c-2",
        size_bytes: 4194304,
        sha256: "d32c463f8e6e1f00f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6",
        placements: [
          { node_id: "NODE-1f9e8a7b-33c4", endpoint: "http://127.0.0.1:9003", role: "PRIMARY", status: "HEALTHY" },
          { node_id: "NODE-8a7f1d2c-90b1", endpoint: "http://127.0.0.1:9001", role: "REPLICA", status: "HEALTHY" }
        ]
      },
      {
        index: 3,
        chunk_id: "CHUNK-7e12c-3",
        size_bytes: 4194304,
        sha256: "e43d574f9f7f2f11a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7",
        placements: [
          { node_id: "NODE-c73d5a1e-88f5", endpoint: "http://127.0.0.1:9004", role: "PRIMARY", status: "HEALTHY" },
          { node_id: "NODE-4e2b9c3f-71a2", endpoint: "http://127.0.0.1:9002", role: "REPLICA", status: "HEALTHY" }
        ]
      },
      {
        index: 4,
        chunk_id: "CHUNK-7e12c-4",
        size_bytes: 4194304,
        sha256: "f54e685f0a8a3f22b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8",
        placements: [
          { node_id: "NODE-8a7f1d2c-90b1", endpoint: "http://127.0.0.1:9001", role: "PRIMARY", status: "HEALTHY" },
          { node_id: "NODE-1f9e8a7b-33c4", endpoint: "http://127.0.0.1:9003", role: "REPLICA", status: "HEALTHY" }
        ]
      },
      {
        index: 5,
        chunk_id: "CHUNK-7e12c-5",
        size_bytes: 4194304,
        sha256: "a65f796f1b9b4f33c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9",
        placements: [
          { node_id: "NODE-c73d5a1e-88f5", endpoint: "http://127.0.0.1:9004", role: "PRIMARY", status: "HEALTHY" },
          { node_id: "NODE-8a7f1d2c-90b1", endpoint: "http://127.0.0.1:9001", role: "REPLICA", status: "HEALTHY" }
        ]
      }
    ]
  },
  {
    file_id: "FILE-3b4c910a-d821",
    filename: "neural_weights_v4.bin",
    original_size_bytes: 16777216, // 16 MB
    encrypted_size_bytes: 16777244,
    chunk_size_bytes: 4194304,
    chunk_count: 4,
    replication_factor: 2,
    erasure_coding: "Reed-Solomon (4+2)",
    encryption_algorithm: "AES-256-GCM",
    owner_id: "default_user",
    created_at: new Date(Date.now() - 3600000 * 22).toISOString(),
    status: "active",
    sha256_checksum: "f82b7c19e5d4a3b2c1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8",
    chunks: [
      {
        index: 0,
        chunk_id: "CHUNK-3b4c9-0",
        size_bytes: 4194304,
        sha256: "71a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
        placements: [
          { node_id: "NODE-8a7f1d2c-90b1", endpoint: "http://127.0.0.1:9001", role: "PRIMARY", status: "HEALTHY" },
          { node_id: "NODE-c73d5a1e-88f5", endpoint: "http://127.0.0.1:9004", role: "REPLICA", status: "HEALTHY" }
        ]
      },
      {
        index: 1,
        chunk_id: "CHUNK-3b4c9-1",
        size_bytes: 4194304,
        sha256: "82b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3",
        placements: [
          { node_id: "NODE-4e2b9c3f-71a2", endpoint: "http://127.0.0.1:9002", role: "PRIMARY", status: "HEALTHY" },
          { node_id: "NODE-1f9e8a7b-33c4", endpoint: "http://127.0.0.1:9003", role: "REPLICA", status: "HEALTHY" }
        ]
      },
      {
        index: 2,
        chunk_id: "CHUNK-3b4c9-2",
        size_bytes: 4194304,
        sha256: "93c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4",
        placements: [
          { node_id: "NODE-c73d5a1e-88f5", endpoint: "http://127.0.0.1:9004", role: "PRIMARY", status: "HEALTHY" },
          { node_id: "NODE-8a7f1d2c-90b1", endpoint: "http://127.0.0.1:9001", role: "REPLICA", status: "HEALTHY" }
        ]
      },
      {
        index: 3,
        chunk_id: "CHUNK-3b4c9-3",
        size_bytes: 4194304,
        sha256: "04d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",
        placements: [
          { node_id: "NODE-1f9e8a7b-33c4", endpoint: "http://127.0.0.1:9003", role: "PRIMARY", status: "HEALTHY" },
          { node_id: "NODE-4e2b9c3f-71a2", endpoint: "http://127.0.0.1:9002", role: "REPLICA", status: "HEALTHY" }
        ]
      }
    ]
  }
];

const INITIAL_REPAIR_JOBS = [
  {
    job_id: "REPAIR-49a81c00-01",
    file_id: "FILE-7e12c98d-a410",
    chunk_id: "CHUNK-7e12c-4",
    status: "SUCCEEDED",
    source_node_id: "NODE-8a7f1d2c-90b1",
    destination_node_id: "NODE-c73d5a1e-88f5",
    bytes_transferred: 4194304,
    sha256_verified: true,
    created_at: new Date(Date.now() - 7200000).toISOString(),
    completed_at: new Date(Date.now() - 7182000).toISOString(),
    trigger_reason: "node_offline_under_replicated"
  },
  {
    job_id: "REPAIR-91b32d11-02",
    file_id: "FILE-3b4c910a-d821",
    chunk_id: "CHUNK-3b4c9-2",
    status: "SUCCEEDED",
    source_node_id: "NODE-4e2b9c3f-71a2",
    destination_node_id: "NODE-1f9e8a7b-33c4",
    bytes_transferred: 4194304,
    sha256_verified: true,
    created_at: new Date(Date.now() - 14400000).toISOString(),
    completed_at: new Date(Date.now() - 14385000).toISOString(),
    trigger_reason: "periodic_reconciliation_sweep"
  }
];

// In-Memory Simulation State
let mockNodes = [...INITIAL_NODES];
let mockFiles = [...INITIAL_FILES];
let mockRepairJobs = [...INITIAL_REPAIR_JOBS];
let mockCreditsBalance = 1485.50;
let mockLedger = [
  { id: "TX-901", timestamp: new Date(Date.now() - 3600000 * 2).toISOString(), type: "STORAGE_REWARD", amount: "+45.20 ECC", description: "Committed 150 GB verified storage availability" },
  { id: "TX-902", timestamp: new Date(Date.now() - 3600000 * 6).toISOString(), type: "BANDWIDTH_BONUS", amount: "+12.80 ECC", description: "Served 24 encrypted chunks via reverse WebSocket relay" },
  { id: "TX-903", timestamp: new Date(Date.now() - 3600000 * 18).toISOString(), type: "REPAIR_INCENTIVE", amount: "+8.50 ECC", description: "Completed self-healing replica copy for CHUNK-7e12c-4" }
];

let mockUsers = [
  { user_id: 'usr-admin-001', username: 'admin', email: 'admin@storeshare.net', role: 'admin', provider_id: null, is_active: true, created_at: '2026-01-01T00:00:00Z' },
  { user_id: 'usr-prov-alpha-002', username: 'provider_alpha', email: 'alpha@nodes.io', role: 'provider', provider_id: 'provider-primary-alpha', is_active: true, created_at: '2026-01-02T00:00:00Z' },
  { user_id: 'usr-cons-alice-003', username: 'alice', email: 'alice@crypto.org', role: 'consumer', provider_id: null, is_active: true, created_at: '2026-01-03T00:00:00Z' },
];

// Helper to handle HTTP calls with fallback
async function fetchWithFallback(url, options = {}, mockHandler) {
  if (isSimulationMode()) {
    // Artificial slight latency for realistic UI feel
    await new Promise(r => setTimeout(r, 120));
    return mockHandler();
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const authToken = getAuthToken();
    const coordToken = getCoordinatorToken();

    const headers = {
      ...(options.headers || {}),
      'Content-Type': 'application/json'
    };

    if (authToken) {
      headers['Authorization'] = `Bearer ${authToken}`;
    } else if (coordToken) {
      headers['X-Auth-Token'] = coordToken;
    }

    const res = await fetch(url, {
      ...options,
      headers,
      credentials: 'include',
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (!res.ok) {
      let errDetail = `Status ${res.status}`;
      try {
        const data = await res.json();
        if (data && data.detail) errDetail = data.detail;
      } catch (e) {}

      if (res.status === 401) {
        throw new Error(`Unauthorized (401): ${errDetail}`);
      }
      if (res.status === 403) {
        throw new Error(`Forbidden (403): ${errDetail}`);
      }
      throw new Error(`Coordinator returned ${res.status}: ${errDetail}`);
    }
    return await res.json();
  } catch (err) {
    if (err.message && (err.message.includes('Forbidden (403)') || err.message.includes('Unauthorized (401)'))) {
      throw err;
    }
    console.warn(`Coordinator request to ${url} failed or offline. Using local simulation fallback.`, err.message);
    return mockHandler();
  }
}

// -------------------------------------------------------------
// Authentication & User Management API Methods
// -------------------------------------------------------------

export async function loginUser({ username_or_email, password }) {
  const url = `${getCoordinatorUrl()}/auth/login`;
  return fetchWithFallback(
    url,
    {
      method: 'POST',
      body: JSON.stringify({ username_or_email, password }),
    },
    () => {
      const matched = mockUsers.find(
        u => (u.username.toLowerCase() === username_or_email.toLowerCase() || u.email.toLowerCase() === username_or_email.toLowerCase())
      );
      if (!matched) {
        throw new Error('Invalid username or password');
      }
      return {
        access_token: `sim-jwt-${matched.role}-${matched.user_id}`,
        token_type: 'bearer',
        expires_in_minutes: 30,
        user: matched,
      };
    }
  );
}

export async function registerUser({ username, email, password }) {
  const url = `${getCoordinatorUrl()}/auth/register`;
  return fetchWithFallback(
    url,
    {
      method: 'POST',
      body: JSON.stringify({ username, email, password }),
    },
    () => {
      const exists = mockUsers.some(u => u.username === username || u.email === email);
      if (exists) {
        throw new Error('Account with this username or email already exists');
      }
      const newUser = {
        user_id: `usr-cons-${Math.random().toString(36).substring(2, 9)}`,
        username,
        email,
        role: 'consumer',
        provider_id: null,
        is_active: true,
        created_at: new Date().toISOString(),
      };
      mockUsers.push(newUser);
      return newUser;
    }
  );
}

export async function getCurrentUser() {
  const url = `${getCoordinatorUrl()}/auth/me`;
  return fetchWithFallback(
    url,
    { method: 'GET' },
    () => {
      const token = getAuthToken();
      if (!token) throw new Error('Not authenticated');
      const found = mockUsers.find(u => token.includes(u.user_id));
      return found || mockUsers[0];
    }
  );
}

export async function logoutUser() {
  const url = `${getCoordinatorUrl()}/auth/logout`;
  return fetchWithFallback(
    url,
    { method: 'POST' },
    () => ({ status: 'logged_out', message: 'Logged out successfully' })
  );
}

export async function getAdminUsers() {
  const url = `${getCoordinatorUrl()}/auth/admin/users`;
  return fetchWithFallback(
    url,
    { method: 'GET' },
    () => ({ users: mockUsers, count: mockUsers.length })
  );
}

export async function updateUserRole(userId, role, providerId = null) {
  const url = `${getCoordinatorUrl()}/auth/admin/users/${userId}/role`;
  return fetchWithFallback(
    url,
    {
      method: 'POST',
      body: JSON.stringify({ role, provider_id: providerId }),
    },
    () => {
      const u = mockUsers.find(x => x.user_id === userId);
      if (u) {
        u.role = role;
        u.provider_id = providerId;
      }
      return { status: 'role_updated', user_id: userId, role, provider_id: providerId };
    }
  );
}

export async function updateUserStatus(userId, isActive) {
  const url = `${getCoordinatorUrl()}/auth/admin/users/${userId}/status`;
  return fetchWithFallback(
    url,
    {
      method: 'POST',
      body: JSON.stringify({ is_active: isActive }),
    },
    () => {
      const u = mockUsers.find(x => x.user_id === userId);
      if (u) u.is_active = isActive;
      return { status: 'status_updated', user_id: userId, is_active: isActive };
    }
  );
}
// -------------------------------------------------------------

export async function checkCoordinatorHealth() {
  const url = `${getCoordinatorUrl()}/health`;
  return fetchWithFallback(url, { method: 'GET' }, () => ({
    status: "online",
    version: "0.9.0",
    service: "Expo Coordinator (Simulation Mode Active)"
  }));
}

export async function getNodes() {
  const url = `${getCoordinatorUrl()}/nodes`;
  return fetchWithFallback(url, { method: 'GET' }, () => ({
    nodes: mockNodes,
    count: mockNodes.length
  }));
}

export async function registerNode(nodeData) {
  const url = `${getCoordinatorUrl()}/nodes/register`;
  return fetchWithFallback(
    url,
    { method: 'POST', body: JSON.stringify(nodeData) },
    () => {
      const newNode = {
        node_id: nodeData.node_id || `NODE-${Math.random().toString(36).substring(2, 10)}`,
        endpoint: nodeData.endpoint,
        advertised_endpoint: nodeData.advertised_endpoint || nodeData.endpoint,
        status: "online",
        connectivity_mode: nodeData.connectivity_mode || "LAN",
        total_capacity_bytes: Number(nodeData.total_capacity_bytes) || 53687091200,
        used_capacity_bytes: 0,
        available_capacity_bytes: Number(nodeData.total_capacity_bytes) || 53687091200,
        is_schedulable: 1,
        provider_id: nodeData.provider_id || "provider-user",
        last_seen: new Date().toISOString(),
        chunks_stored: 0,
        reputation: 100.0,
        latency_ms: 15
      };
      mockNodes = [newNode, ...mockNodes];
      return newNode;
    }
  );
}

export async function toggleNodeScheduling(nodeId, enable) {
  const node = mockNodes.find(n => n.node_id === nodeId);
  if (node) {
    node.is_schedulable = enable ? 1 : 0;
  }
  return { success: true, node_id: nodeId, is_schedulable: enable ? 1 : 0 };
}

export async function drainNode(nodeId) {
  const node = mockNodes.find(n => n.node_id === nodeId);
  if (node) {
    node.status = "draining";
    node.is_schedulable = 0;
  }
  
  // Create simulated repair jobs for all chunks on this draining node
  const activeChunks = mockFiles.flatMap(f => f.chunks || []).filter(c => 
    c.placements.some(p => p.node_id === nodeId)
  );

  const targetReplacement = mockNodes.find(n => n.node_id !== nodeId && n.status === "online");

  activeChunks.forEach((chunk, i) => {
    const job = {
      job_id: `DRAIN-JOB-${Math.random().toString(36).substring(2, 8)}`,
      file_id: "FILE-AUTO",
      chunk_id: chunk.chunk_id,
      status: "RUNNING",
      source_node_id: nodeId,
      destination_node_id: targetReplacement ? targetReplacement.node_id : "NODE-REPLACEMENT",
      bytes_transferred: chunk.size_bytes || 4194304,
      sha256_verified: true,
      created_at: new Date().toISOString(),
      completed_at: null,
      trigger_reason: `node_drain_${nodeId}`
    };
    mockRepairJobs.unshift(job);
    
    // Simulate async migration completion
    setTimeout(() => {
      job.status = "SUCCEEDED";
      job.completed_at = new Date().toISOString();
      if (node && i === activeChunks.length - 1) {
        node.status = "drained";
      }
    }, 2500 + (i * 800));
  });

  return { success: true, message: `Draining initiated for ${nodeId}`, migrated_chunks: activeChunks.length };
}

export async function getFiles() {
  const url = `${getCoordinatorUrl()}/catalog/files`;
  return fetchWithFallback(url, { method: 'GET' }, () => ({
    files: mockFiles
  }));
}

export async function uploadFileSimulation(meta) {
  // Generate realistic deterministic chunks
  const chunkSize = meta.chunkSize || 4194304;
  const chunkCount = Math.max(1, Math.ceil(meta.size / chunkSize));
  const fileId = `FILE-${Math.random().toString(36).substring(2, 10)}`;
  
  const eligibleNodes = mockNodes.filter(n => n.status === "online" && n.is_schedulable === 1);
  const repFactor = meta.replicationFactor || 2;

  const generatedChunks = [];
  for (let i = 0; i < chunkCount; i++) {
    const chunkId = `CHUNK-${fileId.substring(5, 10)}-${i}`;
    const placements = [];
    
    // Pick distinct physical nodes
    const shuffled = [...eligibleNodes].sort(() => 0.5 - Math.random());
    const selected = shuffled.slice(0, Math.min(repFactor, shuffled.length));
    
    selected.forEach((node, idx) => {
      placements.push({
        node_id: node.node_id,
        endpoint: node.endpoint,
        role: idx === 0 ? "PRIMARY" : "REPLICA",
        status: "HEALTHY"
      });
      // Increment node metrics
      node.used_capacity_bytes = Math.min(node.total_capacity_bytes, node.used_capacity_bytes + (meta.size / chunkCount));
      node.available_capacity_bytes = Math.max(0, node.total_capacity_bytes - node.used_capacity_bytes);
      node.chunks_stored += 1;
    });

    generatedChunks.push({
      index: i,
      chunk_id: chunkId,
      size_bytes: Math.min(chunkSize, meta.size - (i * chunkSize)),
      sha256: Array.from({length: 64}, () => Math.floor(Math.random()*16).toString(16)).join(''),
      placements
    });
  }

  const newFile = {
    file_id: fileId,
    filename: meta.name,
    original_size_bytes: meta.size,
    encrypted_size_bytes: meta.size + 28, // 12-byte nonce + 16-byte GCM tag
    chunk_size_bytes: chunkSize,
    chunk_count: chunkCount,
    replication_factor: repFactor,
    erasure_coding: meta.useErasureCoding ? "Reed-Solomon (4+2)" : "None (Full Replica)",
    encryption_algorithm: "AES-256-GCM",
    owner_id: "default_user",
    created_at: new Date().toISOString(),
    status: "active",
    sha256_checksum: Array.from({length: 64}, () => Math.floor(Math.random()*16).toString(16)).join(''),
    chunks: generatedChunks
  };

  mockFiles.unshift(newFile);
  return newFile;
}

export async function deleteFile(fileId) {
  mockFiles = mockFiles.filter(f => f.file_id !== fileId);
  return { status: "deleted", file_id: fileId };
}

export async function getRepairJobs() {
  const url = `${getCoordinatorUrl()}/repair/jobs`;
  return fetchWithFallback(url, { method: 'GET' }, () => ({
    jobs: mockRepairJobs
  }));
}

export async function triggerReconciliation(dryRun = false) {
  const underReplicated = [];
  mockFiles.forEach(f => {
    f.chunks.forEach(c => {
      const healthyNodes = c.placements.filter(p => {
        const node = mockNodes.find(n => n.node_id === p.node_id);
        return node && node.status === "online";
      });
      if (healthyNodes.length < f.replication_factor) {
        underReplicated.push({
          file_id: f.file_id,
          chunk_id: c.chunk_id,
          healthy_count: healthyNodes.length,
          target_count: f.replication_factor
        });
      }
    });
  });

  return {
    dry_run: dryRun,
    reconciliation_timestamp: new Date().toISOString(),
    scanned_files_count: mockFiles.length,
    scanned_chunks_count: mockFiles.reduce((acc, f) => acc + (f.chunks?.length || 0), 0),
    under_replicated_chunks: underReplicated,
    orphaned_chunks_detected: 0,
    orphaned_chunks_cleaned: 0,
    repair_jobs_scheduled: dryRun ? 0 : underReplicated.length
  };
}

export async function getProviderOverview() {
  const totalAllocated = mockNodes.reduce((acc, n) => acc + n.total_capacity_bytes, 0);
  const totalUsed = mockNodes.reduce((acc, n) => acc + n.used_capacity_bytes, 0);
  const totalFree = totalAllocated - totalUsed;
  const avgReputation = (mockNodes.reduce((acc, n) => acc + n.reputation, 0) / mockNodes.length).toFixed(1);

  return {
    provider_id: "provider-primary-alpha",
    node_count: mockNodes.length,
    online_node_count: mockNodes.filter(n => n.status === "online").length,
    total_capacity_bytes: totalAllocated,
    verified_stored_bytes: totalUsed,
    remaining_quota_bytes: totalFree,
    reputation_score: parseFloat(avgReputation),
    ecc_balance: mockCreditsBalance,
    recent_transactions: mockLedger
  };
}
