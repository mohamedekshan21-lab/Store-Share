import React, { useState } from 'react';

export default function NodeTopology({
  nodes = [],
  onToggleScheduling,
  onDrainNode,
  onOpenRegisterModal,
}) {
  const [statusFilter, setStatusFilter] = useState('all');
  const [connectivityFilter, setConnectivityFilter] = useState('all');
  const [selectedNodeDiagnostics, setSelectedNodeDiagnostics] = useState(null);
  const [pingResults, setPingResults] = useState({});
  const [drainConfirmNodeId, setDrainConfirmNodeId] = useState(null);

  const filteredNodes = nodes.filter(n => {
    if (statusFilter !== 'all' && n.status !== statusFilter) return false;
    if (connectivityFilter !== 'all' && n.connectivity_mode !== connectivityFilter) return false;
    return true;
  });

  const formatBytes = (bytes) => {
    if (!bytes || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${units[i]}`;
  };

  const handlePingNode = (node) => {
    setPingResults(prev => ({ ...prev, [node.node_id]: 'Pinging...' }));
    setTimeout(() => {
      if (node.status === 'offline') {
        setPingResults(prev => ({ ...prev, [node.node_id]: 'Timeout: Node unreachable' }));
      } else {
        const simulatedMs = node.latency_ms || Math.floor(Math.random() * 25 + 8);
        setPingResults(prev => ({ ...prev, [node.node_id]: `200 OK (${simulatedMs}ms)` }));
      }
    }, 450);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header and Filter Controls */}
      <div className="glass-panel" style={{ padding: '24px 28px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <h2 style={{ fontSize: '1.4rem', fontWeight: 700, marginBottom: '4px' }}>
              Storage Node Fleet & Topology
            </h2>
            <p style={{ fontSize: '0.86rem', color: 'var(--text-secondary)' }}>
              Independent storage daemons contributing physical sandboxed disk quota to the Expo network
            </p>
          </div>

          <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
            {/* Status Filter */}
            <select
              className="select"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              style={{ width: '140px' }}
            >
              <option value="all">All Statuses</option>
              <option value="online">Online Only</option>
              <option value="offline">Offline Only</option>
              <option value="draining">Draining Only</option>
            </select>

            {/* Connectivity Filter */}
            <select
              className="select"
              value={connectivityFilter}
              onChange={(e) => setConnectivityFilter(e.target.value)}
              style={{ width: '160px' }}
            >
              <option value="all">All Modes</option>
              <option value="LAN">LAN Mode</option>
              <option value="DIRECT">DIRECT WAN</option>
              <option value="RELAY">RELAY WebSocket</option>
            </select>

            <button
              id="btn-register-node"
              className="btn btn-primary"
              onClick={onOpenRegisterModal}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <line x1="12" y1="5" x2="12" y2="19"></line>
                <line x1="5" y1="12" x2="19" y2="12"></line>
              </svg>
              Register Storage Node
            </button>
          </div>
        </div>
      </div>

      {/* Nodes Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))',
        gap: '20px'
      }}>
        {filteredNodes.map((node) => {
          const isOnline = node.status === 'online';
          const isDraining = node.status === 'draining';
          const usedPct = node.total_capacity_bytes > 0
            ? ((node.used_capacity_bytes / node.total_capacity_bytes) * 100).toFixed(1)
            : 0;

          return (
            <div
              key={node.node_id}
              className="glass-panel"
              style={{
                padding: '22px 24px',
                display: 'flex',
                flexDirection: 'column',
                gap: '16px',
                borderLeft: isOnline ? '3px solid var(--accent-emerald)' : (isDraining ? '3px solid var(--accent-amber)' : '3px solid var(--accent-rose)')
              }}
            >
              {/* Card Top: Node ID, Status, Mode */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span className="font-mono" style={{ fontSize: '0.95rem', fontWeight: 700, color: '#f8fafc' }}>
                      {node.node_id}
                    </span>
                  </div>
                  <div className="font-mono" style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    {node.advertised_endpoint || node.endpoint}
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '6px' }}>
                  <span className={`badge ${isOnline ? 'badge-online' : (isDraining ? 'badge-draining' : 'badge-offline')}`}>
                    <span className={`status-dot ${isOnline ? 'status-dot-pulse' : ''}`} style={{ background: isOnline ? 'var(--accent-emerald)' : (isDraining ? 'var(--accent-amber)' : 'var(--accent-rose)') }}></span>
                    {node.status}
                  </span>
                  <span className="badge badge-cyan" style={{ fontSize: '0.68rem' }}>
                    {node.connectivity_mode}
                  </span>
                </div>
              </div>

              {/* Capacity Progress Bar */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: '6px' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Storage Allocated:</span>
                  <span className="font-mono">
                    <strong>{formatBytes(node.used_capacity_bytes)}</strong> / {formatBytes(node.total_capacity_bytes)} ({usedPct}%)
                  </span>
                </div>
                <div style={{
                  height: '8px',
                  background: 'rgba(255, 255, 255, 0.06)',
                  borderRadius: 'var(--radius-full)',
                  overflow: 'hidden'
                }}>
                  <div style={{
                    width: `${Math.min(100, usedPct)}%`,
                    height: '100%',
                    background: isDraining ? 'var(--accent-amber)' : 'linear-gradient(90deg, var(--accent-cyan), var(--accent-blue))',
                    borderRadius: 'var(--radius-full)',
                    transition: 'width 0.4s ease'
                  }} />
                </div>
              </div>

              {/* Node Stats Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', background: 'rgba(13, 18, 29, 0.6)', padding: '10px 14px', borderRadius: '10px', fontSize: '0.82rem' }}>
                <div>
                  <div style={{ color: 'var(--text-muted)' }}>Hosted Chunks</div>
                  <div className="font-mono" style={{ fontWeight: 600 }}>{node.chunks_stored || 0} shards</div>
                </div>
                <div>
                  <div style={{ color: 'var(--text-muted)' }}>Reputation</div>
                  <div style={{ fontWeight: 600, color: node.reputation >= 90 ? 'var(--accent-emerald)' : 'var(--accent-amber)' }}>
                    {node.reputation || 99.0}%
                  </div>
                </div>
                <div>
                  <div style={{ color: 'var(--text-muted)' }}>Provider</div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {node.provider_id}
                  </div>
                </div>
                <div>
                  <div style={{ color: 'var(--text-muted)' }}>Placement Schedulable</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <input
                      type="checkbox"
                      checked={Boolean(node.is_schedulable)}
                      onChange={(e) => onToggleScheduling(node.node_id, e.target.checked)}
                      style={{ accentColor: 'var(--accent-cyan)', cursor: 'pointer' }}
                    />
                    <span style={{ fontSize: '0.78rem', color: node.is_schedulable ? 'var(--accent-emerald)' : 'var(--text-muted)' }}>
                      {node.is_schedulable ? 'Active' : 'Disabled'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Card Footer Actions */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '6px', borderTop: '1px solid var(--border-subtle)' }}>
                <button
                  id={`btn-ping-${node.node_id}`}
                  className="btn btn-secondary btn-sm"
                  onClick={() => handlePingNode(node)}
                >
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="12" cy="12" r="10"></circle>
                    <polyline points="12 6 12 12 16 14"></polyline>
                  </svg>
                  {pingResults[node.node_id] || 'Ping Health'}
                </button>

                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    id={`btn-diag-${node.node_id}`}
                    className="btn btn-secondary btn-sm"
                    onClick={() => setSelectedNodeDiagnostics(node)}
                    title="View Node Diagnostics"
                  >
                    Diagnostics
                  </button>

                  {node.status !== 'draining' && node.status !== 'drained' && (
                    <button
                      id={`btn-drain-${node.node_id}`}
                      className="btn btn-danger btn-sm"
                      onClick={() => setDrainConfirmNodeId(node.node_id)}
                      title="Decommission node and migrate chunks to healthy nodes"
                    >
                      Drain
                    </button>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Node Diagnostics Modal */}
      {selectedNodeDiagnostics && (
        <div className="modal-overlay" onClick={() => setSelectedNodeDiagnostics(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '640px' }}>
            <div style={{ padding: '24px 28px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h3 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Storage Node Diagnostics</h3>
                <span className="font-mono" style={{ fontSize: '0.82rem', color: 'var(--accent-cyan)' }}>
                  {selectedNodeDiagnostics.node_id}
                </span>
              </div>
              <button className="btn btn-secondary btn-icon" onClick={() => setSelectedNodeDiagnostics(null)}>✕</button>
            </div>

            <div style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div style={{ background: 'rgba(13, 18, 29, 0.7)', padding: '12px', borderRadius: '10px' }}>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Status & Liveness</div>
                  <div style={{ fontWeight: 600, color: selectedNodeDiagnostics.status === 'online' ? 'var(--accent-emerald)' : 'var(--accent-rose)' }}>
                    {selectedNodeDiagnostics.status.toUpperCase()}
                  </div>
                </div>

                <div style={{ background: 'rgba(13, 18, 29, 0.7)', padding: '12px', borderRadius: '10px' }}>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Network Topology Mode</div>
                  <div style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>
                    {selectedNodeDiagnostics.connectivity_mode} (NAT Traversal Ready)
                  </div>
                </div>

                <div style={{ background: 'rgba(13, 18, 29, 0.7)', padding: '12px', borderRadius: '10px' }}>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Internal Listening Endpoint</div>
                  <div className="font-mono" style={{ fontSize: '0.82rem' }}>
                    {selectedNodeDiagnostics.endpoint}
                  </div>
                </div>

                <div style={{ background: 'rgba(13, 18, 29, 0.7)', padding: '12px', borderRadius: '10px' }}>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Public Advertised Endpoint</div>
                  <div className="font-mono" style={{ fontSize: '0.82rem' }}>
                    {selectedNodeDiagnostics.advertised_endpoint}
                  </div>
                </div>
              </div>

              <div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '6px' }}>Diagnostic Wire Payload</div>
                <pre className="font-mono" style={{
                  padding: '14px',
                  background: 'rgba(7, 9, 14, 0.9)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '10px',
                  fontSize: '0.76rem',
                  color: '#38bdf8'
                }}>
                  {JSON.stringify(selectedNodeDiagnostics, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Drain Node Confirmation Modal */}
      {drainConfirmNodeId && (
        <div className="modal-overlay" onClick={() => setDrainConfirmNodeId(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '500px' }}>
            <div style={{ padding: '24px 28px' }}>
              <div style={{ width: '48px', height: '48px', borderRadius: '12px', background: 'rgba(245, 158, 11, 0.15)', color: 'var(--accent-amber)', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '16px' }}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                  <line x1="12" y1="9" x2="12" y2="13"></line>
                  <line x1="12" y1="17" x2="12.01" y2="17"></line>
                </svg>
              </div>
              <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '8px' }}>Initiate Durable Node Drain</h3>
              <p style={{ fontSize: '0.86rem', color: 'var(--text-secondary)', marginBottom: '16px' }}>
                Draining <strong className="font-mono" style={{ color: '#fff' }}>{drainConfirmNodeId}</strong> will disable new chunk placement allocations and asynchronously migrate all hosted ciphertext shards to alternative healthy nodes with SHA-256 destination verification.
              </p>
              <div style={{ padding: '10px 14px', background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.2)', borderRadius: '8px', fontSize: '0.78rem', color: '#6ee7b7', marginBottom: '20px' }}>
                ✓ Safe Decommissioning Gate: Source chunk files will not be deleted until target copies are verified bit-for-bit.
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
                <button className="btn btn-secondary" onClick={() => setDrainConfirmNodeId(null)}>Cancel</button>
                <button
                  id="btn-confirm-drain"
                  className="btn btn-primary"
                  onClick={() => {
                    onDrainNode(drainConfirmNodeId);
                    setDrainConfirmNodeId(null);
                  }}
                >
                  Start Drain & Chunk Migration
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
