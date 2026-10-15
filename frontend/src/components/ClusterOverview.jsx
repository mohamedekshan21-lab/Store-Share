import React from 'react';

export default function ClusterOverview({
  nodes = [],
  files = [],
  repairJobs = [],
  onNavigate,
  onOpenUpload,
  onOpenRegisterNode,
  onTriggerReconcile,
  isReconciling
}) {
  const onlineNodes = nodes.filter(n => n.status === 'online');
  const totalCapacity = nodes.reduce((acc, n) => acc + (n.total_capacity_bytes || 0), 0);
  const usedCapacity = nodes.reduce((acc, n) => acc + (n.used_capacity_bytes || 0), 0);
  const freeCapacity = Math.max(0, totalCapacity - usedCapacity);
  
  const formatBytes = (bytes) => {
    if (!bytes || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${units[i]}`;
  };

  const usedPercentage = totalCapacity > 0 ? ((usedCapacity / totalCapacity) * 100).toFixed(1) : 0;
  const healthPercentage = nodes.length > 0 ? ((onlineNodes.length / nodes.length) * 100).toFixed(0) : 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      {/* Hero Banner */}
      <div className="glass-panel glass-panel-glow" style={{ padding: '28px 32px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '20px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
              <span className="badge badge-online">
                <span className="status-dot status-dot-pulse" style={{ background: 'var(--accent-emerald)' }}></span>
                Cluster Operational
              </span>
              <span className="badge badge-cyan">Zero-Knowledge AES-256-GCM</span>
              <span className="badge badge-violet">zfec 4+2 Erasure Coding</span>
            </div>
            <h1 style={{ fontSize: '1.9rem', fontWeight: 800, letterSpacing: '-0.03em', marginBottom: '6px' }}>
              Expo Distributed Storage Network
            </h1>
            <p style={{ color: 'var(--text-secondary)', maxWidth: '680px', fontSize: '0.94rem' }}>
              Decentralized peer-to-peer storage engine where clients encrypt files with authenticated AES-256-GCM before chunking, distributing redundant encrypted shards across independent physical storage nodes with automated integrity failover.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
            <button
              id="hero-btn-upload"
              className="btn btn-primary"
              onClick={onOpenUpload}
              style={{ padding: '10px 20px', fontSize: '0.92rem' }}
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                <polyline points="17 8 12 3 7 8" />
                <line x1="12" y1="3" x2="12" y2="15" />
              </svg>
              Upload Encrypted File
            </button>
            <button
              id="hero-btn-node"
              className="btn btn-secondary"
              onClick={onOpenRegisterNode}
              style={{ padding: '10px 18px', fontSize: '0.92rem' }}
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="16" />
                <line x1="8" y1="12" x2="16" y2="12" />
              </svg>
              Register Storage Node
            </button>
            <button
              id="hero-btn-reconcile"
              className="btn btn-secondary"
              onClick={onTriggerReconcile}
              disabled={isReconciling}
              style={{ padding: '10px 18px', fontSize: '0.92rem' }}
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ animation: isReconciling ? 'spin 1s linear infinite' : 'none' }}>
                <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67" />
              </svg>
              {isReconciling ? 'Reconciling...' : 'Run Cluster Audit'}
            </button>
          </div>
        </div>
      </div>

      {/* Primary KPI Metrics Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
        gap: '18px'
      }}>
        {/* Metric 1: Storage Nodes */}
        <div className="glass-panel" style={{ padding: '20px 24px', cursor: 'pointer' }} onClick={() => onNavigate('nodes')}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Storage Nodes
            </span>
            <div style={{
              width: '32px',
              height: '32px',
              borderRadius: '8px',
              background: 'rgba(6, 182, 212, 0.15)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent-cyan)'
            }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
                <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
                <line x1="6" y1="6" x2="6.01" y2="6"></line>
                <line x1="6" y1="18" x2="6.01" y2="18"></line>
              </svg>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginBottom: '6px' }}>
            <span style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              {onlineNodes.length}
            </span>
            <span style={{ fontSize: '1rem', color: 'var(--text-muted)' }}>
              / {nodes.length} Active
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', color: 'var(--accent-emerald)' }}>
            <span className="status-dot" style={{ background: 'var(--accent-emerald)' }}></span>
            <span>{healthPercentage}% Fleet Availability</span>
          </div>
        </div>

        {/* Metric 2: Total Network Capacity */}
        <div className="glass-panel" style={{ padding: '20px 24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Committed Storage
            </span>
            <div style={{
              width: '32px',
              height: '32px',
              borderRadius: '8px',
              background: 'rgba(59, 130, 246, 0.15)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent-blue)'
            }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <ellipse cx="12" cy="5" rx="9" ry="3"></ellipse>
                <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path>
                <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path>
              </svg>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginBottom: '6px' }}>
            <span style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              {formatBytes(totalCapacity)}
            </span>
          </div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            {formatBytes(freeCapacity)} Remaining Quota
          </div>
        </div>

        {/* Metric 3: Stored Encrypted Data */}
        <div className="glass-panel" style={{ padding: '20px 24px', cursor: 'pointer' }} onClick={() => onNavigate('files')}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Stored Ciphertext
            </span>
            <div style={{
              width: '32px',
              height: '32px',
              borderRadius: '8px',
              background: 'rgba(139, 92, 246, 0.15)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent-violet)'
            }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
              </svg>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginBottom: '6px' }}>
            <span style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              {formatBytes(usedCapacity)}
            </span>
            <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>
              ({usedPercentage}%)
            </span>
          </div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            Across {files.length} registered logical manifests
          </div>
        </div>

        {/* Metric 4: Self-Healing & Repair Status */}
        <div className="glass-panel" style={{ padding: '20px 24px', cursor: 'pointer' }} onClick={() => onNavigate('repair')}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Self-Healing Jobs
            </span>
            <div style={{
              width: '32px',
              height: '32px',
              borderRadius: '8px',
              background: 'rgba(16, 185, 129, 0.15)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent-emerald)'
            }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
              </svg>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginBottom: '6px' }}>
            <span style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              {repairJobs.length}
            </span>
            <span style={{ fontSize: '0.9rem', color: 'var(--accent-emerald)' }}>
              Durable
            </span>
          </div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            100% Replication Verification Pass
          </div>
        </div>
      </div>

      {/* Two Column Layout: Capacity Visualizer & Architectural Pipeline */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: '24px' }}>
        {/* Capacity Breakdown Glass Panel */}
        <div className="glass-panel" style={{ padding: '24px 28px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
            <div>
              <h3 style={{ fontSize: '1.15rem', fontWeight: 700 }}>Cluster Storage Distribution</h3>
              <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>Verified stored bytes vs available provider quotas</p>
            </div>
            <span className="badge badge-cyan">{usedPercentage}% Allocated</span>
          </div>

          {/* Custom Visual Progress Bar */}
          <div style={{
            height: '14px',
            background: 'rgba(255, 255, 255, 0.06)',
            borderRadius: 'var(--radius-full)',
            overflow: 'hidden',
            marginBottom: '20px',
            position: 'relative'
          }}>
            <div style={{
              width: `${Math.min(100, usedPercentage)}%`,
              height: '100%',
              background: 'linear-gradient(90deg, var(--accent-cyan), var(--accent-violet))',
              borderRadius: 'var(--radius-full)',
              boxShadow: '0 0 12px var(--accent-cyan-glow)',
              transition: 'width 0.8s cubic-bezier(0.4, 0, 0.2, 1)'
            }} />
          </div>

          {/* Breakdown Items */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', background: 'rgba(13, 18, 29, 0.6)', borderRadius: '10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ width: '10px', height: '10px', borderRadius: '3px', background: 'var(--accent-cyan)' }}></span>
                <span style={{ fontSize: '0.88rem', color: 'var(--text-secondary)' }}>Verified Encrypted Data</span>
              </div>
              <span className="font-mono" style={{ fontWeight: 600 }}>{formatBytes(usedCapacity)}</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', background: 'rgba(13, 18, 29, 0.6)', borderRadius: '10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ width: '10px', height: '10px', borderRadius: '3px', background: 'rgba(255, 255, 255, 0.2)' }}></span>
                <span style={{ fontSize: '0.88rem', color: 'var(--text-secondary)' }}>Free Available Quota</span>
              </div>
              <span className="font-mono" style={{ fontWeight: 600 }}>{formatBytes(freeCapacity)}</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', background: 'rgba(13, 18, 29, 0.6)', borderRadius: '10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ width: '10px', height: '10px', borderRadius: '3px', background: 'var(--accent-violet)' }}></span>
                <span style={{ fontSize: '0.88rem', color: 'var(--text-secondary)' }}>Configured Fleet Limit</span>
              </div>
              <span className="font-mono" style={{ fontWeight: 600 }}>{formatBytes(totalCapacity)}</span>
            </div>
          </div>
        </div>

        {/* Phase 4B/9A Architecture Flow */}
        <div className="glass-panel" style={{ padding: '24px 28px' }}>
          <div style={{ marginBottom: '16px' }}>
            <h3 style={{ fontSize: '1.15rem', fontWeight: 700 }}>Security & Sharding Pipeline</h3>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>Verified Zero-Knowledge client data flow</p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {/* Step 1 */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '14px', padding: '10px 12px', background: 'rgba(13, 18, 29, 0.5)', borderRadius: '8px' }}>
              <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: 'rgba(6, 182, 212, 0.2)', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: '0.8rem' }}>1</div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: '0.86rem', fontWeight: 600 }}>Client-Side Authenticated Encryption</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>AES-256-GCM authenticated cipher with local DEK. Keys never leave consumer machine.</div>
              </div>
            </div>

            {/* Step 2 */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '14px', padding: '10px 12px', background: 'rgba(13, 18, 29, 0.5)', borderRadius: '8px' }}>
              <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: 'rgba(59, 130, 246, 0.2)', color: 'var(--accent-blue)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: '0.8rem' }}>2</div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: '0.86rem', fontWeight: 600 }}>Deterministic Payload Chunking</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>4 MB binary slicing or Reed-Solomon (4+2) shard generation with SHA-256 checksums.</div>
              </div>
            </div>

            {/* Step 3 */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '14px', padding: '10px 12px', background: 'rgba(13, 18, 29, 0.5)', borderRadius: '8px' }}>
              <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: 'rgba(139, 92, 246, 0.2)', color: 'var(--accent-violet)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: '0.8rem' }}>3</div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: '0.86rem', fontWeight: 600 }}>Multi-Node Distinct Placement</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Coordinator matches optimal nodes (LAN / DIRECT / RELAY); uploads to distinct physical IDs.</div>
              </div>
            </div>

            {/* Step 4 */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '14px', padding: '10px 12px', background: 'rgba(13, 18, 29, 0.5)', borderRadius: '8px' }}>
              <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: 'rgba(16, 185, 129, 0.2)', color: 'var(--accent-emerald)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: '0.8rem' }}>4</div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: '0.86rem', fontWeight: 600 }}>Schema v2 Manifest Registration</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Primary & replica placements registered atomically. Coordinator only stores metadata.</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
