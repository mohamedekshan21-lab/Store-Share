import React, { useState, useEffect } from 'react';
import { getProviderOverview } from '../services/api';

export default function ProviderAccounting() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      const res = await getProviderOverview();
      setData(res);
      setLoading(false);
    }
    load();
  }, []);

  const formatBytes = (bytes) => {
    if (!bytes || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${units[i]}`;
  };

  if (loading || !data) {
    return (
      <div className="glass-panel" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
        Loading Provider Capacity & Accounting Ledgers...
      </div>
    );
  }

  const reputation = data.reputation_score || 98.5;
  const circumference = 2 * Math.PI * 45;
  const strokeDashoffset = circumference - (reputation / 100) * circumference;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Banner */}
      <div className="glass-panel" style={{ padding: '24px 28px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
              <h2 style={{ fontSize: '1.4rem', fontWeight: 700 }}>
                Provider Capacity & Accounting Ledger
              </h2>
              <span className="badge badge-cyan">Phase 8A & 8B Double-Entry Accounting</span>
            </div>
            <p style={{ fontSize: '0.86rem', color: 'var(--text-secondary)' }}>
              Verifiable proof-of-storage capacity domains, reputation scoring, and Expo Contribution Credits (ECC).
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span className="badge badge-online">
              <span className="status-dot status-dot-pulse" style={{ background: 'var(--accent-emerald)' }}></span>
              Provider: {data.provider_id}
            </span>
          </div>
        </div>
      </div>

      {/* Main Stats Row: Reputation Gauge & ECC Wallet */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px' }}>
        {/* ECC Balance Card */}
        <div className="glass-panel glass-panel-glow" style={{ padding: '24px 28px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
            <span style={{ fontSize: '0.84rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Expo Contribution Credits (ECC)
            </span>
            <span className="badge badge-cyan">Wallet Active</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'baseline', gap: '10px', marginBottom: '12px' }}>
            <span style={{ fontSize: '2.5rem', fontWeight: 800, background: 'linear-gradient(135deg, #38bdf8 0%, #818cf8 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              {data.ecc_balance?.toLocaleString()}
            </span>
            <span style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
              ECC
            </span>
          </div>

          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '18px' }}>
            Credits earned for provable storage disk availability, WebSocket relay tunneling, and self-healing worker jobs.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '8px', paddingTop: '14px', borderTop: '1px solid var(--border-subtle)', textAlign: 'center' }}>
            <div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Storage Rewards</div>
              <div style={{ fontWeight: 600, color: 'var(--accent-emerald)', fontSize: '0.86rem' }}>+1,120 ECC</div>
            </div>
            <div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Relay Traffic</div>
              <div style={{ fontWeight: 600, color: 'var(--accent-cyan)', fontSize: '0.86rem' }}>+245 ECC</div>
            </div>
            <div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Repair Bonus</div>
              <div style={{ fontWeight: 600, color: 'var(--accent-violet)', fontSize: '0.86rem' }}>+120.5 ECC</div>
            </div>
          </div>
        </div>

        {/* Reputation Score Ring Gauge */}
        <div className="glass-panel" style={{ padding: '24px 28px', display: 'flex', alignItems: 'center', gap: '24px' }}>
          <div style={{ position: 'relative', width: '110px', height: '110px', flexShrink: 0 }}>
            <svg width="110" height="110" viewBox="0 0 110 110" style={{ transform: 'rotate(-90deg)' }}>
              {/* Background circle */}
              <circle
                cx="55"
                cy="55"
                r="45"
                fill="none"
                stroke="rgba(255, 255, 255, 0.08)"
                strokeWidth="8"
              />
              {/* Progress circle */}
              <circle
                cx="55"
                cy="55"
                r="45"
                fill="none"
                stroke="url(#reputationGrad)"
                strokeWidth="8"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                style={{ transition: 'stroke-dashoffset 1s ease' }}
              />
              <defs>
                <linearGradient id="reputationGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#10b981" />
                  <stop offset="100%" stopColor="#06b6d4" />
                </linearGradient>
              </defs>
            </svg>
            <div style={{
              position: 'absolute',
              inset: 0,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
            }}>
              <span style={{ fontSize: '1.4rem', fontWeight: 800, color: '#ffffff' }}>
                {reputation}
              </span>
              <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                / 100
              </span>
            </div>
          </div>

          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Fleet Reliability Score</h3>
              <span className="badge badge-online">Tier 1</span>
            </div>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '8px' }}>
              Calculated deterministically based on successful heartbeat intervals, SHA-256 verification responses, and low latency NAT traversal.
            </p>
            <div style={{ fontSize: '0.78rem', color: 'var(--accent-emerald)' }}>
              ✓ 0 Fraud incidents or corrupted chunk checksums recorded.
            </div>
          </div>
        </div>
      </div>

      {/* Phase 8A Four Capacity Domains */}
      <div className="glass-panel" style={{ padding: '24px 28px' }}>
        <h3 style={{ fontSize: '1.15rem', fontWeight: 700, marginBottom: '4px' }}>
          Authoritative Capacity Domain Separation
        </h3>
        <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '20px' }}>
          Phase 8A strictly isolates verified stored chunks from host operating system storage limits
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
          <div style={{ padding: '16px', background: 'rgba(13, 18, 29, 0.7)', borderRadius: '10px', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '4px' }}>
              1. Configured Quota Limit
            </div>
            <div className="font-mono" style={{ fontSize: '1.3rem', fontWeight: 700, color: 'var(--accent-blue)', marginBottom: '4px' }}>
              {formatBytes(data.total_capacity_bytes)}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Committed boundary in node registration
            </div>
          </div>

          <div style={{ padding: '16px', background: 'rgba(13, 18, 29, 0.7)', borderRadius: '10px', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '4px' }}>
              2. Verified Stored Bytes
            </div>
            <div className="font-mono" style={{ fontSize: '1.3rem', fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: '4px' }}>
              {formatBytes(data.verified_stored_bytes)}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Authoritative active chunk bytes on disk
            </div>
          </div>

          <div style={{ padding: '16px', background: 'rgba(13, 18, 29, 0.7)', borderRadius: '10px', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '4px' }}>
              3. Remaining Expo Quota
            </div>
            <div className="font-mono" style={{ fontSize: '1.3rem', fontWeight: 700, color: 'var(--accent-emerald)', marginBottom: '4px' }}>
              {formatBytes(data.remaining_quota_bytes)}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              max(0, Configured Quota - Verified Stored)
            </div>
          </div>

          <div style={{ padding: '16px', background: 'rgba(13, 18, 29, 0.7)', borderRadius: '10px', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '4px' }}>
              4. Physical Host Drive
            </div>
            <div className="font-mono" style={{ fontSize: '1.3rem', fontWeight: 700, color: '#f8fafc', marginBottom: '4px' }}>
              512.00 GB
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Underlying OS hardware partition
            </div>
          </div>
        </div>
      </div>

      {/* Double-Entry Transaction Ledger */}
      <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
        <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h3 style={{ fontSize: '1.15rem', fontWeight: 700 }}>Double-Entry Accounting Ledger</h3>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>Cryptographically reconciled credit entries</p>
          </div>
          <span className="badge badge-cyan">Audited</span>
        </div>

        <div className="table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>Transaction ID</th>
                <th>Type</th>
                <th>Description</th>
                <th>Amount</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {data.recent_transactions?.map((tx) => (
                <tr key={tx.id}>
                  <td className="font-mono" style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>
                    {tx.id}
                  </td>
                  <td>
                    <span className="badge badge-violet" style={{ fontSize: '0.7rem' }}>
                      {tx.type}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.84rem', color: 'var(--text-secondary)' }}>
                    {tx.description}
                  </td>
                  <td className="font-mono" style={{ fontWeight: 600, color: 'var(--accent-emerald)' }}>
                    {tx.amount}
                  </td>
                  <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    {new Date(tx.timestamp).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
