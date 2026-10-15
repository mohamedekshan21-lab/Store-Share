import React, { useState, useEffect, useRef } from 'react';
import { checkCoordinatorHealth } from '../services/api';

export default function DiagnosticsConsole({ isSimulation, coordinatorUrl }) {
  const [filter, setFilter] = useState('ALL');
  const [healthStatus, setHealthStatus] = useState(null);
  const [isProbing, setIsProbing] = useState(false);
  const [logs, setLogs] = useState([
    { id: 1, time: new Date(Date.now() - 32000).toISOString(), level: 'INFO', category: 'REGISTRY', text: 'Coordinator NodeRegistry initialized. Connected to SQLite metadata catalog.' },
    { id: 2, time: new Date(Date.now() - 28000).toISOString(), level: 'INFO', category: 'REGISTRY', text: 'Storage node NODE-8a7f1d2c-90b1 registered via LAN endpoint http://127.0.0.1:9001 (50 GB).' },
    { id: 3, time: new Date(Date.now() - 24000).toISOString(), level: 'INFO', category: 'REGISTRY', text: 'Storage node NODE-4e2b9c3f-71a2 registered via DIRECT endpoint http://127.0.0.1:9002 (100 GB).' },
    { id: 4, time: new Date(Date.now() - 20000).toISOString(), level: 'CRYPTO', category: 'CRYPTO', text: 'Client authenticated encryption: AES-256-GCM cipher generated with 96-bit nonce.' },
    { id: 5, time: new Date(Date.now() - 16000).toISOString(), level: 'INFO', category: 'RELAY', text: 'Reverse WebSocket tunnel established with NODE-1f9e8a7b-33c4 (relay://ws.expo.net/node-3).' },
    { id: 6, time: new Date(Date.now() - 12000).toISOString(), level: 'WARN', category: 'PROBE', text: 'Storage node NODE-d31e9a2b-65c8 heartbeat missed for 180s. Transitioned to OFFLINE.' },
    { id: 7, time: new Date(Date.now() - 8000).toISOString(), level: 'REPAIR', category: 'REPAIR', text: 'Autonomous repair sweep: Scheduled replacement replica migration for under-replicated chunks.' },
    { id: 8, time: new Date(Date.now() - 4000).toISOString(), level: 'INFO', category: 'REGISTRY', text: 'Schema v2 manifest committed atomically. Checksum verified bit-for-bit.' },
  ]);

  const terminalEndRef = useRef(null);

  const handleProbeHealth = async () => {
    setIsProbing(true);
    const start = performance.now();
    try {
      const res = await checkCoordinatorHealth();
      const latency = Math.round(performance.now() - start);
      setHealthStatus({
        status: res.status,
        latency,
        service: res.service || 'Expo Coordinator',
        timestamp: new Date().toLocaleTimeString()
      });
      setLogs(prev => [
        ...prev,
        {
          id: Date.now(),
          time: new Date().toISOString(),
          level: 'INFO',
          category: 'PROBE',
          text: `Health probe GET /health: 200 OK (${latency}ms) - ${res.status}`
        }
      ]);
    } catch (err) {
      setHealthStatus({
        status: 'error',
        latency: 0,
        service: err.message,
        timestamp: new Date().toLocaleTimeString()
      });
    } finally {
      setIsProbing(false);
    }
  };

  const filteredLogs = logs.filter(l => {
    if (filter === 'ALL') return true;
    return l.level === filter || l.category === filter;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Banner & Health Probe Action */}
      <div className="glass-panel" style={{ padding: '24px 28px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
              <h2 style={{ fontSize: '1.4rem', fontWeight: 700 }}>
                Diagnostics & Live Console
              </h2>
              <span className="badge badge-cyan">Real-Time Event Stream</span>
            </div>
            <p style={{ fontSize: '0.86rem', color: 'var(--text-secondary)' }}>
              Inspect low-level network packets, cryptographic key events, reverse WebSocket tunnels, and heartbeat probes.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
            <button
              id="btn-probe-coordinator"
              className="btn btn-primary"
              onClick={handleProbeHealth}
              disabled={isProbing}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M22 12h-4l-3 9L9 3l-3 9H2"></path>
              </svg>
              {isProbing ? 'Probing...' : 'Probe /health Endpoint'}
            </button>
          </div>
        </div>

        {healthStatus && (
          <div style={{ marginTop: '16px', padding: '12px 16px', background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.25)', borderRadius: '10px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span className="status-dot status-dot-pulse" style={{ background: 'var(--accent-emerald)' }}></span>
              <span style={{ fontSize: '0.86rem', fontWeight: 600 }}>
                Coordinator Response: 200 OK — {healthStatus.service}
              </span>
            </div>
            <div style={{ display: 'flex', gap: '14px', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              <span>Latency: <strong className="font-mono" style={{ color: 'var(--accent-emerald)' }}>{healthStatus.latency}ms</strong></span>
              <span>Probed: {healthStatus.timestamp}</span>
            </div>
          </div>
        )}
      </div>

      {/* Console Panel */}
      <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
        {/* Terminal Header with Filters */}
        <div style={{
          padding: '14px 20px',
          background: 'rgba(13, 18, 29, 0.95)',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '12px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ display: 'flex', gap: '6px' }}>
              <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#ef4444' }}></span>
              <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#f59e0b' }}></span>
              <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#10b981' }}></span>
            </div>
            <span className="font-mono" style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              expo-coordinator-daemon.log
            </span>
          </div>

          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            {['ALL', 'INFO', 'CRYPTO', 'REPAIR', 'WARN'].map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                style={{
                  padding: '3px 9px',
                  borderRadius: '6px',
                  fontSize: '0.72rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  border: filter === f ? '1px solid var(--accent-cyan)' : '1px solid transparent',
                  background: filter === f ? 'rgba(6, 182, 212, 0.15)' : 'rgba(255, 255, 255, 0.04)',
                  color: filter === f ? 'var(--accent-cyan)' : 'var(--text-muted)'
                }}
              >
                {f}
              </button>
            ))}

            <button
              className="btn btn-secondary btn-sm"
              onClick={() => setLogs([])}
              style={{ fontSize: '0.72rem', padding: '3px 8px' }}
            >
              Clear
            </button>
          </div>
        </div>

        {/* Terminal Log Area */}
        <div style={{
          padding: '18px 22px',
          background: 'rgba(7, 9, 14, 0.96)',
          minHeight: '360px',
          maxHeight: '480px',
          overflowY: 'auto',
          fontFamily: 'var(--font-mono)',
          fontSize: '0.82rem',
          lineHeight: '1.7',
          color: '#cbd5e1'
        }}>
          {filteredLogs.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '40px' }}>
              No log messages matching filter "{filter}".
            </div>
          ) : (
            filteredLogs.map((log) => {
              let badgeColor = 'var(--accent-blue)';
              if (log.level === 'CRYPTO') badgeColor = 'var(--accent-cyan)';
              if (log.level === 'REPAIR') badgeColor = 'var(--accent-violet)';
              if (log.level === 'WARN') badgeColor = 'var(--accent-amber)';

              return (
                <div key={log.id} style={{ display: 'flex', gap: '12px', marginBottom: '6px', alignItems: 'flex-start' }}>
                  <span style={{ color: 'var(--text-muted)', flexShrink: 0, fontSize: '0.74rem' }}>
                    {log.time.split('T')[1].substring(0, 12)}
                  </span>
                  <span style={{
                    color: badgeColor,
                    fontWeight: 700,
                    fontSize: '0.72rem',
                    flexShrink: 0,
                    width: '64px'
                  }}>
                    [{log.level}]
                  </span>
                  <span style={{ color: '#e2e8f0', wordBreak: 'break-all' }}>
                    {log.text}
                  </span>
                </div>
              );
            })
          )}
          <div ref={terminalEndRef} />
        </div>
      </div>
    </div>
  );
}
