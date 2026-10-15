import React from 'react';
import { useAuth } from '../context/AuthContext';

export default function Navbar({ activeTab, setActiveTab, onOpenConfig, isSimulation, isOnline, nodesCount, filesCount }) {
  const { user, role, logout, setAuthModalOpen, setAuthModalTab, switchDemoRole } = useAuth();

  // Define tabs with allowed roles
  const allTabs = [
    {
      id: 'overview',
      label: role === 'provider' ? 'Provider Overview' : 'Cluster Overview',
      icon: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6',
      roles: ['admin', 'provider']
    },
    {
      id: 'files',
      label: role === 'admin' ? 'File Catalog (Audited)' : 'My Files',
      icon: 'M5 19a2 2 0 01-2-2V7a2 2 0 012-2h4l2 2h4a2 2 0 012 2v1M5 19h14a2 2 0 002-2v-5a2 2 0 00-2-2H9a2 2 0 00-2 2v5a2 2 0 01-2 2z',
      count: filesCount,
      roles: ['admin', 'consumer']
    },
    {
      id: 'nodes',
      label: role === 'provider' ? 'My Storage Nodes' : 'Storage Nodes',
      icon: 'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01',
      count: nodesCount,
      roles: ['admin', 'provider']
    },
    {
      id: 'repair',
      label: 'Self-Healing & Repair',
      icon: 'M13 10V3L4 14h7v7l9-11h-7z',
      roles: ['admin']
    },
    {
      id: 'accounting',
      label: role === 'provider' ? 'My Capacity & Credits' : 'Accounting & Credits',
      icon: 'M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
      roles: ['admin', 'provider']
    },
    {
      id: 'users',
      label: 'User Accounts',
      icon: 'M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z',
      roles: ['admin']
    },
    {
      id: 'diagnostics',
      label: 'Diagnostics & Logs',
      icon: 'M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
      roles: ['admin', 'provider']
    },
  ];

  const currentRole = role || 'consumer';
  const visibleTabs = allTabs.filter(t => t.roles.includes(currentRole));

  const roleBadgeStyle =
    currentRole === 'admin'
      ? { background: 'rgba(239, 68, 68, 0.2)', color: '#f87171', border: '1px solid rgba(239, 68, 68, 0.4)' }
      : currentRole === 'provider'
      ? { background: 'rgba(6, 182, 212, 0.2)', color: '#38bdf8', border: '1px solid rgba(6, 182, 212, 0.4)' }
      : { background: 'rgba(16, 185, 129, 0.2)', color: '#34d399', border: '1px solid rgba(16, 185, 129, 0.4)' };

  return (
    <header className="navbar-container" style={{
      position: 'sticky',
      top: 0,
      zIndex: 100,
      background: 'rgba(7, 9, 14, 0.88)',
      backdropFilter: 'blur(16px)',
      borderBottom: '1px solid var(--border-subtle)',
      padding: '0 24px',
    }}>
      <div style={{
        maxWidth: '1440px',
        margin: '0 auto',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        height: '70px',
        gap: '16px'
      }}>
        {/* Brand Logo & Title */}
        <div
          style={{ display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer', flexShrink: 0 }}
          onClick={() => setActiveTab(currentRole === 'consumer' ? 'files' : 'overview')}
        >
          <div style={{
            width: '40px',
            height: '40px',
            borderRadius: '12px',
            background: 'linear-gradient(135deg, rgba(6, 182, 212, 0.2) 0%, rgba(139, 92, 246, 0.2) 100%)',
            border: '1px solid var(--border-glow)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: 'var(--shadow-cyan-glow)'
          }}>
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ color: 'var(--accent-cyan)' }}>
              <polygon points="12 2 2 7 12 12 22 7 12 2" />
              <polyline points="2 17 12 22 22 17" />
              <polyline points="2 12 12 17 22 12" />
            </svg>
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '1.2rem', fontWeight: '800', letterSpacing: '-0.02em', background: 'linear-gradient(135deg, #ffffff 0%, #cbd5e1 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                STORE<span style={{ color: 'var(--accent-cyan)', WebkitTextFillColor: 'var(--accent-cyan)' }}>-SHARE</span>
              </span>
              <span className="badge badge-cyan" style={{ fontSize: '0.65rem', padding: '1px 5px' }}>v0.9.0</span>
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              Expo Distributed Storage Network
            </div>
          </div>
        </div>

        {/* Tab Navigation (Role-Filtered) */}
        <nav style={{ display: 'flex', alignItems: 'center', gap: '4px', overflowX: 'auto', padding: '4px 0' }}>
          {visibleTabs.map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                id={`tab-${tab.id}`}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '7px 12px',
                  borderRadius: '10px',
                  border: isActive ? '1px solid var(--border-glow)' : '1px solid transparent',
                  background: isActive ? 'rgba(6, 182, 212, 0.12)' : 'transparent',
                  color: isActive ? '#38bdf8' : 'var(--text-secondary)',
                  fontWeight: isActive ? 600 : 500,
                  fontSize: '0.84rem',
                  cursor: 'pointer',
                  transition: 'all var(--transition-fast)',
                  whiteSpace: 'nowrap'
                }}
              >
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d={tab.icon} />
                </svg>
                <span>{tab.label}</span>
                {tab.count !== undefined && (
                  <span style={{
                    padding: '1px 5px',
                    fontSize: '0.68rem',
                    borderRadius: '8px',
                    background: isActive ? 'rgba(6, 182, 212, 0.3)' : 'rgba(255, 255, 255, 0.08)',
                    color: isActive ? '#e0f2fe' : 'var(--text-muted)'
                  }}>
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Right Status, Auth Profile & Config Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexShrink: 0 }}>
          {/* User Account & Role Badge */}
          {user ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '4px 10px',
                  borderRadius: '10px',
                  background: 'rgba(13, 18, 29, 0.8)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', lineHeight: '1.2' }}>
                  <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {user.username}
                  </span>
                  <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                    {user.provider_id || (user.email ? user.email.split('@')[0] : '')}
                  </span>
                </div>
                <span
                  style={{
                    fontSize: '0.68rem',
                    fontWeight: 700,
                    letterSpacing: '0.04em',
                    padding: '2px 7px',
                    borderRadius: '6px',
                    textTransform: 'uppercase',
                    ...roleBadgeStyle,
                  }}
                >
                  {user.role}
                </span>
              </div>

              {/* Quick Role Switcher (For local testing) */}
              <div style={{ display: 'flex', gap: '4px' }} title="Quick switch simulated/tested role">
                <button
                  type="button"
                  onClick={() => switchDemoRole('admin')}
                  style={{
                    padding: '3px 6px',
                    fontSize: '0.68rem',
                    borderRadius: '6px',
                    background: currentRole === 'admin' ? 'rgba(239, 68, 68, 0.3)' : 'rgba(255, 255, 255, 0.05)',
                    color: currentRole === 'admin' ? '#f87171' : 'var(--text-muted)',
                    border: '1px solid rgba(255, 255, 255, 0.1)',
                    cursor: 'pointer',
                  }}
                >
                  ADM
                </button>
                <button
                  type="button"
                  onClick={() => switchDemoRole('provider')}
                  style={{
                    padding: '3px 6px',
                    fontSize: '0.68rem',
                    borderRadius: '6px',
                    background: currentRole === 'provider' ? 'rgba(6, 182, 212, 0.3)' : 'rgba(255, 255, 255, 0.05)',
                    color: currentRole === 'provider' ? '#38bdf8' : 'var(--text-muted)',
                    border: '1px solid rgba(255, 255, 255, 0.1)',
                    cursor: 'pointer',
                  }}
                >
                  PRV
                </button>
                <button
                  type="button"
                  onClick={() => switchDemoRole('consumer')}
                  style={{
                    padding: '3px 6px',
                    fontSize: '0.68rem',
                    borderRadius: '6px',
                    background: currentRole === 'consumer' ? 'rgba(16, 185, 129, 0.3)' : 'rgba(255, 255, 255, 0.05)',
                    color: currentRole === 'consumer' ? '#34d399' : 'var(--text-muted)',
                    border: '1px solid rgba(255, 255, 255, 0.1)',
                    cursor: 'pointer',
                  }}
                >
                  CNS
                </button>
              </div>

              {/* Logout Button */}
              <button
                id="btn-logout"
                onClick={logout}
                className="btn btn-secondary"
                style={{ padding: '6px 10px', fontSize: '0.78rem' }}
                title="Sign out of current account"
              >
                Logout
              </button>
            </div>
          ) : (
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                id="btn-login"
                onClick={() => {
                  setAuthModalTab('login');
                  setAuthModalOpen(true);
                }}
                className="btn btn-primary"
                style={{ padding: '6px 14px', fontSize: '0.8rem' }}
              >
                Sign In
              </button>
            </div>
          )}

          {/* Status Indicator */}
          <div
            onClick={onOpenConfig}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '5px 10px',
              borderRadius: '20px',
              background: 'rgba(13, 18, 29, 0.8)',
              border: '1px solid var(--border-subtle)',
              cursor: 'pointer',
              fontSize: '0.75rem',
            }}
            title="Click to view Coordinator Connection Settings"
          >
            <span
              className="status-dot status-dot-pulse"
              style={{
                background: isOnline ? 'var(--accent-emerald)' : 'var(--accent-amber)',
              }}
            />
            <span style={{ color: 'var(--text-secondary)' }}>
              {isSimulation ? 'Sim Mode' : (isOnline ? 'Online' : 'Reconnecting')}
            </span>
          </div>

          {/* Settings Button */}
          <button
            id="btn-settings"
            onClick={onOpenConfig}
            className="btn btn-secondary btn-icon"
            title="Coordinator & Cluster Settings"
            style={{ width: '36px', height: '36px', borderRadius: '10px' }}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="3"></circle>
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
            </svg>
          </button>
        </div>
      </div>
    </header>
  );
}
