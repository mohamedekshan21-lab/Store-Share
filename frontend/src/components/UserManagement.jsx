import React, { useState, useEffect } from 'react';
import { getAdminUsers, updateUserRole, updateUserStatus } from '../services/api';
import { useAuth } from '../context/AuthContext';

export default function UserManagement() {
  const { role, user: currentUser } = useAuth();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  // Editing state
  const [selectedUser, setSelectedUser] = useState(null);
  const [targetRole, setTargetRole] = useState('consumer');
  const [targetProviderId, setTargetProviderId] = useState('');

  const fetchUsers = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getAdminUsers();
      if (res && res.users) {
        setUsers(res.users);
      }
    } catch (err) {
      setError(err.message || 'Failed to fetch user accounts');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (role === 'admin') {
      fetchUsers();
    }
  }, [role]);

  const handleToggleStatus = async (user) => {
    try {
      const newStatus = !user.is_active;
      await updateUserStatus(user.user_id, newStatus);
      setSuccessMsg(`User '${user.username}' status set to ${newStatus ? 'ACTIVE' : 'DEACTIVATED'}.`);
      setUsers(prev => prev.map(u => u.user_id === user.user_id ? { ...u, is_active: newStatus } : u));
      setTimeout(() => setSuccessMsg(null), 4000);
    } catch (err) {
      setError(err.message);
    }
  };

  const handleUpdateRole = async (e) => {
    e.preventDefault();
    if (!selectedUser) return;
    try {
      await updateUserRole(selectedUser.user_id, targetRole, targetProviderId || null);
      setSuccessMsg(`Role for '${selectedUser.username}' updated to ${targetRole.toUpperCase()}.`);
      setUsers(prev => prev.map(u => u.user_id === selectedUser.user_id ? { ...u, role: targetRole, provider_id: targetProviderId || null } : u));
      setSelectedUser(null);
      setTimeout(() => setSuccessMsg(null), 4000);
    } catch (err) {
      setError(err.message);
    }
  };

  if (role !== 'admin') {
    return (
      <div className="glass-card" style={{ padding: '32px', textAlign: 'center', color: '#f87171' }}>
        <h3 style={{ fontSize: '1.25rem', marginBottom: '8px' }}>Access Denied (403 Forbidden)</h3>
        <p style={{ color: 'var(--text-muted)' }}>
          User management and provider enrollment operations require the <strong>ADMIN</strong> role.
        </p>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Title Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '4px' }}>
            User Accounts & Provider Enrollment
          </h2>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Administrative RBAC management, account lifecycle, provider resource authorization, and role revocation.
          </p>
        </div>
        <button
          onClick={fetchUsers}
          className="btn btn-secondary"
          disabled={loading}
          style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="23 4 23 10 17 10"></polyline>
            <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
          </svg>
          {loading ? 'Refreshing...' : 'Refresh Users'}
        </button>
      </div>

      {error && (
        <div style={{ padding: '12px 16px', borderRadius: '8px', background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.4)', color: '#f87171', fontSize: '0.88rem' }}>
          {error}
        </div>
      )}

      {successMsg && (
        <div style={{ padding: '12px 16px', borderRadius: '8px', background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.4)', color: '#34d399', fontSize: '0.88rem' }}>
          {successMsg}
        </div>
      )}

      {/* Role Change Modal */}
      {selectedUser && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(5, 7, 12, 0.85)',
            backdropFilter: 'blur(10px)',
            zIndex: 250,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '20px',
          }}
          onClick={() => setSelectedUser(null)}
        >
          <div
            className="glass-card"
            style={{
              width: '100%',
              maxWidth: '440px',
              padding: '24px',
              background: 'rgba(13, 18, 29, 0.95)',
              border: '1px solid var(--border-glow)',
              borderRadius: '16px',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <h3 style={{ fontSize: '1.2rem', fontWeight: 600, marginBottom: '8px', color: 'var(--text-primary)' }}>
              Change Role: {selectedUser.username}
            </h3>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '16px' }}>
              Updating role will automatically increment role_version and revoke previously issued JWT sessions.
            </p>

            <form onSubmit={handleUpdateRole}>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  Assign Role
                </label>
                <select
                  className="input-field"
                  value={targetRole}
                  onChange={(e) => setTargetRole(e.target.value)}
                  style={{ width: '100%', background: 'rgba(7, 9, 14, 0.8)' }}
                >
                  <option value="consumer">Consumer (Standard file storage user)</option>
                  <option value="provider">Provider (Storage node host)</option>
                  <option value="admin">Admin (Cluster infrastructure manager)</option>
                </select>
              </div>

              {targetRole === 'provider' && (
                <div style={{ marginBottom: '20px' }}>
                  <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                    Authorized Provider ID
                  </label>
                  <input
                    type="text"
                    required
                    className="input-field"
                    placeholder="e.g. provider-primary-alpha"
                    value={targetProviderId}
                    onChange={(e) => setTargetProviderId(e.target.value)}
                    style={{ width: '100%' }}
                  />
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                    Bound nodes registered with this provider ID will be manageable by this user.
                  </div>
                </div>
              )}

              <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end', marginTop: '20px' }}>
                <button type="button" onClick={() => setSelectedUser(null)} className="btn btn-secondary">
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Confirm & Update
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Users Table */}
      <div className="glass-card" style={{ overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.86rem' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-subtle)', background: 'rgba(255, 255, 255, 0.02)' }}>
              <th style={{ padding: '14px 18px', color: 'var(--text-muted)' }}>User</th>
              <th style={{ padding: '14px 18px', color: 'var(--text-muted)' }}>Role</th>
              <th style={{ padding: '14px 18px', color: 'var(--text-muted)' }}>Provider Scope</th>
              <th style={{ padding: '14px 18px', color: 'var(--text-muted)' }}>Status</th>
              <th style={{ padding: '14px 18px', color: 'var(--text-muted)', textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => {
              const isCurrent = currentUser && currentUser.user_id === u.user_id;
              const roleBadgeClass =
                u.role === 'admin'
                  ? 'badge badge-rose'
                  : u.role === 'provider'
                  ? 'badge badge-cyan'
                  : 'badge badge-emerald';

              return (
                <tr
                  key={u.user_id}
                  style={{
                    borderBottom: '1px solid var(--border-subtle)',
                    transition: 'background 0.2s',
                  }}
                >
                  <td style={{ padding: '14px 18px' }}>
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                      {u.username}
                      {isCurrent && (
                        <span style={{ fontSize: '0.68rem', padding: '1px 6px', borderRadius: '4px', background: 'rgba(6, 182, 212, 0.2)', color: '#38bdf8' }}>
                          You
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>{u.email}</div>
                  </td>
                  <td style={{ padding: '14px 18px' }}>
                    <span className={roleBadgeClass} style={{ textTransform: 'uppercase', fontSize: '0.72rem' }}>
                      {u.role}
                    </span>
                  </td>
                  <td style={{ padding: '14px 18px', color: u.provider_id ? '#38bdf8' : 'var(--text-muted)', fontFamily: 'monospace', fontSize: '0.8rem' }}>
                    {u.provider_id || '—'}
                  </td>
                  <td style={{ padding: '14px 18px' }}>
                    <span
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px',
                        fontSize: '0.8rem',
                        color: u.is_active ? '#34d399' : '#f87171',
                      }}
                    >
                      <span
                        style={{
                          width: '8px',
                          height: '8px',
                          borderRadius: '50%',
                          background: u.is_active ? 'var(--accent-emerald)' : 'var(--accent-rose)',
                        }}
                      />
                      {u.is_active ? 'Active' : 'Deactivated'}
                    </span>
                  </td>
                  <td style={{ padding: '14px 18px', textAlign: 'right' }}>
                    <div style={{ display: 'inline-flex', gap: '8px' }}>
                      <button
                        onClick={() => {
                          setSelectedUser(u);
                          setTargetRole(u.role);
                          setTargetProviderId(u.provider_id || '');
                        }}
                        className="btn btn-secondary"
                        style={{ fontSize: '0.75rem', padding: '4px 10px' }}
                      >
                        Edit Role
                      </button>
                      {!isCurrent && (
                        <button
                          onClick={() => handleToggleStatus(u)}
                          className="btn btn-secondary"
                          style={{
                            fontSize: '0.75rem',
                            padding: '4px 10px',
                            color: u.is_active ? '#f87171' : '#34d399',
                            borderColor: u.is_active ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)',
                          }}
                        >
                          {u.is_active ? 'Deactivate' : 'Activate'}
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
