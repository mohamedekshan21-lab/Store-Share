import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';

export default function AuthModal({ isOpen, onClose }) {
  const {
    login,
    register,
    authModalTab,
    setAuthModalTab,
    authError,
    setAuthError,
    isLoading,
    switchDemoRole,
  } = useAuth();

  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [localSuccess, setLocalSuccess] = useState(null);

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setAuthError(null);
    setLocalSuccess(null);

    if (authModalTab === 'register') {
      if (password !== confirmPassword) {
        setAuthError('Passwords do not match');
        return;
      }
      if (password.length < 8) {
        setAuthError('Password must be at least 8 characters');
        return;
      }
      try {
        await register(username, email, password);
        setLocalSuccess('Account created successfully! You can now log in.');
        setUsername('');
        setEmail('');
        setPassword('');
        setConfirmPassword('');
      } catch (err) {
        // Handled in context
      }
    } else {
      try {
        await login(username || email, password);
        onClose();
      } catch (err) {
        // Handled in context
      }
    }
  };

  const handleQuickDemo = (role) => {
    switchDemoRole(role);
    onClose();
  };

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: 'rgba(5, 7, 12, 0.85)',
        backdropFilter: 'blur(10px)',
        zIndex: 200,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '20px',
      }}
      onClick={onClose}
    >
      <div
        className="glass-card"
        style={{
          width: '100%',
          maxWidth: '480px',
          background: 'rgba(13, 18, 29, 0.95)',
          border: '1px solid var(--border-glow)',
          borderRadius: '16px',
          boxShadow: 'var(--shadow-cyan-glow)',
          overflow: 'hidden',
          animation: 'fadeIn 0.2s ease-out',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header Tabs */}
        <div
          style={{
            display: 'flex',
            borderBottom: '1px solid var(--border-subtle)',
            background: 'rgba(7, 9, 14, 0.6)',
          }}
        >
          <button
            type="button"
            onClick={() => {
              setAuthModalTab('login');
              setAuthError(null);
              setLocalSuccess(null);
            }}
            style={{
              flex: 1,
              padding: '16px',
              border: 'none',
              background: authModalTab === 'login' ? 'rgba(6, 182, 212, 0.1)' : 'transparent',
              borderBottom: authModalTab === 'login' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
              color: authModalTab === 'login' ? '#ffffff' : 'var(--text-secondary)',
              fontWeight: 600,
              fontSize: '0.95rem',
              cursor: 'pointer',
              transition: 'all 0.2s',
            }}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => {
              setAuthModalTab('register');
              setAuthError(null);
              setLocalSuccess(null);
            }}
            style={{
              flex: 1,
              padding: '16px',
              border: 'none',
              background: authModalTab === 'register' ? 'rgba(6, 182, 212, 0.1)' : 'transparent',
              borderBottom: authModalTab === 'register' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
              color: authModalTab === 'register' ? '#ffffff' : 'var(--text-secondary)',
              fontWeight: 600,
              fontSize: '0.95rem',
              cursor: 'pointer',
              transition: 'all 0.2s',
            }}
          >
            Register Consumer
          </button>
        </div>

        {/* Body Form */}
        <form onSubmit={handleSubmit} style={{ padding: '24px' }}>
          {authError && (
            <div
              style={{
                padding: '10px 14px',
                borderRadius: '8px',
                background: 'rgba(239, 68, 68, 0.15)',
                border: '1px solid rgba(239, 68, 68, 0.4)',
                color: '#f87171',
                fontSize: '0.85rem',
                marginBottom: '16px',
              }}
            >
              {authError}
            </div>
          )}

          {localSuccess && (
            <div
              style={{
                padding: '10px 14px',
                borderRadius: '8px',
                background: 'rgba(16, 185, 129, 0.15)',
                border: '1px solid rgba(16, 185, 129, 0.4)',
                color: '#34d399',
                fontSize: '0.85rem',
                marginBottom: '16px',
              }}
            >
              {localSuccess}
            </div>
          )}

          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
              {authModalTab === 'register' ? 'Username' : 'Username or Email'}
            </label>
            <input
              type="text"
              required
              className="input-field"
              placeholder={authModalTab === 'register' ? 'e.g. alice' : 'e.g. admin or admin@storeshare.net'}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              style={{ width: '100%' }}
            />
          </div>

          {authModalTab === 'register' && (
            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                Email Address
              </label>
              <input
                type="email"
                required
                className="input-field"
                placeholder="alice@crypto.org"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                style={{ width: '100%' }}
              />
            </div>
          )}

          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
              Password
            </label>
            <input
              type="password"
              required
              className="input-field"
              placeholder="••••••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={{ width: '100%' }}
            />
          </div>

          {authModalTab === 'register' && (
            <div style={{ marginBottom: '20px' }}>
              <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                Confirm Password
              </label>
              <input
                type="password"
                required
                className="input-field"
                placeholder="••••••••••••"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                style={{ width: '100%' }}
              />
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '6px' }}>
                Public registration grants the Consumer role. Argon2id hashed.
              </div>
            </div>
          )}

          <button
            type="submit"
            disabled={isLoading}
            className="btn btn-primary"
            style={{ width: '100%', padding: '12px', fontSize: '0.92rem', marginBottom: '20px' }}
          >
            {isLoading ? 'Authenticating...' : authModalTab === 'login' ? 'Sign In to Store-Share' : 'Create Account'}
          </button>

          {/* Quick Demo Personas Switcher */}
          <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '16px' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textAlign: 'center', marginBottom: '10px' }}>
              Testing / Quick Role Switcher
            </div>
            <div style={{ display: 'flex', gap: '8px', justifyContent: 'center' }}>
              <button
                type="button"
                onClick={() => handleQuickDemo('admin')}
                className="btn btn-secondary"
                style={{ fontSize: '0.75rem', padding: '6px 12px', color: '#f87171' }}
              >
                ADMIN
              </button>
              <button
                type="button"
                onClick={() => handleQuickDemo('provider')}
                className="btn btn-secondary"
                style={{ fontSize: '0.75rem', padding: '6px 12px', color: '#38bdf8' }}
              >
                PROVIDER
              </button>
              <button
                type="button"
                onClick={() => handleQuickDemo('consumer')}
                className="btn btn-secondary"
                style={{ fontSize: '0.75rem', padding: '6px 12px', color: '#34d399' }}
              >
                CONSUMER
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
}
