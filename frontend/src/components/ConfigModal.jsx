import React, { useState } from 'react';
import {
  getCoordinatorUrl,
  setCoordinatorUrl,
  getCoordinatorToken,
  setCoordinatorToken,
  isSimulationMode,
  setSimulationMode,
  checkCoordinatorHealth
} from '../services/api';

export default function ConfigModal({ isOpen, onClose, onConfigSaved }) {
  const [url, setUrl] = useState(getCoordinatorUrl());
  const [token, setToken] = useState(getCoordinatorToken());
  const [simMode, setSimMode] = useState(isSimulationMode());
  const [testResult, setTestResult] = useState(null);
  const [testing, setTesting] = useState(false);

  if (!isOpen) return null;

  const handleTestConnection = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await checkCoordinatorHealth();
      setTestResult({
        success: true,
        message: `Connected successfully! Status: ${res.status} (${res.service || 'Expo Coordinator'})`
      });
    } catch (err) {
      setTestResult({
        success: false,
        message: `Failed to reach Coordinator at ${url}: ${err.message}`
      });
    } finally {
      setTesting(false);
    }
  };

  const handleSave = () => {
    setCoordinatorUrl(url);
    setCoordinatorToken(token);
    setSimulationMode(simMode);
    onConfigSaved({ url, token, simMode });
    onClose();
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '540px' }}>
        <div style={{ padding: '24px 28px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Coordinator Connection Settings</h3>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
              Configure backend control plane endpoint and operating modes
            </p>
          </div>
          <button className="btn btn-secondary btn-icon" onClick={onClose}>✕</button>
        </div>

        <div style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Simulation Toggle */}
          <div style={{
            padding: '16px',
            background: simMode ? 'rgba(6, 182, 212, 0.1)' : 'rgba(13, 18, 29, 0.6)',
            border: simMode ? '1px solid var(--border-glow)' : '1px solid var(--border-subtle)',
            borderRadius: '12px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '16px'
          }}>
            <div>
              <div style={{ fontWeight: 600, fontSize: '0.92rem', marginBottom: '2px', color: simMode ? 'var(--accent-cyan)' : 'var(--text-primary)' }}>
                Interactive Simulation Mode
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                {simMode
                  ? 'Active: Full offline interactive demo cluster with realistic nodes, files, failover & ECC ledger.'
                  : 'Disabled: App will directly query live FastAPI Coordinator over network.'}
              </div>
            </div>
            <input
              id="checkbox-sim-mode"
              type="checkbox"
              checked={simMode}
              onChange={(e) => setSimMode(e.target.checked)}
              style={{ width: '20px', height: '20px', accentColor: 'var(--accent-cyan)', cursor: 'pointer' }}
            />
          </div>

          {/* Coordinator URL Input */}
          <div>
            <label style={{ display: 'block', fontSize: '0.84rem', fontWeight: 600, marginBottom: '6px' }}>
              Coordinator API Base URL
            </label>
            <input
              id="input-config-url"
              type="text"
              className="input font-mono"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="http://127.0.0.1:9000"
            />
            <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '4px' }}>
              Default FastAPI Coordinator server runs at port 9000.
            </div>
          </div>

          {/* Auth Token Input */}
          <div>
            <label style={{ display: 'block', fontSize: '0.84rem', fontWeight: 600, marginBottom: '6px' }}>
              Coordinator / Provider Auth Token (Optional)
            </label>
            <input
              id="input-config-token"
              type="password"
              className="input font-mono"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="secret_provider_token"
            />
            <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '4px' }}>
              Passed via <code className="font-mono">X-Auth-Token</code> header for protected coordinator endpoints.
            </div>
          </div>

          {/* Test Connection Button & Status */}
          <div>
            <button
              id="btn-test-connection"
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={handleTestConnection}
              disabled={testing}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M22 12h-4l-3 9L9 3l-3 9H2"></path>
              </svg>
              {testing ? 'Probing...' : 'Test Health Endpoint'}
            </button>

            {testResult && (
              <div style={{
                marginTop: '10px',
                padding: '10px 14px',
                borderRadius: '8px',
                fontSize: '0.8rem',
                background: testResult.success ? 'rgba(16, 185, 129, 0.1)' : 'rgba(244, 63, 94, 0.1)',
                border: testResult.success ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid rgba(244, 63, 94, 0.3)',
                color: testResult.success ? '#6ee7b7' : '#fda4af'
              }}>
                {testResult.message}
              </div>
            )}
          </div>

          {/* Footer Actions */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '10px' }}>
            <button className="btn btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button id="btn-save-config" className="btn btn-primary" onClick={handleSave}>
              Save & Apply Settings
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
