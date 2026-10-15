import React, { useState } from 'react';

export default function RegisterNodeModal({ isOpen, onClose, onRegisterComplete }) {
  const [nodeId, setNodeId] = useState(`NODE-${Math.random().toString(36).substring(2, 10)}`);
  const [endpoint, setEndpoint] = useState('http://127.0.0.1:9006');
  const [advertisedEndpoint, setAdvertisedEndpoint] = useState('http://192.168.1.106:9006');
  const [connectivityMode, setConnectivityMode] = useState('DIRECT');
  const [capacityGB, setCapacityGB] = useState(50);
  const [providerId, setProviderId] = useState('provider-edge-omega');
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);

    const payload = {
      node_id: nodeId,
      endpoint: endpoint,
      advertised_endpoint: advertisedEndpoint || endpoint,
      connectivity_mode: connectivityMode,
      total_capacity_bytes: capacityGB * 1024 * 1024 * 1024,
      provider_id: providerId,
    };

    await onRegisterComplete(payload);
    setIsSubmitting(false);
    onClose();
  };

  return (
    <div className="modal-overlay" onClick={() => !isSubmitting && onClose()}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '580px' }}>
        <div style={{ padding: '24px 28px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Register Storage Daemon</h3>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
              Enroll an independent storage node into the Coordinator registry
            </p>
          </div>
          {!isSubmitting && (
            <button className="btn btn-secondary btn-icon" onClick={onClose}>✕</button>
          )}
        </div>

        <form onSubmit={handleSubmit} style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.84rem', fontWeight: 600, marginBottom: '6px' }}>
              Node Identifier
            </label>
            <input
              id="input-reg-nodeid"
              type="text"
              className="input font-mono"
              value={nodeId}
              onChange={(e) => setNodeId(e.target.value)}
              required
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.84rem', fontWeight: 600, marginBottom: '6px' }}>
                Local Endpoint
              </label>
              <input
                id="input-reg-endpoint"
                type="text"
                className="input font-mono"
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
                required
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.84rem', fontWeight: 600, marginBottom: '6px' }}>
                Advertised Endpoint
              </label>
              <input
                id="input-reg-advertised"
                type="text"
                className="input font-mono"
                value={advertisedEndpoint}
                onChange={(e) => setAdvertisedEndpoint(e.target.value)}
                placeholder="NAT / WAN reachable address"
              />
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.84rem', fontWeight: 600, marginBottom: '6px' }}>
                Connectivity Mode
              </label>
              <select
                id="select-reg-connectivity"
                className="select"
                value={connectivityMode}
                onChange={(e) => setConnectivityMode(e.target.value)}
              >
                <option value="LAN">LAN (Local Subnet)</option>
                <option value="DIRECT">DIRECT (Public IP / Port-Forwarded)</option>
                <option value="RELAY">RELAY (Reverse WebSocket Tunnel)</option>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.84rem', fontWeight: 600, marginBottom: '6px' }}>
                Allocated Disk Quota (GB)
              </label>
              <input
                id="input-reg-capacity"
                type="number"
                min="5"
                max="5000"
                className="input font-mono"
                value={capacityGB}
                onChange={(e) => setCapacityGB(Number(e.target.value))}
                required
              />
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.84rem', fontWeight: 600, marginBottom: '6px' }}>
              Storage Provider Principal
            </label>
            <input
              id="input-reg-provider"
              type="text"
              className="input"
              value={providerId}
              onChange={(e) => setProviderId(e.target.value)}
              required
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '10px' }}>
            <button type="button" className="btn btn-secondary" onClick={onClose} disabled={isSubmitting}>
              Cancel
            </button>
            <button id="btn-submit-reg-node" type="submit" className="btn btn-primary" disabled={isSubmitting}>
              {isSubmitting ? 'Registering...' : 'Complete Node Registration'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
