import React, { useState } from 'react';

export default function UploadModal({ isOpen, onClose, onUploadComplete, availableNodes = [] }) {
  const [fileName, setFileName] = useState('quantum_telemetry_2026.bin');
  const [fileSizeMB, setFileSizeMB] = useState(12);
  const [replicationFactor, setReplicationFactor] = useState(2);
  const [useErasureCoding, setUseErasureCoding] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);

  if (!isOpen) return null;

  const steps = [
    { label: 'File Hash & Payload', desc: 'Reading file buffer and computing authoritative SHA-256 checksum' },
    { label: 'AES-256 Key & Nonce', desc: 'Generating 256-bit DEK & 96-bit initialization vector in zero-knowledge space' },
    { label: 'AES-256-GCM Encryption', desc: 'Client authenticated cipher generation (keys never leave consumer machine)' },
    { label: 'Deterministic Chunking', desc: 'Slicing into 4 MB discrete chunks with individual SHA-256 hashes' },
    { label: 'Smart Node Placement', desc: 'Selecting distinct physical nodes with highest available capacity and health' },
    { label: 'Parallel Chunk Dispatch', desc: 'Transferring encrypted binary chunks to target storage nodes' },
    { label: 'Atomic Catalog Commit', desc: 'Registering Schema v2 manifest in Coordinator database' },
  ];

  const handleStartUpload = () => {
    setIsProcessing(true);
    setCurrentStep(0);

    const stepInterval = 450;
    let step = 0;

    const timer = setInterval(() => {
      step += 1;
      if (step < steps.length) {
        setCurrentStep(step);
      } else {
        clearInterval(timer);
        setTimeout(async () => {
          const newFile = await onUploadComplete({
            name: fileName,
            size: fileSizeMB * 1024 * 1024,
            replicationFactor,
            useErasureCoding,
            chunkSize: 4194304
          });
          setIsProcessing(false);
          onClose();
        }, 300);
      }
    }, stepInterval);
  };

  return (
    <div className="modal-overlay" onClick={() => !isProcessing && onClose()}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '640px' }}>
        {/* Header */}
        <div style={{ padding: '24px 28px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Upload & Encrypt File</h3>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
              Client-side AES-256-GCM zero-knowledge distributed storage pipeline
            </p>
          </div>
          {!isProcessing && (
            <button className="btn btn-secondary btn-icon" onClick={onClose}>✕</button>
          )}
        </div>

        {/* Content Body */}
        <div style={{ padding: '24px 28px' }}>
          {!isProcessing ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {/* File details input */}
              <div>
                <label style={{ display: 'block', fontSize: '0.86rem', fontWeight: 600, marginBottom: '6px' }}>
                  Target File Name
                </label>
                <input
                  id="input-upload-filename"
                  type="text"
                  className="input"
                  value={fileName}
                  onChange={(e) => setFileName(e.target.value)}
                  placeholder="e.g. dataset.tar.gz"
                />
              </div>

              {/* Size preset / selector */}
              <div>
                <label style={{ display: 'block', fontSize: '0.86rem', fontWeight: 600, marginBottom: '6px' }}>
                  Simulated File Size ({fileSizeMB} MB)
                </label>
                <input
                  type="range"
                  min="2"
                  max="48"
                  step="2"
                  value={fileSizeMB}
                  onChange={(e) => setFileSizeMB(Number(e.target.value))}
                  style={{ width: '100%', accentColor: 'var(--accent-cyan)' }}
                />
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  <span>2 MB (1 Chunk)</span>
                  <span>12 MB (3 Chunks)</span>
                  <span>24 MB (6 Chunks)</span>
                  <span>48 MB (12 Chunks)</span>
                </div>
              </div>

              {/* Redundancy & Placement Settings */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.86rem', fontWeight: 600, marginBottom: '6px' }}>
                    Replication Factor
                  </label>
                  <select
                    className="select"
                    value={replicationFactor}
                    onChange={(e) => setReplicationFactor(Number(e.target.value))}
                  >
                    <option value="1">1x (Single Copy - No Failover)</option>
                    <option value="2">2x (Primary + 1 Distinct Replica)</option>
                    <option value="3">3x (High Availability 3 Distinct Nodes)</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '0.86rem', fontWeight: 600, marginBottom: '6px' }}>
                    Erasure Coding
                  </label>
                  <select
                    className="select"
                    value={useErasureCoding ? 'zfec' : 'none'}
                    onChange={(e) => setUseErasureCoding(e.target.value === 'zfec')}
                  >
                    <option value="none">Standard Replicated Chunks</option>
                    <option value="zfec">Reed-Solomon (4+2 Shards)</option>
                  </select>
                </div>
              </div>

              {/* Security Directive Info */}
              <div style={{ padding: '12px 16px', background: 'rgba(13, 18, 29, 0.7)', border: '1px solid var(--border-subtle)', borderRadius: '10px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                🔒 <strong>Zero-Knowledge Guarantee:</strong> An ephemeral AES-256 Data Encryption Key (DEK) will be generated locally. Only authenticated ciphertext will be transmitted to remote storage nodes.
              </div>

              {/* Action Buttons */}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '10px' }}>
                <button className="btn btn-secondary" onClick={onClose}>
                  Cancel
                </button>
                <button
                  id="btn-confirm-upload"
                  className="btn btn-primary"
                  onClick={handleStartUpload}
                >
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
                  </svg>
                  Execute Cryptographic Upload
                </button>
              </div>
            </div>
          ) : (
            /* Animated Step-by-Step Progress */
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div style={{ textAlign: 'center', marginBottom: '8px' }}>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Processing Pipeline in Progress...
                </div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                  {steps[currentStep].desc}
                </div>
              </div>

              {/* Progress Bar */}
              <div style={{
                height: '8px',
                background: 'rgba(255, 255, 255, 0.08)',
                borderRadius: 'var(--radius-full)',
                overflow: 'hidden',
                position: 'relative'
              }}>
                <div style={{
                  width: `${((currentStep + 1) / steps.length) * 100}%`,
                  height: '100%',
                  background: 'linear-gradient(90deg, var(--accent-cyan), var(--accent-violet))',
                  borderRadius: 'var(--radius-full)',
                  transition: 'width 0.3s ease'
                }} />
              </div>

              {/* Steps List */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {steps.map((st, idx) => {
                  const isDone = idx < currentStep;
                  const isCurrent = idx === currentStep;
                  return (
                    <div
                      key={idx}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '12px',
                        padding: '8px 12px',
                        borderRadius: '8px',
                        background: isCurrent ? 'rgba(6, 182, 212, 0.12)' : (isDone ? 'rgba(16, 185, 129, 0.08)' : 'rgba(255, 255, 255, 0.02)'),
                        border: isCurrent ? '1px solid var(--border-glow)' : '1px solid transparent',
                        transition: 'all 0.2s ease'
                      }}
                    >
                      <div style={{
                        width: '22px',
                        height: '22px',
                        borderRadius: '50%',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontSize: '0.72rem',
                        fontWeight: 700,
                        background: isDone ? 'var(--accent-emerald)' : (isCurrent ? 'var(--accent-cyan)' : 'rgba(255, 255, 255, 0.1)'),
                        color: isDone || isCurrent ? '#07090e' : 'var(--text-muted)'
                      }}>
                        {isDone ? '✓' : idx + 1}
                      </div>
                      <div style={{ flex: 1, fontSize: '0.84rem', fontWeight: isCurrent ? 600 : 400, color: isCurrent ? '#ffffff' : (isDone ? '#94a3b8' : '#64748b') }}>
                        {st.label}
                      </div>
                      {isCurrent && (
                        <span className="badge badge-cyan" style={{ fontSize: '0.68rem', animation: 'pulse 1s infinite' }}>
                          Active
                        </span>
                      )}
                      {isDone && (
                        <span style={{ fontSize: '0.72rem', color: 'var(--accent-emerald)' }}>
                          Done
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
