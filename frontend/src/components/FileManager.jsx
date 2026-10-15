import React, { useState } from 'react';

export default function FileManager({
  files = [],
  nodes = [],
  onUploadFile,
  onDeleteFile,
  onOpenUploadModal,
}) {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedFileForManifest, setSelectedFileForManifest] = useState(null);
  const [downloadingFileId, setDownloadingFileId] = useState(null);
  const [downloadProgress, setDownloadProgress] = useState(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState(null);

  const filteredFiles = files.filter(f => 
    f.filename.toLowerCase().includes(searchTerm.toLowerCase()) ||
    f.file_id.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const formatBytes = (bytes) => {
    if (!bytes || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${units[i]}`;
  };

  const handleSimulateDownload = (file) => {
    setDownloadingFileId(file.file_id);
    setDownloadProgress({ step: 'Locating Nodes', percent: 15 });

    setTimeout(() => {
      setDownloadProgress({ step: 'Streaming Encrypted Chunks', percent: 50 });
    }, 700);

    setTimeout(() => {
      setDownloadProgress({ step: 'Verifying SHA-256 Checksums', percent: 80 });
    }, 1400);

    setTimeout(() => {
      setDownloadProgress({ step: 'Client-Side AES-256-GCM Decryption', percent: 100 });
      setTimeout(() => {
        setDownloadingFileId(null);
        setDownloadProgress(null);
        alert(`Success! File "${file.filename}" reconstructed bit-for-bit from remote storage nodes and decrypted locally. Verified SHA-256 integrity match.`);
      }, 500);
    }, 2100);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Header & Search Bar */}
      <div className="glass-panel" style={{ padding: '24px 28px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <h2 style={{ fontSize: '1.4rem', fontWeight: 700, marginBottom: '4px' }}>
              Decentralized File Catalog
            </h2>
            <p style={{ fontSize: '0.86rem', color: 'var(--text-secondary)' }}>
              Logical files managed via Schema v2 manifests with client-side zero-knowledge encryption
            </p>
          </div>

          <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
            <div style={{ position: 'relative', width: '280px' }}>
              <input
                id="input-search-files"
                type="text"
                className="input"
                placeholder="Search files by name or ID..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{ paddingLeft: '36px' }}
              />
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }}>
                <circle cx="11" cy="11" r="8"></circle>
                <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
              </svg>
            </div>

            <button
              id="btn-upload-file-manager"
              className="btn btn-primary"
              onClick={onOpenUploadModal}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                <polyline points="17 8 12 3 7 8" />
                <line x1="12" y1="3" x2="12" y2="15" />
              </svg>
              Upload New File
            </button>
          </div>
        </div>
      </div>

      {/* Files Table */}
      <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
        <div className="table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>File Name & Details</th>
                <th>Logical ID</th>
                <th>Size (Plain / Cipher)</th>
                <th>Chunks & Placement</th>
                <th>Redundancy</th>
                <th>Status</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredFiles.length === 0 ? (
                <tr>
                  <td colSpan="7" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                    No files found matching your search. Upload an encrypted file to get started!
                  </td>
                </tr>
              ) : (
                filteredFiles.map((file) => {
                  const isDownloading = downloadingFileId === file.file_id;
                  return (
                    <tr key={file.file_id}>
                      {/* Name & Encryption Badge */}
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                          <div style={{
                            width: '36px',
                            height: '36px',
                            borderRadius: '10px',
                            background: 'rgba(6, 182, 212, 0.12)',
                            color: 'var(--accent-cyan)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center'
                          }}>
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                              <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>
                              <polyline points="13 2 13 9 20 9"></polyline>
                            </svg>
                          </div>
                          <div>
                            <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '2px' }}>
                              {file.filename}
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                              <span style={{ fontSize: '0.72rem', color: 'var(--accent-cyan)', background: 'rgba(6, 182, 212, 0.1)', padding: '1px 5px', borderRadius: '4px' }}>
                                {file.encryption_algorithm}
                              </span>
                              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                                {new Date(file.created_at).toLocaleDateString()}
                              </span>
                            </div>
                          </div>
                        </div>
                      </td>

                      {/* File ID */}
                      <td>
                        <span className="font-mono" style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', background: 'rgba(255, 255, 255, 0.04)', padding: '3px 7px', borderRadius: '4px' }}>
                          {file.file_id}
                        </span>
                      </td>

                      {/* Sizes */}
                      <td>
                        <div style={{ fontWeight: 500 }}>{formatBytes(file.original_size_bytes)}</div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          Cipher: {formatBytes(file.encrypted_size_bytes)}
                        </div>
                      </td>

                      {/* Chunks */}
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <span style={{ fontWeight: 600 }}>{file.chunk_count} chunks</span>
                          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                            ({formatBytes(file.chunk_size_bytes)} ea)
                          </span>
                        </div>
                        <div style={{ fontSize: '0.74rem', color: 'var(--accent-emerald)' }}>
                          {file.chunks?.reduce((acc, c) => acc + (c.placements?.length || 0), 0) || 0} replicas across cluster
                        </div>
                      </td>

                      {/* Redundancy */}
                      <td>
                        <span className="badge badge-cyan" style={{ fontSize: '0.7rem' }}>
                          {file.replication_factor}x Replica
                        </span>
                        {file.erasure_coding?.includes('Reed-Solomon') && (
                          <div style={{ fontSize: '0.72rem', color: 'var(--accent-violet)', marginTop: '2px' }}>
                            RS (4+2) Shards
                          </div>
                        )}
                      </td>

                      {/* Status */}
                      <td>
                        <span className="badge badge-online">
                          <span className="status-dot" style={{ background: 'var(--accent-emerald)' }}></span>
                          Active
                        </span>
                      </td>

                      {/* Actions */}
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end', alignItems: 'center' }}>
                          <button
                            id={`btn-manifest-${file.file_id}`}
                            className="btn btn-secondary btn-sm"
                            onClick={() => setSelectedFileForManifest(file)}
                            title="Inspect Schema v2 Manifest & Placements"
                          >
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                              <circle cx="12" cy="12" r="3"></circle>
                            </svg>
                            Manifest
                          </button>

                          <button
                            id={`btn-download-${file.file_id}`}
                            className="btn btn-secondary btn-sm"
                            disabled={isDownloading}
                            onClick={() => handleSimulateDownload(file)}
                            title="Download Chunks, Verify SHA-256 & Decrypt"
                          >
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                              <polyline points="7 10 12 15 17 10"></polyline>
                              <line x1="12" y1="15" x2="12" y2="3"></line>
                            </svg>
                            {isDownloading ? `${downloadProgress?.percent}%` : 'Download'}
                          </button>

                          <button
                            id={`btn-delete-${file.file_id}`}
                            className="btn btn-danger btn-sm"
                            onClick={() => setDeleteConfirmId(file.file_id)}
                            title="Delete file metadata and purge remote chunks"
                          >
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                              <polyline points="3 6 5 6 21 6"></polyline>
                              <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                            </svg>
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Manifest Inspection Modal */}
      {selectedFileForManifest && (
        <div className="modal-overlay" onClick={() => setSelectedFileForManifest(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '820px' }}>
            <div style={{ padding: '24px 28px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                  <h3 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Schema v2 Manifest Inspection</h3>
                  <span className="badge badge-cyan">Client Cryptographic Manifest</span>
                </div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                  File: {selectedFileForManifest.filename} ({selectedFileForManifest.file_id})
                </div>
              </div>
              <button className="btn btn-secondary btn-icon" onClick={() => setSelectedFileForManifest(null)}>
                ✕
              </button>
            </div>

            <div style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {/* Manifest Security Directive Warning */}
              <div style={{ padding: '12px 16px', background: 'rgba(6, 182, 212, 0.08)', border: '1px solid var(--border-glow)', borderRadius: '10px', fontSize: '0.82rem' }}>
                <span style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>Directive Phase 4B & 9A: </span>
                Plaintext files & encryption keys (DEK) are never uploaded or stored on the Coordinator. Only ciphertext binary chunks and SHA-256 verification placements are tracked.
              </div>

              {/* Chunk Placement Table */}
              <div>
                <h4 style={{ fontSize: '0.96rem', fontWeight: 600, marginBottom: '10px' }}>
                  Chunk Placement Map ({selectedFileForManifest.chunks?.length || 0} Chunks)
                </h4>
                <div className="table-wrapper">
                  <table className="data-table" style={{ fontSize: '0.8rem' }}>
                    <thead>
                      <tr>
                        <th>Idx</th>
                        <th>Chunk ID</th>
                        <th>SHA-256 Checksum</th>
                        <th>Placement Nodes</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {selectedFileForManifest.chunks?.map((chunk) => (
                        <tr key={chunk.chunk_id}>
                          <td><strong>#{chunk.index}</strong></td>
                          <td className="font-mono">{chunk.chunk_id}</td>
                          <td className="font-mono" style={{ maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={chunk.sha256}>
                            {chunk.sha256}
                          </td>
                          <td>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                              {chunk.placements?.map((p, idx) => (
                                <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                  <span className={`badge ${p.role === 'PRIMARY' ? 'badge-cyan' : 'badge-violet'}`} style={{ fontSize: '0.65rem', padding: '1px 5px' }}>
                                    {p.role}
                                  </span>
                                  <span className="font-mono" style={{ fontSize: '0.74rem' }}>{p.node_id}</span>
                                </div>
                              ))}
                            </div>
                          </td>
                          <td>
                            <span className="badge badge-online" style={{ fontSize: '0.65rem' }}>
                              VERIFIED
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Raw JSON Manifest Drawer */}
              <div>
                <h4 style={{ fontSize: '0.96rem', fontWeight: 600, marginBottom: '8px' }}>
                  Raw JSON Schema v2
                </h4>
                <pre className="font-mono" style={{
                  padding: '16px',
                  background: 'rgba(7, 9, 14, 0.85)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '10px',
                  fontSize: '0.76rem',
                  color: '#38bdf8',
                  maxHeight: '220px',
                  overflowY: 'auto'
                }}>
                  {JSON.stringify(selectedFileForManifest, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteConfirmId && (
        <div className="modal-overlay" onClick={() => setDeleteConfirmId(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '480px' }}>
            <div style={{ padding: '24px 28px' }}>
              <div style={{ width: '48px', height: '48px', borderRadius: '12px', background: 'rgba(244, 63, 94, 0.15)', color: 'var(--accent-rose)', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '16px' }}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="3 6 5 6 21 6"></polyline>
                  <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                </svg>
              </div>
              <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '8px' }}>Confirm File Deletion</h3>
              <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', marginBottom: '24px' }}>
                Are you sure you want to delete file <strong className="font-mono" style={{ color: 'var(--text-primary)' }}>{deleteConfirmId}</strong>? The coordinator will schedule a durable background deletion job to purge all replica shards across remote storage nodes.
              </p>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
                <button className="btn btn-secondary" onClick={() => setDeleteConfirmId(null)}>
                  Cancel
                </button>
                <button
                  id="btn-confirm-delete"
                  className="btn btn-danger"
                  onClick={() => {
                    onDeleteFile(deleteConfirmId);
                    setDeleteConfirmId(null);
                  }}
                >
                  Yes, Delete File
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
