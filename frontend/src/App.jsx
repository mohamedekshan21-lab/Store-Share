import React, { useState, useEffect, useCallback } from 'react';
import Navbar from './components/Navbar';
import ClusterOverview from './components/ClusterOverview';
import FileManager from './components/FileManager';
import NodeTopology from './components/NodeTopology';
import SelfHealing from './components/SelfHealing';
import ProviderAccounting from './components/ProviderAccounting';
import DiagnosticsConsole from './components/DiagnosticsConsole';
import UserManagement from './components/UserManagement';
import UploadModal from './components/UploadModal';
import RegisterNodeModal from './components/RegisterNodeModal';
import ConfigModal from './components/ConfigModal';
import AuthModal from './components/AuthModal';
import { AuthProvider, useAuth } from './context/AuthContext';

import {
  getNodes,
  getFiles,
  getRepairJobs,
  uploadFileSimulation,
  deleteFile,
  registerNode,
  toggleNodeScheduling,
  drainNode,
  triggerReconciliation,
  checkCoordinatorHealth,
  isSimulationMode,
  getCoordinatorUrl,
} from './services/api';

function AppContent() {
  const { role, user, authModalOpen, setAuthModalOpen, accessDeniedMessage, setAccessDeniedMessage } = useAuth();
  const currentRole = role || 'consumer';

  // Default active tab based on role
  const [activeTab, setActiveTab] = useState(() => (currentRole === 'consumer' ? 'files' : 'overview'));
  const [nodes, setNodes] = useState([]);
  const [files, setFiles] = useState([]);
  const [repairJobs, setRepairJobs] = useState([]);
  const [isOnline, setIsOnline] = useState(true);
  const [isSimulation, setIsSimulation] = useState(isSimulationMode());
  const [isReconciling, setIsReconciling] = useState(false);

  // Modals state
  const [uploadModalOpen, setUploadModalOpen] = useState(false);
  const [registerModalOpen, setRegisterModalOpen] = useState(false);
  const [configModalOpen, setConfigModalOpen] = useState(false);

  // Auto-switch tab if current tab is not permitted for active role
  useEffect(() => {
    if (currentRole === 'consumer' && activeTab !== 'files') {
      setActiveTab('files');
    } else if (currentRole === 'provider' && (activeTab === 'repair' || activeTab === 'users')) {
      setActiveTab('overview');
    }
  }, [currentRole, activeTab]);

  // Fetch initial and recurring data
  const refreshClusterData = useCallback(async () => {
    try {
      const [nodesRes, filesRes, repairRes, healthRes] = await Promise.all([
        getNodes(),
        getFiles(),
        getRepairJobs(),
        checkCoordinatorHealth(),
      ]);

      if (nodesRes && nodesRes.nodes) setNodes(nodesRes.nodes);
      if (filesRes && filesRes.files) setFiles(filesRes.files);
      if (repairRes && repairRes.jobs) setRepairJobs(repairRes.jobs);
      setIsOnline(healthRes.status === 'online');
    } catch (err) {
      if (err.message && err.message.includes('403')) {
        setAccessDeniedMessage(err.message);
      }
      console.warn('Auto-refresh encountered issue; using simulation cache.', err);
    }
  }, [setAccessDeniedMessage]);

  useEffect(() => {
    refreshClusterData();
    const interval = setInterval(refreshClusterData, 12000);
    return () => clearInterval(interval);
  }, [refreshClusterData]);

  // Upload handler
  const handleUploadComplete = async (meta) => {
    const newFile = await uploadFileSimulation(meta);
    await refreshClusterData();
    return newFile;
  };

  // Delete handler
  const handleDeleteFile = async (fileId) => {
    await deleteFile(fileId);
    await refreshClusterData();
  };

  // Register node handler
  const handleRegisterNode = async (nodeData) => {
    const newNode = await registerNode(nodeData);
    await refreshClusterData();
    return newNode;
  };

  // Toggle node scheduling
  const handleToggleScheduling = async (nodeId, enable) => {
    await toggleNodeScheduling(nodeId, enable);
    setNodes(prev => prev.map(n => n.node_id === nodeId ? { ...n, is_schedulable: enable ? 1 : 0 } : n));
  };

  // Drain node handler
  const handleDrainNode = async (nodeId) => {
    await drainNode(nodeId);
    setNodes(prev => prev.map(n => n.node_id === nodeId ? { ...n, status: 'draining', is_schedulable: 0 } : n));
    await refreshClusterData();
  };

  // Reconciliation handler
  const handleTriggerReconcile = async (dryRun = true) => {
    setIsReconciling(true);
    try {
      const report = await triggerReconciliation(dryRun);
      await refreshClusterData();
      return report;
    } finally {
      setIsReconciling(false);
    }
  };

  // Config saved callback
  const handleConfigSaved = ({ simMode }) => {
    setIsSimulation(simMode);
    refreshClusterData();
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      {/* Navbar Header */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenConfig={() => setConfigModalOpen(true)}
        isSimulation={isSimulation}
        isOnline={isOnline}
        nodesCount={nodes.length}
        filesCount={files.length}
      />

      {/* Access Denied Warning Banner */}
      {accessDeniedMessage && (
        <div
          style={{
            maxWidth: '1440px',
            width: '100%',
            margin: '16px auto 0',
            padding: '12px 24px',
          }}
        >
          <div
            style={{
              padding: '12px 18px',
              borderRadius: '10px',
              background: 'rgba(239, 68, 68, 0.15)',
              border: '1px solid rgba(239, 68, 68, 0.4)',
              color: '#f87171',
              fontSize: '0.88rem',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="8" x2="12" y2="12"></line>
                <line x1="12" y1="16" x2="12.01" y2="16"></line>
              </svg>
              <span>{accessDeniedMessage}</span>
            </div>
            <button
              onClick={() => setAccessDeniedMessage(null)}
              style={{
                background: 'transparent',
                border: 'none',
                color: '#f87171',
                cursor: 'pointer',
                fontWeight: 600,
                fontSize: '1rem',
              }}
            >
              ×
            </button>
          </div>
        </div>
      )}

      {/* Main Container */}
      <main style={{ flex: 1, maxWidth: '1440px', width: '100%', margin: '0 auto', padding: '32px 24px' }}>
        {activeTab === 'overview' && (currentRole === 'admin' || currentRole === 'provider') && (
          <ClusterOverview
            nodes={nodes}
            files={files}
            repairJobs={repairJobs}
            onNavigate={setActiveTab}
            onOpenUpload={() => setUploadModalOpen(true)}
            onOpenRegisterNode={() => setRegisterModalOpen(true)}
            onTriggerReconcile={() => handleTriggerReconcile(true)}
            isReconciling={isReconciling}
          />
        )}

        {activeTab === 'files' && (
          <FileManager
            files={files}
            nodes={nodes}
            onOpenUploadModal={() => setUploadModalOpen(true)}
            onDeleteFile={handleDeleteFile}
          />
        )}

        {activeTab === 'nodes' && (currentRole === 'admin' || currentRole === 'provider') && (
          <NodeTopology
            nodes={nodes}
            onToggleScheduling={handleToggleScheduling}
            onDrainNode={handleDrainNode}
            onOpenRegisterModal={() => setRegisterModalOpen(true)}
          />
        )}

        {activeTab === 'repair' && currentRole === 'admin' && (
          <SelfHealing
            repairJobs={repairJobs}
            nodes={nodes}
            files={files}
            onTriggerReconcile={handleTriggerReconcile}
            isReconciling={isReconciling}
          />
        )}

        {activeTab === 'accounting' && (currentRole === 'admin' || currentRole === 'provider') && (
          <ProviderAccounting />
        )}

        {activeTab === 'users' && currentRole === 'admin' && (
          <UserManagement />
        )}

        {activeTab === 'diagnostics' && (currentRole === 'admin' || currentRole === 'provider') && (
          <DiagnosticsConsole
            isSimulation={isSimulation}
            coordinatorUrl={getCoordinatorUrl()}
          />
        )}
      </main>

      {/* Modals */}
      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
      />

      <UploadModal
        isOpen={uploadModalOpen}
        onClose={() => setUploadModalOpen(false)}
        onUploadComplete={handleUploadComplete}
        availableNodes={nodes}
      />

      <RegisterNodeModal
        isOpen={registerModalOpen}
        onClose={() => setRegisterModalOpen(false)}
        onRegisterComplete={handleRegisterNode}
      />

      <ConfigModal
        isOpen={configModalOpen}
        onClose={() => setConfigModalOpen(false)}
        onConfigSaved={handleConfigSaved}
      />

      {/* Footer */}
      <footer style={{
        borderTop: '1px solid var(--border-subtle)',
        background: 'rgba(7, 9, 14, 0.95)',
        padding: '20px 24px',
        marginTop: 'auto',
      }}>
        <div style={{
          maxWidth: '1440px',
          margin: '0 auto',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '12px',
          fontSize: '0.8rem',
          color: 'var(--text-muted)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Expo Store-Share</span>
            <span>•</span>
            <span>Zero-Knowledge Distributed Storage Architecture (Phases 1–9A)</span>
          </div>
          <div style={{ display: 'flex', gap: '16px' }}>
            <span>Client AES-256-GCM</span>
            <span>Reed-Solomon (4+2)</span>
            <span>Auto Self-Healing</span>
            <span>Reverse WebSocket Relays</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
