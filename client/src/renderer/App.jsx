import React, { useEffect, useState } from 'react';

export default function App() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchHealthStatus = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch('http://localhost:5000/api/health');
      if (!response.ok && response.status !== 503) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }
      const json = await response.json();
      setData(json);
    } catch (err) {
      setError(err.message || 'Failed to connect to backend server');
      setData(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealthStatus();
    const interval = setInterval(fetchHealthStatus, 10000);
    return () => clearInterval(interval);
  }, []);

  const backendOnline = data !== null;
  const dbConnected = data?.database?.connected ?? false;

  return (
    <div className="container">
      <header className="header">
        <div className="title-group">
          <div className="logo-badge">SV</div>
          <div>
            <h1>SecureVault</h1>
            <p className="subtitle">Cycle 0 — Project Foundation (JavaScript MVP)</p>
          </div>
        </div>
      </header>

      <main className="grid">
        {/* Backend Server Status Card */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Express Backend</h2>
            <div className={`status-indicator ${loading ? 'loading' : backendOnline ? 'online' : 'offline'}`}>
              <span className={`dot ${loading ? 'pulse' : ''}`}></span>
              {loading ? 'Checking...' : backendOnline ? 'Online' : 'Offline'}
            </div>
          </div>
          <div className="card-body">
            <div className="info-row">
              <span className="info-label">Endpoint</span>
              <span className="info-value">http://localhost:5000/api/health</span>
            </div>
            <div className="info-row">
              <span className="info-label">Uptime</span>
              <span className="info-value">
                {data?.backend?.uptime ? `${Math.floor(data.backend.uptime)}s` : 'N/A'}
              </span>
            </div>
          </div>
        </div>

        {/* PostgreSQL Database Status Card */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">PostgreSQL Database</h2>
            <div className={`status-indicator ${loading ? 'loading' : dbConnected ? 'online' : 'offline'}`}>
              <span className={`dot ${loading ? 'pulse' : ''}`}></span>
              {loading ? 'Checking...' : dbConnected ? 'Connected' : 'Disconnected'}
            </div>
          </div>
          <div className="card-body">
            <div className="info-row">
              <span className="info-label">Driver</span>
              <span className="info-value">pg (Pool)</span>
            </div>
            <div className="info-row">
              <span className="info-label">Message</span>
              <span className="info-value">
                {data?.database?.message || (error ? 'Backend unreachable' : 'N/A')}
              </span>
            </div>
            {data?.database?.timestamp && (
              <div className="info-row">
                <span className="info-label">DB Server Time</span>
                <span className="info-value">
                  {new Date(data.database.timestamp).toLocaleTimeString()}
                </span>
              </div>
            )}
          </div>
        </div>
      </main>

      <button className="refresh-button" onClick={fetchHealthStatus} disabled={loading}>
        {loading ? 'Refreshing...' : 'Refresh Connection Status'}
      </button>

      {error && (
        <div className="error-banner">
          <strong>Backend Connection Error:</strong> {error}. Ensure Express server is running at port 5000.
        </div>
      )}
    </div>
  );
}
