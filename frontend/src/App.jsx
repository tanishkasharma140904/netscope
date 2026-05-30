import React, { useState } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Dashboard from './components/Dashboard';
import ThreatTicker from './components/ThreatTicker';
import ThreatCenter from './pages/ThreatCenter';
import SessionsPage from './pages/SessionsPage';
import InventoryPage from './pages/InventoryPage';
import ExecutiveCenter from './pages/ExecutiveCenter';
import PortAnalysis from './pages/PortAnalysis';
import AppIntelligence from './pages/AppIntelligence';
import GeoIntelligence from './pages/GeoIntelligence';
import SessionAnalyticsPage from './pages/SessionAnalyticsPage';
import AlertHistoryPage from './pages/AlertHistoryPage';
import TrafficLogsPage from './pages/TrafficLogsPage';
import SecurityEventsPage from './pages/SecurityEventsPage';
import { ConnectionProvider } from './context/ConnectionContext';
import ErrorBoundary from './components/ErrorBoundary';
import { ServerCrash } from 'lucide-react';

import HostProfileModal from './components/HostProfileModal';

export default function App() {
  const [currentPage, setCurrentPage] = useState('dashboard');
  
  // Real-time telemetry asset details global state
  const [activeHostIp, setActiveHostIp] = useState(null);

  // Render subpages with fault isolation boundaries
  const renderContent = () => {
    switch (currentPage) {
      case 'dashboard':
        return (
          <ErrorBoundary>
            <Dashboard 
              onHostClick={setActiveHostIp}
            />
          </ErrorBoundary>
        );
      case 'threats':
        return (
          <ErrorBoundary>
            <ThreatCenter 
              onHostClick={setActiveHostIp}
            />
          </ErrorBoundary>
        );
      case 'sessions':
        return (
          <ErrorBoundary>
            <SessionsPage 
              onHostClick={setActiveHostIp}
            />
          </ErrorBoundary>
        );
      case 'inventory':
        return (
          <ErrorBoundary>
            <InventoryPage 
              onHostClick={setActiveHostIp}
            />
          </ErrorBoundary>
        );
      case 'executive':
        return (
          <ErrorBoundary>
            <ExecutiveCenter />
          </ErrorBoundary>
        );
      case 'ports':
        return (
          <ErrorBoundary>
            <PortAnalysis />
          </ErrorBoundary>
        );
      case 'apps':
        return (
          <ErrorBoundary>
            <AppIntelligence />
          </ErrorBoundary>
        );
      case 'geo':
        return (
          <ErrorBoundary>
            <GeoIntelligence />
          </ErrorBoundary>
        );
      case 'session_analytics':
        return (
          <ErrorBoundary>
            <SessionAnalyticsPage 
              onHostClick={setActiveHostIp}
            />
          </ErrorBoundary>
        );
      case 'alerts_history':
        return (
          <ErrorBoundary>
            <AlertHistoryPage />
          </ErrorBoundary>
        );
      case 'traffic_logs':
        return (
          <ErrorBoundary>
            <TrafficLogsPage />
          </ErrorBoundary>
        );
      case 'security_events':
        return (
          <ErrorBoundary>
            <SecurityEventsPage />
          </ErrorBoundary>
        );
      default:
        return (
          <div className="flex flex-col items-center justify-center h-[70vh] border border-dashed border-slate-800 rounded-2xl bg-slate-900/10 p-12 text-center max-w-xl mx-auto space-y-4">
            <div className="bg-slate-900 border border-slate-800 p-4 rounded-full text-slate-400">
              <ServerCrash className="w-8 h-8 text-cyan-400" />
            </div>
            <h3 className="text-lg font-bold text-slate-200 tracking-wide uppercase font-mono">
              Operational Node Shell // {currentPage.toUpperCase()}
            </h3>
            <p className="text-slate-500 text-xs font-mono max-w-xs">
              Component route not found.
            </p>
          </div>
        );
    }
  };

  return (
    <ConnectionProvider>
      <div className="flex flex-col bg-slate-950 text-slate-100 h-screen overflow-hidden">
        {/* Global Threat Ticker with isolated fault boundary */}
        <ErrorBoundary>
          <ThreatTicker />
        </ErrorBoundary>

        <div className="flex flex-1 overflow-hidden">
          {/* Sidebar Navigation */}
          <ErrorBoundary>
            <Sidebar currentPage={currentPage} setCurrentPage={setCurrentPage} />
          </ErrorBoundary>

          {/* Main Console Viewport */}
          <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
            {/* Global Operations Header */}
            <ErrorBoundary>
              <Header onWallboardClick={() => setCurrentPage('dashboard')} />
            </ErrorBoundary>

            {/* Scrollable Operations Area */}
            <main className="flex-1 overflow-y-auto p-8 bg-slate-950/20">
              {renderContent()}
            </main>
          </div>
        </div>

        {/* Global Forensic Overlays */}
        <ErrorBoundary>
          {activeHostIp && (
            <HostProfileModal 
              ip={activeHostIp} 
              onClose={() => setActiveHostIp(null)} 
            />
          )}
        </ErrorBoundary>
      </div>
    </ConnectionProvider>
  );
}
