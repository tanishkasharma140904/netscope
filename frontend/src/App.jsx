import React, { useState } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Dashboard from './components/Dashboard';
import ThreatTicker from './components/ThreatTicker';
import Wallboard from './components/Wallboard';
import ThreatCenter from './pages/ThreatCenter';
import SessionsPage from './pages/SessionsPage';
import InventoryPage from './pages/InventoryPage';
import ForensicsPage from './pages/ForensicsPage';
import ExecutiveCenter from './pages/ExecutiveCenter';
import { ConnectionProvider } from './context/ConnectionContext';
import ErrorBoundary from './components/ErrorBoundary';
import { ServerCrash } from 'lucide-react';

import ThreatDetailDrawer from './components/ThreatDetailDrawer';
import HostProfileModal from './components/HostProfileModal';
import SessionDrilldownModal from './components/SessionDrilldownModal';

export default function App() {
  const [currentPage, setCurrentPage] = useState('dashboard');
  
  // Forensic investigation global states
  const [activeThreat, setActiveThreat] = useState(null);
  const [activeHostIp, setActiveHostIp] = useState(null);
  const [activeSession, setActiveSession] = useState(null);

  // Render subpages with fault isolation boundaries
  const renderContent = () => {
    switch (currentPage) {
      case 'dashboard':
        return (
          <ErrorBoundary>
            <Dashboard 
              onThreatClick={setActiveThreat}
              onHostClick={setActiveHostIp}
              onSessionClick={setActiveSession}
            />
          </ErrorBoundary>
        );
      case 'threats':
        return (
          <ErrorBoundary>
            <ThreatCenter 
              onThreatClick={setActiveThreat}
              onHostClick={setActiveHostIp}
            />
          </ErrorBoundary>
        );
      case 'sessions':
        return (
          <ErrorBoundary>
            <SessionsPage 
              onSessionClick={setActiveSession}
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
      case 'forensics':
        return (
          <ErrorBoundary>
            <ForensicsPage 
              onHostClick={setActiveHostIp}
              onSessionClick={setActiveSession}
              onThreatClick={setActiveThreat}
            />
          </ErrorBoundary>
        );
      case 'executive':
        return (
          <ErrorBoundary>
            <ExecutiveCenter />
          </ErrorBoundary>
        );
      case 'analytics':
        return (
          <div className="flex flex-col items-center justify-center h-[70vh] font-mono text-xs text-slate-500 space-y-4">
            <div className="w-8 h-8 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin"></div>
            <span>INITIALIZING FULLSCREEN WALLBOARD DISPLAY...</span>
          </div>
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
          <ThreatTicker onThreatClick={setActiveThreat} />
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
              <Header onWallboardClick={() => setCurrentPage('analytics')} />
            </ErrorBoundary>

            {/* Scrollable Operations Area */}
            <main className="flex-1 overflow-y-auto p-8 bg-slate-950/20">
              {renderContent()}
            </main>
          </div>
        </div>

        {/* Fullscreen Wallboard SOC overlay */}
        {currentPage === 'analytics' && (
          <ErrorBoundary>
            <Wallboard 
              onClose={() => setCurrentPage('dashboard')} 
              onThreatClick={setActiveThreat}
            />
          </ErrorBoundary>
        )}

        {/* Global Forensic Overlays */}
        <ErrorBoundary>
          {activeThreat && (
            <ThreatDetailDrawer 
              alert={activeThreat} 
              onClose={() => setActiveThreat(null)} 
              onHostClick={setActiveHostIp} 
            />
          )}
        </ErrorBoundary>

        <ErrorBoundary>
          {activeHostIp && (
            <HostProfileModal 
              ip={activeHostIp} 
              onClose={() => setActiveHostIp(null)} 
            />
          )}
        </ErrorBoundary>

        <ErrorBoundary>
          {activeSession && (
            <SessionDrilldownModal 
              session={activeSession} 
              onClose={() => setActiveSession(null)} 
            />
          )}
        </ErrorBoundary>
      </div>
    </ConnectionProvider>
  );
}
