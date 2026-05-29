import React from 'react';
import { useConnection } from '../context/ConnectionContext';
import { 
  ShieldAlert, 
  Activity, 
  Tv, 
  Minimize2, 
  AlertTriangle 
} from 'lucide-react';
import LiveCounter from './LiveCounter';
import { ProtocolDonutChart } from './LiveCharts';
import ErrorBoundary from './ErrorBoundary';

export default function Wallboard({ onClose, onThreatClick }) {
  const {
    stats,
    activeThreats,
    apiStatus,
    lastUpdated
  } = useConnection();

  const formatBandwidth = (bps) => {
    if (bps >= 1000000) return `${(bps / 1000000).toFixed(2)} Mbps`;
    if (bps >= 1000) return `${(bps / 1000).toFixed(2)} Kbps`;
    return `${bps} bps`;
  };

  return (
    <div className="fixed inset-0 bg-slate-950 text-slate-100 z-50 p-8 flex flex-col justify-between overflow-y-auto">
      {/* Top Banner Header */}
      <div className="flex justify-between items-center border-b border-slate-900 pb-4">
        <div className="flex items-center gap-3">
          <div className="bg-rose-500/10 border border-rose-500/20 p-2 rounded-lg text-rose-500 animate-pulse">
            <Tv className="w-6 h-6" />
          </div>
          <div>
            <h1 className="font-extrabold text-xl tracking-wider text-slate-100 uppercase font-mono">
              NetScope AI // Wallboard SOC Display
            </h1>
            <p className="text-[10px] text-slate-500 font-mono tracking-widest uppercase mt-0.5">
              Live Audited Operations Center Monitor
            </p>
          </div>
        </div>

        {/* Action Widgets */}
        <div className="flex items-center gap-4">
          {apiStatus === 'OFFLINE' && (
            <span className="text-[10px] font-mono text-rose-400 border border-rose-500/20 bg-rose-500/5 px-2.5 py-1 rounded animate-pulse uppercase">
              CONNECTION FAILURE — LAST DATA CACHED ({lastUpdated})
            </span>
          )}
          <div className="flex items-center gap-2 border border-slate-800 bg-slate-900/40 px-3 py-1.5 rounded-lg text-xs font-mono text-slate-400">
            <Activity className="w-4 h-4 text-cyan-400 animate-pulse" />
            <span>Telemetry: {apiStatus === 'ONLINE' ? 'INGESTING' : 'OFFLINE'}</span>
          </div>
          <button 
            onClick={onClose}
            className="flex items-center gap-2 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 rounded-lg text-xs font-semibold text-slate-300 font-mono transition-colors cursor-pointer"
          >
            <Minimize2 className="w-3.5 h-3.5" />
            <span>Minimize</span>
          </button>
        </div>
      </div>

      {/* Main Grid View */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-3 gap-6 my-6">
        {/* Left Side: Score & Gauge (1/3 width) */}
        <div className="bg-slate-900/40 border border-slate-900 p-6 rounded-2xl flex flex-col justify-between items-center text-center">
          <div>
            <span className="text-xs font-mono font-bold tracking-widest text-slate-500 uppercase">
              Threat Score Indicator
            </span>
            <p className="text-[9px] text-slate-600 font-mono uppercase mt-0.5">
              Live security health audit
            </p>
          </div>

          {/* Radial score gauge */}
          <div className="relative flex items-center justify-center my-6">
            <div className={`absolute w-36 h-36 rounded-full filter blur-2xl opacity-15 ${
              stats.threat_score > 70 ? 'bg-rose-500' : stats.threat_score > 40 ? 'bg-orange-500' : 'bg-emerald-500'
            }`} />
            <svg className="w-48 h-48 transform -rotate-90">
              <circle cx="96" cy="96" r="82" fill="none" stroke="#0b0f19" strokeWidth="12" />
              <circle 
                cx="96" cy="96" r="82" fill="none" 
                stroke={stats.threat_score > 70 ? '#ef4444' : stats.threat_score > 40 ? '#f97316' : '#10b981'} 
                strokeWidth="12" 
                strokeDasharray="515" 
                strokeDashoffset={515 - (515 * stats.threat_score) / 100}
                strokeLinecap="round"
                className="transition-all duration-1000"
              />
            </svg>
            <div className="absolute flex flex-col items-center">
              <span className="text-5xl font-extrabold font-mono text-slate-100">{stats.threat_score}</span>
              <span className="text-[10px] text-slate-500 font-mono tracking-widest uppercase mt-1">THREAT LEVEL</span>
            </div>
          </div>

          <div className="w-full space-y-3 font-mono text-xs">
            <div className="flex justify-between border-b border-slate-900/60 pb-2">
              <span className="text-slate-500 uppercase">Severity Category:</span>
              <span className={`font-bold ${
                stats.threat_score > 70 ? 'text-rose-400' : stats.threat_score > 40 ? 'text-orange-400' : 'text-emerald-400'
              }`}>{stats.risk_level}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500 uppercase">Current Bandwidth:</span>
              <span className="text-cyan-400 font-bold">{formatBandwidth(stats.bandwidth_bps)}</span>
            </div>
          </div>
        </div>

        {/* Center: Live Counter & Protocols (1/3 width) */}
        <div className="bg-slate-900/40 border border-slate-900 p-6 rounded-2xl flex flex-col justify-between">
          <div>
            <span className="text-xs font-mono font-bold tracking-widest text-slate-500 uppercase">
              Proportional protocol capture
            </span>
            <p className="text-[9px] text-slate-600 font-mono uppercase mt-0.5">
              Protocol splits parsed on wire interface
            </p>
          </div>
          
          <ErrorBoundary>
            <ProtocolDonutChart stats={stats} />
          </ErrorBoundary>

          <div className="border-t border-slate-900/60 pt-4">
            <ErrorBoundary>
              <LiveCounter value={stats.total_packets} />
            </ErrorBoundary>
          </div>
        </div>

        {/* Right Side: Security Warning timeline (1/3 width) */}
        <div className="bg-slate-900/40 border border-slate-900 p-6 rounded-2xl flex flex-col justify-between">
          <div className="flex justify-between items-center border-b border-slate-900/60 pb-3 mb-3">
            <div>
              <span className="text-xs font-mono font-bold tracking-widest text-slate-500 uppercase flex items-center gap-1">
                <ShieldAlert className="w-3.5 h-3.5 text-rose-500 animate-pulse" />
                Live Ingress Alerts
              </span>
              <p className="text-[9px] text-slate-600 font-mono uppercase mt-0.5">
                Real-time security logs timeline
              </p>
            </div>
            <span className="text-[10px] font-mono text-slate-500 px-2 py-0.5 bg-slate-950 border border-slate-900 rounded font-bold uppercase">
              Ticking
            </span>
          </div>

          {/* List */}
          <div className="flex-1 space-y-2 overflow-y-auto max-h-[260px] pr-1 font-mono text-[9px] text-slate-400">
            {activeThreats.length > 0 ? (
              activeThreats.slice(0, 7).map((alert, index) => (
                <div 
                  key={index}
                  onClick={() => onThreatClick && onThreatClick(alert)}
                  className="p-2.5 bg-slate-950/60 border border-slate-900 hover:border-cyan-500/30 hover:bg-slate-950/90 rounded flex items-center gap-2 cursor-pointer transition-all"
                >
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-500 shrink-0 animate-pulse" />
                  <span className="font-semibold text-slate-300 tracking-wide leading-relaxed">{alert}</span>
                </div>
              ))
            ) : (
              <div className="text-center text-slate-600 py-16 uppercase">
                awaiting security sensor telemetry events...
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Footer Info */}
      <div className="border-t border-slate-900 pt-4 flex justify-between text-[10px] font-mono text-slate-500">
        <span>SENSOR STATUS: PATROLLING eth0</span>
        <span>AUDITED // ENTERPRISE SECURITY operations node // Last updated: {lastUpdated}</span>
      </div>
    </div>
  );
}
