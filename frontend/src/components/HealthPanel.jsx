import React from 'react';
import { useConnection } from '../context/ConnectionContext';
import { Activity, Shield, Database, Radio, Clock } from 'lucide-react';

export default function HealthPanel() {
  const {
    apiStatus,
    dbStatus,
    wsStatsStatus,
    wsThreatsStatus,
    wsHostsStatus,
    apiLatency,
    lastUpdated
  } = useConnection();

  const getStatusBadgeStyle = (status) => {
    if (status === 'ONLINE') return 'text-emerald-400 border-emerald-500/20 bg-emerald-500/5';
    if (status === 'RECONNECTING') return 'text-amber-400 border-amber-500/20 bg-amber-500/5 animate-pulse';
    return 'text-rose-400 border-rose-500/20 bg-rose-500/5';
  };

  const getStatusDot = (status) => {
    if (status === 'ONLINE') return 'bg-emerald-500';
    if (status === 'RECONNECTING') return 'bg-amber-500 animate-ping';
    return 'bg-rose-500';
  };

  return (
    <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-6 rounded-xl flex flex-col justify-between font-mono text-xs text-slate-300 shadow-2xl space-y-4">
      {/* Title */}
      <div className="flex justify-between items-center border-b border-slate-800/60 pb-3">
        <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider flex items-center gap-1.5">
          <Shield className="w-3.5 h-3.5 text-cyan-400" />
          SOC Endpoint Diagnostics
        </span>
        <span className="text-[8px] text-slate-600 font-bold uppercase">SECURE LINK</span>
      </div>

      {/* Grid Diagnostics */}
      <div className="grid grid-cols-2 gap-4">
        {/* API STATUS */}
        <div className="p-3 bg-slate-950/40 border border-slate-900 rounded-lg space-y-1.5">
          <span className="text-[9px] text-slate-500 uppercase font-bold flex items-center gap-1">
            <Activity className="w-3 h-3 text-cyan-400" />
            FastAPI REST API
          </span>
          <div className="flex justify-between items-center">
            <span className={`px-2 py-0.5 border rounded text-[9px] font-bold ${getStatusBadgeStyle(apiStatus)}`}>
              {apiStatus}
            </span>
            <span className="text-[9px] text-slate-500 font-bold">
              {apiStatus === 'ONLINE' ? `${apiLatency} ms` : 'N/A'}
            </span>
          </div>
        </div>

        {/* DATABASE STATUS */}
        <div className="p-3 bg-slate-950/40 border border-slate-900 rounded-lg space-y-1.5">
          <span className="text-[9px] text-slate-500 uppercase font-bold flex items-center gap-1">
            <Database className="w-3 h-3 text-cyan-400" />
            SQLite DB
          </span>
          <div className="flex justify-between items-center">
            <span className={`px-2 py-0.5 border rounded text-[9px] font-bold ${getStatusBadgeStyle(dbStatus)}`}>
              {dbStatus}
            </span>
            <div className="flex items-center gap-1.5">
              <span className={`w-1.5 h-1.5 rounded-full ${getStatusDot(dbStatus)}`} />
            </div>
          </div>
        </div>
      </div>

      {/* WebSocket Stream Boundaries */}
      <div className="p-3.5 bg-slate-950/40 border border-slate-900 rounded-lg space-y-2.5">
        <span className="text-[9px] text-slate-500 uppercase font-bold flex items-center gap-1 border-b border-slate-900/60 pb-1.5">
          <Radio className="w-3 h-3 text-cyan-400" />
          WebSocket Stream Boundaries
        </span>
        <div className="space-y-1.5 font-mono text-[9px] text-slate-400">
          <div className="flex justify-between items-center">
            <span className="uppercase">Stats Channel (/stats)</span>
            <span className={`font-bold ${wsStatsStatus === 'ONLINE' ? 'text-cyan-400' : 'text-slate-600'}`}>
              {wsStatsStatus === 'ONLINE' ? 'CONNECTED' : 'OFFLINE'}
            </span>
          </div>
          <div className="flex justify-between items-center">
            <span className="uppercase">Threats Channel (/threats)</span>
            <span className={`font-bold ${wsThreatsStatus === 'ONLINE' ? 'text-cyan-400' : 'text-slate-600'}`}>
              {wsThreatsStatus === 'ONLINE' ? 'CONNECTED' : 'OFFLINE'}
            </span>
          </div>
          <div className="flex justify-between items-center">
            <span className="uppercase">Hosts Channel (/hosts)</span>
            <span className={`font-bold ${wsHostsStatus === 'ONLINE' ? 'text-cyan-400' : 'text-slate-600'}`}>
              {wsHostsStatus === 'ONLINE' ? 'CONNECTED' : 'OFFLINE'}
            </span>
          </div>
        </div>
      </div>

      {/* Latency and Last Updated Footer */}
      <div className="border-t border-slate-800/60 pt-3 flex justify-between items-center text-[9px] text-slate-500">
        <span className="flex items-center gap-1 uppercase">
          <Clock className="w-3.5 h-3.5 text-slate-500" />
          Last Telemetry frame:
        </span>
        <span className="font-bold text-slate-400">{lastUpdated}</span>
      </div>
    </div>
  );
}
