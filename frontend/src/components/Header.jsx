import React, { useState, useEffect } from 'react';
import { useConnection } from '../context/ConnectionContext';
import { Cpu, Tv, Database, Radio } from 'lucide-react';

export default function Header({ onWallboardClick }) {
  const {
    apiStatus,
    globalWsStatus,
    apiLatency,
    lastUpdated
  } = useConnection();

  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const getStatusBadge = (status) => {
    if (status === 'ONLINE') {
      return (
        <span className="flex items-center gap-1.5 text-emerald-400 font-extrabold font-mono">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
          ONLINE
        </span>
      );
    }
    if (status === 'RECONNECTING') {
      return (
        <span className="flex items-center gap-1.5 text-amber-400 font-extrabold font-mono animate-pulse">
          <span className="w-2 h-2 rounded-full bg-amber-500 animate-ping"></span>
          RECONNECTING...
        </span>
      );
    }
    if (status === 'DEGRADED') {
      return (
        <span className="flex items-center gap-1.5 text-yellow-500 font-extrabold font-mono animate-pulse">
          <span className="w-2 h-2 rounded-full bg-yellow-500"></span>
          DEGRADED
        </span>
      );
    }
    return (
      <span className="flex items-center gap-1.5 text-rose-400 font-extrabold font-mono">
        <span className="w-2 h-2 rounded-full bg-rose-500"></span>
        OFFLINE
      </span>
    );
  };

  return (
    <header className="bg-slate-900 border-b border-slate-800 h-16 flex items-center justify-between px-8 sticky top-0 z-40">
      {/* Title */}
      <div className="flex items-center gap-2">
        <Cpu className="w-5 h-5 text-cyan-400" />
        <h2 className="text-sm font-semibold tracking-wider text-slate-200 uppercase font-mono">
          Security Console // Operational Node
        </h2>
      </div>

      {/* Control Widgets & Badges */}
      <div className="flex items-center gap-6">
        {/* API STATUS */}
        <div className="flex items-center gap-2 border border-slate-800 bg-slate-950/60 px-3 py-1.5 rounded-lg text-xs font-mono">
          <Database className={`w-3.5 h-3.5 ${apiStatus === 'ONLINE' ? 'text-emerald-400' : apiStatus === 'RECONNECTING' ? 'text-amber-400' : 'text-rose-400'}`} />
          <span className="text-slate-500 font-bold uppercase">REST API:</span>
          {getStatusBadge(apiStatus)}
          {apiStatus === 'ONLINE' && (
            <span className="text-[10px] text-slate-600 font-bold">({apiLatency}ms)</span>
          )}
        </div>

        {/* WS STATUS */}
        <div className="flex items-center gap-2 border border-slate-800 bg-slate-950/60 px-3 py-1.5 rounded-lg text-xs font-mono">
          <Radio className={`w-3.5 h-3.5 ${globalWsStatus === 'ONLINE' ? 'text-cyan-400 animate-pulse' : 'text-rose-400'}`} />
          <span className="text-slate-500 font-bold uppercase">STREAM:</span>
          {getStatusBadge(globalWsStatus)}
        </div>

        {/* WALLBOARD BUTTON */}
        <button
          onClick={onWallboardClick}
          className="flex items-center gap-2 border border-slate-800 bg-slate-950/60 hover:bg-slate-900/60 hover:border-cyan-500/30 hover:shadow-[0_0_15px_rgba(6,182,212,0.1)] px-3 py-1.5 rounded-lg text-xs font-mono text-slate-300 transition-all duration-250 cursor-pointer"
        >
          <Tv className="w-3.5 h-3.5 text-cyan-400" />
          <span>WALLBOARD</span>
        </button>

        {/* Live Clock & Last Updated */}
        <div className="text-slate-400 text-xs font-mono border-l border-slate-800 pl-6 flex flex-col items-end">
          <span className="text-slate-200 font-bold">{time.toLocaleTimeString([], { hour12: false })}</span>
          <span className="text-[9px] text-slate-600 tracking-wider font-extrabold uppercase mt-0.5">
            Updated: {lastUpdated}
          </span>
        </div>
      </div>
    </header>
  );
}
