import React from 'react';
import { useConnection } from '../context/ConnectionContext';
import { ShieldAlert, AlertOctagon, Info } from 'lucide-react';

export default function ThreatTicker() {
  const { activeThreats, wsThreatsStatus } = useConnection();

  const displayAlerts = activeThreats.length > 0 ? activeThreats : ["No active threats."];

  return (
    <div className="bg-slate-950 border-b border-slate-900 h-8 flex items-center overflow-hidden w-full relative z-50 text-[10px] font-mono text-cyan-400">
      <div className="absolute left-0 top-0 bottom-0 bg-slate-950 px-4 flex items-center gap-1.5 border-r border-slate-900 z-10 font-bold uppercase tracking-wider text-rose-500">
        <ShieldAlert className="w-3.5 h-3.5 animate-pulse" />
        Intelligence Alert Feed
      </div>
      <div className="flex gap-16 animate-marquee whitespace-nowrap pl-[180px]">
        {/* Loop the alerts array for seamless marquee translation */}
        {[...displayAlerts, ...displayAlerts].map((alert, i) => {
          const isWarning = alert !== "No active threats.";
          return (
            <span key={i} className="flex items-center gap-2">
              {isWarning ? (
                <AlertOctagon className="w-3.5 h-3.5 text-rose-500 animate-bounce" />
              ) : (
                <Info className="w-3.5 h-3.5 text-cyan-400" />
              )}
              <span className={`font-semibold tracking-wide ${isWarning ? 'text-rose-400 font-bold' : 'text-slate-500'}`}>
                {alert}
              </span>
            </span>
          );
        })}
      </div>
    </div>
  );
}
