import React from 'react';

export default function SkeletonLoader({ message = "Retrieving operational telemetry..." }) {
  return (
    <div className="flex flex-col items-center justify-center p-12 border border-slate-900 bg-slate-950/40 rounded-xl space-y-4 font-mono text-xs text-slate-500 animate-pulse w-full min-h-[300px]">
      {/* Pulsing circular core */}
      <div className="relative flex items-center justify-center">
        <div className="w-10 h-10 rounded-full border border-slate-800 flex items-center justify-center">
          <div className="w-5 h-5 rounded-full border border-cyan-500/20 border-t-cyan-500 animate-spin"></div>
        </div>
      </div>

      <div className="text-center space-y-1.5 w-full max-w-[280px]">
        <p className="font-extrabold text-[10px] text-slate-400 uppercase tracking-widest">{message}</p>
        <div className="h-1.5 bg-slate-900 rounded-full w-full overflow-hidden relative">
          <div className="absolute top-0 bottom-0 left-0 bg-cyan-500/30 w-1/2 rounded-full animate-[shimmer_1.5s_infinite_linear]"></div>
        </div>
        <p className="text-[8px] text-slate-600 uppercase tracking-widest">PATROLLING Ethernet bounds // eth0</p>
      </div>
    </div>
  );
}
