import React from 'react';
import { ShieldAlert } from 'lucide-react';

export default function EmptyState({ message = "Awaiting active telemetry event logs..." }) {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center border border-dashed border-slate-800/80 bg-slate-950/20 rounded-xl space-y-3 font-mono min-h-[220px] w-full">
      <div className="p-2.5 bg-slate-900/60 border border-slate-800 rounded-full text-slate-500">
        <ShieldAlert className="w-6 h-6 text-slate-500 opacity-30" />
      </div>
      <div>
        <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest leading-relaxed">
          {message}
        </h4>
        <p className="text-[8px] text-slate-600 uppercase tracking-wider mt-1.5">
          Boundary status: nominal // Awaiting network traffic triggers
        </p>
      </div>
    </div>
  );
}
