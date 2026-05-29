import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Activity } from 'lucide-react';

export default function LiveCounter({ value }) {
  const [pulse, setPulse] = useState(false);

  // Trigger a visual packet glow pulse whenever the packet count increments
  useEffect(() => {
    if (value > 0) {
      setPulse(true);
      const timer = setTimeout(() => setPulse(false), 200);
      return () => clearTimeout(timer);
    }
  }, [value]);

  // Pad the counter to show an impressive 8-digit sequence (e.g. 00012345)
  const paddedValue = String(value).padStart(8, '0');

  return (
    <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-6 rounded-xl flex items-center justify-between relative overflow-hidden group">
      {/* Dynamic glow effect */}
      <AnimatePresence>
        {pulse && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 0.15 }}
            exit={{ opacity: 0 }}
            className="absolute inset-0 bg-cyan-500 pointer-events-none filter blur-xl"
          />
        )}
      </AnimatePresence>

      <div>
        <span className="text-xs font-mono font-semibold tracking-wider text-slate-500 uppercase flex items-center gap-1.5">
          <Activity className="w-3.5 h-3.5 text-cyan-400" />
          Live Ingestion Counter
        </span>
        <div className="mt-3 flex gap-1">
          {paddedValue.split('').map((char, index) => (
            <div
              key={index}
              className={`w-9 h-12 flex items-center justify-center font-mono font-extrabold text-2xl border rounded-lg transition-all duration-200 ${
                pulse 
                  ? 'border-cyan-500/60 bg-cyan-950/40 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.15)]' 
                  : char === '0' 
                    ? 'border-slate-800 bg-slate-950/60 text-slate-700' 
                    : 'border-slate-700 bg-slate-950 text-slate-200'
              }`}
            >
              {char}
            </div>
          ))}
        </div>
      </div>

      <div className="text-right flex flex-col justify-center font-mono">
        <span className="text-[10px] text-slate-500 tracking-wider">NETWORK STATUS</span>
        <span className={`text-xs font-bold ${pulse ? 'text-cyan-400' : 'text-slate-400'}`}>
          {pulse ? '• SNIFFING DATA' : '• MONITORING IDLE'}
        </span>
      </div>
    </div>
  );
}
