import React from 'react';
import { motion } from 'framer-motion';

export default function StatCard({ title, value, subtitle, icon: Icon, colorClass = "text-cyan-400", borderClass = "border-slate-800", progress, statusText, subValue }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className={`bg-slate-900/60 backdrop-blur-md border ${borderClass} p-6 rounded-xl flex flex-col justify-between h-40 relative overflow-hidden group`}
    >
      {/* Decorative background hover glow */}
      <div className="absolute inset-0 bg-gradient-to-tr from-transparent via-transparent to-slate-800/10 opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none" />

      {/* Top row */}
      <div className="flex items-center justify-between z-10">
        <span className="text-xs font-mono font-semibold tracking-wider text-slate-500 uppercase">
          {title}
        </span>
        <div className={`p-2 bg-slate-950/80 rounded-lg border border-slate-800/60 ${colorClass}`}>
          <Icon className="w-4 h-4" />
        </div>
      </div>

      {/* Center value */}
      <div className="my-2 z-10">
        <div className="flex items-baseline gap-2">
          <span className="text-3xl font-extrabold font-mono tracking-tight text-slate-100">
            {value}
          </span>
          {subValue && (
            <span className="text-xs font-mono text-slate-500">{subValue}</span>
          )}
        </div>
      </div>

      {/* Bottom status */}
      <div className="w-full z-10">
        {progress !== undefined ? (
          <div className="space-y-1.5">
            <div className="w-full bg-slate-950 rounded-full h-1.5 border border-slate-800/40">
              <div 
                className={`h-full rounded-full transition-all duration-500 ${
                  progress > 70 
                    ? 'bg-rose-500' 
                    : progress > 40 
                      ? 'bg-orange-500' 
                      : progress > 20 
                        ? 'bg-amber-500' 
                        : 'bg-emerald-500'
                }`}
                style={{ width: `${progress}%` }}
              />
            </div>
            <div className="flex justify-between text-[10px] font-mono text-slate-500">
              <span>{subtitle}</span>
              <span className="font-bold">{statusText}</span>
            </div>
          </div>
        ) : (
          <div className="flex justify-between items-center text-[10px] font-mono text-slate-500">
            <span>{subtitle}</span>
            {statusText && <span className="font-bold text-slate-400">{statusText}</span>}
          </div>
        )}
      </div>
    </motion.div>
  );
}
