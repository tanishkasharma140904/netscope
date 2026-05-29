import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Network, Activity, ArrowRight, ShieldAlert, Cpu, Database, Flame, Clock } from 'lucide-react';
import axios from 'axios';
import SkeletonLoader from './SkeletonLoader';

const isPrivateIP = (ip) => {
  return ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.') || ip === '127.0.0.1' || ip === 'localhost';
};

export default function SessionDrilldownModal({ session, onClose }) {
  if (!session) return null;

  const [loading, setLoading] = useState(true);
  const [threats, setThreats] = useState([]);

  const fetchSessionThreats = async () => {
    try {
      setLoading(true);
      // Fetch dynamic alerts list to match if source_ip or destination_ip participated
      const response = await axios.get('/api/threats');
      const alerts = response.data.recent_alerts || [];
      const matched = alerts.filter(a => 
        a.toLowerCase().includes(session.source_ip) || a.toLowerCase().includes(session.destination_ip)
      );
      setThreats(matched);
      setLoading(false);
    } catch (e) {
      console.error("[SESSION DRILLDOWN ERROR] Failed to fetch threats:", e);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSessionThreats();
  }, [session]);

  const formatBytes = (num) => {
    if (num >= 1024 * 1024) return `${(num / (1024 * 1024)).toFixed(2)} MB`;
    if (num >= 1024) return `${(num / 1024).toFixed(2)} KB`;
    return `${num} B`;
  };

  // derived transfer rates calculation (Task 3)
  const durationSec = parseFloat(session.duration) || 1.0;
  const avgRateBps = Math.round((session.bytes * 8) / durationSec);
  const formatRate = (bps) => {
    if (bps >= 1000000) return `${(bps / 1000000).toFixed(2)} Mbps`;
    if (bps >= 1000) return `${(bps / 1000).toFixed(2)} Kbps`;
    return `${bps} bps`;
  };

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        {/* Backdrop overlay */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
          className="absolute inset-0 bg-slate-950/80 backdrop-blur-[2px]"
        />

        {/* Modal body */}
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
          className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl shadow-2xl relative overflow-hidden flex flex-col"
        >
          {/* Header */}
          <div className="p-6 border-b border-slate-800 flex justify-between items-center bg-slate-950/20">
            <div className="flex items-center gap-2.5">
              <Network className="w-5 h-5 text-cyan-400 animate-pulse" />
              <div>
                <h3 className="font-extrabold text-sm font-mono tracking-wider text-slate-100 uppercase">
                  Session Conversation Drill-Down
                </h3>
                <p className="text-[9px] text-slate-500 font-mono tracking-widest uppercase">
                  Telemetry Handshake Auditing
                </p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-1.5 hover:bg-slate-800 border border-transparent hover:border-slate-700 rounded-lg text-slate-400 hover:text-slate-200 transition-all cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Body Content */}
          <div className="p-6 space-y-6 font-mono text-xs text-slate-300">
            {loading ? (
              <SkeletonLoader message="Analysing session socket metadata..." />
            ) : (
              <>
                {/* Visual Connection Vector */}
                <div className="flex items-center justify-around bg-slate-950/40 border border-slate-900 p-5 rounded-xl text-center">
                  <div className="space-y-1">
                    <span className="text-[8px] text-slate-500 font-extrabold uppercase">Source IP</span>
                    <h4 className="text-sm font-extrabold text-slate-100">{session.source_ip}</h4>
                    <span className="text-[9px] text-slate-600 block">Port: {session.source_port}</span>
                  </div>

                  <div className="flex flex-col items-center gap-1.5">
                    <span className="px-2 py-0.5 border border-cyan-500/30 bg-cyan-500/10 text-cyan-400 rounded-full font-bold text-[9px]">
                      {session.protocol}
                    </span>
                    <ArrowRight className="w-5 h-5 text-cyan-500 animate-pulse" />
                  </div>

                  <div className="space-y-1">
                    <span className="text-[8px] text-slate-500 font-extrabold uppercase">Destination IP</span>
                    <h4 className="text-sm font-extrabold text-slate-100">{session.destination_ip}</h4>
                    <span className="text-[9px] text-slate-600 block">Port: {session.destination_port}</span>
                  </div>
                </div>

                {/* Session Analytics row */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="p-4 bg-slate-950/40 border border-slate-900 rounded-xl space-y-1">
                    <span className="text-[9px] text-slate-500 uppercase font-bold flex items-center gap-1.5">
                      <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                      Packet Count
                    </span>
                    <h4 className="text-lg font-black text-slate-200">{session.packets} pkts</h4>
                  </div>

                  <div className="p-4 bg-slate-950/40 border border-slate-900 rounded-xl space-y-1">
                    <span className="text-[9px] text-slate-500 uppercase font-bold flex items-center gap-1.5">
                      <Database className="w-3.5 h-3.5 text-cyan-400" />
                      Total Octets
                    </span>
                    <h4 className="text-lg font-black text-slate-200">{formatBytes(session.bytes)}</h4>
                  </div>

                  <div className="p-4 bg-slate-950/40 border border-slate-900 rounded-xl space-y-1">
                    <span className="text-[9px] text-slate-500 uppercase font-bold flex items-center gap-1.5">
                      <Activity className="w-3.5 h-3.5 text-cyan-400" />
                      Average Rate
                    </span>
                    <h4 className="text-lg font-black text-slate-200">{formatRate(avgRateBps)}</h4>
                  </div>

                  <div className="p-4 bg-slate-950/40 border border-slate-900 rounded-xl space-y-1">
                    <span className="text-[9px] text-slate-500 uppercase font-bold flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-cyan-400" />
                      Duration
                    </span>
                    <h4 className="text-lg font-black text-cyan-400">{session.duration}s</h4>
                  </div>
                </div>

                {/* Session Threat Correlation */}
                <div className="p-4 bg-slate-950/40 border border-slate-900 rounded-xl space-y-3">
                  <span className="text-[9px] text-slate-500 uppercase font-bold flex items-center gap-1.5 border-b border-slate-900/60 pb-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-rose-500 animate-pulse" />
                    Correlated Anomaly Incidents
                  </span>
                  
                  <div className="space-y-1.5 max-h-[120px] overflow-y-auto pr-1">
                    {threats.length > 0 ? (
                      threats.map((alert, idx) => (
                        <div key={idx} className="p-2.5 bg-slate-950 border border-slate-900 rounded flex items-center gap-2 font-mono text-[9px]">
                          <Flame className="w-3.5 h-3.5 text-rose-500 animate-pulse shrink-0" />
                          <span className="text-slate-300 font-semibold">{alert}</span>
                        </div>
                      ))
                    ) : (
                      <div className="text-center text-slate-600 py-4 uppercase text-[9px]">
                        Nominal posture: Zero alert correlations for this session path.
                      </div>
                    )}
                  </div>
                </div>
              </>
            )}
          </div>

          {/* Footer */}
          <div className="p-4 border-t border-slate-800 bg-slate-950/40 flex justify-between items-center text-[9px] text-slate-500 font-mono">
            <span>Session UID: socket_conversation_path</span>
            <span>SECURE FORENSIC AUDIT PATH</span>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
