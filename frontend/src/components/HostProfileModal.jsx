import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Server } from 'lucide-react';
import SkeletonLoader from './SkeletonLoader';

const isPrivateIP = (ip) => {
  return ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.') || ip === '127.0.0.1' || ip === 'localhost';
};

export default function HostProfileModal({ ip, onClose }) {
  const [loading, setLoading] = useState(true);
  const [hostDetails, setHostDetails] = useState({
    packets: 0,
    firstSeen: 'N/A',
    lastSeen: 'N/A',
    threatCount: 0,
    protocols: []
  });

  const fetchHostProfile = async () => {
    try {
      setLoading(true);
      
      // 1. Fetch active session mappings for protocols
      const sessionsRes = await axios.get('/api/sessions');
      const activeSessions = sessionsRes.data.active_sessions || [];

      // 2. Fetch inventory mapping to resolve first_seen / last_seen & packet count
      const inventoryRes = await axios.get('/api/inventory');
      const inventoryHosts = inventoryRes.data.hosts || [];
      const matchedInventory = inventoryHosts.find(h => h.ip === ip);

      // 3. Fetch threat anomalies to count alerts matching this IP
      const threatsRes = await axios.get('/api/threats');
      const alerts = threatsRes.data.recent_alerts || [];
      const matchedAlerts = alerts.filter(a => a.toLowerCase().includes(ip.toLowerCase()));

      const hostSessions = activeSessions.filter(s => s.source_ip === ip || s.destination_ip === ip);
      const parsedProtocols = new Set();
      hostSessions.forEach(s => {
        parsedProtocols.add(s.protocol);
      });

      setHostDetails({
        packets: matchedInventory ? matchedInventory.packet_count : hostSessions.reduce((sum, s) => sum + s.packets, 0),
        firstSeen: matchedInventory ? matchedInventory.first_seen : 'N/A',
        lastSeen: matchedInventory ? matchedInventory.last_seen : 'N/A',
        threatCount: matchedAlerts.length,
        protocols: Array.from(parsedProtocols)
      });

      setLoading(false);
    } catch (e) {
      console.error("[HOST INVESTIGATION ERROR] Failed to drill down host metrics:", e);
      setLoading(false);
    }
  };

  useEffect(() => {
    if (ip) {
      fetchHostProfile();
    }
  }, [ip]);

  // Dynamic risk calculation logic
  const calculateRisk = (packets, threatCount) => {
    if (threatCount > 2 || packets > 1200) return 'CRITICAL';
    if (threatCount > 0 || packets > 600) return 'HIGH';
    if (packets > 200) return 'MEDIUM';
    return 'LOW';
  };

  const riskRating = calculateRisk(hostDetails.packets, hostDetails.threatCount);

  const getRiskColor = (risk) => {
    if (risk === 'CRITICAL') return 'text-rose-400 border-rose-500/30 bg-rose-500/10';
    if (risk === 'HIGH') return 'text-orange-400 border-orange-500/30 bg-orange-500/10';
    if (risk === 'MEDIUM') return 'text-amber-400 border-amber-500/30 bg-amber-500/10';
    return 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
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
          className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-md shadow-2xl relative overflow-hidden flex flex-col"
        >
          {/* Header */}
          <div className="p-6 border-b border-slate-800 flex justify-between items-center bg-slate-950/20">
            <div className="flex items-center gap-2.5">
              <Server className="w-5 h-5 text-cyan-400 animate-pulse" />
              <div>
                <h3 className="font-extrabold text-sm font-mono tracking-wider text-slate-100 uppercase">
                  Network Host Profile
                </h3>
                <p className="text-[9px] text-slate-500 font-mono tracking-widest uppercase">
                  Telemetry Asset Dossier
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
          <div className="p-6 space-y-6 font-mono text-xs">
            {loading ? (
              <SkeletonLoader message={`Retrieving forensic profile for ${ip}...`} />
            ) : (
              <div className="space-y-4">
                {/* IP Header */}
                <div className="bg-slate-950/30 border border-slate-900 p-4 rounded-xl space-y-1.5">
                  <span className="text-[9px] text-slate-500 font-extrabold uppercase">Discovered IPv4 Address</span>
                  <h2 className="text-xl font-black text-slate-100 tracking-tight">{ip}</h2>
                  <span className={`px-2 py-0.5 border rounded uppercase font-bold text-[8px] inline-block ${
                    isPrivateIP(ip) ? 'bg-blue-500/10 border-blue-500/20 text-blue-400' : 'bg-orange-500/10 border-orange-500/20 text-orange-400'
                  }`}>
                    {isPrivateIP(ip) ? 'INTERNAL LAN ASSET' : 'EXTERNAL INTERFACE'}
                  </span>
                </div>

                {/* Key Fields Grid */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="p-3 bg-slate-950/40 border border-slate-900 rounded-lg space-y-1">
                    <span className="text-[8px] text-slate-500 uppercase font-bold">First Observed</span>
                    <span className="text-slate-200 font-bold block">{hostDetails.firstSeen}</span>
                  </div>

                  <div className="p-3 bg-slate-950/40 border border-slate-900 rounded-lg space-y-1">
                    <span className="text-[8px] text-slate-500 uppercase font-bold">Last Observed</span>
                    <span className="text-slate-200 font-bold block">{hostDetails.lastSeen}</span>
                  </div>

                  <div className="p-3 bg-slate-950/40 border border-slate-900 rounded-lg space-y-1">
                    <span className="text-[8px] text-slate-500 uppercase font-bold">Packet Ingest</span>
                    <span className="text-slate-200 font-extrabold block text-xs">{hostDetails.packets} pkts</span>
                  </div>

                  <div className="p-3 bg-slate-950/40 border border-slate-900 rounded-lg space-y-1">
                    <span className="text-[8px] text-slate-500 uppercase font-bold">Risk Posture</span>
                    <span className={`px-2 py-0.5 border rounded uppercase font-bold text-[9px] block text-center mt-0.5 ${getRiskColor(riskRating)}`}>
                      {riskRating}
                    </span>
                  </div>
                </div>

                {/* Protocols Observed */}
                {hostDetails.protocols.length > 0 && (
                  <div className="p-4 bg-slate-950/40 border border-slate-900 rounded-xl space-y-2">
                    <span className="text-[9px] text-slate-500 uppercase font-bold block border-b border-slate-900/60 pb-1.5">
                      Protocols Observed
                    </span>
                    <div className="flex flex-wrap gap-2">
                      {hostDetails.protocols.map((proto, idx) => (
                        <span key={idx} className="px-2 py-0.5 border border-cyan-500/20 bg-cyan-500/5 text-cyan-400 rounded text-[8px] font-bold uppercase">
                          {proto}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="p-4 border-t border-slate-800 bg-slate-950/40 flex justify-between items-center text-[9px] text-slate-500 font-mono">
            <span>Asset UID: {ip}</span>
            <span>SECURE AUDIT PATH</span>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
