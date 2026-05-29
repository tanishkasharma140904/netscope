import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Server, Activity, Network, ShieldAlert, Clock, Database } from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts';
import SkeletonLoader from './SkeletonLoader';
import EmptyState from './EmptyState';

const isPrivateIP = (ip) => {
  return ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.') || ip === '127.0.0.1' || ip === 'localhost';
};

export default function HostProfileModal({ ip, onClose }) {
  const [loading, setLoading] = useState(true);
  const [hostDetails, setHostDetails] = useState({
    packets: 0,
    bytes: 0,
    sessionsCount: 0,
    firstSeen: 'N/A',
    lastSeen: 'N/A',
    threatCount: 0,
    protocols: []
  });
  const [timelineData, setTimelineData] = useState([]);

  const fetchHostProfile = async () => {
    try {
      setLoading(true);
      
      // 1. Fetch active session mappings
      const sessionsRes = await axios.get('/api/sessions');
      const activeSessions = sessionsRes.data.active_sessions || [];

      // 2. Fetch inventory mapping to resolve first_seen / last_seen
      const inventoryRes = await axios.get('/api/inventory');
      const inventoryHosts = inventoryRes.data.hosts || [];
      const matchedInventory = inventoryHosts.find(h => h.ip === ip);

      // 3. Fetch threat anomalies to count alerts matching this IP
      const threatsRes = await axios.get('/api/threats');
      const alerts = threatsRes.data.recent_alerts || [];
      const matchedAlerts = alerts.filter(a => a.toLowerCase().includes(ip));

      // Filter active sessions matching host
      const hostSessions = activeSessions.filter(s => s.source_ip === ip || s.destination_ip === ip);
      
      let totalPackets = matchedInventory ? matchedInventory.packet_count : 0;
      let totalBytes = 0;
      const parsedProtocols = new Set();

      hostSessions.forEach(s => {
        totalBytes += s.bytes;
        parsedProtocols.add(s.protocol);
      });

      // 4. Fetch historical sessions from database to build Host Timeline
      const historyRes = await axios.get('/api/history/sessions?limit=200');
      const historicalSessions = historyRes.data || [];
      
      const chronologicalTimeline = historicalSessions
        .filter(s => s.source_ip === ip || s.destination_ip === ip)
        .map(s => ({
          timeLabel: new Date(s.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }),
          packets: s.packets,
          bytes: parseFloat((s.bytes / 1024).toFixed(2)) // KB
        }))
        .reverse(); // Sort oldest to newest

      setHostDetails({
        packets: totalPackets || hostSessions.reduce((sum, s) => sum + s.packets, 0),
        bytes: totalBytes,
        sessionsCount: hostSessions.length,
        firstSeen: matchedInventory ? matchedInventory.first_seen : 'N/A',
        lastSeen: matchedInventory ? matchedInventory.last_seen : 'N/A',
        threatCount: matchedAlerts.length,
        protocols: Array.from(parsedProtocols)
      });

      setTimelineData(chronologicalTimeline);
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

  const formatBytes = (num) => {
    if (num >= 1024 * 1024) return `${(num / (1024 * 1024)).toFixed(2)} MB`;
    if (num >= 1024) return `${(num / 1024).toFixed(2)} KB`;
    return `${num} B`;
  };

  // Dynamic risk calculation logic (Task 2)
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
          className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl shadow-2xl relative overflow-hidden flex flex-col max-h-[90vh]"
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
          <div className="flex-1 overflow-y-auto p-6 space-y-6 font-mono text-xs">
            {loading ? (
              <SkeletonLoader message={`Retrieving forensic profile for ${ip}...`} />
            ) : (
              <>
                {/* Master Details Row */}
                <div className="flex flex-col md:flex-row justify-between md:items-center gap-4 bg-slate-950/30 border border-slate-900 p-5 rounded-xl">
                  <div className="space-y-1.5">
                    <span className="text-[9px] text-slate-500 font-extrabold uppercase">Discovered IPv4 Address</span>
                    <h2 className="text-xl font-black text-slate-100 tracking-tight">{ip}</h2>
                    <span className={`px-2 py-0.5 border rounded uppercase font-bold text-[8px] inline-block ${
                      isPrivateIP(ip) ? 'bg-blue-500/10 border-blue-500/20 text-blue-400' : 'bg-orange-500/10 border-orange-500/20 text-orange-400'
                    }`}>
                      {isPrivateIP(ip) ? 'INTERNAL LAN ASSET' : 'EXTERNAL INTERFACE'}
                    </span>
                  </div>

                  <div className="flex items-center gap-6">
                    <div className="text-right">
                      <span className="text-[9px] text-slate-500 font-bold block uppercase">First Discovered</span>
                      <span className="text-slate-300 font-bold">{hostDetails.firstSeen}</span>
                    </div>
                    <div className="text-right border-l border-slate-800 pl-6">
                      <span className="text-[9px] text-slate-500 font-bold block uppercase">Last Observed</span>
                      <span className="text-slate-300 font-bold">{hostDetails.lastSeen}</span>
                    </div>
                    <div className="text-right border-l border-slate-800 pl-6">
                      <span className="text-[9px] text-slate-500 font-bold block uppercase">Forensic Rating</span>
                      <span className={`px-2.5 py-0.5 border rounded uppercase font-bold text-[9px] block text-center mt-0.5 ${getRiskColor(riskRating)}`}>
                        {riskRating}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Primary Metrics Grid */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="p-4 bg-slate-950/40 border border-slate-900 rounded-xl space-y-1">
                    <span className="text-[9px] text-slate-500 uppercase font-bold flex items-center gap-1.5">
                      <Activity className="w-3.5 h-3.5 text-cyan-400" />
                      Packet Ingest
                    </span>
                    <h4 className="text-2xl font-black text-slate-200">{hostDetails.packets}</h4>
                    <span className="text-[8px] text-slate-600 block uppercase">TOTAL PACKETS PARSED</span>
                  </div>

                  <div className="p-4 bg-slate-950/40 border border-slate-900 rounded-xl space-y-1">
                    <span className="text-[9px] text-slate-500 uppercase font-bold flex items-center gap-1.5">
                      <Database className="w-3.5 h-3.5 text-cyan-400" />
                      Volume Exchanged
                    </span>
                    <h4 className="text-2xl font-black text-slate-200">{formatBytes(hostDetails.bytes)}</h4>
                    <span className="text-[8px] text-slate-600 block uppercase">OCTETS AUDITED</span>
                  </div>

                  <div className="p-4 bg-slate-950/40 border border-slate-900 rounded-xl space-y-1">
                    <span className="text-[9px] text-slate-500 uppercase font-bold flex items-center gap-1.5">
                      <Network className="w-3.5 h-3.5 text-cyan-400" />
                      Active Conversations
                    </span>
                    <h4 className="text-2xl font-black text-slate-200">{hostDetails.sessionsCount}</h4>
                    <span className="text-[8px] text-slate-600 block uppercase">SOCKET CONNECTIONS</span>
                  </div>

                  <div className="p-4 bg-slate-950/40 border border-slate-900 rounded-xl space-y-1">
                    <span className="text-[9px] text-slate-500 uppercase font-bold flex items-center gap-1.5">
                      <ShieldAlert className="w-3.5 h-3.5 text-rose-500 animate-pulse" />
                      Anomalies Flagged
                    </span>
                    <h4 className={`text-2xl font-black ${hostDetails.threatCount > 0 ? 'text-rose-500' : 'text-slate-200'}`}>
                      {hostDetails.threatCount}
                    </h4>
                    <span className="text-[8px] text-slate-600 block uppercase">SEGMENT ALERT HITS</span>
                  </div>
                </div>

                {/* Protocols Used & Detailed Lists */}
                <div className="p-4 bg-slate-950/40 border border-slate-900 rounded-xl space-y-2">
                  <span className="text-[9px] text-slate-500 uppercase font-bold block border-b border-slate-900/60 pb-1.5">
                    Protocols Audited
                  </span>
                  <div className="flex gap-2">
                    {hostDetails.protocols.length > 0 ? (
                      hostDetails.protocols.map((proto, idx) => (
                        <span key={idx} className="px-2 py-0.5 border border-cyan-500/20 bg-cyan-500/5 text-cyan-400 rounded text-[9px] font-bold">
                          {proto}
                        </span>
                      ))
                    ) : (
                      <span className="text-slate-600 italic">No protocols resolved.</span>
                    )}
                  </div>
                </div>

                {/* Host Activity Timeline Chart */}
                <div className="p-5 bg-slate-950/40 border border-slate-900 rounded-xl space-y-4">
                  <div>
                    <h3 className="text-xs font-bold text-slate-200 uppercase flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-cyan-400" />
                      Host Activity Timeline Chronology
                    </h3>
                    <p className="text-[9px] text-slate-500">
                      Historical session volume (packets and payload KB) committed to SQLite database for this host
                    </p>
                  </div>

                  <div className="h-56 w-full">
                    {timelineData.length === 0 ? (
                      <EmptyState message="Awaiting historical database logs..." />
                    ) : (
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={timelineData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                          <defs>
                            <linearGradient id="hostPps" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.2}/>
                              <stop offset="95%" stopColor="#00f0ff" stopOpacity={0}/>
                            </linearGradient>
                          </defs>
                          <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" vertical={false} />
                          <XAxis dataKey="timeLabel" stroke="#475569" fontSize={9} fontFamily="monospace" tickLine={false} />
                          <YAxis stroke="#475569" fontSize={9} fontFamily="monospace" tickLine={false} axisLine={false} />
                          <Tooltip
                            contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                            itemStyle={{ fontSize: '11px', fontFamily: 'monospace' }}
                          />
                          <Area 
                            type="monotone" 
                            dataKey="packets" 
                            stroke="#00f0ff" 
                            strokeWidth={2}
                            fillOpacity={1} 
                            fill="url(#hostPps)" 
                          />
                        </AreaChart>
                      </ResponsiveContainer>
                    )}
                  </div>
                </div>
              </>
            )}
          </div>

          {/* Footer */}
          <div className="p-4 border-t border-slate-800 bg-slate-950/40 flex justify-between items-center text-[9px] text-slate-500 font-mono">
            <span>Asset UID: {ip}</span>
            <span>SECURE FORENSIC AUDIT PATH</span>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
