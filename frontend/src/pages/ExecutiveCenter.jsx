import React from 'react';
import { useConnection } from '../context/ConnectionContext';
import { motion } from 'framer-motion';
import { 
  ShieldCheck, 
  TrendingDown, 
  FileLock2, 
  CheckCircle2,
  AlertOctagon,
  AlertTriangle
} from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell } from 'recharts';
import SkeletonLoader from '../components/SkeletonLoader';
import EmptyState from '../components/EmptyState';

export default function ExecutiveCenter() {
  const { 
    summaryData, 
    loadingSummary, 
    apiStatus, 
    lastUpdated 
  } = useConnection();

  const getSeverityColor = (level) => {
    if (level === 'CRITICAL') return 'text-rose-500 bg-rose-500/10 border-rose-500/20';
    if (level === 'HIGH') return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
    if (level === 'MEDIUM') return 'text-amber-500 bg-amber-500/10 border-amber-500/20';
    return 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20';
  };

  const getDynamicNarrative = () => {
    const assetStatus = summaryData.total_hosts > 0 
      ? `monitoring ${summaryData.total_hosts} active host nodes` 
      : "discovering network host assets";
      
    const sessionStatus = summaryData.total_sessions > 0 
      ? `auditing ${summaryData.total_sessions} active socket sessions` 
      : "establishing socket filters";
      
    const alertStatus = summaryData.total_alerts > 0 
      ? `flagging ${summaryData.total_alerts} security anomalies` 
      : "with zero active alert flags";

    const riskPostures = {
      CRITICAL: "immediate containment procedures are advised",
      HIGH: "security operations center teams should escalate analysis",
      MEDIUM: "elevated anomalous packet activity is under review",
      LOW: "nominal traffic thresholds are observed"
    };
    
    const actionPlan = riskPostures[summaryData.risk_level] || "nominal posture active";

    return (
      <div className="space-y-3">
        <p className="text-[11px] text-slate-400 leading-relaxed">
          NetScope security patrol sensors are active on physical adapters, currently {assetStatus} and {sessionStatus}.
        </p>
        <p className="text-[11px] text-slate-400 leading-relaxed">
          The threat scan reports an index of <span className="text-cyan-400 font-bold">{summaryData.threat_score}/100</span> ({summaryData.risk_level} risk posture) {alertStatus}. Under current boundary thresholds, {actionPlan}.
        </p>
        {summaryData.top_application !== 'None' && summaryData.top_application !== 'N/A' && (
          <p className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">
            DOMINANT APP PROTOCOL: {summaryData.top_application}
          </p>
        )}
      </div>
    );
  };

  if (loadingSummary) {
    return <SkeletonLoader message="Analyzing Board-level health indices..." />;
  }

  const chartData = [
    { name: 'Discovered Assets', count: summaryData.total_hosts, fill: '#06b6d4' },
    { name: 'Communications Links', count: summaryData.total_sessions, fill: '#3b82f6' },
    { name: 'Active Security Anomalies', count: summaryData.total_alerts, fill: '#ef4444' }
  ];

  const hasData = summaryData.total_hosts > 0 || summaryData.total_sessions > 0;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Title */}
      <div className="flex justify-between items-center border-b border-slate-800/60 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 tracking-tight">
            Executive Security Command Center
          </h2>
          <p className="text-slate-500 text-xs mt-1">
            Operational indices and infrastructure posture auditing for CISO and board members.
          </p>
        </div>
        
        {/* Offline Warning System */}
        {apiStatus === 'OFFLINE' && (
          <div className="flex items-center gap-2 border border-rose-500/20 bg-rose-500/5 px-3 py-1.5 rounded-lg text-xs font-mono text-rose-400 animate-pulse">
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            <span>BACKEND OFFLINE — Cache Preserved (Last updated: {lastUpdated})</span>
          </div>
        )}
      </div>

      {!hasData ? (
        <EmptyState message="No network telemetry captured yet" />
      ) : (
        <>
          {/* Grid Row 1: Giant KPIs */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Security Health Score Dial */}
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="bg-slate-900/60 backdrop-blur-lg border border-slate-800 p-6 rounded-2xl flex flex-col justify-between items-center text-center h-64 shadow-2xl"
            >
              <span className="text-xs font-mono font-semibold tracking-wider text-slate-500 uppercase">
                Enterprise Security Health
              </span>
              <div className="relative flex items-center justify-center my-3">
                {/* Pulsing glow behind health */}
                <div className={`absolute w-24 h-24 rounded-full filter blur-xl opacity-20 ${
                  summaryData.security_health > 70 ? 'bg-emerald-500' : summaryData.security_health > 40 ? 'bg-amber-500' : 'bg-rose-500'
                }`} />
                <svg className="w-32 h-32 transform -rotate-90">
                  <circle cx="64" cy="64" r="54" fill="none" stroke="#0f172a" strokeWidth="8" />
                  <circle 
                    cx="64" cy="64" r="54" fill="none" 
                    stroke={summaryData.security_health > 70 ? '#10b981' : summaryData.security_health > 40 ? '#f59e0b' : '#ef4444'} 
                    strokeWidth="8" 
                    strokeDasharray="339" 
                    strokeDashoffset={339 - (339 * summaryData.security_health) / 100}
                    strokeLinecap="round"
                    className="transition-all duration-1000"
                  />
                </svg>
                <div className="absolute flex flex-col items-center">
                  <span className="text-3xl font-extrabold font-mono text-slate-100">{summaryData.security_health}%</span>
                  <span className="text-[9px] text-slate-500 font-mono tracking-widest uppercase mt-0.5">HEALTHY</span>
                </div>
              </div>
              <p className="text-[10px] font-mono text-slate-500">
                Computed offset against active alerts parsed on physical segment
              </p>
            </motion.div>

            {/* Threat Level */}
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.1 }}
              className="bg-slate-900/60 backdrop-blur-lg border border-slate-800 p-6 rounded-2xl flex flex-col justify-between h-64 shadow-2xl"
            >
              <div className="flex justify-between items-center">
                <span className="text-xs font-mono font-semibold tracking-wider text-slate-500 uppercase">
                  Threat Score Assessment
                </span>
                <AlertOctagon className={`w-4 h-4 ${summaryData.threat_score > 40 ? 'text-rose-500' : 'text-slate-400'}`} />
              </div>
              <div className="my-auto flex flex-col items-center justify-center">
                <span className="text-5xl font-extrabold font-mono tracking-tighter text-slate-100">
                  {summaryData.threat_score}
                </span>
                <span className={`text-xs font-mono font-bold border rounded px-2.5 py-0.5 uppercase tracking-wider mt-3 ${
                  getSeverityColor(summaryData.risk_level)
                }`}>
                  {summaryData.risk_level} Severity Rating
                </span>
              </div>
              <div className="border-t border-slate-800/60 pt-3 flex justify-between text-[9px] font-mono text-slate-500">
                <span>AUDIT CODE: passive_wire</span>
                <span>INTEGRITY: SECURE</span>
              </div>
            </motion.div>

            {/* CISO Operational Diagnostics */}
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.2 }}
              className="bg-slate-900/60 backdrop-blur-lg border border-slate-800 p-6 rounded-2xl flex flex-col justify-between h-64 font-mono text-xs space-y-4 shadow-2xl"
            >
              <span className="text-xs font-mono font-semibold tracking-wider text-slate-500 uppercase border-b border-slate-800/60 pb-2">
                Audit Metadata Summary
              </span>
              <div className="flex-1 flex flex-col justify-center space-y-3">
                <div className="flex justify-between">
                  <span className="text-slate-500 uppercase">Top Threat Ingress:</span>
                  <span className="text-slate-300 font-bold max-w-[150px] truncate text-right">{summaryData.top_threat}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500 uppercase">Dominant App Layer:</span>
                  <span className="text-slate-300 font-bold">{summaryData.top_application}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500 uppercase">Ingest Port Scan:</span>
                  <span className="text-slate-300 font-bold">{summaryData.total_alerts > 0 ? 'MONITORED' : 'NOMINAL'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500 uppercase">Platform Status:</span>
                  <span className="text-emerald-400 font-bold flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" /> STABLE
                  </span>
                </div>
              </div>
            </motion.div>
          </div>

          {/* Central Segment: Visual Summaries & Reports */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Active Volume bar charts */}
            <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800 p-6 rounded-xl space-y-4 shadow-2xl">
              <div>
                <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
                  Asset Volume Metrics
                </h3>
                <p className="text-[10px] text-slate-500 font-mono">
                  Absolute volume scale comparison for discovered nodes and links
                </p>
              </div>
              <div className="h-60 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={chartData} layout="vertical" margin={{ top: 10, right: 10, left: 30, bottom: 5 }}>
                    <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" horizontal={false} />
                    <XAxis type="number" stroke="#475569" fontSize={10} fontFamily="monospace" />
                    <YAxis type="category" dataKey="name" stroke="#475569" fontSize={10} fontFamily="monospace" />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                      itemStyle={{ fontSize: '12px', fontFamily: 'monospace' }}
                    />
                    <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                      {chartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.fill} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Narrative Executive Posture report */}
            <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl flex flex-col justify-between font-mono shadow-2xl">
              <div className="space-y-4">
                <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  Executive Narrative
                </h3>
                {getDynamicNarrative()}
                <div className="border border-slate-800 bg-slate-950/60 p-3 rounded-lg flex items-center justify-between text-[10px] text-slate-500">
                  <div className="flex items-center gap-1.5">
                    <TrendingDown className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Threat Posture: {summaryData.threat_score > 40 ? 'ELEVATED' : 'DECREASING'}</span>
                  </div>
                  <span className={`font-bold ${summaryData.threat_score > 40 ? 'text-rose-400' : 'text-emerald-400'}`}>
                    {summaryData.threat_score > 40 ? 'WARNING' : 'SAFE'}
                  </span>
                </div>
              </div>
              <div className="border-t border-slate-800/60 pt-4 flex justify-between text-[9px] text-slate-500 uppercase">
                <span>sensor: online</span>
                <span>node: active</span>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
