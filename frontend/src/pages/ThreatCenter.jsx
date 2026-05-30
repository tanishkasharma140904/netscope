import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useConnection } from '../context/ConnectionContext';
import { 
  ShieldAlert, 
  Search, 
  Filter, 
  AlertTriangle, 
  Shield, 
  Skull 
} from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell } from 'recharts';
import SkeletonLoader from '../components/SkeletonLoader';
import EmptyState from '../components/EmptyState';

export default function ThreatCenter({ onHostClick }) {
  const { apiStatus, lastUpdated } = useConnection();
  const [threatData, setThreatData] = useState({
    threat_score: 0,
    risk_level: 'LOW',
    active_threats: [],
    recent_alerts: []
  });
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [loading, setLoading] = useState(true);

  const fetchThreats = async () => {
    try {
      const response = await axios.get('/api/threats');
      setThreatData({
        threat_score: response.data.threat_score || 0,
        risk_level: response.data.risk_level || 'LOW',
        active_threats: response.data.active_threats || [],
        recent_alerts: response.data.recent_alerts || []
      });
      setLoading(false);
    } catch (e) {
      console.error("[THREAT CENTER API ERROR] Recovery triggered, preserving cached records:", e);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();
    const timer = setInterval(fetchThreats, 5000);
    return () => clearInterval(timer);
  }, []);

  // Filter logs based on search term & severity filters
  const filteredAlerts = threatData.recent_alerts.filter((alert) => {
    const matchesSearch = alert.toLowerCase().includes(searchTerm.toLowerCase());
    
    if (filterSeverity === 'ALL') return matchesSearch;
    if (filterSeverity === 'CRITICAL') return matchesSearch && (alert.toUpperCase().includes('CRITICAL') || alert.toUpperCase().includes('HOST DOMINANCE'));
    if (filterSeverity === 'HIGH') return matchesSearch && (alert.toUpperCase().includes('HIGH') || alert.toUpperCase().includes('PORT SCAN') || alert.toUpperCase().includes('RECONNAISSANCE'));
    return matchesSearch && !alert.toUpperCase().includes('CRITICAL') && !alert.toUpperCase().includes('HIGH') && !alert.toUpperCase().includes('HOST DOMINANCE');
  });

  // Calculate severity categories for chart representation
  const getSeverityCounts = () => {
    let critical = 0;
    let high = 0;
    let medium = 0;

    threatData.recent_alerts.forEach((alert) => {
      const a = alert.toUpperCase();
      if (a.includes('CRITICAL') || a.includes('HOST DOMINANCE')) {
        critical++;
      } else if (a.includes('HIGH') || a.includes('PORT SCAN') || a.includes('RECONNAISSANCE')) {
        high++;
      } else {
        medium++;
      }
    });

    return [
      { name: 'Critical Severity', count: critical, color: '#f43f5e' },
      { name: 'High Severity', count: high, color: '#f97316' },
      { name: 'Medium Severity', count: medium, color: '#f59e0b' }
    ];
  };

  const chartData = getSeverityCounts();

  const getAlertSeverity = (alert) => {
    const a = alert.toUpperCase();
    if (a.includes('CRITICAL') || a.includes('DOMINANCE')) return 'CRITICAL';
    if (a.includes('HIGH') || a.includes('PORT SCAN') || a.includes('RECON')) return 'HIGH';
    return 'MEDIUM';
  };

  const getBadgeStyle = (severity) => {
    if (severity === 'CRITICAL') return 'bg-rose-500/10 border-rose-500/20 text-rose-400';
    if (severity === 'HIGH') return 'bg-orange-500/10 border-orange-500/20 text-orange-400';
    return 'bg-amber-500/10 border-amber-500/20 text-amber-400';
  };

  if (loading) {
    return <SkeletonLoader message="Analyzing threat intelligence logs..." />;
  }

  const hasAlerts = threatData.recent_alerts.length > 0;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Title */}
      <div className="flex justify-between items-center border-b border-slate-800/60 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 tracking-tight">
            Threat Intelligence Center
          </h2>
          <p className="text-slate-500 text-xs mt-1">
            Real-time deep analysis of captured alerts, anomalies, and active network threats.
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

      {/* Overview Cards Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Total Ingress Warnings */}
        <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl flex items-center justify-between font-mono">
          <div className="space-y-1">
            <span className="text-[10px] text-slate-500 font-bold uppercase">Alerts Captured</span>
            <h4 className="text-3xl font-extrabold text-slate-100">{threatData.recent_alerts.length}</h4>
            <span className="text-[9px] text-slate-600 block">MAX IN MEMORY OVERFLOW: 20</span>
          </div>
          <AlertTriangle className="w-10 h-10 text-orange-500 opacity-20" />
        </div>

        {/* Current Active Anomaly Ticks */}
        <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl flex items-center justify-between font-mono">
          <div className="space-y-1">
            <span className="text-[10px] text-slate-500 font-bold uppercase">Active Anomalies</span>
            <h4 className="text-3xl font-extrabold text-rose-500">{threatData.active_threats.length}</h4>
            <span className="text-[9px] text-slate-600 block">CURRENT TICK TRIGGERED</span>
          </div>
          <Skull className="w-10 h-10 text-rose-500 opacity-20" />
        </div>

        {/* Security Health status */}
        <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl flex items-center justify-between font-mono">
          <div className="space-y-1">
            <span className="text-[10px] text-slate-500 font-bold uppercase">Threat Score Index</span>
            <h4 className={`text-3xl font-extrabold ${
              threatData.threat_score > 40 ? 'text-rose-500' : 'text-emerald-500'
            }`}>{threatData.threat_score}/100</h4>
            <span className="text-[9px] text-slate-600 block">CAP POSTURE LIMIT: 100</span>
          </div>
          <Shield className="w-10 h-10 text-emerald-500 opacity-20" />
        </div>
      </div>

      {/* Main Analysis grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Filterable alerts timeline (2/3 width) */}
        <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800 p-6 rounded-xl flex flex-col justify-between min-h-[350px]">
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
              <div>
                <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
                  Threat Activity Timeline Log
                </h3>
                <p className="text-[10px] text-slate-500 font-mono">
                  Ingress chronological sensor captures
                </p>
              </div>

              {/* Filters */}
              <div className="flex gap-2">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
                  <input
                    type="text"
                    placeholder="Search logs..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800/80 rounded-lg text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500 w-40"
                  />
                </div>
                <div className="relative flex items-center">
                  <Filter className="w-3.5 h-3.5 text-slate-500 absolute left-2.5" />
                  <select
                    value={filterSeverity}
                    onChange={(e) => setFilterSeverity(e.target.value)}
                    className="pl-8 pr-2 py-1.5 bg-slate-950 border border-slate-800/80 rounded-lg text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500 appearance-none cursor-pointer"
                  >
                    <option value="ALL">Severity: ALL</option>
                    <option value="CRITICAL">Severity: CRIT</option>
                    <option value="HIGH">Severity: HIGH</option>
                    <option value="MEDIUM">Severity: MED</option>
                  </select>
                </div>
              </div>
            </div>

            {/* List */}
            <div className="space-y-2 max-h-[250px] overflow-y-auto pr-1">
              {!hasAlerts ? (
                <EmptyState message="No threats detected" />
              ) : filteredAlerts.length > 0 ? (
                filteredAlerts.map((alert, index) => {
                  const severity = getAlertSeverity(alert);
                  return (
                    <div 
                      key={index}
                      className="p-3 bg-slate-950/60 border border-slate-900 rounded-lg flex items-center justify-between gap-4 font-mono text-[10px] text-slate-300"
                    >
                      <div className="flex items-center gap-3">
                        <span className={`px-2 py-0.5 border rounded uppercase font-bold text-[9px] ${
                          getBadgeStyle(severity)
                        }`}>
                          {severity}
                        </span>
                        <span className="font-semibold text-slate-200">{alert}</span>
                      </div>
                      <span className="text-slate-600 font-bold shrink-0">LOGGED</span>
                    </div>
                  );
                })
              ) : (
                <div className="text-center text-slate-600 py-12 font-mono text-xs">
                  No alerts match the active search parameters.
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Severity Distribution chart (1/3 width) */}
        <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
              Anomalies Severity Distribution
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              Proportional distribution of captured logs
            </p>
          </div>
          
          <div className="h-60 w-full mt-4">
            {!hasAlerts ? (
              <EmptyState message="No alerts available" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} margin={{ top: 10, right: 5, left: -25, bottom: 0 }}>
                  <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="name" stroke="#475569" fontSize={9} fontFamily="monospace" tickLine={false} />
                  <YAxis stroke="#475569" fontSize={9} fontFamily="monospace" tickLine={false} axisLine={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                    itemStyle={{ fontSize: '12px', fontFamily: 'monospace' }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {chartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
