import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useConnection } from '../context/ConnectionContext';
import { 
  AlertCircle, 
  AlertTriangle,
  Search,
  Filter
} from 'lucide-react';
import SkeletonLoader from '../components/SkeletonLoader';
import EmptyState from '../components/EmptyState';

export default function AlertHistoryPage() {
  const { apiStatus, lastUpdated } = useConnection();
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterCategory, setFilterCategory] = useState('ALL');

  const fetchAlerts = async () => {
    try {
      const params = {};
      if (filterCategory !== 'ALL') params.category = filterCategory;
      if (filterSeverity !== 'ALL') params.severity = filterSeverity;
      if (searchTerm) params.search = searchTerm;
      
      const response = await axios.get('/api/alert-history', { params });
      setAlerts(response.data || []);
      setLoading(false);
    } catch (e) {
      console.error("[ALERT HISTORY API ERROR] Preserving cached database logs:", e);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
    const timer = setInterval(fetchAlerts, 5000); // refresh every 5s
    return () => clearInterval(timer);
  }, [searchTerm, filterSeverity, filterCategory]);

  if (loading) {
    return <SkeletonLoader message="Retrieving security incident history database logs..." />;
  }

  function getSeverityStyle(sev) {
    if (sev === 'CRITICAL') return 'bg-rose-500/10 border-rose-500/20 text-rose-400';
    if (sev === 'HIGH') return 'bg-orange-500/10 border-orange-500/20 text-orange-400';
    if (sev === 'MEDIUM') return 'bg-amber-500/10 border-amber-500/20 text-amber-400';
    return 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400';
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Title */}
      <div className="flex justify-between items-center border-b border-slate-800/60 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
            <AlertCircle className="w-6 h-6 text-rose-400 animate-pulse" />
            Alert Incident Database
          </h2>
          <p className="text-slate-500 text-xs mt-1">
            Historical audit log of security threats and protocol anomalies recorded inside SQLite database.
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

      {/* Main Table Card */}
      <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl space-y-4">
        {/* Filters */}
        <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
              Anomalies Database Archive
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              Audit log listing all historic security events mapped by the anomaly detector
            </p>
          </div>

          <div className="flex flex-wrap gap-2 w-full lg:w-auto">
            {/* Search */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
              <input
                type="text"
                placeholder="Search messages..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800/80 rounded-lg text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500 w-44"
              />
            </div>

            {/* Severity Filter */}
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
                <option value="LOW">Severity: LOW</option>
              </select>
            </div>

            {/* Category Filter */}
            <div className="relative flex items-center">
              <Filter className="w-3.5 h-3.5 text-slate-500 absolute left-2.5" />
              <select
                value={filterCategory}
                onChange={(e) => setFilterCategory(e.target.value)}
                className="pl-8 pr-2 py-1.5 bg-slate-950 border border-slate-800/80 rounded-lg text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500 appearance-none cursor-pointer"
              >
                <option value="ALL">Category: ALL</option>
                <option value="Anomaly">Category: Anomaly</option>
                <option value="Port Scan">Category: Port Scan</option>
                <option value="Reconnaissance">Category: Recon</option>
                <option value="Suspicious Port">Category: Susp Port</option>
                <option value="Bandwidth Spike">Category: Bandwidth Spike</option>
                <option value="Protocol Abuse">Category: Protocol Abuse</option>
                <option value="Network Dominance">Category: Network Dominance</option>
              </select>
            </div>
          </div>
        </div>

        {/* Alerts Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-[10px] font-mono text-slate-300 border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-500 text-left uppercase">
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Category</th>
                <th className="py-2.5 px-3 text-center">Severity</th>
                <th className="py-2.5 px-3">Anomaly Assessment Log</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan="4" className="py-6">
                    <EmptyState message="No alerts found in database logs matching current parameters." />
                  </td>
                </tr>
              ) : (
                alerts.slice(0, 50).map((alert) => (
                  <tr 
                    key={alert.id}
                    className="border-b border-slate-800/50 bg-slate-950/20 hover:bg-slate-950/60 transition-colors"
                  >
                    <td className="py-3 px-3 text-slate-400 whitespace-nowrap">{alert.timestamp}</td>
                    <td className="py-3 px-3">
                      <span className="bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 text-[8px] font-extrabold px-1.5 py-0.5 rounded uppercase">
                        {alert.alert_type}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-center">
                      <span className={`px-2 py-0.5 border rounded uppercase font-bold text-[9px] ${getSeverityStyle(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-200 font-semibold max-w-md overflow-hidden text-ellipsis whitespace-nowrap">
                      {alert.message}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
