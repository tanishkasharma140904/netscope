import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useConnection } from '../context/ConnectionContext';
import { 
  ShieldAlert, 
  AlertTriangle,
  Search,
  Filter,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';
import SkeletonLoader from '../components/SkeletonLoader';
import EmptyState from '../components/EmptyState';

export default function SecurityEventsPage() {
  const { apiStatus, lastUpdated } = useConnection();
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);

  const [searchTerm, setSearchTerm] = useState('');
  const [filterClass, setFilterClass] = useState('ALL');
  
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 12;

  const fetchSecurityEvents = async () => {
    try {
      const params = {};
      if (searchTerm) params.search = searchTerm;
      const response = await axios.get('/api/security-events', { params });
      setEvents(response.data.events || []);
      setLoading(false);
    } catch (e) {
      console.error("[SECURITY EVENTS API ERROR] Preserving cache records:", e);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSecurityEvents();
    const timer = setInterval(fetchSecurityEvents, 5000); // refresh every 5s
    return () => clearInterval(timer);
  }, [searchTerm]);

  if (loading) {
    return <SkeletonLoader message="Parsing live security alerts event logging spoolers..." />;
  }

  function getSeverity(cls) {
    if (cls === 'Port Scan' || cls === 'Reconnaissance') return 'HIGH';
    if (cls === 'Suspicious Port' || cls === 'Bandwidth Spike') return 'HIGH';
    if (cls === 'Network Dominance') return 'CRITICAL';
    return 'MEDIUM';
  }

  function getSeverityStyle(sev) {
    if (sev === 'CRITICAL') return 'bg-rose-500/10 border-rose-500/20 text-rose-400';
    if (sev === 'HIGH') return 'bg-orange-500/10 border-orange-500/20 text-orange-400';
    if (sev === 'MEDIUM') return 'bg-amber-500/10 border-amber-500/20 text-amber-400';
    return 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400';
  }

  const filteredEvents = events.filter(e => {
    if (filterClass === 'ALL') return true;
    return e.classification === filterClass;
  });

  const totalPages = Math.ceil(filteredEvents.length / itemsPerPage);
  const paginatedEvents = filteredEvents.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Title */}
      <div className="flex justify-between items-center border-b border-slate-800/60 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-orange-400" />
            Security Incident Log Stream
          </h2>
          <p className="text-slate-500 text-xs mt-1">
            Raw file capture from alerts.log showing real-time security triggers classified by engine rules.
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

      {/* Main Console View */}
      <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl space-y-4">
        {/* Filters */}
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
              alerts.log Live Spooler
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              Raw anomalies parsed chronologically from active log files
            </p>
          </div>

          <div className="flex gap-2">
            {/* Search */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
              <input
                type="text"
                placeholder="Search log messages..."
                value={searchTerm}
                onChange={(e) => {
                  setSearchTerm(e.target.value);
                  setCurrentPage(1);
                }}
                className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800/80 rounded-lg text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500 w-44"
              />
            </div>

            {/* Classification Filter */}
            <div className="relative flex items-center">
              <Filter className="w-3.5 h-3.5 text-slate-500 absolute left-2.5" />
              <select
                value={filterClass}
                onChange={(e) => {
                  setFilterClass(e.target.value);
                  setCurrentPage(1);
                }}
                className="pl-8 pr-2 py-1.5 bg-slate-950 border border-slate-800/80 rounded-lg text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500 appearance-none cursor-pointer"
              >
                <option value="ALL">Class: ALL</option>
                <option value="Anomaly">Class: Anomaly</option>
                <option value="Port Scan">Class: Port Scan</option>
                <option value="Reconnaissance">Class: Recon</option>
                <option value="Suspicious Port">Class: Susp Port</option>
                <option value="Bandwidth Spike">Class: Bandwidth Spike</option>
                <option value="Protocol Abuse">Class: Protocol Abuse</option>
                <option value="Network Dominance">Class: Network Dominance</option>
              </select>
            </div>
          </div>
        </div>

        {/* Events Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-[10px] font-mono text-slate-300 border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-500 text-left uppercase">
                <th className="py-2.5 px-3">Alert Time</th>
                <th className="py-2.5 px-3">Classification</th>
                <th className="py-2.5 px-3 text-center">Risk</th>
                <th className="py-2.5 px-3">Event Anomaly Message</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan="4" className="py-6">
                    <EmptyState message="No raw security anomalies parsed from alerts.log" />
                  </td>
                </tr>
              ) : (
                paginatedEvents.map((evt) => {
                  const sev = getSeverity(evt.classification);
                  return (
                    <tr 
                      key={evt.id}
                      className="border-b border-slate-850 bg-slate-950/10 hover:bg-slate-950/50 transition-colors"
                    >
                      <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">{evt.timestamp}</td>
                      <td className="py-2.5 px-3">
                        <span className="bg-orange-500/10 text-orange-400 border border-orange-500/20 text-[8px] font-extrabold px-1.5 py-0.5 rounded uppercase">
                          {evt.classification}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-center">
                        <span className={`px-2 py-0.5 border rounded uppercase font-bold text-[9px] ${getSeverityStyle(sev)}`}>
                          {sev}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-200 font-semibold">{evt.message}</td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex justify-between items-center border-t border-slate-800/60 pt-4 font-mono text-[10px] text-slate-500">
            <span>Showing {(currentPage - 1) * itemsPerPage + 1} - {Math.min(currentPage * itemsPerPage, filteredEvents.length)} of {filteredEvents.length} alert events</span>
            
            <div className="flex gap-2">
              <button
                disabled={currentPage === 1}
                onClick={() => setCurrentPage(prev => prev - 1)}
                className="p-1.5 bg-slate-950 border border-slate-850 hover:bg-slate-800 rounded text-slate-400 hover:text-slate-200 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
              <span className="flex items-center px-3 py-1.5 border border-slate-850 bg-slate-950/40 rounded font-semibold text-slate-300">
                PAGE {currentPage} OF {totalPages}
              </span>
              <button
                disabled={currentPage === totalPages}
                onClick={() => setCurrentPage(prev => prev + 1)}
                className="p-1.5 bg-slate-950 border border-slate-850 hover:bg-slate-800 rounded text-slate-400 hover:text-slate-200 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
