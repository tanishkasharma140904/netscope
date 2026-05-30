import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useConnection } from '../context/ConnectionContext';
import { 
  TrendingUp, 
  AlertTriangle,
  Clock,
  Database,
  Activity,
  ArrowRightLeft,
  ChevronLeft,
  ChevronRight,
  Search
} from 'lucide-react';
import SkeletonLoader from '../components/SkeletonLoader';
import EmptyState from '../components/EmptyState';

export default function SessionAnalyticsPage({ onHostClick }) {
  const { apiStatus, lastUpdated } = useConnection();
  const [analytics, setAnalytics] = useState({
    active_sessions_count: 0,
    expired_sessions_count: 0,
    longest_session: null,
    largest_session: null,
    most_active_session: null
  });
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;

  const fetchSessionData = async () => {
    try {
      const [analyticsRes, sessionsRes] = await Promise.all([
        axios.get('/api/session-analytics'),
        axios.get('/api/sessions')
      ]);
      setAnalytics(analyticsRes.data);
      setSessions(sessionsRes.data.active_sessions || []);
      setLoading(false);
    } catch (e) {
      console.error("[SESSION ANALYTICS PAGE ERROR] Preserving local metrics caches:", e);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSessionData();
    const timer = setInterval(fetchSessionData, 5000); // refresh every 5s
    return () => clearInterval(timer);
  }, []);

  if (loading) {
    return <SkeletonLoader message="Deconstructing live socket connection descriptors..." />;
  }

  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function getProtoStyle(proto) {
    if (proto === 'TCP') return 'bg-blue-500/10 border-blue-500/20 text-blue-400';
    if (proto === 'UDP') return 'bg-cyan-500/10 border-cyan-500/20 text-cyan-400';
    if (proto === 'ICMP') return 'bg-amber-500/10 border-amber-500/20 text-amber-400';
    return 'bg-slate-500/10 border-slate-500/20 text-slate-400';
  }

  const filteredSessions = sessions.filter(s => {
    const term = searchTerm.toLowerCase();
    return (
      s.source_ip.toLowerCase().includes(term) ||
      s.destination_ip.toLowerCase().includes(term) ||
      s.protocol.toLowerCase().includes(term) ||
      String(s.source_port).includes(term) ||
      String(s.destination_port).includes(term)
    );
  });

  const totalPages = Math.ceil(filteredSessions.length / itemsPerPage);
  const paginatedSessions = filteredSessions.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Title */}
      <div className="flex justify-between items-center border-b border-slate-800/60 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
            <TrendingUp className="w-6 h-6 text-cyan-400" />
            Session Analytics Engine
          </h2>
          <p className="text-slate-500 text-xs mt-1">
            Millisecond lock socket monitoring providing detailed forensic summaries of socket lifespans.
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

      {/* KPI Cards (Active/Expired) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-6 rounded-xl relative group overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
            <ArrowRightLeft className="w-16 h-16 text-cyan-400" />
          </div>
          <p className="text-[10px] text-slate-500 font-mono tracking-widest uppercase">ACTIVE CONNS</p>
          <h4 className="text-2xl font-bold text-slate-100 mt-2 font-mono">
            {analytics.active_sessions_count.toLocaleString()} Sessions
          </h4>
          <p className="text-xs text-slate-400 mt-2 font-mono">
            Live telemetry tracks: <span className="text-cyan-400 font-semibold">{sessions.length} detailed</span>
          </p>
        </div>

        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-6 rounded-xl relative group overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
            <Clock className="w-16 h-16 text-rose-400" />
          </div>
          <p className="text-[10px] text-slate-500 font-mono tracking-widest uppercase">TOTAL EXPIRED & RECLAIMED</p>
          <h4 className="text-2xl font-bold text-rose-400 mt-2 font-mono">
            {analytics.expired_sessions_count.toLocaleString()} Sessions
          </h4>
          <p className="text-xs text-slate-400 mt-2 font-mono">
            Uptime auto-recovery: <span className="text-cyan-400 font-semibold">Enabled</span>
          </p>
        </div>
      </div>

      {/* Extremum Sessions Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Longest Session */}
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-5 rounded-xl space-y-3 relative group overflow-hidden">
          <div className="absolute top-0 right-0 p-3 opacity-10">
            <Clock className="w-12 h-12 text-cyan-400" />
          </div>
          <p className="text-[9px] text-slate-500 font-mono tracking-widest uppercase font-bold">LONGEST DURATION</p>
          {analytics.longest_session ? (
            <div className="font-mono text-[10px] space-y-1">
              <div className="text-slate-100 font-bold hover:text-cyan-400 cursor-pointer overflow-hidden text-ellipsis whitespace-nowrap" onClick={() => onHostClick && onHostClick(analytics.longest_session.source_ip)}>
                {analytics.longest_session.source_ip}
              </div>
              <div className="text-slate-500">→ {analytics.longest_session.destination_ip}</div>
              <div className="text-slate-300 mt-1 flex justify-between">
                <span>Duration: <span className="text-cyan-400 font-bold">{analytics.longest_session.duration}s</span></span>
                <span>{analytics.longest_session.protocol}</span>
              </div>
            </div>
          ) : (
            <p className="text-xs text-slate-600 font-mono">No sessions tracked</p>
          )}
        </div>

        {/* Largest Session */}
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-5 rounded-xl space-y-3 relative group overflow-hidden">
          <div className="absolute top-0 right-0 p-3 opacity-10">
            <Database className="w-12 h-12 text-cyan-400" />
          </div>
          <p className="text-[9px] text-slate-500 font-mono tracking-widest uppercase font-bold">LARGEST VOLUME</p>
          {analytics.largest_session ? (
            <div className="font-mono text-[10px] space-y-1">
              <div className="text-slate-100 font-bold hover:text-cyan-400 cursor-pointer overflow-hidden text-ellipsis whitespace-nowrap" onClick={() => onHostClick && onHostClick(analytics.largest_session.source_ip)}>
                {analytics.largest_session.source_ip}
              </div>
              <div className="text-slate-500">→ {analytics.largest_session.destination_ip}</div>
              <div className="text-slate-300 mt-1 flex justify-between">
                <span>Volume: <span className="text-cyan-400 font-bold">{formatBytes(analytics.largest_session.bytes)}</span></span>
                <span>{analytics.largest_session.protocol}</span>
              </div>
            </div>
          ) : (
            <p className="text-xs text-slate-600 font-mono">No sessions tracked</p>
          )}
        </div>

        {/* Most Active Session */}
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-5 rounded-xl space-y-3 relative group overflow-hidden">
          <div className="absolute top-0 right-0 p-3 opacity-10">
            <Activity className="w-12 h-12 text-cyan-400" />
          </div>
          <p className="text-[9px] text-slate-500 font-mono tracking-widest uppercase font-bold">MOST ACTIVE (PACKETS)</p>
          {analytics.most_active_session ? (
            <div className="font-mono text-[10px] space-y-1">
              <div className="text-slate-100 font-bold hover:text-cyan-400 cursor-pointer overflow-hidden text-ellipsis whitespace-nowrap" onClick={() => onHostClick && onHostClick(analytics.most_active_session.source_ip)}>
                {analytics.most_active_session.source_ip}
              </div>
              <div className="text-slate-500">→ {analytics.most_active_session.destination_ip}</div>
              <div className="text-slate-300 mt-1 flex justify-between">
                <span>Packets: <span className="text-cyan-400 font-bold">{analytics.most_active_session.packets} pkts</span></span>
                <span>{analytics.most_active_session.protocol}</span>
              </div>
            </div>
          ) : (
            <p className="text-xs text-slate-600 font-mono">No sessions tracked</p>
          )}
        </div>
      </div>

      {/* Main Table view */}
      <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl space-y-4">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
              Active Connection Sockets
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              List of active stateful TCP and UDP sessions discovered on network segment
            </p>
          </div>
          
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search sockets..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setCurrentPage(1);
              }}
              className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800/80 rounded-lg text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500 w-44"
            />
          </div>
        </div>

        {/* Sessions table */}
        <div className="overflow-x-auto">
          <table className="w-full text-[10px] font-mono text-slate-300 border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-500 text-left uppercase">
                <th className="py-2.5 px-3">Protocol</th>
                <th className="py-2.5 px-3">Source Endpoint</th>
                <th className="py-2.5 px-3">Destination Endpoint</th>
                <th className="py-2.5 px-3 text-right">Packets</th>
                <th className="py-2.5 px-3 text-right">Bytes</th>
                <th className="py-2.5 px-3 text-right">Duration</th>
              </tr>
            </thead>
            <tbody>
              {filteredSessions.length === 0 ? (
                <tr>
                  <td colSpan="6" className="py-6">
                    <EmptyState message="No sessions discovered on segment" />
                  </td>
                </tr>
              ) : (
                paginatedSessions.map((session, idx) => (
                  <tr 
                    key={idx}
                    className="border-b border-slate-800/50 bg-slate-950/20 hover:bg-slate-950/60 transition-colors"
                  >
                    <td className="py-2.5 px-3">
                      <span className={`px-1.5 py-0.5 border rounded uppercase font-bold text-[8px] ${getProtoStyle(session.protocol)}`}>
                        {session.protocol}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-semibold">
                      <button onClick={() => onHostClick && onHostClick(session.source_ip)} className="hover:text-cyan-400 hover:underline font-semibold text-slate-100">
                        {session.source_ip}
                      </button>
                      <span className="text-slate-500">:</span>
                      <span className="text-slate-400">{session.source_port}</span>
                    </td>
                    <td className="py-2.5 px-3 font-semibold">
                      <button onClick={() => onHostClick && onHostClick(session.destination_ip)} className="hover:text-cyan-400 hover:underline font-semibold text-slate-100">
                        {session.destination_ip}
                      </button>
                      <span className="text-slate-500">:</span>
                      <span className="text-slate-400">{session.destination_port}</span>
                    </td>
                    <td className="py-2.5 px-3 text-right text-slate-200">{session.packets.toLocaleString()} pkts</td>
                    <td className="py-2.5 px-3 text-right text-slate-200">{formatBytes(session.bytes)}</td>
                    <td className="py-2.5 px-3 text-right text-slate-400 font-bold">{session.duration}s</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex justify-between items-center border-t border-slate-800/60 pt-4 font-mono text-[10px] text-slate-500">
            <span>Showing {(currentPage - 1) * itemsPerPage + 1} - {Math.min(currentPage * itemsPerPage, filteredSessions.length)} of {filteredSessions.length} active sessions</span>
            
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
