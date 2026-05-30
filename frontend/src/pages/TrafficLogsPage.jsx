import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useConnection } from '../context/ConnectionContext';
import { 
  Terminal, 
  AlertTriangle,
  Search,
  ChevronLeft,
  ChevronRight,
  RefreshCw
} from 'lucide-react';
import SkeletonLoader from '../components/SkeletonLoader';
import EmptyState from '../components/EmptyState';

export default function TrafficLogsPage() {
  const { apiStatus, lastUpdated } = useConnection();
  const [logs, setLogs] = useState([]);
  const [totalLogs, setTotalLogs] = useState(0);
  const [loading, setLoading] = useState(true);

  const [searchTerm, setSearchTerm] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const logsPerPage = 50;

  const fetchTrafficLogs = async () => {
    try {
      const params = {
        page: currentPage,
        limit: logsPerPage
      };
      if (searchTerm) params.search = searchTerm;
      
      const response = await axios.get('/api/traffic-logs', { params });
      setLogs(response.data.logs || []);
      setTotalLogs(response.data.total || 0);
      setLoading(false);
    } catch (e) {
      console.error("[TRAFFIC LOGS API ERROR] Preserving cached logs state:", e);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTrafficLogs();
  }, [currentPage, searchTerm]);

  useEffect(() => {
    if (!autoRefresh) return;
    const timer = setInterval(fetchTrafficLogs, 5000); // refresh every 5s if active
    return () => clearInterval(timer);
  }, [currentPage, searchTerm, autoRefresh]);

  if (loading) {
    return <SkeletonLoader message="Streaming packet ingestion traffic logs directly from sniffer spool..." />;
  }

  const totalPages = Math.ceil(totalLogs / logsPerPage);

  function getProtoStyle(proto) {
    if (proto === 'TCP') return 'bg-blue-500/10 border-blue-500/20 text-blue-400';
    if (proto === 'UDP') return 'bg-cyan-500/10 border-cyan-500/20 text-cyan-400';
    if (proto === 'ICMP') return 'bg-amber-500/10 border-amber-500/20 text-amber-400';
    return 'bg-slate-500/10 border-slate-500/20 text-slate-400';
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Title */}
      <div className="flex justify-between items-center border-b border-slate-800/60 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
            <Terminal className="w-6 h-6 text-cyan-400" />
            Live Packet Ingestion Logs
          </h2>
          <p className="text-slate-500 text-xs mt-1">
            Real-time stdout spool capturing all packet metadata parsed by the Scapy kernel.
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

      {/* Main Console Log Terminal */}
      <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl space-y-4">
        {/* Search / Toggle Panel */}
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
              Packet Spool Console
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              Displaying chronological log packets parsed from traffic.log
            </p>
          </div>

          <div className="flex gap-2">
            {/* Search Input */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
              <input
                type="text"
                placeholder="Search logs..."
                value={searchTerm}
                onChange={(e) => {
                  setSearchTerm(e.target.value);
                  setCurrentPage(1);
                }}
                className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800/80 rounded-lg text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500 w-44"
              />
            </div>

            {/* Auto Refresh Toggler */}
            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              className={`flex items-center gap-1.5 px-3 py-1.5 border rounded-lg text-xs font-mono font-bold cursor-pointer transition-colors ${
                autoRefresh 
                  ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400' 
                  : 'bg-slate-950 border-slate-800 text-slate-500 hover:bg-slate-800/50'
              }`}
            >
              <RefreshCw className={`w-3.5 h-3.5 ${autoRefresh ? 'animate-spin' : ''}`} />
              <span>{autoRefresh ? 'AUTO' : 'PAUSED'}</span>
            </button>
          </div>
        </div>

        {/* Logs Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-[10px] font-mono text-slate-300 border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-500 text-left uppercase">
                <th className="py-2 px-3">Timestamp</th>
                <th className="py-2 px-3">Protocol</th>
                <th className="py-2 px-3">Source Socket</th>
                <th className="py-2 px-3">Destination Socket</th>
                <th className="py-2 px-3 text-right">Size</th>
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 ? (
                <tr>
                  <td colSpan="5" className="py-6">
                    <EmptyState message="No traffic events found in traffic.log log spools." />
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr 
                    key={log.id}
                    className="border-b border-slate-850 bg-slate-950/10 hover:bg-slate-950/50 font-mono transition-colors"
                  >
                    <td className="py-2 px-3 text-slate-400 whitespace-nowrap">{log.timestamp}</td>
                    <td className="py-2 px-3">
                      <span className={`px-1.5 py-0.5 border rounded text-[8px] font-bold ${getProtoStyle(log.protocol)}`}>
                        {log.protocol}
                      </span>
                    </td>
                    <td className="py-2 px-3 font-semibold text-slate-100">
                      {log.source_ip}
                      <span className="text-slate-500">:</span>
                      <span className="text-slate-400">{log.source_port}</span>
                    </td>
                    <td className="py-2 px-3 font-semibold text-slate-100">
                      {log.destination_ip}
                      <span className="text-slate-500">:</span>
                      <span className="text-slate-400">{log.destination_port}</span>
                    </td>
                    <td className="py-2 px-3 text-right font-bold text-slate-300">{log.packet_size} B</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Panel */}
        {totalPages > 1 && (
          <div className="flex justify-between items-center border-t border-slate-800/60 pt-4 font-mono text-[10px] text-slate-500">
            <span>Showing {(currentPage - 1) * logsPerPage + 1} - {Math.min(currentPage * logsPerPage, totalLogs)} of {totalLogs.toLocaleString()} log entries</span>
            
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
