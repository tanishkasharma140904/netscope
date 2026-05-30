import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useConnection } from '../context/ConnectionContext';
import { 
  Network, 
  Search, 
  ArrowUpDown, 
  Activity, 
  Database, 
  Flame,
  AlertTriangle
} from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell } from 'recharts';
import SkeletonLoader from '../components/SkeletonLoader';
import EmptyState from '../components/EmptyState';

export default function SessionsPage({ onHostClick }) {
  const { apiStatus, lastUpdated } = useConnection();
  const [sessions, setSessions] = useState([]);
  const [sessionCount, setSessionCount] = useState(0);
  const [searchTerm, setSearchTerm] = useState('');
  const [sortField, setSortField] = useState('packets');
  const [sortOrder, setSortOrder] = useState('desc');
  const [loading, setLoading] = useState(true);

  const fetchSessions = async () => {
    try {
      const response = await axios.get('/api/sessions');
      setSessions(response.data.active_sessions || []);
      setSessionCount(response.data.session_count || 0);
      setLoading(false);
    } catch (e) {
      console.error("[SESSIONS PAGE API ERROR] Recovery triggered, preserving cached records:", e);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSessions();
    const timer = setInterval(fetchSessions, 5000);
    return () => clearInterval(timer);
  }, []);

  const formatBytes = (num) => {
    if (num >= 1024 * 1024) return `${(num / (1024 * 1024)).toFixed(2)} MB`;
    if (num >= 1024) return `${(num / 1024).toFixed(2)} KB`;
    return `${num} B`;
  };

  const filteredSessions = sessions.filter((s) => {
    const term = searchTerm.toLowerCase();
    return s.source_ip.toLowerCase().includes(term) || s.destination_ip.toLowerCase().includes(term);
  });

  const sortedSessions = [...filteredSessions].sort((a, b) => {
    const aVal = a[sortField];
    const bVal = b[sortField];
    if (sortOrder === 'asc') return aVal > bVal ? 1 : -1;
    return aVal < bVal ? 1 : -1;
  });

  const toggleSort = (field) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  const getProtocolData = () => {
    let tcp = 0;
    let udp = 0;
    let icmp = 0;

    sessions.forEach(s => {
      if (s.protocol === 'TCP') tcp++;
      else if (s.protocol === 'UDP') udp++;
      else if (s.protocol === 'ICMP') icmp++;
    });

    return [
      { name: 'TCP', count: tcp, fill: '#3b82f6' },
      { name: 'UDP', count: udp, fill: '#06b6d4' },
      { name: 'ICMP', count: icmp, fill: '#f59e0b' }
    ];
  };

  const chartData = getProtocolData();

  const getTopSessionMetrics = () => {
    if (sessions.length === 0) return { largest: 'N/A', longest: 'N/A' };
    const largest = [...sessions].sort((a, b) => b.bytes - a.bytes)[0];
    const longest = [...sessions].sort((a, b) => b.duration - a.duration)[0];

    return {
      largest: largest ? `${largest.source_ip} → ${largest.destination_ip} (${formatBytes(largest.bytes)})` : 'N/A',
      longest: longest ? `${longest.source_ip} → ${longest.destination_ip} (${longest.duration}s)` : 'N/A'
    };
  };

  const topMetrics = getTopSessionMetrics();

  if (loading) {
    return <SkeletonLoader message="Analyzing communication sessions..." />;
  }

  const hasSessions = sessions.length > 0;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Title */}
      <div className="flex justify-between items-center border-b border-slate-800/60 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 tracking-tight">
            Passive Session Analytics
          </h2>
          <p className="text-slate-500 text-xs mt-1">
            Real-time metadata, protocol distributions, and volume rates of monitored network conversations.
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

      {/* Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 font-mono">
        <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-[10px] text-slate-500 font-bold uppercase">Active Connections</span>
            <h4 className="text-3xl font-extrabold text-slate-100">{sessionCount}</h4>
            <span className="text-[9px] text-slate-600 block">REAL-TIME IN MEMORY</span>
          </div>
          <Activity className="w-10 h-10 text-cyan-400 opacity-20" />
        </div>

        <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-[10px] text-slate-500 font-bold uppercase">Largest Data Session</span>
            <h5 className="text-xs font-bold text-slate-300 truncate max-w-[220px]">{topMetrics.largest}</h5>
            <span className="text-[9px] text-slate-600 block">TOP INGRESS VOLUME</span>
          </div>
          <Database className="w-10 h-10 text-purple-400 opacity-20" />
        </div>

        <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-xl flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-[10px] text-slate-500 font-bold uppercase">Longest Session Duration</span>
            <h5 className="text-xs font-bold text-slate-300 truncate max-w-[220px]">{topMetrics.longest}</h5>
            <span className="text-[9px] text-slate-600 block">MAX TEMPORAL CONVERSATION</span>
          </div>
          <Flame className="w-10 h-10 text-amber-500 opacity-20" />
        </div>
      </div>

      {/* Protocol Session count charts */}
      <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl flex flex-col justify-between">
        <div>
          <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
            Sessions Protocol Splits
          </h3>
          <p className="text-[10px] text-slate-500 font-mono">
            Active sockets parsed across protocols
          </p>
        </div>
        <div className="h-60 w-full mt-4">
          {!hasSessions ? (
            <EmptyState message="No traffic data available" />
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
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Passive Communication Sessions Log */}
      <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl space-y-4">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
              Passive Communication Sessions Log
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              Live sessions captured on ethernet boundaries
            </p>
          </div>
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search IPs..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800/80 rounded-lg text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500 w-48"
            />
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-[10px] font-mono text-slate-300 border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-500 text-left uppercase">
                <th className="py-2.5 px-3">Protocol</th>
                <th className="py-2.5 px-3">Source IP</th>
                <th className="py-2.5 px-3">Destination IP</th>
                <th className="py-2.5 px-3 cursor-pointer select-none hover:text-slate-200" onClick={() => toggleSort('packets')}>
                  Packets <ArrowUpDown className="w-3 h-3 inline ml-1" />
                </th>
                <th className="py-2.5 px-3 cursor-pointer select-none hover:text-slate-200" onClick={() => toggleSort('bytes')}>
                  Bytes <ArrowUpDown className="w-3 h-3 inline ml-1" />
                </th>
                <th className="py-2.5 px-3 cursor-pointer select-none hover:text-slate-200" onClick={() => toggleSort('duration')}>
                  Duration <ArrowUpDown className="w-3 h-3 inline ml-1" />
                </th>
              </tr>
            </thead>
            <tbody>
              {!hasSessions ? (
                <tr>
                  <td colSpan="6" className="py-6">
                    <EmptyState message="No active sessions detected" />
                  </td>
                </tr>
              ) : sortedSessions.length > 0 ? (
                sortedSessions.map((session, index) => (
                  <tr 
                    key={index}
                    className="border-b border-slate-800/50 bg-slate-950/20 hover:bg-slate-950/60 transition-colors"
                  >
                    <td className="py-2.5 px-3">
                      <span className={`px-1.5 py-0.5 rounded font-extrabold text-[9px] ${
                        session.protocol === 'TCP' ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' : 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                      }`}>
                        {session.protocol}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-100 font-semibold">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onHostClick && onHostClick(session.source_ip);
                        }}
                        className="hover:text-cyan-400 hover:underline cursor-pointer text-left font-semibold text-slate-100"
                      >
                        {session.source_ip}
                      </button>
                      :{session.source_port}
                    </td>
                    <td className="py-2.5 px-3 text-slate-100 font-semibold">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onHostClick && onHostClick(session.destination_ip);
                        }}
                        className="hover:text-cyan-400 hover:underline cursor-pointer text-left font-semibold text-slate-100"
                      >
                        {session.destination_ip}
                      </button>
                      :{session.destination_port}
                    </td>
                    <td className="py-2.5 px-3 font-semibold">{session.packets} pkts</td>
                    <td className="py-2.5 px-3 font-semibold text-slate-200">{formatBytes(session.bytes)}</td>
                    <td className="py-2.5 px-3 font-semibold text-cyan-400">{session.duration}s</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="6" className="text-center text-slate-600 py-12">
                    No sessions match the active search filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
