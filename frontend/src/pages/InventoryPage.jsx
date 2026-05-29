import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useConnection } from '../context/ConnectionContext';
import { 
  Server, 
  Search, 
  ArrowUpDown, 
  ShieldAlert, 
  ChevronLeft, 
  ChevronRight,
  AlertTriangle
} from 'lucide-react';
import SkeletonLoader from '../components/SkeletonLoader';
import EmptyState from '../components/EmptyState';

export default function InventoryPage({ onHostClick }) {
  const { apiStatus, lastUpdated } = useConnection();
  const [hosts, setHosts] = useState([]);
  const [hostCount, setHostCount] = useState(0);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterRisk, setFilterRisk] = useState('ALL');
  const [sortField, setSortField] = useState('packets');
  const [sortOrder, setSortOrder] = useState('desc');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 8;
  const [loading, setLoading] = useState(true);

  const fetchInventory = async () => {
    try {
      const response = await axios.get('/api/inventory');
      setHosts(response.data.hosts || []);
      setHostCount(response.data.host_count || 0);
      setLoading(false);
    } catch (e) {
      console.error("[INVENTORY PAGE API ERROR] Recovery triggered, preserving cached records:", e);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchInventory();
    const timer = setInterval(fetchInventory, 10000); // refresh every 10s
    return () => clearInterval(timer);
  }, []);

  const getHostRisk = (host) => {
    const isPrivate = host.ip.startsWith('192.168.') || host.ip.startsWith('10.') || host.ip.startsWith('172.');
    if (!isPrivate && host.packet_count > 500) return 'CRITICAL';
    if (host.packet_count > 1000) return 'HIGH';
    if (!isPrivate) return 'MEDIUM';
    return 'LOW';
  };

  const getRiskStyle = (risk) => {
    if (risk === 'CRITICAL') return 'bg-rose-500/10 border-rose-500/20 text-rose-400';
    if (risk === 'HIGH') return 'bg-orange-500/10 border-orange-500/20 text-orange-400';
    if (risk === 'MEDIUM') return 'bg-amber-500/10 border-amber-500/20 text-amber-400';
    return 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400';
  };

  const filteredHosts = hosts.filter((h) => {
    const matchesSearch = h.ip.toLowerCase().includes(searchTerm.toLowerCase());
    const risk = getHostRisk(h);
    
    if (filterRisk === 'ALL') return matchesSearch;
    return matchesSearch && risk === filterRisk;
  });

  const sortedHosts = [...filteredHosts].sort((a, b) => {
    let aVal = a[sortField === 'risk' ? 'packets' : sortField];
    let bVal = b[sortField === 'risk' ? 'packets' : sortField];
    
    if (typeof aVal === 'string') {
      if (sortOrder === 'asc') return aVal.localeCompare(bVal);
      return bVal.localeCompare(aVal);
    }
    
    if (sortOrder === 'asc') return aVal > bVal ? 1 : -1;
    return aVal < bVal ? 1 : -1;
  });

  const totalPages = Math.ceil(sortedHosts.length / itemsPerPage);
  const paginatedHosts = sortedHosts.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

  const toggleSort = (field) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  if (loading) {
    return <SkeletonLoader message="Analyzing registered asset inventory..." />;
  }

  const hasHosts = hosts.length > 0;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Title */}
      <div className="flex justify-between items-center border-b border-slate-800/60 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 tracking-tight">
            Registered Asset Inventory
          </h2>
          <p className="text-slate-500 text-xs mt-1">
            Passive indexing of internal and external network nodes discovered on segments.
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

      {/* Main Table view */}
      <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl space-y-4">
        {/* Filters */}
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
              Asset Discovered IPv4 Index
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              List of passive host nodes mapped on network segment
            </p>
          </div>
          
          <div className="flex gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
              <input
                type="text"
                placeholder="Search IPs..."
                value={searchTerm}
                onChange={(e) => {
                  setSearchTerm(e.target.value);
                  setCurrentPage(1);
                }}
                className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800/80 rounded-lg text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500 w-44"
              />
            </div>
            
            <div className="relative flex items-center">
              <ShieldAlert className="w-3.5 h-3.5 text-slate-500 absolute left-2.5" />
              <select
                value={filterRisk}
                onChange={(e) => {
                  setFilterRisk(e.target.value);
                  setCurrentPage(1);
                }}
                className="pl-8 pr-2 py-1.5 bg-slate-950 border border-slate-800/80 rounded-lg text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500 appearance-none cursor-pointer"
              >
                <option value="ALL">Risk: ALL</option>
                <option value="CRITICAL">Risk: CRIT</option>
                <option value="HIGH">Risk: HIGH</option>
                <option value="MEDIUM">Risk: MED</option>
                <option value="LOW">Risk: LOW</option>
              </select>
            </div>
          </div>
        </div>

        {/* Table representation */}
        <div className="overflow-x-auto">
          <table className="w-full text-[10px] font-mono text-slate-300 border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-500 text-left uppercase">
                <th className="py-2.5 px-3 cursor-pointer select-none hover:text-slate-200" onClick={() => toggleSort('ip')}>
                  IP Address <ArrowUpDown className="w-3 h-3 inline ml-1" />
                </th>
                <th className="py-2.5 px-3">Classification</th>
                <th className="py-2.5 px-3">First Detected</th>
                <th className="py-2.5 px-3">Last Active</th>
                <th className="py-2.5 px-3 cursor-pointer select-none hover:text-slate-200" onClick={() => toggleSort('packets')}>
                  Packet Volume <ArrowUpDown className="w-3 h-3 inline ml-1" />
                </th>
                <th className="py-2.5 px-3 cursor-pointer select-none hover:text-slate-200" onClick={() => toggleSort('risk')}>
                  Risk Posture <ArrowUpDown className="w-3 h-3 inline ml-1" />
                </th>
              </tr>
            </thead>
            <tbody>
              {!hasHosts ? (
                <tr>
                  <td colSpan="6" className="py-6">
                    <EmptyState message="No hosts discovered" />
                  </td>
                </tr>
              ) : paginatedHosts.length > 0 ? (
                paginatedHosts.map((host, index) => {
                  const risk = getHostRisk(host);
                  const isPrivate = host.ip.startsWith('192.168.') || host.ip.startsWith('10.') || host.ip.startsWith('172.');
                  return (
                    <tr 
                      key={index}
                      className="border-b border-slate-800/50 bg-slate-950/20 hover:bg-slate-950/60 transition-colors"
                    >
                      <td className="py-2.5 px-3 text-slate-100 font-semibold">
                        <button
                          onClick={() => onHostClick && onHostClick(host.ip)}
                          className="hover:text-cyan-400 hover:underline cursor-pointer text-left font-semibold text-slate-100"
                        >
                          {host.ip}
                        </button>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className={`px-1.5 py-0.5 rounded font-extrabold text-[8px] border uppercase ${
                          isPrivate ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20' : 'bg-orange-500/10 text-orange-400 border-orange-500/20'
                        }`}>
                          {isPrivate ? 'Internal Asset' : 'External Endpoint'}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-400">{host.first_seen}</td>
                      <td className="py-2.5 px-3 text-slate-400">{host.last_seen}</td>
                      <td className="py-2.5 px-3 font-semibold">{host.packet_count} pkts</td>
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 border rounded uppercase font-bold text-[9px] ${
                          getRiskStyle(risk)
                        }`}>
                          {risk}
                        </span>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan="6" className="text-center text-slate-600 py-12">
                    No hosts match the active filter parameters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination controls */}
        {totalPages > 1 && (
          <div className="flex justify-between items-center border-t border-slate-800/60 pt-4 font-mono text-[10px] text-slate-500">
            <span>Showing {(currentPage - 1) * itemsPerPage + 1} - {Math.min(currentPage * itemsPerPage, sortedHosts.length)} of {sortedHosts.length} hosts</span>
            
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
