import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useConnection } from '../context/ConnectionContext';
import { 
  Globe, 
  AlertTriangle,
  Server,
  ArrowRightLeft
} from 'lucide-react';
import SkeletonLoader from '../components/SkeletonLoader';
import EmptyState from '../components/EmptyState';

export default function GeoIntelligence() {
  const { apiStatus, lastUpdated } = useConnection();
  const [geoData, setGeoData] = useState({
    internal_connections: 0,
    external_connections: 0,
    internal_ratio: 0.0,
    external_ratio: 0.0,
    top_external_hosts: []
  });
  const [loading, setLoading] = useState(true);

  const fetchGeo = async () => {
    try {
      const response = await axios.get('/api/geo');
      setGeoData(response.data);
      setLoading(false);
    } catch (e) {
      console.error("[GEO INTELLIGENCE API ERROR] Recovery triggered, preserving cache:", e);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGeo();
    const timer = setInterval(fetchGeo, 5000); // refresh every 5s
    return () => clearInterval(timer);
  }, []);

  if (loading) {
    return <SkeletonLoader message="Mapping internal and external telemetry routing segments..." />;
  }

  const totalConnections = geoData.internal_connections + geoData.external_connections;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Title */}
      <div className="flex justify-between items-center border-b border-slate-800/60 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
            <Globe className="w-6 h-6 text-cyan-400" />
            Geo Intelligence & Segment Profiling
          </h2>
          <p className="text-slate-500 text-xs mt-1">
            Analyzing boundaries between private RFC1918 segments (internal) and public WAN endpoints (external).
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

      {/* Connection metrics KPI row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Internal Connections */}
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-6 rounded-xl relative group overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
            <Server className="w-16 h-16 text-emerald-400" />
          </div>
          <p className="text-[10px] text-slate-500 font-mono tracking-widest uppercase">INTERNAL LAN SOCKETS</p>
          <h4 className="text-2xl font-bold text-emerald-400 mt-2 font-mono">
            {geoData.internal_connections.toLocaleString()}
          </h4>
          <p className="text-xs text-slate-400 mt-2 font-mono">
            Ratio: <span className="text-emerald-400 font-semibold">{geoData.internal_ratio}%</span>
          </p>
        </div>

        {/* External Connections */}
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-6 rounded-xl relative group overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
            <Globe className="w-16 h-16 text-orange-400" />
          </div>
          <p className="text-[10px] text-slate-500 font-mono tracking-widest uppercase">EXTERNAL WAN ENDPOINTS</p>
          <h4 className="text-2xl font-bold text-orange-400 mt-2 font-mono">
            {geoData.external_connections.toLocaleString()}
          </h4>
          <p className="text-xs text-slate-400 mt-2 font-mono">
            Ratio: <span className="text-orange-400 font-semibold">{geoData.external_ratio}%</span>
          </p>
        </div>

        {/* Total Segment Connections */}
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-6 rounded-xl relative group overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
            <ArrowRightLeft className="w-16 h-16 text-cyan-400" />
          </div>
          <p className="text-[10px] text-slate-500 font-mono tracking-widest uppercase">TOTAL COMM LINKS</p>
          <h4 className="text-2xl font-bold text-slate-100 mt-2 font-mono">
            {totalConnections.toLocaleString()}
          </h4>
          <p className="text-xs text-slate-400 mt-2 font-mono">
            Endpoint distribution: <span className="text-cyan-400 font-semibold">Standard Ingested</span>
          </p>
        </div>
      </div>

      {/* Ratios & External IP rankings block */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Ratios progress cards (2/3 width) */}
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-6 rounded-xl lg:col-span-2 space-y-6">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
              Segment Boundary Ratios
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              Live traffic distribution comparing trusted internal segments with untrusted external targets
            </p>
          </div>

          <div className="space-y-6 font-mono">
            {/* Internal Bar */}
            <div className="space-y-2">
              <div className="flex justify-between text-xs text-slate-300">
                <span className="flex items-center gap-1.5 text-emerald-400 font-bold">
                  <span className="w-2 h-2 rounded-full bg-emerald-400" />
                  TRUSTED PRIVATE (RFC1918)
                </span>
                <span className="font-bold">{geoData.internal_ratio}%</span>
              </div>
              <div className="w-full bg-slate-950 border border-slate-850 h-5 rounded overflow-hidden">
                <div 
                  className="bg-emerald-500 h-full rounded transition-all duration-500 shadow-[0_0_8px_#10b981]" 
                  style={{ width: `${geoData.internal_ratio}%` }}
                />
              </div>
            </div>

            {/* External Bar */}
            <div className="space-y-2">
              <div className="flex justify-between text-xs text-slate-300">
                <span className="flex items-center gap-1.5 text-orange-400 font-bold">
                  <span className="w-2 h-2 rounded-full bg-orange-400" />
                  UNTRUSTED EXTERNAL WAN
                </span>
                <span className="font-bold">{geoData.external_ratio}%</span>
              </div>
              <div className="w-full bg-slate-950 border border-slate-850 h-5 rounded overflow-hidden">
                <div 
                  className="bg-orange-500 h-full rounded transition-all duration-500 shadow-[0_0_8px_#f97316]" 
                  style={{ width: `${geoData.external_ratio}%` }}
                />
              </div>
            </div>

            {/* Tactical assessment */}
            <div className="bg-slate-950/40 border border-slate-850 p-4 rounded-lg space-y-2">
              <p className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Operational Summary</p>
              <p className="text-xs text-slate-400 leading-relaxed">
                {geoData.external_connections > geoData.internal_connections 
                  ? "⚠️ Telemetry is demonstrating dominant external packet routing. Ensure all WAN access is protected by valid perimeter policies."
                  : "✅ Traffic boundaries are clean. The majority of network transactions are bounded within standard internal segment rings."}
              </p>
            </div>
          </div>
        </div>

        {/* External IP Rankings (1/3 width) */}
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-6 rounded-xl space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
              External IP Rankings
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              Top public endpoints sorted by ingestion packet count
            </p>
          </div>

          <div className="overflow-y-auto max-h-[300px]">
            <table className="w-full text-[10px] font-mono text-slate-300 border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-500 text-left uppercase">
                  <th className="py-2.5 px-1">Rank</th>
                  <th className="py-2.5 px-1">Public Endpoint</th>
                  <th className="py-2.5 px-1 text-right">Packets</th>
                </tr>
              </thead>
              <tbody>
                {geoData.top_external_hosts.length === 0 ? (
                  <tr>
                    <td colSpan="3" className="py-6">
                      <EmptyState message="No external endpoints detected" />
                    </td>
                  </tr>
                ) : (
                  geoData.top_external_hosts.map((host, idx) => (
                    <tr 
                      key={idx}
                      className="border-b border-slate-850 hover:bg-slate-950/60 transition-colors"
                    >
                      <td className="py-3 px-1 text-slate-500 font-bold">{idx + 1}</td>
                      <td className="py-3 px-1 text-orange-400 font-semibold">{host.ip}</td>
                      <td className="py-3 px-1 text-right font-bold text-slate-300">
                        {host.packet_count.toLocaleString()} pkts
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
