import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useConnection } from '../context/ConnectionContext';
import { 
  Activity, 
  AlertTriangle,
  DoorOpen,
  Layers
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell
} from 'recharts';
import SkeletonLoader from '../components/SkeletonLoader';
import EmptyState from '../components/EmptyState';

export default function PortAnalysis() {
  const { apiStatus, lastUpdated } = useConnection();
  const [topPorts, setTopPorts] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchPorts = async () => {
    try {
      const response = await axios.get('/api/ports');
      setTopPorts(response.data.top_ports || []);
      setLoading(false);
    } catch (e) {
      console.error("[PORT ANALYSIS API ERROR] Recovery triggered, preserving cache:", e);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPorts();
    const timer = setInterval(fetchPorts, 5000); // refresh every 5s
    return () => clearInterval(timer);
  }, []);

  if (loading) {
    return <SkeletonLoader message="Performing port and protocol scanning analysis..." />;
  }

  const totalPortPackets = topPorts.reduce((acc, curr) => acc + curr.packet_count, 0);
  const dataWithPercentage = topPorts.map((p) => ({
    ...p,
    percentage: totalPortPackets > 0 ? roundToTwo((p.packet_count / totalPortPackets) * 100) : 0
  }));

  const mostActive = dataWithPercentage[0] || null;

  function roundToTwo(num) {
    return +(Math.round(num + "e+2")  + "e-2");
  }

  // Recharts color spectrum for ports
  const COLORS = [
    '#22d3ee', // Cyan
    '#3b82f6', // Blue
    '#a855f7', // Purple
    '#ec4899', // Pink
    '#f43f5e', // Rose
    '#f97316', // Orange
    '#eab308', // Yellow
    '#10b981', // Emerald
    '#64748b', // Slate
    '#475569'  // Darker Slate
  ];

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Title block */}
      <div className="flex justify-between items-center border-b border-slate-800/60 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
            <Activity className="w-6 h-6 text-cyan-400" />
            Port Analysis & Service Fingerprinting
          </h2>
          <p className="text-slate-500 text-xs mt-1">
            Real-time port tracking mapping TCP and UDP sockets to their standardized or ephemeral service signatures.
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

      {/* KPI Cards Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Most Active Port */}
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-6 rounded-xl relative group overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
            <DoorOpen className="w-16 h-16 text-cyan-400" />
          </div>
          <p className="text-[10px] text-slate-500 font-mono tracking-widest uppercase">MOST ACTIVE PORT</p>
          <h4 className="text-2xl font-bold text-slate-100 mt-2 font-mono">
            {mostActive ? `PORT ${mostActive.port}` : 'N/A'}
          </h4>
          <p className="text-xs text-slate-400 mt-2 font-mono">
            Traffic Volume: <span className="text-cyan-400 font-semibold">{mostActive ? mostActive.packet_count.toLocaleString() : 0} pkts</span>
          </p>
        </div>

        {/* Most Active Service */}
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-6 rounded-xl relative group overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
            <Layers className="w-16 h-16 text-cyan-400" />
          </div>
          <p className="text-[10px] text-slate-500 font-mono tracking-widest uppercase">MOST ACTIVE SERVICE</p>
          <h4 className="text-2xl font-bold text-slate-100 mt-2 font-mono">
            {mostActive ? mostActive.service : 'N/A'}
          </h4>
          <p className="text-xs text-slate-400 mt-2 font-mono">
            Service Dominance: <span className="text-cyan-400 font-semibold">{mostActive ? mostActive.percentage : 0}%</span>
          </p>
        </div>

        {/* Total Monitored Ports */}
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-6 rounded-xl relative group overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
            <Activity className="w-16 h-16 text-cyan-400" />
          </div>
          <p className="text-[10px] text-slate-500 font-mono tracking-widest uppercase">MONITORED PORT HEADERS</p>
          <h4 className="text-2xl font-bold text-slate-100 mt-2 font-mono">
            {topPorts.length} Active
          </h4>
          <p className="text-xs text-slate-400 mt-2 font-mono">
            Sum of packet logs: <span className="text-cyan-400 font-semibold">{totalPortPackets.toLocaleString()} pkts</span>
          </p>
        </div>
      </div>

      {/* Charts & Table section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Horizontal Bar Chart (2/3 width) */}
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-6 rounded-xl lg:col-span-2 space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
              Port Bandwidth Distribution
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              Visual spectrum representing the packet frequency distribution across top endpoints
            </p>
          </div>
          
          <div className="h-[300px] w-full font-mono text-[9px]">
            {topPorts.length === 0 ? (
              <EmptyState message="No port scans or telemetry collected yet" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={dataWithPercentage}
                  layout="vertical"
                  margin={{ top: 10, right: 30, left: 10, bottom: 5 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                  <XAxis type="number" stroke="#64748b" />
                  <YAxis 
                    dataKey="port" 
                    type="category" 
                    stroke="#64748b" 
                    tickFormatter={(val) => `Port ${val}`}
                  />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                    itemStyle={{ fontSize: '12px', fontFamily: 'monospace' }}
                    labelStyle={{ color: '#94a3b8' }}
                    formatter={(value, name, props) => [`${value} packets (${props.payload.percentage}%)`, 'Volume']}
                  />
                  <Bar dataKey="packet_count" radius={[0, 4, 4, 0]}>
                    {dataWithPercentage.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Detailed Metrics Table (1/3 width) */}
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-6 rounded-xl space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
              Service Signatures Log
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              Live sorted records matching network sockets to protocols
            </p>
          </div>

          <div className="overflow-y-auto max-h-[300px]">
            <table className="w-full text-[10px] font-mono text-slate-300 border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-500 text-left uppercase">
                  <th className="py-2 px-1">Rank</th>
                  <th className="py-2 px-1 text-center">Port</th>
                  <th className="py-2 px-1">Service</th>
                  <th className="py-2 px-1 text-right">Packets</th>
                  <th className="py-2 px-1 text-right">Usage</th>
                </tr>
              </thead>
              <tbody>
                {dataWithPercentage.length === 0 ? (
                  <tr>
                    <td colSpan="5" className="py-6">
                      <EmptyState message="No port records" />
                    </td>
                  </tr>
                ) : (
                  dataWithPercentage.map((port, idx) => (
                    <tr 
                      key={idx}
                      className="border-b border-slate-850 hover:bg-slate-950/60 transition-colors"
                    >
                      <td className="py-2.5 px-1 text-slate-500 font-bold">{port.rank}</td>
                      <td className="py-2.5 px-1 text-slate-100 font-bold text-center">{port.port}</td>
                      <td className="py-2.5 px-1">
                        <span className="bg-cyan-500/10 text-cyan-400 border border-cyan-500/25 text-[8px] font-extrabold px-1.5 py-0.5 rounded uppercase">
                          {port.service}
                        </span>
                      </td>
                      <td className="py-2.5 px-1 text-right font-semibold text-slate-300">
                        {port.packet_count.toLocaleString()}
                      </td>
                      <td className="py-2.5 px-1 text-right font-semibold text-slate-400">
                        {port.percentage}%
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
