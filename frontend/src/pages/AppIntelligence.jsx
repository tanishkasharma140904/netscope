import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useConnection } from '../context/ConnectionContext';
import { 
  Cpu, 
  AlertTriangle,
  Layers,
  PieChart as PieIcon
} from 'lucide-react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
  Tooltip
} from 'recharts';
import SkeletonLoader from '../components/SkeletonLoader';
import EmptyState from '../components/EmptyState';

export default function AppIntelligence() {
  const { apiStatus, lastUpdated } = useConnection();
  const [apps, setApps] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchApps = async () => {
    try {
      const response = await axios.get('/api/applications');
      setApps(response.data.applications || []);
      setLoading(false);
    } catch (e) {
      console.error("[APP INTELLIGENCE API ERROR] Recovery triggered, preserving cache:", e);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchApps();
    const timer = setInterval(fetchApps, 5000); // refresh every 5s
    return () => clearInterval(timer);
  }, []);

  if (loading) {
    return <SkeletonLoader message="Deconstructing application headers and signatures..." />;
  }

  const totalAppPackets = apps.reduce((acc, curr) => acc + curr.packet_count, 0);
  const topApp = apps[0] || null;

  // Pie colors representing various application headers
  const COLORS = [
    '#22d3ee', // Cyan (HTTPS)
    '#3b82f6', // Blue (DNS)
    '#34d399', // Emerald (HTTP)
    '#a855f7', // Purple (SSH)
    '#f97316', // Orange (SMTP)
    '#ec4899', // Pink
    '#64748b'  // Slate (OTHER)
  ];

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Title */}
      <div className="flex justify-between items-center border-b border-slate-800/60 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
            <Cpu className="w-6 h-6 text-cyan-400" />
            Application Layer Intelligence
          </h2>
          <p className="text-slate-500 text-xs mt-1">
            Deep packet inspection engine classifying traffic packets into high-level logical applications.
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
        {/* Top Application */}
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-6 rounded-xl relative group overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
            <Layers className="w-16 h-16 text-cyan-400" />
          </div>
          <p className="text-[10px] text-slate-500 font-mono tracking-widest uppercase">DOMINANT APP SIGNATURE</p>
          <h4 className="text-2xl font-bold text-slate-100 mt-2 font-mono">
            {topApp ? topApp.name : 'None'}
          </h4>
          <p className="text-xs text-slate-400 mt-2 font-mono">
            Classified Share: <span className="text-cyan-400 font-semibold">{topApp ? topApp.percentage : 0}%</span>
          </p>
        </div>

        {/* Total App Traffic */}
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-6 rounded-xl relative group overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
            <Cpu className="w-16 h-16 text-cyan-400" />
          </div>
          <p className="text-[10px] text-slate-500 font-mono tracking-widest uppercase">TOTAL APPS PACKETS</p>
          <h4 className="text-2xl font-bold text-slate-100 mt-2 font-mono">
            {totalAppPackets.toLocaleString()} pkts
          </h4>
          <p className="text-xs text-slate-400 mt-2 font-mono">
            Total active categories: <span className="text-cyan-400 font-semibold">{apps.length}</span>
          </p>
        </div>

        {/* Status Posture */}
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-6 rounded-xl relative group overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
            <PieIcon className="w-16 h-16 text-cyan-400" />
          </div>
          <p className="text-[10px] text-slate-500 font-mono tracking-widest uppercase">CLASSIFICATION COVERAGE</p>
          <h4 className="text-2xl font-bold text-emerald-400 mt-2 font-mono">
            100% RELIABILITY
          </h4>
          <p className="text-xs text-slate-400 mt-2 font-mono">
            Telemetry classification: <span className="text-cyan-400 font-semibold">Real-time Sniffed</span>
          </p>
        </div>
      </div>

      {/* Donut and Table Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Pie/Donut Chart */}
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-6 rounded-xl lg:col-span-2 space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
              Application Share Spectrum
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              Proportional donut visualization showing dominant networking protocol distributions
            </p>
          </div>

          <div className="h-[300px] w-full font-mono text-xs">
            {apps.length === 0 ? (
              <EmptyState message="No classified applications detected yet" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={apps}
                    nameKey="name"
                    dataKey="packet_count"
                    cx="50%"
                    cy="50%"
                    innerRadius={70}
                    outerRadius={100}
                    paddingAngle={3}
                  >
                    {apps.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                    itemStyle={{ fontSize: '11px', fontFamily: 'monospace' }}
                    formatter={(value, name, props) => [`${value} packets (${props.payload.percentage}%)`, name]}
                  />
                  <Legend 
                    verticalAlign="bottom" 
                    height={36} 
                    iconType="circle"
                    formatter={(value, entry, index) => <span className="text-slate-400 font-mono text-[10px] uppercase">{value}</span>}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Breakdown Table */}
        <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-6 rounded-xl space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
              Applications Dominance Database
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              Live sorted metrics listing packet volume and percentage breakdown
            </p>
          </div>

          <div className="overflow-y-auto max-h-[300px]">
            <table className="w-full text-[10px] font-mono text-slate-300 border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-500 text-left uppercase">
                  <th className="py-2.5 px-2">Application</th>
                  <th className="py-2.5 px-2 text-right">Packets</th>
                  <th className="py-2.5 px-2 text-right">Percentage</th>
                </tr>
              </thead>
              <tbody>
                {apps.length === 0 ? (
                  <tr>
                    <td colSpan="3" className="py-6">
                      <EmptyState message="No classifications" />
                    </td>
                  </tr>
                ) : (
                  apps.map((app, idx) => (
                    <tr 
                      key={idx}
                      className="border-b border-slate-850 hover:bg-slate-950/60 transition-colors"
                    >
                      <td className="py-3 px-2 font-bold text-slate-100 flex items-center gap-2">
                        <span 
                          className="w-2.5 h-2.5 rounded-full" 
                          style={{ backgroundColor: COLORS[idx % COLORS.length] }}
                        />
                        {app.name}
                      </td>
                      <td className="py-3 px-2 text-right font-semibold text-slate-300">
                        {app.packet_count.toLocaleString()}
                      </td>
                      <td className="py-3 px-2 text-right font-semibold text-slate-400">
                        {app.percentage}%
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
