import React, { useState, useEffect } from 'react';
import { useConnection } from '../context/ConnectionContext';
import { 
  ShieldAlert, 
  Activity, 
  Users, 
  HardDrive, 
  Server,
  AlertTriangle
} from 'lucide-react';
import StatCard from './StatCard';
import LiveCounter from './LiveCounter';
import { LiveTimelineChart, ProtocolDonutChart } from './LiveCharts';
import AttackMap from './AttackMap';
import TopologyGraph from './TopologyGraph';
import HealthPanel from './HealthPanel';
import ErrorBoundary from './ErrorBoundary';
import SkeletonLoader from './SkeletonLoader';

export default function Dashboard({ onThreatClick, onHostClick, onSessionClick }) {
  const { 
    stats, 
    summaryData, 
    loadingSummary, 
    apiStatus, 
    lastUpdated 
  } = useConnection();

  const [timeline, setTimeline] = useState([]);

  // Append new telemetry ticks to Recharts timeline whenever context stats updates
  useEffect(() => {
    if (!stats || stats.total_packets === 0) return;

    setTimeline((prev) => {
      const timeLabel = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
      const next = [
        ...prev,
        {
          timeLabel,
          packets_per_second: stats.packets_per_second || 0,
          bandwidth_kbps: parseFloat(((stats.bandwidth_bps || 0) / 1000).toFixed(2))
        }
      ];
      if (next.length > 30) {
        next.shift();
      }
      return next;
    });
  }, [stats]);

  // Format bits to human-readable network bandwidth speed rates
  const formatBandwidth = (bps) => {
    if (bps >= 1000000000) return `${(bps / 1000000000).toFixed(2)} Gbps`;
    if (bps >= 1000000) return `${(bps / 1000000).toFixed(2)} Mbps`;
    if (bps >= 1000) return `${(bps / 1000).toFixed(2)} Kbps`;
    return `${bps} bps`;
  };

  const getThreatStyle = (score) => {
    if (score > 70) return { text: "CRITICAL", color: "text-rose-500", border: "border-rose-500/30", bg: "bg-rose-500/10" };
    if (score > 40) return { text: "HIGH", color: "text-orange-500", border: "border-orange-500/30", bg: "bg-orange-500/10" };
    if (score > 20) return { text: "MEDIUM", color: "text-amber-500", border: "border-amber-500/30", bg: "bg-amber-500/10" };
    return { text: "LOW", color: "text-emerald-500", border: "border-emerald-500/30", bg: "bg-emerald-500/10" };
  };

  if (loadingSummary) {
    return <SkeletonLoader message="Analyzing border security summary..." />;
  }

  const threatStyle = getThreatStyle(stats.threat_score);

  return (
    <div className="space-y-6">
      {/* Title & Offline Warnings */}
      <div className="flex justify-between items-center border-b border-slate-800/60 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 tracking-tight">
            Platform Dashboard
          </h2>
          <p className="text-slate-500 text-xs mt-1">
            Real-time ingestion telemetry and passive traffic heuristics.
          </p>
        </div>
        {apiStatus === 'OFFLINE' && (
          <div className="flex items-center gap-2 border border-rose-500/20 bg-rose-500/5 px-3 py-1.5 rounded-lg text-xs font-mono text-rose-400 animate-pulse">
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            <span>BACKEND OFFLINE — Cache Preserved (Last updated: {lastUpdated})</span>
          </div>
        )}
      </div>

      {/* Grid Row 1: Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Threat Score Card */}
        <StatCard
          title="Threat Score"
          value={`${stats.threat_score}/100`}
          subtitle="System Security Health Gauge"
          statusText={`${100 - stats.threat_score}% SAFE`}
          icon={ShieldAlert}
          colorClass={threatStyle.color}
          borderClass={threatStyle.border}
          progress={stats.threat_score}
        />

        {/* Risk Level Card */}
        <StatCard
          title="Risk Rating"
          value={stats.risk_level}
          subtitle="Active Threat Category"
          statusText="Live Engine"
          icon={Activity}
          colorClass={threatStyle.color}
          borderClass={threatStyle.border}
        />

        {/* Discovered Hosts Card */}
        <StatCard
          title="Active Assets"
          value={summaryData.total_hosts}
          subtitle="Discovered Network Hosts"
          statusText="IPv4 Discovery"
          icon={Server}
          colorClass="text-blue-400"
        />

        {/* Active Sessions Card */}
        <StatCard
          title="Active Sessions"
          value={summaryData.total_sessions}
          subtitle="Monitored Communication Links"
          statusText="Live Scapy"
          icon={Users}
          colorClass="text-cyan-400"
        />

        {/* Traffic Ingestion Card */}
        <StatCard
          title="Ingestion Rate"
          value={formatBandwidth(stats.bandwidth_bps)}
          subValue={`// ${stats.packets_per_second} pps`}
          subtitle="Real-time Bandwidth Ingested"
          statusText="Network Adapter"
          icon={HardDrive}
          colorClass="text-purple-400"
        />
      </div>

      {/* Ingestion Counter */}
      <ErrorBoundary>
        <LiveCounter value={stats.total_packets} />
      </ErrorBoundary>

      {/* Central Visualizations */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Timeline Chart (2/3 width) */}
        <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800 p-6 rounded-xl space-y-4">
          <div className="flex justify-between items-center">
            <div>
              <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
                Telemetry Chronometer (Timeline)
              </h3>
              <p className="text-[10px] text-slate-500 font-mono">
                Ingested Traffic Volumetrics (PPS & Bandwidth) over last 30 seconds
              </p>
            </div>
            <div className="flex gap-3 text-[10px] font-mono">
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-blue-500"></span> PPS</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-cyan-500"></span> Bandwidth (Kbps)</span>
            </div>
          </div>
          <ErrorBoundary>
            <LiveTimelineChart data={timeline} type="pps" />
          </ErrorBoundary>
          <ErrorBoundary>
            <LiveTimelineChart data={timeline} type="bps" />
          </ErrorBoundary>
        </div>

        {/* Protocol Doughnut (1/3 width) */}
        <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl flex flex-col justify-between animate-fade-in">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
              Protocol Distribution
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              Proportional protocol layers captured on the wire
            </p>
          </div>
          <ErrorBoundary>
            <ProtocolDonutChart stats={stats} />
          </ErrorBoundary>
          <div className="border-t border-slate-800/60 pt-4 flex justify-between text-[10px] font-mono text-slate-500">
            <span>Ingestion Mode: PASSIVE</span>
            <span>Adapter: ACTIVE</span>
          </div>
        </div>
      </div>

      {/* Attack Map, Network Topology circular node graph, and Health Diagnostics panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 grid grid-cols-1 md:grid-cols-2 gap-6">
          <ErrorBoundary>
            <AttackMap />
          </ErrorBoundary>
          <ErrorBoundary>
            <TopologyGraph onHostClick={onHostClick} />
          </ErrorBoundary>
        </div>
        <ErrorBoundary>
          <HealthPanel />
        </ErrorBoundary>
      </div>
    </div>
  );
}
