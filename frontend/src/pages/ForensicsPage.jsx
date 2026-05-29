import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useConnection } from '../context/ConnectionContext';
import { 
  FolderClosed, 
  Search, 
  Database, 
  ShieldAlert, 
  Clock, 
  TrendingUp, 
  Download, 
  Printer, 
  PlusCircle, 
  Network, 
  Server,
  AlertTriangle
} from 'lucide-react';
import SkeletonLoader from '../components/SkeletonLoader';
import EmptyState from '../components/EmptyState';
import ErrorBoundary from '../components/ErrorBoundary';

export default function ForensicsPage({ onHostClick, onSessionClick, onThreatClick }) {
  const { apiStatus, lastUpdated } = useConnection();
  
  // State variables
  const [loading, setLoading] = useState(true);
  const [snapshots, setSnapshots] = useState([]);
  const [snapshotName, setSnapshotName] = useState('');
  const [capturing, setCapturing] = useState(false);
  const [activeSnapshot, setActiveSnapshot] = useState(null);

  // Search Engine states
  const [searchTerm, setSearchTerm] = useState('');
  const [searchResults, setSearchResults] = useState({ hosts: [], sessions: [], alerts: [] });
  const [rawTelemetry, setRawTelemetry] = useState({ hosts: [], sessions: [], alerts: [] });

  // Incident Timeline and Correlation states
  const [timeline, setTimeline] = useState([]);
  const [correlations, setCorrelations] = useState([]);

  const fetchForensicsData = async () => {
    try {
      setLoading(true);
      // 1. Fetch SQLite forensic snapshots
      const snapResponse = await axios.get('/api/forensics/snapshot');
      setSnapshots(snapResponse.data || []);

      // 2. Fetch live metrics for searches and timelines
      const invResponse = await axios.get('/api/inventory');
      const sessionsResponse = await axios.get('/api/sessions');
      const threatsResponse = await axios.get('/api/threats');

      const liveHosts = invResponse.data.hosts || [];
      const liveSessions = sessionsResponse.data.active_sessions || [];
      const liveAlerts = threatsResponse.data.recent_alerts || [];

      setRawTelemetry({
        hosts: liveHosts,
        sessions: liveSessions,
        alerts: liveAlerts
      });

      // Build Chronological Incident Timeline (Task 7)
      // Merge hosts discoveries and alert events
      const mergedEvents = [];
      liveHosts.forEach(h => {
        mergedEvents.push({
          time: h.first_seen,
          timeValue: new Date(h.first_seen).getTime(),
          type: 'DISCOVERY',
          message: `Host Discovered: ${h.ip} on physical segment`,
          badgeColor: 'bg-blue-500/10 text-blue-400 border-blue-500/20'
        });
      });

      liveAlerts.forEach(alert => {
        // Assume alerts have standard timestamps, if not fallback to last_seen dates
        const parts = alert.split(' // ');
        const timestamp = parts[0] || new Date().toLocaleString();
        const alertMsg = parts[1] || alert;
        mergedEvents.push({
          time: timestamp,
          timeValue: new Date(timestamp).getTime() || Date.now(),
          type: 'ALERT',
          message: `Anomaly Triggered: ${alertMsg}`,
          badgeColor: 'bg-rose-500/10 text-rose-400 border-rose-500/20'
        });
      });

      // Sort chronological (oldest to newest)
      const sortedEvents = mergedEvents
        .sort((a, b) => a.timeValue - b.timeValue)
        .slice(-8); // Get latest 8 incident blocks

      setTimeline(sortedEvents);

      // Build Threat Correlations (Task 4)
      const parsedCorrelations = [];
      const keywords = ['HOST DOMINANCE', 'PORT SCAN', 'ICMP SPIKE', 'RECON'];

      liveAlerts.forEach((alert, index) => {
        const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
        const ip = alert.match(ipRegex)?.[0] || '';
        if (!ip) return;

        const matchedKey = keywords.find(k => alert.toUpperCase().includes(k)) || 'SUSPICIOUS FLOW';

        // Trace related sessions
        const relatedSessions = liveSessions.filter(s => s.source_ip === ip || s.destination_ip === ip);
        const uniqueDestinations = new Set(relatedSessions.map(s => s.destination_ip));
        const uniquePorts = new Set(relatedSessions.map(s => s.destination_port));

        parsedCorrelations.push({
          id: index,
          threatName: matchedKey,
          affectedIp: ip,
          sessionsCount: relatedSessions.length,
          hostsCount: uniqueDestinations.size || 1,
          ports: Array.from(uniquePorts).slice(0, 4) // Show top 4 ports
        });
      });

      setCorrelations(parsedCorrelations.slice(0, 3)); // show top 3 alerts correlations

      setLoading(false);
    } catch (e) {
      console.error("[FORENSICS API ERROR] Offline recovery triggered:", e);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchForensicsData();
  }, []);

  // Global Search Engine Handler (Task 5)
  useEffect(() => {
    if (!searchTerm.trim()) {
      setSearchResults({ hosts: [], sessions: [], alerts: [] });
      return;
    }

    const term = searchTerm.toLowerCase();

    // 1. Search Discovered Hosts
    const hostMatches = rawTelemetry.hosts.filter(h => 
      h.ip.toLowerCase().includes(term) ||
      h.first_seen.toLowerCase().includes(term) ||
      h.last_seen.toLowerCase().includes(term)
    );

    // 2. Search Active Sessions
    const sessionMatches = rawTelemetry.sessions.filter(s => 
      s.source_ip.toLowerCase().includes(term) ||
      s.destination_ip.toLowerCase().includes(term) ||
      s.protocol.toLowerCase().includes(term) ||
      String(s.source_port).includes(term) ||
      String(s.destination_port).includes(term)
    );

    // 3. Search triggers warnings alert logs
    const alertMatches = rawTelemetry.alerts.filter(a => 
      a.toLowerCase().includes(term)
    );

    setSearchResults({
      hosts: hostMatches,
      sessions: sessionMatches,
      alerts: alertMatches
    });
  }, [searchTerm, rawTelemetry]);

  // Capture SQLite Snapshot (Task 8)
  const handleCaptureSnapshot = async (e) => {
    e.preventDefault();
    if (!snapshotName.trim()) return;

    try {
      setCapturing(true);
      const response = await axios.post(`/api/forensics/snapshot?snapshot_name=${encodeURIComponent(snapshotName)}`);
      
      if (response.data.status === 'success') {
        setSnapshotName('');
        // Reload SQLite snaps inventory
        fetchForensicsData();
      }
      setCapturing(false);
    } catch (err) {
      console.error("[SNAPSHOT FAILED] SQLite write failure:", err);
      setCapturing(false);
    }
  };

  // Export Direct JSON snapshot payload
  const handleExportJSON = (snap) => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(snap, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `netscope_snapshot_${snap.id}_forensics.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  if (loading) {
    return <SkeletonLoader message="Analysing digital forensics workspace..." />;
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Title */}
      <div className="flex justify-between items-center border-b border-slate-800/60 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 tracking-tight">
            Cyber Threat Investigation & Forensics Center
          </h2>
          <p className="text-slate-500 text-xs mt-1">
            Manual SQLite forensic snapshots, multi-vector threat correlations, chronological incident timelines, and printable report compilers.
          </p>
        </div>

        {/* Offline Alert Warning */}
        {apiStatus === 'OFFLINE' && (
          <div className="flex items-center gap-2 border border-rose-500/20 bg-rose-500/5 px-3 py-1.5 rounded-lg text-xs font-mono text-rose-400 animate-pulse">
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            <span>BACKEND OFFLINE — Cache Preserved (Last updated: {lastUpdated})</span>
          </div>
        )}
      </div>

      {/* Main Grid: Global Search and Snapshot Capturer */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Global Hunt Search Bar (2/3 width) */}
        <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800 p-6 rounded-xl space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
              Global Security Threat Hunting Search
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              Perform instant search queries across IPs, ports, alerts, sessions, or protocols
            </p>
          </div>

          <div className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5" />
            <input
              type="text"
              placeholder="Search e.g. 8.8.8.8, 443, TCP, PORT SCAN..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Search Result Matrices */}
          {searchTerm.trim() && (
            <div className="space-y-4 max-h-[300px] overflow-y-auto pr-1 border-t border-slate-800/60 pt-4 font-mono text-[10px]">
              {searchResults.hosts.length === 0 && searchResults.sessions.length === 0 && searchResults.alerts.length === 0 ? (
                <div className="text-center text-slate-600 py-6">No matching telemetry blocks captured.</div>
              ) : (
                <>
                  {/* Hosts Matches */}
                  {searchResults.hosts.length > 0 && (
                    <div className="space-y-1.5">
                      <span className="text-[9px] text-slate-500 font-bold uppercase block">Discovered Hosts Matches ({searchResults.hosts.length})</span>
                      {searchResults.hosts.map((h, i) => (
                        <div key={i} className="p-2 bg-slate-950/60 border border-slate-900 rounded flex justify-between items-center">
                          <button 
                            onClick={() => onHostClick && onHostClick(h.ip)} 
                            className="text-cyan-400 font-bold hover:underline cursor-pointer text-left"
                          >
                            {h.ip}
                          </button>
                          <span className="text-slate-500">{h.packet_count} pkts // Detected: {h.last_seen}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Sessions Matches */}
                  {searchResults.sessions.length > 0 && (
                    <div className="space-y-1.5">
                      <span className="text-[9px] text-slate-500 font-bold uppercase block">Active Sessions Matches ({searchResults.sessions.length})</span>
                      {searchResults.sessions.map((s, i) => (
                        <div key={i} className="p-2 bg-slate-950/60 border border-slate-900 rounded flex justify-between items-center">
                          <button 
                            onClick={() => onSessionClick && onSessionClick(s)} 
                            className="text-slate-300 font-semibold hover:text-cyan-400 hover:underline cursor-pointer text-left"
                          >
                            {s.source_ip}:{s.source_port} → {s.destination_ip}:{s.destination_port}
                          </button>
                          <span className="text-cyan-400 font-bold uppercase">{s.protocol} ({s.packets} pkts)</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Alerts Matches */}
                  {searchResults.alerts.length > 0 && (
                    <div className="space-y-1.5">
                      <span className="text-[9px] text-slate-500 font-bold uppercase block">Anomalies Alerts Matches ({searchResults.alerts.length})</span>
                      {searchResults.alerts.map((a, i) => (
                        <div key={i} className="p-2 bg-slate-950/60 border border-slate-900 rounded flex gap-2 items-center">
                          <span className="text-rose-400 font-bold shrink-0">[ALERT]</span>
                          <button 
                            onClick={() => onThreatClick && onThreatClick(a)} 
                            className="text-slate-300 hover:text-rose-400 hover:underline cursor-pointer text-left"
                          >
                            {a}
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>

        {/* SQLite Snapshot Capturer (1/3 width) */}
        <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl flex flex-col justify-between h-full min-h-[190px]">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
              Capture Forensic Snapshot
            </h3>
            <p className="text-[10px] text-slate-500 font-mono mb-4">
              Commit the current sniffer memory state instantly into SQLite DB records
            </p>
          </div>

          <form onSubmit={handleCaptureSnapshot} className="space-y-3 font-mono text-xs">
            <input
              type="text"
              placeholder="e.g. Ingress incident sweep A..."
              value={snapshotName}
              onChange={(e) => setSnapshotName(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            />
            <button
              type="submit"
              disabled={capturing || !snapshotName.trim()}
              className="w-full py-2 bg-cyan-500 hover:bg-cyan-600 disabled:opacity-40 disabled:cursor-not-allowed border border-cyan-400 hover:border-cyan-500 rounded-lg text-slate-950 font-bold tracking-wide flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
            >
              <PlusCircle className="w-4 h-4" />
              <span>{capturing ? 'COMMITTING SNAPSHOT...' : 'CAPTURE LIVE THREAT STATE'}</span>
            </button>
          </form>
        </div>
      </div>

      {/* Incident Timeline and Threat Correlation Matrices */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Correlation Engine (2/3 width) */}
        <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800 p-6 rounded-xl space-y-4 min-h-[300px]">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              Threat Correlation Engine (Task 4)
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              Live multi-vector relationship parsing mapping Alert → Host IP → Related Sessions → Mapped Ports
            </p>
          </div>

          <div className="space-y-3">
            {correlations.length === 0 ? (
              <EmptyState message="No correlated anomalies discovered" />
            ) : (
              correlations.map((corr) => (
                <div key={corr.id} className="p-4 bg-slate-950/40 border border-slate-900 rounded-xl space-y-3 font-mono text-[10px] text-slate-400 leading-relaxed shadow-lg">
                  {/* Visual Impact Flow tree */}
                  <div className="flex justify-between items-center border-b border-slate-900/60 pb-2">
                    <button 
                      onClick={() => onThreatClick && onThreatClick(corr.threatName)} 
                      className="text-rose-400 font-extrabold hover:underline flex items-center gap-1 cursor-pointer text-left"
                    >
                      <ShieldAlert className="w-3.5 h-3.5 animate-pulse" />
                      THREAT CLASS: {corr.threatName}
                    </button>
                    <span className="text-slate-500 uppercase">TELEMETRY CORRELATED</span>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
                    <div className="p-2 bg-slate-900/40 rounded border border-slate-900">
                      <span className="text-[8px] text-slate-500 block uppercase font-bold">Affected IP</span>
                      <button 
                        onClick={() => onHostClick && onHostClick(corr.affectedIp)} 
                        className="text-slate-200 font-extrabold text-[11px] mt-0.5 hover:text-cyan-400 hover:underline cursor-pointer text-center block w-full"
                      >
                        {corr.affectedIp}
                      </button>
                    </div>
                    <div className="p-2 bg-slate-900/40 rounded border border-slate-900">
                      <span className="text-[8px] text-slate-500 block uppercase font-bold">Trace Sessions</span>
                      <span className="text-cyan-400 font-extrabold text-[11px] mt-0.5 block">{corr.sessionsCount} paths</span>
                    </div>
                    <div className="p-2 bg-slate-900/40 rounded border border-slate-900">
                      <span className="text-[8px] text-slate-500 block uppercase font-bold">Related Hosts</span>
                      <span className="text-slate-200 font-extrabold text-[11px] mt-0.5 block">{corr.hostsCount} hosts</span>
                    </div>
                    <div className="p-2 bg-slate-900/40 rounded border border-slate-900">
                      <span className="text-[8px] text-slate-500 block uppercase font-bold">Impact Ports</span>
                      <div className="flex gap-1 justify-center mt-0.5">
                        {corr.ports.map((p, idx) => (
                          <span key={idx} className="px-1 border border-cyan-500/20 bg-cyan-500/5 text-cyan-400 font-bold rounded text-[8px]">{p}</span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Incident Chronology Timeline (1/3 width) */}
        <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl flex flex-col justify-between h-full min-h-[300px]">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider flex items-center gap-1.5">
              <Clock className="w-4 h-4 text-cyan-400" />
              Incident Timeline (Task 7)
            </h3>
            <p className="text-[10px] text-slate-500 font-mono mb-4">
              Passive sniffer discovery & alerts chronological event chain
            </p>
          </div>

          <div className="flex-1 space-y-3.5 overflow-y-auto max-h-[220px] pr-1 font-mono text-[9px] text-slate-400 border-l-2 border-slate-800 pl-4 ml-2 relative">
            {timeline.length === 0 ? (
              <div className="text-center text-slate-600 py-16 uppercase">Awaiting sniffer discovery events...</div>
            ) : (
              timeline.map((evt, idx) => (
                <div key={idx} className="relative space-y-1">
                  {/* Timeline dot */}
                  <div className="absolute -left-[21px] top-1.5 w-2 h-2 rounded-full bg-cyan-500 border border-slate-900" />
                  <div className="flex justify-between items-center text-slate-500">
                    <span className="font-bold">{evt.time}</span>
                    <span className={`px-1.5 py-0.2 border rounded uppercase font-bold text-[7px] ${evt.badgeColor}`}>{evt.type}</span>
                  </div>
                  <p className="text-slate-300 leading-normal">{evt.message}</p>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Manual Snapshots Archive & Incident Report Compiler */}
      <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-xl space-y-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider flex items-center gap-1.5">
            <Database className="w-4 h-4 text-cyan-400" />
            CISO Manual SQLite Snapshots Archive
          </h3>
          <p className="text-[10px] text-slate-500 font-mono">
            Captured historical threat records. Click any captured snapshot to compile a PDF Incident report or download a JSON matrix.
          </p>
        </div>

        {/* Snapshots Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {snapshots.length === 0 ? (
            <div className="col-span-full">
              <EmptyState message="No forensic snapshots archived in SQLite" />
            </div>
          ) : (
            snapshots.map((snap) => (
              <div key={snap.id} className="p-5 bg-slate-950/40 border border-slate-800/80 rounded-xl hover:border-slate-700 transition-all flex flex-col justify-between h-44 shadow-lg">
                <div className="space-y-1 font-mono">
                  <span className="text-[8px] text-slate-500 font-extrabold uppercase">SNAPSHOT ID: #{snap.id}</span>
                  <h4 className="text-xs font-extrabold text-slate-200 uppercase truncate max-w-[220px]">{snap.snapshot_name}</h4>
                  <p className="text-[9px] text-slate-500 flex items-center gap-1">
                    <Clock className="w-3.5 h-3.5" />
                    Captured: {snap.timestamp}
                  </p>
                </div>

                <div className="border-t border-slate-900/60 pt-3 mt-4 flex gap-3 font-mono text-[9px]">
                  <button
                    onClick={() => setActiveSnapshot(snap)}
                    className="flex-1 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded text-slate-300 font-bold flex items-center justify-center gap-1 transition-colors cursor-pointer"
                  >
                    <Printer className="w-3.5 h-3.5" />
                    <span>Compile Report</span>
                  </button>
                  <button
                    onClick={() => handleExportJSON(snap)}
                    className="p-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded text-cyan-400 hover:text-cyan-300 transition-colors cursor-pointer"
                    title="Export JSON Matrix"
                  >
                    <Download className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Printable Incident Report Modal Overlay (Task 9) */}
      {activeSnapshot && (
        <AnimatePresence>
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <div className="absolute inset-0 bg-slate-950/80 backdrop-blur-[2px]" onClick={() => setActiveSnapshot(null)} />
            
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-3xl shadow-2xl relative flex flex-col max-h-[85vh] z-10"
            >
              {/* Modal Header */}
              <div className="p-6 border-b border-slate-800 flex justify-between items-center bg-slate-950/20 print:hidden">
                <span className="font-extrabold text-sm font-mono tracking-wider text-slate-100 uppercase">
                  Incident Report Compiler
                </span>
                <div className="flex gap-2">
                  <button
                    onClick={() => window.print()}
                    className="px-3 py-1.5 bg-cyan-500 hover:bg-cyan-600 border border-cyan-400 text-slate-950 font-mono text-[10px] font-bold rounded flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <Printer className="w-3.5 h-3.5" />
                    <span>Print PDF</span>
                  </button>
                  <button
                    onClick={() => setActiveSnapshot(null)}
                    className="p-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-400 hover:text-slate-200 rounded cursor-pointer"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Printable Body Content (Task 9) */}
              <div className="flex-1 overflow-y-auto p-8 space-y-6 font-mono text-xs text-slate-300 print:text-slate-950 print:bg-white print:p-0">
                {/* Print Title Block */}
                <div className="text-center space-y-2 border-b-2 border-dashed border-slate-800 print:border-slate-950 pb-6">
                  <h1 className="text-lg font-black tracking-wider text-slate-100 print:text-slate-950 uppercase">
                    NetScope AI // INCIDENT REPORT EXECUTIVE DOSSIER
                  </h1>
                  <div className="flex justify-center gap-6 text-[10px] text-slate-500 print:text-slate-600">
                    <span>REPORT ID: #INC-{activeSnapshot.id}</span>
                    <span>TIMESTAMP: {activeSnapshot.timestamp}</span>
                    <span>POSTURE: AUDITED</span>
                  </div>
                </div>

                {/* Section 1: Executive Posture & Risk Assessment */}
                <div className="space-y-3">
                  <h3 className="text-sm font-extrabold text-slate-200 print:text-slate-950 border-b border-slate-800 print:border-slate-950 pb-1.5 uppercase">
                    1. Operational Risk Assessment
                  </h3>
                  <div className="grid grid-cols-3 gap-6 bg-slate-950/40 print:bg-slate-100 p-4 rounded-lg border border-slate-900 print:border-slate-300">
                    <div>
                      <span className="text-[9px] text-slate-500 block uppercase">Threat Index</span>
                      <span className="text-xl font-extrabold text-rose-500 print:text-rose-600">{activeSnapshot.stats.threat_score || 0}/100</span>
                    </div>
                    <div>
                      <span className="text-[9px] text-slate-500 block uppercase">Risk Classification</span>
                      <span className="text-xl font-extrabold text-slate-300 print:text-slate-800">{activeSnapshot.stats.risk_level || 'LOW'}</span>
                    </div>
                    <div>
                      <span className="text-[9px] text-slate-500 block uppercase">Active Inventories</span>
                      <span className="text-xl font-extrabold text-cyan-400 print:text-cyan-600">
                        {activeSnapshot.hosts.host_count || 0} Hosts // {activeSnapshot.sessions.session_count || 0} Links
                      </span>
                    </div>
                  </div>
                </div>

                {/* Section 2: Flagged Anomalies */}
                <div className="space-y-3">
                  <h3 className="text-sm font-extrabold text-slate-200 print:text-slate-950 border-b border-slate-800 print:border-slate-950 pb-1.5 uppercase">
                    2. Security Anomalies Logs
                  </h3>
                  <div className="space-y-2">
                    {activeSnapshot.threats.recent_alerts && activeSnapshot.threats.recent_alerts.length > 0 ? (
                      activeSnapshot.threats.recent_alerts.slice(0, 5).map((a, i) => (
                        <div key={i} className="p-2.5 bg-slate-950/40 print:bg-slate-50 border border-slate-900 print:border-slate-200 rounded text-[10px] text-slate-400 print:text-slate-700 flex gap-2">
                          <span className="text-rose-500 font-bold shrink-0">[HIT]</span>
                          <span>{a}</span>
                        </div>
                      ))
                    ) : (
                      <div className="text-slate-500 italic">No anomalies logged at snapshot window.</div>
                    )}
                  </div>
                </div>

                {/* Section 3: Recommended Remediations */}
                <div className="space-y-3">
                  <h3 className="text-sm font-extrabold text-slate-200 print:text-slate-950 border-b border-slate-800 print:border-slate-950 pb-1.5 uppercase">
                    3. Recommended Mitigation Actions
                  </h3>
                  <div className="space-y-2.5 text-[10px] text-slate-400 print:text-slate-800">
                    <div className="p-3 bg-slate-950/40 print:bg-slate-50 border border-slate-900 print:border-slate-200 rounded space-y-1">
                      <span className="font-extrabold text-slate-200 print:text-slate-950">A. Quarantine & Containment Protocols:</span>
                      <p className="leading-relaxed">Quarantine any external hosts flagging high-volume anomalies. Block TCP scans and port sweep sweeps globally on perimeter firewalls.</p>
                    </div>
                    <div className="p-3 bg-slate-950/40 print:bg-slate-50 border border-slate-900 print:border-slate-200 rounded space-y-1">
                      <span className="font-extrabold text-slate-200 print:text-slate-950">B. Exposed Service Hardening:</span>
                      <p className="leading-relaxed">Audit internal listening services on common ports (SSH, RDP, SMB) and deactivate exposed unencrypted service interfaces on local asset boundaries.</p>
                    </div>
                  </div>
                </div>

                {/* Section 4: Signature Sign-off */}
                <div className="border-t border-slate-800 print:border-slate-950 pt-8 flex justify-between items-end text-[9px] text-slate-500 print:text-slate-600">
                  <div className="space-y-1">
                    <span>SECURITY CHIEF OPERATIONS OFFICE</span>
                    <div className="h-6 w-32 border-b border-slate-700 print:border-slate-400" />
                    <span>AUDITED CISO COMPLIANCE OFFICER</span>
                  </div>
                  <div className="text-right">
                    <span>NETSCOPE AI OPERATIONS CORE</span>
                    <span>POSTURE RATING: VALIDATED</span>
                  </div>
                </div>
              </div>
            </motion.div>
          </div>
        </AnimatePresence>
      )}
    </div>
  );
}
