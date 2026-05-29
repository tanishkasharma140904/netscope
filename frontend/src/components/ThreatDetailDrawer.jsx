import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, ShieldAlert, Users, Server, Radio, ClipboardList, CheckSquare } from 'lucide-react';

const THREAT_CLASSIFICATIONS = {
  'HOST DOMINANCE': {
    name: 'Single Host Dominance Anomaly',
    category: 'Volume Exhaustion / Ingress Dominance',
    classification: 'CWE-400: Uncontrolled Resource Consumption',
    description: 'A single network host is transmitting or receiving an abnormally high volume of frames relative to segment baselines. This usually indicates malware bulk exfiltration, local data mirroring, or horizontal server backups.',
    action: [
      'Query the Host Profile in the Asset Inventory to check historical first/last seen flags.',
      'Check active TCP/UDP ports to identify the running application protocol.',
      'Quarantine the affected host IP segment at the edge router boundary.',
      'Inspect host endpoints for bulk data exfiltration processes or unauthorized tools.'
    ]
  },
  'PORT SCAN': {
    name: 'Active Port Scan Sweep',
    category: 'Reconnaissance / Probe Scanning',
    classification: 'MITRE ATT&CK T1046: Network Service Discovery',
    description: 'An internal or external host is attempting socket handshakes across a broad range of port designations in a brief temporal window. This indicates pre-attack reconnaissance mapping service availability.',
    action: [
      'Identify target ports to see if the scanning node targeted sensitive services (SSH, RDP, SMB).',
      'Verify if any scan probes established full TCP connections (successful handshakes).',
      'Block the scanner IP address globally in the firewall ingress access lists.',
      'Validate that local systems are not running unnecessary exposed open listening services.'
    ]
  },
  'ICMP SPIKE': {
    name: 'ICMP Volume Anomaly (Ping Flood)',
    category: 'Resource Flooding / Ping Sweeps',
    classification: 'MITRE ATT&CK T1498: Network Denial of Service',
    description: 'A sudden burst of ICMP echo-request or echo-reply packets captured on network boundary sniffer boundaries. Suggestive of active segment sweeps or ping flooding designed to check asset online states.',
    action: [
      'Check top target hosts to see if the ICMP burst is concentrated on a single critical node.',
      'Verify if host ICMP rates suggest active Denial of Service (DoS) probe sweeps.',
      'Enforce ICMP rate limiting limits on edge boundaries.',
      'Verify that critical servers are configured to ignore ICMP pings in high-security zones.'
    ]
  },
  'RECONNAISSANCE': {
    name: 'Active Network Reconnaissance Probe',
    category: 'Pre-Attack Discovery / Recon Sweeps',
    classification: 'MITRE ATT&CK T1595: Active Scanning',
    description: 'Broad scanning heuristically flagged by Scapy thread parsers mapping network inventory, active hosts, and protocol structures across segment bounds.',
    action: [
      'Trace all session paths established by the probing IP address.',
      'Inspect if scanner probed common ports (e.g. 21, 22, 23, 80, 443, 445).',
      'Verify if any local nodes responded to active recon handshakes.',
      'Deploy network honeytoken ports to trap active pre-attack scouts.'
    ]
  }
};

const getDefaultThreat = (alertText) => {
  return {
    name: alertText || 'Anomalous Boundary Traffic Spike',
    category: 'Traffic Anomaly / General Security Flag',
    classification: 'CWE-693: Protection Mechanism Failure',
    description: `NetScope sniffer threads parsed a traffic spike exceeding standard passive wire baselines: "${alertText}". This suggest elevated activity boundaries under current evaluations.`,
    action: [
      'Drill down into sessions for IPs flagged in the warning log message.',
      'Verify that sniffer packets do not show signs of fragmented payload payloads.',
      'Compare bandwidth BPS rates with standard historical baseline snapshots.',
      'Acknowledge the alert and continue active surveillance patrol on the adapter.'
    ]
  };
};

export default function ThreatDetailDrawer({ alert, onClose, onHostClick }) {
  if (!alert) return null;

  // Match keyword to classification
  const matchedKey = Object.keys(THREAT_CLASSIFICATIONS).find(key => 
    alert.toUpperCase().includes(key)
  ) || '';

  const details = matchedKey ? THREAT_CLASSIFICATIONS[matchedKey] : getDefaultThreat(alert);

  // Extract IP if present in the alert string (simple regex)
  const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
  const matchedIp = alert.match(ipRegex)?.[0] || 'N/A';

  const isCritical = alert.toUpperCase().includes('CRITICAL') || alert.toUpperCase().includes('DOMINANCE');
  const riskLevel = isCritical ? 'CRITICAL' : alert.toUpperCase().includes('HIGH') || alert.toUpperCase().includes('PORT SCAN') ? 'HIGH' : 'MEDIUM';
  const threatScore = riskLevel === 'CRITICAL' ? 85 : riskLevel === 'HIGH' ? 65 : 45;

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex justify-end">
        {/* Backdrop blur overlay */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
          className="absolute inset-0 bg-slate-950/60 backdrop-blur-[2px]"
        />

        {/* Sliding Panel */}
        <motion.div
          initial={{ x: '100%' }}
          animate={{ x: 0 }}
          exit={{ x: '100%' }}
          transition={{ type: 'spring', damping: 25, stiffness: 180 }}
          className="relative w-full max-w-lg bg-slate-900 border-l border-slate-800 shadow-2xl h-full flex flex-col justify-between z-10"
        >
          {/* Header */}
          <div className="p-6 border-b border-slate-800 flex justify-between items-center bg-slate-950/20">
            <div className="flex items-center gap-2.5">
              <ShieldAlert className={`w-5 h-5 ${isCritical ? 'text-rose-500 animate-pulse' : 'text-orange-400'}`} />
              <div>
                <h3 className="font-extrabold text-sm font-mono tracking-wider text-slate-100 uppercase">
                  Investigation Dossier
                </h3>
                <p className="text-[9px] text-slate-500 font-mono tracking-widest uppercase">
                  Forensic Threat Analyzer
                </p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-1.5 hover:bg-slate-800 border border-transparent hover:border-slate-700 rounded-lg text-slate-400 hover:text-slate-200 transition-all cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Scrollable Content */}
          <div className="flex-1 overflow-y-auto p-6 space-y-6 font-mono text-xs">
            {/* Title block */}
            <div className="space-y-2">
              <span className={`px-2 py-0.5 border rounded uppercase font-bold text-[9px] ${
                riskLevel === 'CRITICAL' ? 'bg-rose-500/10 border-rose-500/20 text-rose-400' : riskLevel === 'HIGH' ? 'bg-orange-500/10 border-orange-500/20 text-orange-400' : 'bg-amber-500/10 border-amber-500/20 text-amber-400'
              }`}>
                {riskLevel} RISK // SCORE {threatScore}
              </span>
              <h2 className="text-base font-bold text-slate-100 uppercase leading-snug">
                {details.name}
              </h2>
            </div>

            {/* Impact Metrics Grid */}
            <div className="grid grid-cols-2 gap-4">
              <div className="p-3 bg-slate-950/40 border border-slate-900 rounded-lg space-y-1">
                <span className="text-[9px] text-slate-500 uppercase font-bold flex items-center gap-1">
                  <Server className="w-3 h-3 text-cyan-400" />
                  Affected Host IP
                </span>
                {matchedIp !== 'N/A' ? (
                  <button 
                    onClick={() => {
                      onHostClick(matchedIp);
                      onClose();
                    }}
                    className="text-cyan-400 font-extrabold hover:underline text-left cursor-pointer"
                  >
                    {matchedIp} (Investigate)
                  </button>
                ) : (
                  <span className="text-slate-400 font-extrabold">GATEWAY SYSTEM</span>
                )}
              </div>

              <div className="p-3 bg-slate-950/40 border border-slate-900 rounded-lg space-y-1">
                <span className="text-[9px] text-slate-500 uppercase font-bold flex items-center gap-1">
                  <Radio className="w-3 h-3 text-cyan-400" />
                  Classification
                </span>
                <span className="text-slate-300 font-bold truncate block" title={details.classification}>
                  {details.classification.split(':')[0]}
                </span>
              </div>
            </div>

            {/* Deep Description */}
            <div className="space-y-2 bg-slate-950/40 border border-slate-900 p-4 rounded-lg">
              <span className="text-[9px] text-slate-500 uppercase font-bold flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" />
                Threat Description & Analysis
              </span>
              <p className="text-slate-400 leading-relaxed text-[11px]">
                {details.description}
              </p>
            </div>

            {/* Recommended remediations */}
            <div className="space-y-3">
              <span className="text-[9px] text-slate-500 uppercase font-bold flex items-center gap-1.5 border-b border-slate-900/60 pb-1.5">
                <ClipboardList className="w-3.5 h-3.5 text-cyan-400" />
                CISO Remediation Protocol checklist
              </span>
              <div className="space-y-2.5">
                {details.action.map((act, index) => (
                  <div key={index} className="flex gap-2.5 items-start p-2.5 bg-slate-950/20 border border-slate-900/60 rounded">
                    <CheckSquare className="w-4 h-4 text-cyan-500 shrink-0 mt-0.5" />
                    <span className="text-[10px] text-slate-300 leading-relaxed">{act}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Footer Info */}
          <div className="p-4 border-t border-slate-800 bg-slate-950/40 flex justify-between items-center text-[9px] text-slate-500 font-mono">
            <span>Dossier Hash: passive_scapy</span>
            <span>SECURE PATHWAY</span>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
