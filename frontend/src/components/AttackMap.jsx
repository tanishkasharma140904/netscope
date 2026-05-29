import React, { useState, useEffect, useRef } from 'react';
import { useConnection } from '../context/ConnectionContext';
import { motion, AnimatePresence } from 'framer-motion';
import { Globe, ShieldAlert, Crosshair, MapPin } from 'lucide-react';
import EmptyState from './EmptyState';

const isPrivateIP = (ip) => {
  return ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.') || ip === '127.0.0.1' || ip === 'localhost';
};

const mapIpToCoords = (ip) => {
  if (isPrivateIP(ip)) {
    return { x: 53, y: 45, isPrivate: true };
  }
  const parts = ip.split('.').map(Number);
  const sum = parts.reduce((a, b) => a + b, 0);
  const x = 12 + ((parts[0] * 7 + parts[1] * 13 + sum) % 76);
  const y = 22 + ((parts[2] * 11 + parts[3] * 17 + sum) % 56);
  return { x, y, isPrivate: false };
};

const getGeoLabel = (ip) => {
  const parts = ip.split('.').map(Number);
  if (parts[0] === 8) return 'DNS Service';
  if (parts[0] >= 1 && parts[0] <= 126) return 'WAN Class A';
  if (parts[0] >= 128 && parts[0] <= 191) return 'WAN Class B';
  return 'WAN Class C';
};

export default function AttackMap() {
  const { hosts } = useConnection();
  const [attacks, setAttacks] = useState([]);
  const [log, setLog] = useState([]);
  const prevHostsRef = useRef({});

  // Helper to trigger arc trajectory animation
  const triggerFlow = (ip, packetDiff, packetTotal) => {
    const source = mapIpToCoords(ip);
    const target = { x: 53, y: 45 };
    const id = Math.random();
    
    const newAttack = {
      id,
      source,
      target,
      ip,
      timestamp: new Date().toLocaleTimeString([], { hour12: false })
    };

    setAttacks(prev => [...prev, newAttack]);
    
    setLog(prev => [
      {
        id,
        message: `[FLOW TELEMETRY] Mapped ingress: ${ip} (${getGeoLabel(ip)}) → Local Gateway (+${packetDiff} pkts)`,
        threat: packetTotal > 1000 ? 'CRITICAL' : 'MEDIUM',
        time: newAttack.timestamp
      },
      ...prev
    ].slice(0, 5));

    setTimeout(() => {
      setAttacks(prev => prev.filter(a => a.id !== id));
    }, 2500);
  };

  // Listen to hosts updates and calculate packets difference
  useEffect(() => {
    if (!Array.isArray(hosts) || hosts.length === 0) return;

    const prevHosts = prevHostsRef.current;
    const nextHosts = {};

    hosts.forEach((host) => {
      const ip = host.ip;
      const nextCount = host.packets || 0;
      const prevCount = prevHosts[ip] || 0;

      nextHosts[ip] = nextCount;

      // If external IP and packet volume increased, sweep curved path
      if (!isPrivateIP(ip) && nextCount > prevCount && prevCount > 0) {
        triggerFlow(ip, nextCount - prevCount, nextCount);
      }
    });

    prevHostsRef.current = nextHosts;
  }, [hosts]);

  const externalHosts = Array.isArray(hosts) ? hosts.filter(h => !isPrivateIP(h.ip)) : [];

  const mapNodes = (Array.isArray(hosts) ? hosts : []).map((host) => {
    const ip = host.ip;
    const packets = host.packets || 0;
    const coords = mapIpToCoords(ip);
    return {
      ip,
      packets,
      x: coords.x,
      y: coords.y,
      isPrivate: coords.isPrivate,
      threat: packets > 1000 ? 'CRITICAL' : 'MEDIUM'
    };
  });

  // Always keep target gateway node present
  const centralGateNode = {
    ip: '192.168.1.1',
    packets: 0,
    x: 53,
    y: 45,
    isPrivate: true,
    threat: 'TARGET'
  };

  const finalNodes = [centralGateNode, ...mapNodes.filter(n => !n.isPrivate)];

  return (
    <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-6 rounded-xl flex flex-col justify-between h-[450px]">
      {/* Header Info */}
      <div className="flex justify-between items-center mb-4 border-b border-slate-800/60 pb-3">
        <div className="flex items-center gap-2">
          <Globe className="w-5 h-5 text-cyan-400" />
          <div>
            <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
              Telemetry Cyber Threat Map
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              Live external connection attempts plotted on coordinate vectors
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 border border-cyan-500/20 bg-cyan-500/5 px-2.5 py-1 rounded text-[10px] font-mono text-cyan-400">
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>WIRE PATROL: ONLINE</span>
        </div>
      </div>

      {/* SVG Canvas Map */}
      <div className="flex-1 w-full bg-slate-950/60 border border-slate-900 rounded-xl relative overflow-hidden flex items-center justify-center">
        {/* Decorative Grid Lines */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#0f172a_1px,transparent_1px),linear-gradient(to_bottom,#0f172a_1px,transparent_1px)] bg-[size:30px_30px] opacity-40 z-0" />

        {externalHosts.length === 0 ? (
          <div className="absolute inset-0 flex items-center justify-center z-20 p-6">
            <EmptyState message="No external hosts detected" />
          </div>
        ) : (
          <>
            <svg viewBox="0 0 100 100" className="w-full h-full preserve-3d absolute inset-0 z-10">
              {/* WORLD OUTLINES */}
              <path d="M 10 25 Q 20 20 28 25 T 38 35 T 25 45 Z" fill="none" stroke="#1e293b" strokeWidth="0.8" />
              <path d="M 25 50 Q 35 60 30 75 T 26 90 Z" fill="none" stroke="#1e293b" strokeWidth="0.8" />
              <path d="M 45 20 Q 60 15 80 20 T 95 30 T 90 45 T 70 50 Q 55 45 45 35 Z" fill="none" stroke="#1e293b" strokeWidth="0.8" />
              <path d="M 45 40 Q 55 45 58 60 T 55 75 T 48 85" fill="none" stroke="#1e293b" strokeWidth="0.8" />
              <path d="M 80 68 Q 88 70 90 80 T 78 85 Z" fill="none" stroke="#1e293b" strokeWidth="0.8" />

              {/* Plot Node pins */}
              {finalNodes.map((node, index) => {
                const isTarget = node.threat === 'TARGET';
                return (
                  <g key={index}>
                    {/* Node Ring Ping */}
                    <circle 
                      cx={node.x} 
                      cy={node.y} 
                      r={isTarget ? 3.5 : 2} 
                      fill={isTarget ? '#06b6d4' : '#ef4444'} 
                      className="opacity-25"
                    >
                      <animate 
                        attributeName="r" 
                        values={isTarget ? "2.5;7.5;2.5" : "1.5;4.5;1.5"} 
                        dur={isTarget ? "2.5s" : "2s"} 
                        repeatCount="indefinite" 
                      />
                      <animate 
                        attributeName="opacity" 
                        values="0.4;0;0.4" 
                        dur={isTarget ? "2.5s" : "2s"} 
                        repeatCount="indefinite" 
                      />
                    </circle>

                    {/* Central pin point */}
                    <circle 
                      cx={node.x} 
                      cy={node.y} 
                      r={isTarget ? 1.2 : 0.8} 
                      fill={isTarget ? '#00f0ff' : '#ff3b30'} 
                    />
                  </g>
                );
              })}

              {/* Draw attack connection arcs */}
              <AnimatePresence>
                {attacks.map((atk) => {
                  const x1 = atk.source.x;
                  const y1 = atk.source.y;
                  const x2 = atk.target.x;
                  const y2 = atk.target.y;
                  
                  const mx = (x1 + x2) / 2;
                  const my = (y1 + y2) / 2 - 15; 

                  return (
                    <g key={atk.id}>
                      {/* Glowing background arc */}
                      <path
                        d={`M ${x1} ${y1} Q ${mx} ${my} ${x2} ${y2}`}
                        fill="none"
                        stroke={atk.threat === 'CRITICAL' ? '#f43f5e' : '#06b6d4'}
                        strokeWidth="0.8"
                        strokeOpacity="0.4"
                        strokeDasharray="2, 2"
                      />

                      {/* Pulsing signal dot travelling along the path */}
                      <motion.path
                        d={`M ${x1} ${y1} Q ${mx} ${my} ${x2} ${y2}`}
                        fill="none"
                        stroke={atk.threat === 'CRITICAL' ? '#f43f5e' : '#00f0ff'}
                        strokeWidth="1.2"
                        strokeDasharray="4 96"
                        initial={{ strokeDashoffset: 100 }}
                        animate={{ strokeDashoffset: 0 }}
                        transition={{ duration: 2.2, ease: "linear" }}
                      />
                    </g>
                  );
                })}
              </AnimatePresence>
            </svg>

            {/* Dynamic target lock on center target */}
            <div 
              className="absolute border border-cyan-500/30 rounded-full flex items-center justify-center pointer-events-none filter shadow-[0_0_10px_rgba(6,182,212,0.1)] w-8 h-8 animate-[spin_20s_linear_infinite] z-10"
              style={{ left: '53%', top: '45%', transform: 'translate(-50%, -50%)' }}
            >
              <Crosshair className="w-4 h-4 text-cyan-400 opacity-60" />
            </div>
          </>
        )}
      </div>

      {/* Map attack live console log */}
      <div className="mt-4 border-t border-slate-800/60 pt-3 flex flex-col space-y-1 font-mono text-[10px]">
        {log.length > 0 ? (
          log.map((item) => (
            <div key={item.id} className="flex justify-between items-center text-slate-400 py-0.5 px-2 bg-slate-950/40 rounded border border-slate-900">
              <div className="flex items-center gap-2">
                <span className={`w-1.5 h-1.5 rounded-full ${
                  item.threat === 'CRITICAL' ? 'bg-rose-500 animate-pulse' : 'bg-orange-500'
                }`} />
                <span className="truncate max-w-[450px]">{item.message}</span>
              </div>
              <span className="text-slate-600 font-bold">{item.time}</span>
            </div>
          ))
        ) : (
          <div className="text-center text-slate-600 py-2">
            awaiting external connection telemetry on eth0 interface...
          </div>
        )}
      </div>
    </div>
  );
}
