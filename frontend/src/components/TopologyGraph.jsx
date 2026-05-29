import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { ReactFlow, Controls, Background } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Network, RefreshCw } from 'lucide-react';

export default function TopologyGraph({ onHostClick }) {
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [loading, setLoading] = useState(true);

  const onNodeClick = (event, node) => {
    if (node.id !== 'central-node' && onHostClick) {
      onHostClick(node.id);
    }
  };

  const fetchTopology = async () => {
    try {
      setLoading(true);
      const response = await axios.get('/api/inventory');
      const hosts = response.data.hosts || [];
      
      // 1. Initialize Central Node
      const centralNodeId = 'central-node';
      const newNodes = [
        {
          id: centralNodeId,
          type: 'default',
          data: { label: '🛡️ Local Gate/Node\n192.168.1.1' },
          position: { x: 380, y: 220 },
          style: {
            background: '#0c4a6e',
            color: '#00f0ff',
            border: '2px solid #00f0ff',
            borderRadius: '10px',
            fontSize: '11px',
            fontFamily: 'monospace',
            fontWeight: 'bold',
            padding: '10px',
            width: 150,
            textAlign: 'center',
            boxShadow: '0 0 15px rgba(0, 240, 255, 0.25)'
          }
        }
      ];

      const newEdges = [];
      const totalHosts = hosts.slice(0, 12); // Limit to top 12 active hosts for clean layout spacing
      const N = totalHosts.length;
      const R = 180; // Circular radius spacing offset

      // 2. Compute circular positions for hosts branches
      totalHosts.forEach((host, index) => {
        const ip = host.ip;
        
        // Skip central node duplicate plotting
        if (ip === '192.168.1.1' || ip === '127.0.0.1') return;

        const theta = (2 * Math.PI * index) / N;
        const x = 380 + R * Math.cos(theta);
        const y = 220 + R * Math.sin(theta);

        // Classification & Styling rules
        const isPrivate = ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.');
        const isHighVolume = host.packet_count > 1000;
        
        let label = `${isPrivate ? '🖥️' : '🌐'} ${ip}\nVol: ${host.packet_count}`;
        let bg = '#0f172a';
        let stroke = '#06b6d4'; // standard internal
        let text = '#94a3b8';
        let glow = 'rgba(6, 182, 212, 0.1)';

        if (!isPrivate) {
          stroke = '#f97316'; // external orange warning
          glow = 'rgba(249, 115, 22, 0.15)';
        }

        if (isHighVolume) {
          stroke = '#f43f5e'; // high volume threat warning
          glow = 'rgba(244, 63, 94, 0.25)';
          label = `⚠ ${ip}\nCritical Vol: ${host.packet_count}`;
        }

        newNodes.push({
          id: ip,
          type: 'default',
          data: { label },
          position: { x, y },
          style: {
            background: bg,
            color: stroke,
            border: `1px solid ${stroke}`,
            borderRadius: '8px',
            fontSize: '9px',
            fontFamily: 'monospace',
            padding: '8px',
            width: 130,
            textAlign: 'center',
            boxShadow: `0 0 10px ${glow}`
          }
        });

        // 3. Connect branches to central gateway node
        newEdges.push({
          id: `edge-${ip}`,
          source: centralNodeId,
          target: ip,
          animated: true,
          style: {
            stroke: stroke,
            strokeWidth: isHighVolume ? 2 : 1,
            opacity: 0.6
          }
        });
      });

      setNodes(newNodes);
      setEdges(newEdges);
      setLoading(false);
    } catch (e) {
      console.error("Topology fetch error:", e);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTopology();
    const timer = setInterval(fetchTopology, 10000); // Auto-update map canvas every 10s
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 p-6 rounded-xl flex flex-col justify-between h-[450px]">
      {/* Header */}
      <div className="flex justify-between items-center mb-4 border-b border-slate-800/60 pb-3">
        <div className="flex items-center gap-2">
          <Network className="w-5 h-5 text-cyan-400" />
          <div>
            <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
              Passive Network Topology Visualizer
            </h3>
            <p className="text-[10px] text-slate-500 font-mono">
              Live mapping of host nodes connected to local gateway interface
            </p>
          </div>
        </div>
        <button 
          onClick={fetchTopology}
          className="p-1.5 bg-slate-950 border border-slate-850 hover:bg-slate-800 rounded transition-colors text-slate-400 hover:text-slate-200"
          title="Refresh Graph"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* React Flow Canvas */}
      <div className="flex-1 w-full bg-slate-950/60 border border-slate-900 rounded-xl overflow-hidden relative">
        {loading && nodes.length === 0 ? (
          <div className="absolute inset-0 flex items-center justify-center font-mono text-xs text-slate-500 z-20">
            Constructing node clusters...
          </div>
        ) : null}

        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodeClick={onNodeClick}
          fitView
          attributionPosition="bottom-left"
          proOptions={{ hideAttribution: true }}
          minZoom={0.5}
          maxZoom={1.5}
        >
          <Background color="#1e293b" gap={16} size={1} />
          <Controls 
            style={{ 
              display: 'flex', 
              flexDirection: 'row', 
              bottom: 10, 
              left: 10,
              background: '#0f172a',
              border: '1px solid #334155',
              borderRadius: '6px',
              padding: '2px',
              boxShadow: 'none'
            }} 
            showInteractive={false}
          />
        </ReactFlow>
      </div>

      {/* Legend status indicators */}
      <div className="mt-4 border-t border-slate-800/60 pt-3 flex justify-around text-[9px] font-mono text-slate-500">
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded bg-cyan-500"></span> INTERNAL ASSET</span>
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded bg-orange-500"></span> EXTERNAL HOST</span>
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded bg-rose-500"></span> HIGH INGEST / CRITICAL</span>
      </div>
    </div>
  );
}
