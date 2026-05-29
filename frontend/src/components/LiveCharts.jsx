import React from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  Legend
} from 'recharts';

export function LiveTimelineChart({ data, type = 'pps' }) {
  const config = type === 'bps' 
    ? {
        stroke: '#06b6d4',
        fill: 'url(#colorBps)',
        label: 'Bandwidth (Kbps)',
        dataKey: 'bandwidth_kbps',
        unit: ' Kbps'
      }
    : {
        stroke: '#3b82f6',
        fill: 'url(#colorPps)',
        label: 'Traffic Ingestion (PPS)',
        dataKey: 'packets_per_second',
        unit: ' PPS'
      };

  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="colorBps" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.2}/>
              <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
            </linearGradient>
            <linearGradient id="colorPps" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.2}/>
              <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
            </linearGradient>
          </defs>
          <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" vertical={false} />
          <XAxis 
            dataKey="timeLabel" 
            stroke="#475569" 
            fontSize={10} 
            fontFamily="monospace"
            tickLine={false}
          />
          <YAxis 
            stroke="#475569" 
            fontSize={10} 
            fontFamily="monospace" 
            tickLine={false}
            axisLine={false}
          />
          <Tooltip
            contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
            labelStyle={{ color: '#94a3b8', fontFamily: 'monospace', fontSize: '11px' }}
            itemStyle={{ color: config.stroke, fontSize: '12px', fontFamily: 'monospace' }}
            formatter={(value) => [`${value}${config.unit}`, config.label]}
          />
          <Area 
            type="monotone" 
            dataKey={config.dataKey} 
            stroke={config.stroke} 
            strokeWidth={2}
            fill={config.fill} 
            animationDuration={300}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

export function ProtocolDonutChart({ stats }) {
  const chartData = [
    { name: 'TCP', value: stats.tcp || 0, color: '#3b82f6' },
    { name: 'UDP', value: stats.udp || 0, color: '#06b6d4' },
    { name: 'ICMP', value: stats.icmp || 0, color: '#f59e0b' },
    { name: 'Other', value: stats.other || 0, color: '#64748b' }
  ];

  const totalPackets = chartData.reduce((sum, item) => sum + item.value, 0);

  return (
    <div className="h-64 w-full flex items-center justify-center">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={chartData}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={80}
            paddingAngle={totalPackets > 0 ? 4 : 0}
            dataKey="value"
          >
            {chartData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
            itemStyle={{ fontSize: '12px', fontFamily: 'monospace' }}
            formatter={(value, name) => [`${value} pkts`, name]}
          />
          <Legend 
            verticalAlign="bottom" 
            height={36} 
            iconType="circle"
            formatter={(value, entry) => {
              const item = chartData.find(d => d.name === value);
              const count = item ? item.value : 0;
              return <span className="text-xs font-mono text-slate-400">{value}: {count} pkts</span>;
            }}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
