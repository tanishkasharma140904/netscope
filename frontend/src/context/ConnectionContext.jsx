import React, { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react';
import axios from 'axios';

const ConnectionContext = createContext(null);

export const useConnection = () => {
  const context = useContext(ConnectionContext);
  if (!context) {
    throw new Error('useConnection must be used within a ConnectionProvider');
  }
  return context;
};

export const ConnectionProvider = ({ children }) => {
  // Telemetry payloads
  const [stats, setStats] = useState({
    total_packets: 0,
    tcp: 0,
    udp: 0,
    icmp: 0,
    other: 0,
    bandwidth_bps: 0,
    packets_per_second: 0,
    threat_score: 0,
    risk_level: 'LOW'
  });
  const [activeThreats, setActiveThreats] = useState([]);
  const [hosts, setHosts] = useState([]);
  const [summaryData, setSummaryData] = useState({
    threat_score: 0,
    risk_level: 'LOW',
    security_health: 100,
    total_hosts: 0,
    total_sessions: 0,
    total_alerts: 0,
    top_threat: 'None',
    top_application: 'None'
  });

  const [loadingSummary, setLoadingSummary] = useState(true);

  // Connection and Latency States
  const [apiStatus, setApiStatus] = useState('OFFLINE');
  const [dbStatus, setDbStatus] = useState('OFFLINE');
  const [wsStatsStatus, setWsStatsStatus] = useState('OFFLINE');
  const [wsThreatsStatus, setWsThreatsStatus] = useState('OFFLINE');
  const [wsHostsStatus, setWsHostsStatus] = useState('OFFLINE');
  const [apiLatency, setApiLatency] = useState(0);
  const [lastUpdated, setLastUpdated] = useState('N/A');

  // WebSocket connections references
  const wsStatsRef = useRef(null);
  const wsThreatsRef = useRef(null);
  const wsHostsRef = useRef(null);

  // Auto-recovery timers references
  const wsStatsRetryDelay = useRef(1000);
  const wsThreatsRetryDelay = useRef(1000);
  const wsHostsRetryDelay = useRef(1000);

  const statsTimerIdRef = useRef(null);
  const threatsTimerIdRef = useRef(null);
  const hostsTimerIdRef = useRef(null);

  // Central timestamp builder
  const updateTimestamp = () => {
    const timeString = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    setLastUpdated(timeString);
  };

  // REST api polling loop with latency and recovery tracking
  const checkApiHealth = useCallback(async () => {
    const startTime = performance.now();
    try {
      if (apiStatus === 'OFFLINE') {
        setApiStatus('RECONNECTING');
      }
      const API_BASE =
      window.location.hostname.includes('netlify.app')
        ? 'https://netscope-backend-6fbb.onrender.com'
        : '';
    
    const response = await axios.get(
      `${API_BASE}/api/executive-summary`
    );
      const latency = Math.round(performance.now() - startTime);

      const s = response.data;
      setSummaryData({
        threat_score: s.threat_score || 0,
        risk_level: s.risk_level || 'LOW',
        security_health: s.security_health !== undefined ? s.security_health : (100 - (s.threat_score || 0)),
        total_hosts: s.total_hosts || 0,
        total_sessions: s.total_sessions || 0,
        total_alerts: s.total_alerts || 0,
        top_threat: s.top_threat || 'None',
        top_application: s.top_application || 'None'
      });

      setApiLatency(latency);
      setApiStatus(latency > 800 ? 'DEGRADED' : 'ONLINE');
      setDbStatus('ONLINE');
      setLoadingSummary(false);
      updateTimestamp();
    } catch (e) {
      console.error("[HEALTH SYSTEM] API connection check failed:", e);
      setApiStatus('OFFLINE');
      setDbStatus('OFFLINE');
      setApiLatency(0);
      // summary loading only completes on successful REST contact
    }
  }, [apiStatus]);

  useEffect(() => {
    checkApiHealth();
    const interval = setInterval(checkApiHealth, 5000);
    return () => clearInterval(interval);
  }, [checkApiHealth]);

  // Unified WebSocket connection engine
  const connectWebSocket = useCallback((urlPath, setPayload, setWsStatus, retryDelayRef, wsRef, timerIdRef) => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    
    let host = window.location.host;

    // Local development
    if (
      !host ||
      host.includes(':3000') ||
      host.includes(':3001') ||
      host.includes(':5173') ||
      window.location.protocol === 'file:'
    ) {
      host = '127.0.0.1:8000';
    }
    
    // Netlify Production
    if (window.location.hostname.includes('netlify.app')) {
      host = 'netscope-backend-6fbb.onrender.com';
    }

    const wsUrl = `${protocol}//${host}${urlPath}`;

    if (timerIdRef.current) {
      clearTimeout(timerIdRef.current);
    }

    setWsStatus('RECONNECTING');
    console.log(`[WS SYSTEM] Attempting connection to ${urlPath}... (Retry Delay: ${retryDelayRef.current}ms)`);
    
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      console.log(`[WS SYSTEM] Connected successfully to ${urlPath}`);
      setWsStatus('ONLINE');
      retryDelayRef.current = 1000; // Reset exponential backoff back to baseline
      updateTimestamp();
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        setPayload(data);
        updateTimestamp();
      } catch (e) {
        console.error(`[WS SYSTEM] Parse error on ${urlPath}:`, e);
      }
    };

    ws.onclose = () => {
      console.log(`[WS SYSTEM] Disconnected from ${urlPath}. Retrying in ${retryDelayRef.current}ms...`);
      setWsStatus('OFFLINE');
      
      // Setup exponential backoff cap at 30 seconds delay
      timerIdRef.current = setTimeout(() => {
        retryDelayRef.current = Math.min(retryDelayRef.current * 2, 30000);
        connectWebSocket(urlPath, setPayload, setWsStatus, retryDelayRef, wsRef, timerIdRef);
      }, retryDelayRef.current);
    };

    ws.onerror = (err) => {
      console.error(`[WS SYSTEM ERROR] Connection failed on ${urlPath}`);
      ws.close();
    };
  }, []);

  // Launch WebSocket stream engines on provider mount
  useEffect(() => {
    connectWebSocket('/ws/live/stats', setStats, setWsStatsStatus, wsStatsRetryDelay, wsStatsRef, statsTimerIdRef);
    connectWebSocket('/ws/live/threats', (data) => setActiveThreats(data.active_threats || []), setWsThreatsStatus, wsThreatsRetryDelay, wsThreatsRef, threatsTimerIdRef);
    connectWebSocket('/ws/live/hosts', setHosts, setWsHostsStatus, wsHostsRetryDelay, wsHostsRef, hostsTimerIdRef);

    return () => {
      if (wsStatsRef.current) wsStatsRef.current.close();
      if (wsThreatsRef.current) wsThreatsRef.current.close();
      if (wsHostsRef.current) wsHostsRef.current.close();
      
      if (statsTimerIdRef.current) clearTimeout(statsTimerIdRef.current);
      if (threatsTimerIdRef.current) clearTimeout(threatsTimerIdRef.current);
      if (hostsTimerIdRef.current) clearTimeout(hostsTimerIdRef.current);
    };
  }, [connectWebSocket]);

  // Derived overall status
  const globalWsStatus = 
    wsStatsStatus === 'ONLINE' && wsThreatsStatus === 'ONLINE' && wsHostsStatus === 'ONLINE'
      ? 'ONLINE'
      : wsStatsStatus === 'OFFLINE' || wsThreatsStatus === 'OFFLINE' || wsHostsStatus === 'OFFLINE'
        ? 'OFFLINE'
        : 'RECONNECTING';

  const value = {
    stats,
    activeThreats,
    hosts,
    summaryData,
    loadingSummary,
    apiStatus,
    dbStatus,
    wsStatsStatus,
    wsThreatsStatus,
    wsHostsStatus,
    globalWsStatus,
    apiLatency,
    lastUpdated,
    triggerApiRefresh: checkApiHealth
  };

  return (
    <ConnectionContext.Provider value={value}>
      {children}
    </ConnectionContext.Provider>
  );
};
