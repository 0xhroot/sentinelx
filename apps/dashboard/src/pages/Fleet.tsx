import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Users, Wifi, WifiOff, Server, Clock, Shield } from 'lucide-react';
import StatCard from '../components/StatCard';

interface Agent {
  id: string;
  hostname: string;
  ip: string;
  status: 'online' | 'offline';
  last_seen: string;
  latency: number;
  threats: number;
}

export default function Fleet() {
  const [agents] = useState<Agent[]>([
    { id: 'agent-001', hostname: 'prod-web-01', ip: '10.0.1.10', status: 'online', last_seen: new Date().toISOString(), latency: 12, threats: 3 },
    { id: 'agent-002', hostname: 'prod-db-01', ip: '10.0.1.20', status: 'online', last_seen: new Date().toISOString(), latency: 8, threats: 0 },
    { id: 'agent-003', hostname: 'staging-app-01', ip: '10.0.2.10', status: 'offline', last_seen: new Date(Date.now() - 3600000).toISOString(), latency: 0, threats: 1 },
    { id: 'agent-004', hostname: 'dev-worker-01', ip: '10.0.3.10', status: 'online', last_seen: new Date().toISOString(), latency: 25, threats: 0 },
  ]);

  const onlineCount = agents.filter((a) => a.status === 'online').length;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard label="Total Agents" value={agents.length} icon={<Users size={18} />} color="blue" />
        <StatCard label="Online" value={onlineCount} icon={<Wifi size={18} />} color="green" />
        <StatCard label="Offline" value={agents.length - onlineCount} icon={<WifiOff size={18} />} color="red" />
        <StatCard label="Total Threats" value={agents.reduce((a, b) => a + b.threats, 0)} icon={<Shield size={18} />} color="orange" />
      </div>

      <div className="sx-card p-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: 'rgba(255,255,255,0.35)' }}>
          Fleet Agents
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {agents.map((agent, i) => (
            <motion.div key={agent.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.1 }}
              className="p-4 rounded-xl transition-all cursor-pointer"
              style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)' }}>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Server size={14} style={{ color: '#60A5FA' }} />
                  <span className="text-sm font-medium" style={{ color: 'rgba(255,255,255,0.85)' }}>{agent.hostname}</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <div className="w-1.5 h-1.5 rounded-full"
                    style={{ background: agent.status === 'online' ? '#22C55E' : '#EF4444' }} />
                  <span className="text-[10px] font-medium"
                    style={{ color: agent.status === 'online' ? '#4ADE80' : '#F87171' }}>
                    {agent.status}
                  </span>
                </div>
              </div>
              <div className="grid grid-cols-3 gap-2 text-[10px]">
                <div>
                  <span style={{ color: 'rgba(255,255,255,0.2)' }}>IP</span>
                  <p className="font-mono mt-0.5" style={{ color: 'rgba(255,255,255,0.5)' }}>{agent.ip}</p>
                </div>
                <div>
                  <span style={{ color: 'rgba(255,255,255,0.2)' }}>Latency</span>
                  <p className="mt-0.5" style={{ color: agent.latency > 20 ? '#FACC15' : 'rgba(255,255,255,0.5)' }}>{agent.latency}ms</p>
                </div>
                <div>
                  <span style={{ color: 'rgba(255,255,255,0.2)' }}>Threats</span>
                  <p className="mt-0.5" style={{ color: agent.threats > 0 ? '#F87171' : '#4ADE80' }}>{agent.threats}</p>
                </div>
              </div>
              <div className="flex items-center gap-1 mt-3 text-[9px]" style={{ color: 'rgba(255,255,255,0.15)' }}>
                <Clock size={9} />
                Last seen: {new Date(agent.last_seen).toLocaleTimeString()}
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </div>
  );
}
