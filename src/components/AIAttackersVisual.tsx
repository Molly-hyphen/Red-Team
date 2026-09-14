import React, { useState, useEffect } from 'react';
import { Shield, Eye, Bug, Key, Cpu, CheckCircle, FileCode, Sparkles, Terminal, Activity } from 'lucide-react';

interface AgentNode {
  id: string;
  name: string;
  role: string;
  icon: React.ElementType;
  angle: number; // in degrees
  color: string;
  status: 'probing' | 'analyzing' | 'verifying' | 'active';
  telemetry: string;
}

export const AIAttackersVisual: React.FC = () => {
  const [activeTelemetryIndex, setActiveTelemetryIndex] = useState(0);
  const [targetPulse, setTargetPulse] = useState(false);

  const agents: AgentNode[] = [
    {
      id: 'recon',
      name: 'RECON AGENT',
      role: 'Surface & Route Mapper',
      icon: Eye,
      angle: 0,
      color: '#38bdf8', // sky-400
      status: 'analyzing',
      telemetry: 'Mapped 18 REST endpoints & 4 internal GraphQL resolvers',
    },
    {
      id: 'web',
      name: 'WEB ATTACK AGENT',
      role: 'Injection & Payload Engine',
      icon: Bug,
      angle: 60,
      color: '#f43f5e', // rose-500
      status: 'probing',
      telemetry: 'Executing AST taint trace on /api/checkout SQL parameter',
    },
    {
      id: 'auth',
      name: 'AUTH AGENT',
      role: 'JWT & Token Arbitrage',
      icon: Key,
      angle: 120,
      color: '#fbbf24', // amber-400
      status: 'probing',
      telemetry: 'Testing RS256/HS256 signature algorithm confusion',
    },
    {
      id: 'api',
      name: 'API AGENT',
      role: 'BOLA & IDOR Validator',
      icon: Cpu,
      angle: 180,
      color: '#818cf8', // indigo-400
      status: 'active',
      telemetry: 'Testing tenant boundary isolation on /v2/orders/:id',
    },
    {
      id: 'validation',
      name: 'VALIDATION AGENT',
      role: 'Empirical Proof & Zero-FP',
      icon: CheckCircle,
      angle: 240,
      color: '#10b981', // emerald-500
      status: 'verifying',
      telemetry: 'Confirming payload execution with AST source line verification',
    },
    {
      id: 'reporting',
      name: 'REPORTING AGENT',
      role: 'CVSS & Remediation Matrix',
      icon: FileCode,
      angle: 300,
      color: '#06b6d4', // cyan-500
      status: 'active',
      telemetry: 'Compiling structured executive & developer mitigation patch',
    },
  ];

  useEffect(() => {
    const interval = setInterval(() => {
      setActiveTelemetryIndex((prev) => (prev + 1) % agents.length);
      setTargetPulse(true);
      setTimeout(() => setTargetPulse(false), 600);
    }, 2400);

    return () => clearInterval(interval);
  }, [agents.length]);

  return (
    <div className="relative w-full max-w-4xl mx-auto py-12 px-4 select-none">
      {/* Outer Glow Background */}
      <div className="absolute inset-0 bg-radial from-sky-900/10 via-transparent to-transparent pointer-events-none" />

      {/* Main Interactive Diagram Container */}
      <div className="relative aspect-square max-w-[540px] mx-auto flex items-center justify-center">
        {/* Orbital Rings */}
        <div className="absolute inset-4 rounded-full border border-sky-500/10 border-dashed animate-[spin_120s_linear_infinite]" />
        <div className="absolute inset-16 rounded-full border border-cyan-500/15 border-dotted animate-[spin_90s_linear_infinite_reverse]" />
        <div className="absolute inset-28 rounded-full border border-blue-600/20" />

        {/* Center Target Node */}
        <div className="relative z-20 flex flex-col items-center justify-center">
          <div
            className={`relative w-24 h-24 rounded-2xl bg-gradient-to-br from-[#0c1e38] via-[#081527] to-[#040a14] border-2 flex flex-col items-center justify-center p-3 text-center transition-all duration-500 shadow-2xl ${
              targetPulse
                ? 'border-rose-500 shadow-rose-500/40 scale-105'
                : 'border-sky-400/80 shadow-sky-500/30'
            }`}
          >
            {/* Ping Wave */}
            <div className="absolute -inset-1 rounded-2xl bg-sky-400/20 animate-ping pointer-events-none opacity-40" />
            
            <Shield className="w-7 h-7 text-sky-300 mb-1" />
            <span className="text-[11px] font-black tracking-widest text-white uppercase font-mono">
              TARGET
            </span>
            <span className="text-[8px] font-mono text-sky-400/80">
              APP / REPO
            </span>
          </div>

          <div className="absolute -bottom-8 px-2.5 py-0.5 rounded-full bg-[#09152b] border border-sky-500/30 text-[9px] font-mono text-sky-300 flex items-center gap-1.5 shadow-md">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <span>Target Protected Sandbox</span>
          </div>
        </div>

        {/* Orbiting Agent Nodes */}
        {agents.map((agent, index) => {
          const Icon = agent.icon;
          const isActive = index === activeTelemetryIndex;
          const rad = (agent.angle * Math.PI) / 180;
          // Radius percentage from center
          const radius = 42; // in percentage of container
          const x = 50 + radius * Math.cos(rad);
          const y = 50 + radius * Math.sin(rad);

          return (
            <div
              key={agent.id}
              style={{
                left: `${x}%`,
                top: `${y}%`,
                transform: 'translate(-50%, -50%)',
              }}
              className="absolute z-20 flex flex-col items-center group cursor-pointer transition-transform duration-300 hover:scale-110"
              onClick={() => setActiveTelemetryIndex(index)}
            >
              {/* Connection laser line towards center (50%, 50%) */}
              <svg className="absolute inset-0 pointer-events-none -z-10 overflow-visible w-0 h-0">
                <line
                  x1="0"
                  y1="0"
                  x2={`${(50 - x) * 4.8}px`}
                  y2={`${(50 - y) * 4.8}px`}
                  stroke={isActive ? agent.color : 'rgba(56, 189, 248, 0.2)'}
                  strokeWidth={isActive ? '2' : '1'}
                  strokeDasharray={isActive ? '4 2' : '2 4'}
                  className={isActive ? 'animate-pulse' : ''}
                />
              </svg>

              {/* Agent Node Icon Card */}
              <div
                className={`relative w-14 h-14 sm:w-16 sm:h-16 rounded-2xl bg-[#09152b] border flex flex-col items-center justify-center p-2 transition-all duration-300 shadow-xl ${
                  isActive
                    ? 'border-sky-300 shadow-sky-500/40 ring-2 ring-sky-400/30 scale-110'
                    : 'border-[#18315a] hover:border-sky-400/60'
                }`}
                style={{
                  boxShadow: isActive ? `0 0 20px ${agent.color}40` : undefined,
                }}
              >
                <Icon
                  className="w-5 h-5 sm:w-6 sm:h-6 transition-transform group-hover:rotate-6"
                  style={{ color: agent.color }}
                />
                <span className="text-[8px] sm:text-[9px] font-bold font-mono text-slate-200 mt-1 uppercase text-center leading-none">
                  {agent.id}
                </span>
                {isActive && (
                  <span
                    className="absolute -top-1 -right-1 w-3 h-3 rounded-full border-2 border-[#09152b] animate-ping"
                    style={{ backgroundColor: agent.color }}
                  />
                )}
              </div>

              {/* Tooltip on hover/active */}
              <div
                className={`mt-1.5 px-2 py-0.5 rounded bg-[#061021]/90 border text-[9px] font-mono whitespace-nowrap transition-all ${
                  isActive
                    ? 'border-sky-400 text-sky-200 shadow-sm'
                    : 'border-slate-800 text-slate-400 opacity-80 group-hover:opacity-100'
                }`}
              >
                {agent.name}
              </div>
            </div>
          );
        })}
      </div>

      {/* Live Agent Telemetry Stream Box */}
      <div className="mt-8 bg-[#071326]/90 border border-[#162d52] rounded-2xl p-4 max-w-xl mx-auto shadow-2xl backdrop-blur-md">
        <div className="flex items-center justify-between border-b border-[#142849] pb-2.5 mb-2.5 text-xs">
          <div className="flex items-center gap-2 font-mono">
            <Activity className="w-4 h-4 text-sky-400 animate-pulse" />
            <span className="text-slate-300 font-semibold">Active Agent Stream:</span>
            <span
              className="font-bold px-2 py-0.5 rounded text-[10px]"
              style={{
                backgroundColor: `${agents[activeTelemetryIndex].color}20`,
                color: agents[activeTelemetryIndex].color,
                border: `1px solid ${agents[activeTelemetryIndex].color}50`,
              }}
            >
              {agents[activeTelemetryIndex].name}
            </span>
          </div>
          <span className="text-[10px] font-mono text-slate-400 flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            Autonomous
          </span>
        </div>

        <div className="flex items-start gap-3">
          <div className="p-2 rounded-xl bg-[#0b1b36] border border-[#1d3a68] shrink-0">
            <Terminal className="w-4 h-4 text-sky-300" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-xs font-mono text-slate-300 leading-relaxed break-words">
              <span className="text-sky-400 font-bold">$ </span>
              {agents[activeTelemetryIndex].telemetry}
            </div>
            <div className="text-[10px] text-slate-400 mt-1 font-mono">
              Role: <span className="text-slate-200">{agents[activeTelemetryIndex].role}</span> • Status:{' '}
              <span className="text-emerald-400 capitalize">{agents[activeTelemetryIndex].status}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
