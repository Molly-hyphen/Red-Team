import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Terminal,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Play,
  FileCode,
  Zap,
  Globe,
  Cpu,
  Layers,
} from 'lucide-react';

export const LandingProductPreview: React.FC<{ onGetStarted: () => void }> = ({ onGetStarted }) => {
  const [activeTab, setActiveTab] = useState<'live' | 'findings' | 'ast'>('live');
  const [ticker, setTicker] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setTicker((t) => (t + 1) % 1000);
    }, 1500);
    return () => clearInterval(timer);
  }, []);

  const mockLogs = [
    { time: '14:02:11', agent: 'ASTRecon', msg: 'Parsed 42 route handlers & exported Prisma schemas', type: 'info' },
    { time: '14:02:14', agent: 'SQLiProbe', msg: 'Taint sink located at db/orders.ts:88 without parameterization', type: 'warn' },
    { time: '14:02:18', agent: 'Validator', msg: 'Reproduced SQL injection payload on /api/orders?filter=\' OR 1=1--', type: 'crit' },
    { time: '14:02:22', agent: 'AuthAgent', msg: 'Verified JWT secret entropy: weak fallback token detected', type: 'warn' },
    { time: '14:02:26', agent: 'DefenseCheck', msg: 'CSP Nonce Header & HSTS verified resilient on root domain', type: 'safe' },
  ];

  return (
    <div className="relative w-full max-w-5xl mx-auto rounded-3xl bg-[#061021]/90 border border-[#1b3660] shadow-2xl shadow-sky-950/50 overflow-hidden backdrop-blur-xl group">
      {/* Top Window Bar */}
      <div className="flex items-center justify-between px-4 py-3 bg-[#08152b] border-b border-[#142849]">
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 rounded-full bg-rose-500/80" />
          <div className="w-3 h-3 rounded-full bg-amber-500/80" />
          <div className="w-3 h-3 rounded-full bg-emerald-500/80" />
          <span className="ml-2 text-xs font-mono text-slate-400 font-semibold hidden sm:inline">
            Red Team Autonomous SecOps • Live Assessment Session
          </span>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/40 text-[10px] font-mono text-emerald-300">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
            <span>Target Active: api.production-demo.internal</span>
          </div>

          <button
            onClick={onGetStarted}
            className="px-3 py-1 bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 text-white rounded-lg text-xs font-semibold shadow transition-all cursor-pointer flex items-center gap-1"
          >
            <span>Launch Live</span>
            <Play className="w-3 h-3 fill-current" />
          </button>
        </div>
      </div>

      {/* Internal Navigation Tabs */}
      <div className="flex items-center gap-2 px-4 py-2.5 bg-[#071324] border-b border-[#122340] text-xs font-mono">
        <button
          onClick={() => setActiveTab('live')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl transition ${
            activeTab === 'live'
              ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          <span>Live Attack Stream</span>
        </button>

        <button
          onClick={() => setActiveTab('findings')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl transition ${
            activeTab === 'findings'
              ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
          <span>Confirmed Findings (3)</span>
        </button>

        <button
          onClick={() => setActiveTab('ast')}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl transition ${
            activeTab === 'ast'
              ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileCode className="w-3.5 h-3.5 text-cyan-400" />
          <span>AST Source Verifier</span>
        </button>
      </div>

      {/* Main Preview Content */}
      <div className="p-4 sm:p-6 grid grid-cols-1 lg:grid-cols-3 gap-4 bg-gradient-to-b from-[#061021] to-[#040a14]">
        {/* Left 2 Cols: Main Viewport */}
        <div className="lg:col-span-2 space-y-4">
          {/* Target & Metric Header */}
          <div className="grid grid-cols-3 gap-3">
            <div className="p-3 rounded-2xl bg-[#09172e] border border-[#162d52]">
              <div className="text-[10px] font-mono uppercase text-slate-400">Risk Score</div>
              <div className="text-xl font-bold text-rose-400 flex items-center gap-1.5 mt-0.5">
                <span>8.8</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800">
                  HIGH
                </span>
              </div>
            </div>

            <div className="p-3 rounded-2xl bg-[#09172e] border border-[#162d52]">
              <div className="text-[10px] font-mono uppercase text-slate-400">Endpoints Mapped</div>
              <div className="text-xl font-bold text-sky-300 flex items-center gap-1.5 mt-0.5">
                <span>38</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-sky-950 text-sky-300 border border-sky-800">
                  100%
                </span>
              </div>
            </div>

            <div className="p-3 rounded-2xl bg-[#09172e] border border-[#162d52]">
              <div className="text-[10px] font-mono uppercase text-slate-400">Verified Proofs</div>
              <div className="text-xl font-bold text-emerald-300 flex items-center gap-1.5 mt-0.5">
                <span>100%</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                  ZERO FP
                </span>
              </div>
            </div>
          </div>

          {activeTab === 'live' && (
            <div className="rounded-2xl bg-[#030914] border border-[#132849] p-4 font-mono text-xs space-y-2.5">
              <div className="flex items-center justify-between text-[11px] text-slate-400 border-b border-slate-800 pb-2">
                <span className="flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-sky-400" />
                  Terminal Attack Stream
                </span>
                <span className="text-emerald-400">SHA-256 Verified: 4a9f...b12c</span>
              </div>

              {mockLogs.map((log, i) => (
                <div key={i} className="flex items-start gap-2 text-[11px] leading-relaxed">
                  <span className="text-slate-400 shrink-0">{log.time}</span>
                  <span className="text-sky-400 font-semibold shrink-0">[{log.agent}]</span>
                  <span
                    className={
                      log.type === 'crit'
                        ? 'text-rose-300 font-bold bg-rose-950/40 px-1 rounded'
                        : log.type === 'warn'
                        ? 'text-amber-300'
                        : log.type === 'safe'
                        ? 'text-emerald-300'
                        : 'text-slate-300'
                    }
                  >
                    {log.msg}
                  </span>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'findings' && (
            <div className="space-y-2">
              <div className="p-3 rounded-2xl bg-[#0f172a] border border-rose-500/30 flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-600 text-white font-mono">
                      CRITICAL
                    </span>
                    <span className="text-xs font-bold text-white font-mono">CWE-89: SQL Injection (SQLi)</span>
                  </div>
                  <div className="text-[11px] text-slate-300 mt-1">
                    Route: <span className="font-mono text-sky-300">/api/orders?filter=</span> • Line 88
                  </div>
                </div>
                <span className="text-[10px] font-mono text-emerald-400 px-2 py-1 bg-emerald-950/60 border border-emerald-500/40 rounded-lg">
                  ✓ Proof Verified
                </span>
              </div>

              <div className="p-3 rounded-2xl bg-[#0f172a] border border-amber-500/30 flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-600 text-white font-mono">
                      HIGH
                    </span>
                    <span className="text-xs font-bold text-white font-mono">CWE-639: IDOR Tenant Escape</span>
                  </div>
                  <div className="text-[11px] text-slate-300 mt-1">
                    Route: <span className="font-mono text-sky-300">/api/invoices/:id</span> • Cross-user readout
                  </div>
                </div>
                <span className="text-[10px] font-mono text-emerald-400 px-2 py-1 bg-emerald-950/60 border border-emerald-500/40 rounded-lg">
                  ✓ Proof Verified
                </span>
              </div>
            </div>
          )}

          {activeTab === 'ast' && (
            <div className="p-3.5 rounded-2xl bg-[#040a14] border border-[#162d52] font-mono text-xs text-slate-300 space-y-2">
              <div className="text-[11px] text-sky-400 flex items-center justify-between">
                <span>Verified Source Line: server/routes/orders.ts:88</span>
                <span className="text-emerald-400">AST Taint Verified</span>
              </div>
              <pre className="bg-[#02060d] p-3 rounded-xl border border-slate-800 text-[11px] text-rose-300 overflow-x-auto">
                {`87:  const filterQuery = req.query.filter;
88:  // SINK: Unparameterized string interpolation
89:  const result = await db.$queryRawUnsafe(\`SELECT * FROM orders WHERE \${filterQuery}\`);`}
              </pre>
            </div>
          )}
        </div>

        {/* Right 1 Col: Active Agents & Defenses */}
        <div className="space-y-3">
          <div className="p-3.5 rounded-2xl bg-[#08152b] border border-[#162d52]">
            <div className="text-xs font-bold text-slate-200 mb-2 flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-sky-400" />
              <span>Orchestrated Agents</span>
            </div>
            <div className="space-y-2 text-[11px] font-mono">
              <div className="flex items-center justify-between p-2 rounded-xl bg-[#0c1e38] border border-[#1b3866]">
                <span className="text-sky-300">ReconAgent</span>
                <span className="text-emerald-400">COMPLETE</span>
              </div>
              <div className="flex items-center justify-between p-2 rounded-xl bg-[#0c1e38] border border-[#1b3866]">
                <span className="text-sky-300">PayloadInjector</span>
                <span className="text-amber-400 animate-pulse">PROBING</span>
              </div>
              <div className="flex items-center justify-between p-2 rounded-xl bg-[#0c1e38] border border-[#1b3866]">
                <span className="text-sky-300">ASTProofValidator</span>
                <span className="text-cyan-400">ACTIVE</span>
              </div>
            </div>
          </div>

          <div className="p-3.5 rounded-2xl bg-[#08152b] border border-[#162d52]">
            <div className="text-xs font-bold text-slate-200 mb-2 flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span>Active Defenses Logged</span>
            </div>
            <div className="space-y-1.5 text-[11px] text-slate-300">
              <div className="flex items-center gap-1.5">
                <span className="text-emerald-400">✓</span>
                <span>Bcrypt Salt rounds ≥ 12</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-emerald-400">✓</span>
                <span>Strict Rate Limiting (120 req/m)</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-emerald-400">✓</span>
                <span>Parameterized ORM bindings</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
