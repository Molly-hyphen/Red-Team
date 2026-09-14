import React, { useState } from 'react';
import { motion } from 'motion/react';
import { ShieldAlert, ShieldCheck, AlertTriangle, Cpu, Terminal, Zap, CheckCircle2, ArrowRight } from 'lucide-react';

interface ThreatFactor {
  id: string;
  name: string;
  category: string;
  weight: number;
  active: boolean;
  desc: string;
  cwe: string;
}

export const LandingRiskCalculator: React.FC<{ onGetStarted: () => void }> = ({ onGetStarted }) => {
  const [factors, setFactors] = useState<ThreatFactor[]>([
    {
      id: 'sqli',
      name: 'Unparameterized Raw SQL Intermediary',
      category: 'Injection',
      weight: 3.2,
      active: true,
      desc: 'AST taint trace detected direct string interpolation on database query sinks.',
      cwe: 'CWE-89',
    },
    {
      id: 'idor',
      name: 'Unenforced Tenant Authorization (BOLA/IDOR)',
      category: 'Broken Auth',
      weight: 2.8,
      active: true,
      desc: 'Missing user ownership check before resolving object retrieval endpoints.',
      cwe: 'CWE-639',
    },
    {
      id: 'jwt',
      name: 'Weak JWT Secret Key / Algorithm Confusion',
      category: 'Crypto Failures',
      weight: 2.1,
      active: true,
      desc: 'Symmetric fallback key vulnerable to brute-force or none-algorithm bypass.',
      cwe: 'CWE-327',
    },
    {
      id: 'secrets',
      name: 'Exposed Hardcoded API Credentials in Git',
      category: 'Secret Leak',
      weight: 1.6,
      active: false,
      desc: 'Plaintext staging tokens found in static configuration repository files.',
      cwe: 'CWE-798',
    },
    {
      id: 'ssrf',
      name: 'Blind Server-Side Request Forgery Sink',
      category: 'Network Boundary',
      weight: 2.4,
      active: false,
      desc: 'Unrestricted remote URL fetching without loopback address filtering.',
      cwe: 'CWE-918',
    },
  ]);

  const toggleFactor = (id: string) => {
    setFactors((prev) =>
      prev.map((f) => (f.id === id ? { ...f, active: !f.active } : f))
    );
  };

  const totalScore = Math.min(
    10.0,
    factors
      .filter((f) => f.active)
      .reduce((sum, f) => sum + f.weight, 0.5)
  );

  const getRiskTier = (score: number) => {
    if (score >= 7.5) return { label: 'CRITICAL THREAT LEVEL', color: 'text-rose-400', bg: 'bg-rose-950/60', border: 'border-rose-500/50', barColor: 'bg-rose-500' };
    if (score >= 5.0) return { label: 'HIGH RISK EXPOSURE', color: 'text-amber-400', bg: 'bg-amber-950/60', border: 'border-amber-500/50', barColor: 'bg-amber-500' };
    if (score >= 2.5) return { label: 'MODERATE RISK POSTURE', color: 'text-sky-300', bg: 'bg-sky-950/60', border: 'border-sky-500/50', barColor: 'bg-sky-500' };
    return { label: 'HARDENED / LOW RISK', color: 'text-emerald-400', bg: 'bg-emerald-950/60', border: 'border-emerald-500/50', barColor: 'bg-emerald-500' };
  };

  const tier = getRiskTier(totalScore);

  return (
    <div className="w-full max-w-5xl mx-auto rounded-3xl bg-[#061124]/90 border border-[#18335d] p-6 sm:p-8 shadow-2xl backdrop-blur-xl relative overflow-hidden">
      {/* Background glow */}
      <div className="absolute top-0 right-0 w-80 h-80 bg-sky-500/10 rounded-full blur-3xl pointer-events-none" />

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#142849] pb-6 mb-6">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sky-500/10 border border-sky-500/30 text-sky-400 text-xs font-mono uppercase tracking-wider mb-2">
            <Zap className="w-3.5 h-3.5 text-sky-400" />
            <span>Interactive Risk Engine Simulator</span>
          </div>
          <h3 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
            Simulate Your Application's Attack Surface Exposure
          </h3>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Toggle threat scenarios to observe real-time CVSS 3.1 score recalculation, blast radius modeling, and automated mitigation steps.
          </p>
        </div>

        <div className={`p-4 rounded-2xl border ${tier.border} ${tier.bg} flex items-center gap-4 shrink-0 transition-all duration-300`}>
          <div>
            <div className="text-[10px] font-mono uppercase text-slate-400">Calculated CVSS Score</div>
            <div className={`text-3xl font-black font-mono ${tier.color} flex items-baseline gap-1.5`}>
              <span>{totalScore.toFixed(1)}</span>
              <span className="text-xs text-slate-400 font-normal">/ 10.0</span>
            </div>
            <div className={`text-[10px] font-bold font-mono tracking-wider ${tier.color} mt-0.5`}>
              {tier.label}
            </div>
          </div>

          <div className="w-12 h-12 rounded-xl bg-[#030a17] border border-[#1b3b6e] flex items-center justify-center">
            {totalScore >= 5.0 ? (
              <ShieldAlert className={`w-6 h-6 ${tier.color} animate-pulse`} />
            ) : (
              <ShieldCheck className={`w-6 h-6 ${tier.color}`} />
            )}
          </div>
        </div>
      </div>

      {/* Progress meter bar */}
      <div className="mb-8">
        <div className="flex justify-between text-xs font-mono text-slate-400 mb-2">
          <span>THREAT RADIUS METER</span>
          <span>{Math.round((totalScore / 10) * 100)}% COMPROMISE PROBABILITY</span>
        </div>
        <div className="w-full h-3 bg-[#030915] rounded-full overflow-hidden p-0.5 border border-[#142849]">
          <motion.div
            className={`h-full rounded-full ${tier.barColor}`}
            initial={{ width: '0%' }}
            animate={{ width: `${(totalScore / 10) * 100}%` }}
            transition={{ type: 'spring', stiffness: 80, damping: 15 }}
          />
        </div>
      </div>

      {/* Toggles Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-8">
        {factors.map((factor) => (
          <div
            key={factor.id}
            onClick={() => toggleFactor(factor.id)}
            className={`p-4 rounded-2xl border transition-all duration-200 cursor-pointer flex items-start justify-between gap-3 ${
              factor.active
                ? 'bg-[#091b36] border-sky-400/80 shadow-lg shadow-sky-950/40'
                : 'bg-[#040d1c]/60 border-[#122340] hover:border-slate-700 opacity-60 hover:opacity-90'
            }`}
          >
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#0e2447] text-sky-300 border border-[#1b3f75]">
                  {factor.cwe}
                </span>
                <span className="text-xs font-semibold text-slate-200 truncate">
                  {factor.name}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed line-clamp-2">
                {factor.desc}
              </p>
            </div>

            <div className="shrink-0 pt-0.5">
              <span
                className={`w-6 h-6 rounded-lg flex items-center justify-center text-xs font-bold transition-all ${
                  factor.active
                    ? 'bg-sky-500 text-white shadow-md shadow-sky-500/40'
                    : 'bg-[#0c1a2f] border border-slate-700 text-slate-500'
                }`}
              >
                {factor.active ? '✓' : '+'}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Footer call to action */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-4 rounded-2xl bg-[#030915] border border-[#122340]">
        <div className="flex items-center gap-3 text-xs font-mono text-slate-300">
          <Terminal className="w-4 h-4 text-sky-400 shrink-0" />
          <span>Ready to execute real-time automated reconnaissance on your codebase?</span>
        </div>

        <button
          onClick={onGetStarted}
          className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 text-white text-xs font-bold font-mono tracking-wide shadow-lg shadow-sky-500/25 transition-all cursor-pointer flex items-center gap-2 shrink-0 hover:scale-105 active:scale-95"
        >
          <span>Audit Your App Live</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
};
