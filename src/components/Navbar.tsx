import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Terminal,
  Play,
  FileText,
  Globe,
  Wrench,
  ShieldCheck,
  Shield,
  Sparkles,
  GitCompare,
  Award,
} from 'lucide-react';
import { safeFetchJson } from '../lib/safeFetch';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  isScanning: boolean;
  onOpenLaunchModal: () => void;
  onOpenTestSuite: () => void;
  findingsCount: number;
  onBackToLanding?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  isScanning,
  onOpenLaunchModal,
  onOpenTestSuite,
  findingsCount,
  onBackToLanding,
}) => {
  const [aiStatus, setAiStatus] = useState<{
    available: boolean;
    provider: 'gemini' | 'ollama' | 'heuristic_engine';
    is_local: boolean;
    model: string;
    details?: string;
  }>({
    available: true,
    provider: 'gemini',
    is_local: false,
    model: 'Gemini 3.7 Flash',
  });

  useEffect(() => {
    safeFetchJson<any>('/api/ai/status')
      .then((res) => {
        if (res.success && res.data) {
          const data = res.data;
          setAiStatus({
            available: data.status === 'ok' || data.has_gemini_key || data.ollama_reachable,
            provider: data.active_provider || 'gemini',
            is_local: Boolean(data.is_local),
            model: data.model || 'Gemini 3.7 Flash',
            details: data.details,
          });
        }
      })
      .catch(() => {
        // Keep active default
      });
  }, []);

  const tabs = [
    { id: 'assessment', label: 'Live Red Team', shortLabel: 'Live Attack', icon: Terminal },
    { id: 'findings', label: 'Findings & Proof', shortLabel: 'Findings', icon: ShieldAlert, badge: findingsCount },
    { id: 'surface', label: 'Attack Surface', shortLabel: 'Surface', icon: Globe },
    { id: 'reports', label: 'Audit Report', shortLabel: 'Report', icon: FileText },
    { id: 'history', label: 'Version Diff & History', shortLabel: 'History', icon: GitCompare },
    { id: 'scope', label: 'Scope Guardian', shortLabel: 'Scope', icon: ShieldCheck },
    { id: 'tools', label: 'Tool Sandbox', shortLabel: 'Sandbox', icon: Wrench },
  ];

  return (
    <header className="bg-[#050e1f]/95 border-b border-[#122340] text-slate-100 sticky top-0 z-30 shadow-xl backdrop-blur-xl w-full max-w-full">
      <div className="w-full max-w-[1920px] mx-auto px-3 sm:px-4 lg:px-6">
        <div className="flex flex-wrap items-center justify-between gap-y-2.5 gap-x-2 sm:gap-x-3 py-2.5 w-full min-w-0">
          {/* Logo & Platform Name */}
          <div
            onClick={onBackToLanding}
            className={`flex items-center space-x-2.5 shrink-0 ${
              onBackToLanding ? 'cursor-pointer hover:opacity-90 group' : ''
            }`}
            title={onBackToLanding ? 'Return to Red Team Landing Overview' : 'Red Team'}
          >
            <div className="w-9 h-9 sm:w-10 sm:h-10 rounded-xl bg-gradient-to-br from-sky-400 via-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-sky-500/25 ring-1 ring-sky-300/40 transition-transform group-hover:scale-105 shrink-0">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div className="flex flex-col">
              <span className="font-extrabold text-lg sm:text-xl tracking-tight bg-gradient-to-r from-white via-sky-100 to-sky-300 bg-clip-text text-transparent font-sans leading-none">
                Red Team
              </span>
              <span className="text-[9px] sm:text-[10px] font-mono text-sky-400/80 tracking-wider uppercase font-semibold mt-0.5">
                Autonomous SecOps
              </span>
            </div>
          </div>

          {/* Navigation Tabs - Intelligent auto-reflow / wrapping */}
          <nav className="flex flex-wrap items-center gap-1 sm:gap-1.5 p-1 rounded-2xl bg-[#071326]/90 border border-[#162f55] shadow-lg shadow-black/40 backdrop-blur-md min-w-0 max-w-full">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  title={tab.label}
                  className={`relative flex items-center space-x-1.5 px-2.5 xl:px-3 py-1.5 rounded-xl text-xs font-bold tracking-wide transition-all duration-200 whitespace-nowrap cursor-pointer group shrink-0 ${
                    isActive
                      ? 'bg-gradient-to-r from-sky-500 via-cyan-500 to-blue-600 text-white shadow-md shadow-sky-500/30 ring-1 ring-sky-300/50'
                      : 'text-slate-300 hover:text-white hover:bg-[#0e2142]/80'
                  }`}
                >
                  <Icon
                    className={`w-3.5 h-3.5 transition-transform group-hover:scale-110 shrink-0 ${
                      isActive ? 'text-white drop-shadow' : 'text-sky-400 group-hover:text-cyan-300'
                    }`}
                  />
                  <span className="hidden sm:inline">{tab.label}</span>
                  <span className="sm:hidden">{tab.shortLabel}</span>
                  {tab.badge !== undefined && tab.badge > 0 && (
                    <span
                      className={`ml-1 px-1.5 py-0.2 rounded-full text-[10px] font-mono font-bold transition-all shrink-0 ${
                        isActive
                          ? 'bg-white text-sky-950 shadow-sm'
                          : 'bg-rose-500/20 text-rose-300 border border-rose-500/40 animate-pulse'
                      }`}
                    >
                      {tab.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>

          {/* Right Action Controls - ALWAYS IN VIEWPORT */}
          <div className="flex items-center gap-2 sm:gap-2.5 shrink-0 ml-auto xl:ml-0">
            {/* Architecture Test Suite Button */}
            <button
              onClick={onOpenTestSuite}
              className="flex items-center space-x-1.5 px-2.5 sm:px-3 py-1.5 rounded-xl border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-200 text-xs font-semibold shadow-sm transition-all shrink-0 cursor-pointer"
              title="Run 10-Point Architectural & Golden Rule Test Suite"
            >
              <Award className="w-3.5 h-3.5 text-amber-400 shrink-0" />
              <span className="hidden sm:inline">10-Point Tests</span>
              <span className="sm:hidden">Tests</span>
            </button>

            {/* AI Engine Status Pill */}
            <div
              className={`hidden md:flex items-center space-x-1.5 px-2.5 sm:px-3 py-1.5 rounded-xl border text-[11px] font-mono shadow-sm cursor-pointer transition-all hover:scale-[1.02] shrink-0 ${
                aiStatus.provider === 'ollama'
                  ? 'bg-[#061e1a] border-emerald-500/40 text-emerald-300 shadow-emerald-950/40'
                  : 'bg-[#09152b] border-[#18315a] text-sky-300 shadow-sky-950/40'
              }`}
              title={aiStatus.details || `Active AI Engine: ${aiStatus.model}`}
              onClick={() => setActiveTab('tools')}
            >
              <span
                className={`w-2 h-2 rounded-full animate-pulse shadow-sm shrink-0 ${
                  aiStatus.provider === 'ollama'
                    ? 'bg-emerald-400 shadow-emerald-400'
                    : 'bg-cyan-400 shadow-cyan-400'
                }`}
              />
              <Sparkles
                className={`w-3.5 h-3.5 shrink-0 ${
                  aiStatus.provider === 'ollama' ? 'text-emerald-400' : 'text-sky-400'
                }`}
              />
              <span className="font-semibold">{aiStatus.model}</span>
              {aiStatus.is_local && (
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-900/60 border border-emerald-500/40 text-emerald-300 font-bold uppercase tracking-wider">
                  Local
                </span>
              )}
            </div>

            {/* + New Assessment Button - ALWAYS VISIBLE */}
            <button
              onClick={onOpenLaunchModal}
              disabled={isScanning}
              className={`flex items-center space-x-1.5 sm:space-x-2 px-3 sm:px-4 py-2 rounded-xl text-xs font-bold tracking-wide shadow-lg transition-all shrink-0 cursor-pointer ${
                isScanning
                  ? 'bg-amber-600/80 text-white cursor-not-allowed animate-pulse'
                  : 'bg-gradient-to-r from-sky-500 via-cyan-500 to-blue-600 hover:from-sky-400 hover:to-cyan-400 text-white shadow-sky-500/25 ring-1 ring-sky-300/40 hover:scale-[1.02] active:scale-[0.98]'
              }`}
            >
              <Play className="w-3.5 h-3.5 fill-current shrink-0" />
              <span className="whitespace-nowrap">{isScanning ? 'Scanning...' : '+ New Assessment'}</span>
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
export default Navbar;
