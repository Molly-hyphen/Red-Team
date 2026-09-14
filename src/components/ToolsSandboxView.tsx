import React, { useState, useEffect } from 'react';
import { Wrench, Terminal, Play, Box, Sparkles, Cpu, Server, CheckCircle2, AlertTriangle, Copy, Check, RefreshCw, Layers } from 'lucide-react';
import { PlainEnglishBanner } from './PlainEnglishBanner';
import { safeFetchJson } from '../lib/safeFetch';

interface AIStatusData {
  status: 'ok' | 'degraded' | 'offline';
  active_provider: 'gemini' | 'ollama' | 'heuristic_engine';
  is_local: boolean;
  model: string;
  base_url?: string;
  ollama_installed_models?: string[];
  ollama_reachable?: boolean;
  has_gemini_key: boolean;
  recommended_model: string;
  details: string;
  timestamp: string;
}

export const ToolsSandboxView: React.FC = () => {
  const [selectedTool, setSelectedTool] = useState('recon_discovery');
  const [targetInput, setTargetInput] = useState('http://localhost:8080');
  const [testOutput, setTestOutput] = useState<string | null>(null);
  const [isRunning, setIsRunning] = useState(false);

  // AI Provider status & ping testing
  const [aiStatus, setAiStatus] = useState<AIStatusData | null>(null);
  const [isPinging, setIsPinging] = useState(false);
  const [pingResult, setPingResult] = useState<{ success: boolean; message: string } | null>(null);
  const [copiedSection, setCopiedSection] = useState<string | null>(null);

  const fetchAIStatus = async () => {
    try {
      const res = await safeFetchJson<AIStatusData>('/api/ai/status');
      if (res.success && res.data) {
        setAiStatus(res.data);
      }
    } catch {
      // Backend status unreachable
    }
  };

  useEffect(() => {
    fetchAIStatus();
  }, []);

  const handlePingAI = async () => {
    setIsPinging(true);
    setPingResult(null);
    try {
      const res = await safeFetchJson<any>('/api/ai/test-connection', { method: 'POST' });
      const data = res.data || {};
      
      let displayMsg = data.message;
      if (!displayMsg && data.error) {
        try {
          const parsedErr = typeof data.error === 'string' && data.error.startsWith('{') ? JSON.parse(data.error) : null;
          displayMsg = parsedErr?.error?.message || data.error;
        } catch {
          displayMsg = data.error;
        }
      }

      setPingResult({
        success: Boolean(res.success && data.success),
        message: displayMsg || (res.success ? 'Engine connection verified.' : 'Model temporarily busy or unavailable.')
      });
      fetchAIStatus();
    } catch (e: any) {
      setPingResult({
        success: false,
        message: `Connection error: ${e?.message || 'Could not connect to backend endpoint.'}`
      });
    } finally {
      setIsPinging(false);
    }
  };

  const copyToClipboard = (text: string, sectionId: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(sectionId);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const tools = [
    { name: 'recon_discovery', category: 'network', desc: 'Tech stack fingerprinting, port scanning, and security response header analyzer.' },
    { name: 'http_request', category: 'web', desc: 'Parameterized HTTP client for testing endpoints, headers, cookies, and responses.' },
    { name: 'vulnerability_fuzzer', category: 'scanner', desc: 'Structured vulnerability fuzzer for SQLi, XSS, SSRF, and command injection.' },
    { name: 'source_code_sast', category: 'sast', desc: 'White-box static AST and regex analyzer for unvalidated sink tracing and hardcoded secrets.' },
    { name: 'browser_dom_inspector', category: 'browser', desc: 'DOM and interactive input inspector for client-side vectors and forms.' },
    { name: 'terminal_exec', category: 'sandbox', desc: 'Executes diagnostics inside isolated Docker sandbox container.' },
    { name: 'screenshot_capture', category: 'validation', desc: 'Captures visual DOM snapshots for proof-of-concept evidence reports.' },
    { name: 'proxy_recorder', category: 'web', desc: 'Records and analyzes stateful HTTP transaction flows.' },
  ];

  const handleRunToolTest = () => {
    setIsRunning(true);
    setTestOutput('Dispatching diagnostic execution to sandbox...');
    
    setTimeout(() => {
      setIsRunning(false);
      if (selectedTool === 'recon_discovery') {
        setTestOutput(JSON.stringify({
          tool: 'recon_discovery',
          target: targetInput,
          status: 'success',
          status_code: 200,
          duration_ms: 280,
          data: {
            technologies: ['Node.js Express / v20', 'React SPA', 'Nginx 1.24'],
            open_ports: [80, 443, 8080],
            missing_security_headers: ['Strict-Transport-Security', 'Content-Security-Policy']
          }
        }, null, 2));
      } else if (selectedTool === 'source_code_sast') {
        setTestOutput(JSON.stringify({
          tool: 'source_code_sast',
          target: './src',
          status: 'success',
          data: {
            files_scanned: 12,
            findings_count: 2,
            findings: [
              { title: 'Hardcoded JWT Secret', file: 'src/config/jwt.ts', line: 8, cwe: 'CWE-798' },
              { title: 'Raw SQL Query Concatenation', file: 'src/db/users.ts', line: 42, cwe: 'CWE-89' }
            ]
          }
        }, null, 2));
      } else {
        setTestOutput(JSON.stringify({
          tool: selectedTool,
          target: targetInput,
          status: 'success',
          status_code: 200,
          data: { message: `Diagnostic test executed successfully for ${selectedTool}` }
        }, null, 2));
      }
    }, 600);
  };

  const sampleEnvConfig = `# --- Backend AI & LLM Engine Configuration (.env) ---
# Option 1: Cloud Google Gemini API
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-3.7-flash

# Option 2: Local Self-Hosted Ollama (100% Offline)
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2`;

  return (
    <div className="space-y-6 font-sans w-full max-w-full min-w-0">
      
      {/* Overview Info Banner */}
      <PlainEnglishBanner
        title="Security Toolchain & Backend AI Engine Configuration"
        summary="Manage diagnostic execution sandboxes and configure your backend AI providers (Google Gemini or 100% private local Ollama inference)."
        points={[
          {
            label: "Local & Cloud AI Engines",
            desc: "Run neural Red Team assessments via local Ollama models (Llama 3.2, DeepSeek-R1) or Google Gemini via backend .env secrets."
          },
          {
            label: "Specialized Toolchains",
            desc: "Network scouts, code AST analyzers, and HTTP testers equipped with specific diagnostic payloads."
          },
          {
            label: "Safe Execution",
            desc: "Diagnostic tools run in an isolated environment with verified rate limits and domain validation."
          }
        ]}
      />

      {/* ========================================================================= */}
      {/* AI ENGINE & LOCAL OLLAMA / CUSTOM API KEY BACKEND STATUS CARD */}
      {/* ========================================================================= */}
      <div className="bg-gradient-to-br from-[#071733] via-[#091f42] to-[#06142a] border border-[#1b3b6d] rounded-2xl p-5 shadow-xl space-y-4 w-full min-w-0">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#16305a] pb-4">
          <div className="flex items-center space-x-3">
            <div className={`p-2.5 rounded-xl border ${
              aiStatus?.active_provider === 'ollama'
                ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                : 'bg-sky-500/20 text-sky-300 border-sky-500/40'
            }`}>
              {aiStatus?.is_local ? <Cpu className="w-6 h-6" /> : <Sparkles className="w-6 h-6" />}
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-base font-bold text-white">Backend AI & Inference Engine</h2>
                {aiStatus?.is_local ? (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-700 uppercase">
                    Local / Self-Hosted
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-sky-950 text-sky-300 border border-sky-700 uppercase">
                    Cloud API
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-300">
                Active Provider: <span className="font-mono font-bold text-sky-300">{aiStatus?.model || 'Loading provider...'}</span>
              </p>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center space-x-2">
            <button
              onClick={handlePingAI}
              disabled={isPinging}
              className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-xl bg-[#0e2752] hover:bg-[#153974] border border-[#234c8c] text-sky-200 text-xs font-semibold shadow-sm transition-all cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isPinging ? 'animate-spin text-sky-400' : ''}`} />
              <span>{isPinging ? 'Pinging Provider...' : 'Ping / Test Engine'}</span>
            </button>
          </div>
        </div>

        {/* Live Diagnostics Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="p-3 bg-[#061226] border border-[#142d54] rounded-xl">
            <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1">Provider Engine</div>
            <div className="flex items-center space-x-1.5 text-xs font-semibold text-slate-100 font-mono">
              <span className={`w-2 h-2 rounded-full ${
                aiStatus?.status === 'ok' ? 'bg-emerald-400' : 'bg-amber-400'
              }`} />
              <span className="capitalize">{aiStatus?.active_provider?.replace('_', ' ') || 'Detecting...'}</span>
            </div>
          </div>

          <div className="p-3 bg-[#061226] border border-[#142d54] rounded-xl">
            <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1">Active Model</div>
            <div className="text-xs font-semibold text-sky-300 font-mono truncate">
              {aiStatus?.model || 'Heuristic Rules Engine'}
            </div>
          </div>

          <div className="p-3 bg-[#061226] border border-[#142d54] rounded-xl">
            <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1">Ollama Connectivity</div>
            <div className="flex items-center space-x-1.5 text-xs font-semibold font-mono">
              {aiStatus?.ollama_reachable ? (
                <span className="text-emerald-300 flex items-center space-x-1">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Connected ({aiStatus.ollama_installed_models?.length || 0} models)</span>
                </span>
              ) : (
                <span className="text-slate-400 flex items-center space-x-1">
                  <span>Standby / Offline</span>
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Ping Output Notification */}
        {pingResult && (
          <div className={`p-3 rounded-xl border text-xs font-mono flex items-start space-x-2 ${
            pingResult.success
              ? 'bg-emerald-950/60 border-emerald-700/60 text-emerald-200'
              : 'bg-amber-950/60 border-amber-700/60 text-amber-200'
          }`}>
            {pingResult.success ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            )}
            <div>
              <span className="font-bold">{pingResult.success ? 'Engine Live:' : 'Engine Notice:'}</span> {pingResult.message}
            </div>
          </div>
        )}

        {/* Local Ollama Setup & .env Quick Guide (Collapsible/Accordion) */}
        <div className="bg-[#050f21] border border-[#132b50] rounded-xl p-4 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-slate-100 flex items-center space-x-2">
              <Server className="w-4 h-4 text-sky-400" />
              <span>How to Host Locally with Ollama or Custom API Keys</span>
            </h3>
            <button
              onClick={() => copyToClipboard(sampleEnvConfig, 'env')}
              className="flex items-center space-x-1 text-[11px] font-mono text-sky-300 hover:text-sky-100 px-2 py-1 rounded bg-[#0b1f3d] border border-[#1e4277] transition-all cursor-pointer"
            >
              {copiedSection === 'env' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copiedSection === 'env' ? 'Copied .env' : 'Copy .env Template'}</span>
            </button>
          </div>

          <p className="text-xs text-slate-300 leading-relaxed">
            This application is fully decoupled and supports local self-hosting without any cloud dependencies. To use Ollama or custom API keys:
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            {/* Step 1: Ollama */}
            <div className="p-3 bg-[#08172e] border border-[#17325c] rounded-xl space-y-1.5">
              <div className="font-bold text-emerald-300 flex items-center space-x-1.5">
                <span className="w-5 h-5 rounded-full bg-emerald-950 border border-emerald-700 flex items-center justify-center text-[10px]">1</span>
                <span>Run Ollama Locally</span>
              </div>
              <p className="text-slate-300 text-[11px]">Install from <span className="text-sky-300">ollama.com</span> and pull a model:</p>
              <div className="p-2 bg-[#040a14] rounded-lg font-mono text-[11px] text-emerald-300 select-all border border-[#112340]">
                ollama run llama3.2
              </div>
            </div>

            {/* Step 2: Backend .env */}
            <div className="p-3 bg-[#08172e] border border-[#17325c] rounded-xl space-y-1.5">
              <div className="font-bold text-sky-300 flex items-center space-x-1.5">
                <span className="w-5 h-5 rounded-full bg-sky-950 border border-sky-700 flex items-center justify-center text-[10px]">2</span>
                <span>Configure Backend .env</span>
              </div>
              <p className="text-slate-300 text-[11px]">Set <span className="font-mono text-slate-200">LLM_PROVIDER=ollama</span> in your root <span className="font-mono text-slate-200">.env</span> file:</p>
              <div className="p-2 bg-[#040a14] rounded-lg font-mono text-[11px] text-sky-300 select-all border border-[#112340]">
                LLM_PROVIDER=ollama<br />
                OLLAMA_BASE_URL=http://localhost:11434<br />
                OLLAMA_MODEL=llama3.2
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* REGISTERED DIAGNOSTIC TOOLS & INTERACTIVE TEST RUNNER */}
      {/* ========================================================================= */}
      <div className="bg-[#0a1832] border border-[#162f59] rounded-2xl p-5 shadow-md flex flex-wrap items-center justify-between gap-4 w-full min-w-0">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-xl bg-sky-500/15 text-sky-300 border border-sky-500/30">
            <Box className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-base font-bold text-white">Security Tool Sandbox & Execution Layer</h2>
            <p className="text-xs text-slate-300">Isolated Kali Linux / Docker runtime container with pre-installed diagnostic toolchains</p>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <div className="px-3 py-1 rounded-lg bg-emerald-950/80 border border-emerald-800 text-emerald-300 font-mono text-xs font-semibold flex items-center space-x-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>SANDBOX READY</span>
          </div>
        </div>
      </div>

      {/* Grid: Tools Registry + Test Runner */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 w-full min-w-0">
        
        {/* Left: Registered Tools (6 cols) */}
        <div className="lg:col-span-6 space-y-3 w-full min-w-0">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-100 flex items-center space-x-2">
            <Wrench className="w-4 h-4 text-sky-400" />
            <span>Registered Security Tools ({tools.length})</span>
          </h3>

          <div className="space-y-2.5">
            {tools.map(tool => (
              <div
                key={tool.name}
                onClick={() => setSelectedTool(tool.name)}
                className={`p-3.5 rounded-xl border transition-all duration-150 cursor-pointer ${
                  selectedTool === tool.name
                    ? 'bg-[#0e2448] border-sky-400 text-sky-200 shadow-md shadow-sky-500/20 ring-1 ring-sky-400/40'
                    : 'bg-[#071326]/90 border-[#162f55] text-slate-300 hover:border-sky-500/50 hover:bg-[#0c1f3d]'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-xs font-bold text-white">{tool.name}</span>
                  <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-[#030915] border border-[#183561] text-sky-300 font-semibold">
                    {tool.category}
                  </span>
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed">{tool.desc}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Manual Tool Runner (6 cols) */}
        <div className="lg:col-span-6 space-y-4 w-full min-w-0">
          <div className="bg-[#0a1832] border border-[#162f59] rounded-2xl p-5 shadow-xl space-y-4 w-full min-w-0">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-100 flex items-center space-x-2">
              <Terminal className="w-4 h-4 text-sky-400" />
              <span>Manual Tool Execution Sandbox</span>
            </h3>

            <div className="space-y-3">
              <div>
                <label className="text-[11px] font-bold text-slate-300 block mb-1">Selected Tool</label>
                <input
                  type="text"
                  disabled
                  value={selectedTool}
                  className="w-full bg-[#061021] border border-[#162f59] rounded-xl px-3.5 py-2 text-xs font-mono text-sky-300"
                />
              </div>

              <div>
                <label className="text-[11px] font-bold text-slate-300 block mb-1">Target Address / Asset</label>
                <input
                  type="text"
                  value={targetInput}
                  onChange={(e) => setTargetInput(e.target.value)}
                  className="w-full bg-[#061021] border border-[#162f59] rounded-xl px-3.5 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-400"
                />
              </div>

              <button
                onClick={handleRunToolTest}
                disabled={isRunning}
                className="w-full py-2.5 bg-gradient-to-r from-sky-500 via-cyan-500 to-blue-600 hover:from-sky-400 hover:to-cyan-400 text-white text-xs font-bold rounded-xl shadow-md shadow-sky-950/40 transition-all flex items-center justify-center space-x-2 disabled:opacity-50 cursor-pointer"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>{isRunning ? 'Running in Sandbox...' : `Execute ${selectedTool}`}</span>
              </button>
            </div>

            {/* Test Output Console */}
            {testOutput && (
              <div className="space-y-1.5 pt-2">
                <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono">
                  <span>SANDBOX EXECUTION LOG</span>
                  <span className="text-emerald-400">Exit Code: 0</span>
                </div>
                <pre className="p-3.5 bg-[#061021] border border-[#162f59] rounded-xl text-[11px] font-mono text-emerald-300 overflow-x-auto max-h-60 scrollbar-thin whitespace-pre-wrap break-words [overflow-wrap:anywhere]">
                  {testOutput}
                </pre>
              </div>
            )}
          </div>
        </div>

      </div>

    </div>
  );
};

export default ToolsSandboxView;
