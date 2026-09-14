import React, { useState } from 'react';
import { ShieldCheck, ArrowRight, Ban, CheckCircle2, Sliders, AlertOctagon } from 'lucide-react';
import { ScopeConfig } from '../types';
import { PlainEnglishBanner } from './PlainEnglishBanner';

interface ScopeGuardianViewProps {
  scopeConfig: ScopeConfig;
}

export const ScopeGuardianView: React.FC<ScopeGuardianViewProps> = ({ scopeConfig }) => {
  const [testUrl, setTestUrl] = useState('https://analytics.google.com/collect');
  const [testResult, setTestResult] = useState<{ allowed: boolean; reason: string; rule: string } | null>(null);

  const handleTestUrl = () => {
    if (!testUrl.trim()) return;

    try {
      const urlObj = new URL(testUrl.startsWith('http') ? testUrl : `http://${testUrl}`);
      const hostname = urlObj.hostname;
      const port = urlObj.port ? parseInt(urlObj.port) : (urlObj.protocol === 'https:' ? 443 : 80);
      const pathname = urlObj.pathname;

      // Check excluded paths
      const isExcluded = scopeConfig.excluded_paths.some(p => pathname.startsWith(p));
      if (isExcluded) {
        setTestResult({
          allowed: false,
          reason: `Path '${pathname}' matches excluded safety blacklists (e.g. /logout, /delete-account).`,
          rule: 'Excluded Paths Rule'
        });
        return;
      }

      // Check allowed domains
      const isDomainAllowed = scopeConfig.allowed_domains.some(d => hostname === d || hostname.endsWith(`.${d}`));
      if (!isDomainAllowed) {
        setTestResult({
          allowed: false,
          reason: `Domain '${hostname}' is NOT in your authorized scope list (${scopeConfig.allowed_domains.join(', ')}). The probe is dropped before hitting the network.`,
          rule: 'Domain Whitelist Enforcement'
        });
        return;
      }

      // Check port
      const isPortAllowed = scopeConfig.allowed_ports.includes(port);
      if (!isPortAllowed) {
        setTestResult({
          allowed: false,
          reason: `Port ${port} is not in the allowed ports list (${scopeConfig.allowed_ports.join(', ')}). Probe blocked to prevent touching sensitive internal hardware ports.`,
          rule: 'Port Boundary Rule'
        });
        return;
      }

      setTestResult({
        allowed: true,
        reason: `Target '${hostname}:${port}${pathname}' matches all authorized domain and safety criteria. Permitted for assessment.`,
        rule: 'Authorized Scope Match'
      });
    } catch {
      setTestResult({
        allowed: false,
        reason: 'Invalid URL format. Please provide a valid HTTP/HTTPS address.',
        rule: 'Syntax Validation'
      });
    }
  };

  return (
    <div className="space-y-6 font-sans w-full max-w-full min-w-0">
      
      {/* Overview Info Banner */}
      <PlainEnglishBanner
        title="What is Scope Guardian & Why Does it Show 100% Guarded?"
        summary="When autonomous AI agents test a website, web pages frequently contain links to third-party services (like Google Analytics, Stripe, AWS, or CDNs). Scope Guardian acts as an automated firewall inside the AI engine: it intercepts every outbound network packet before it leaves, ensuring the bots NEVER accidentally attack websites you don't own."
        points={[
          {
            label: "Why '100% Guarded'?",
            desc: "100% means zero unauthorized packets escaped into the wild. 100% of out-of-scope requests (e.g. external analytics or unapproved domains) were intercepted and blocked."
          },
          {
            label: "No Collateral Damage",
            desc: "Prevents legal and technical liabilities by confining AI testing exclusively to your authorized domain and ports."
          },
          {
            label: "DoS / Destruction Prevention",
            desc: "Permanently disables flood attacks and destructive payload modes so your target server never crashes."
          }
        ]}
      />

      {/* Scope Guardian Header Banner */}
      <div className="bg-[#0a1832] border border-[#162f59] rounded-2xl p-5 shadow-lg flex flex-wrap items-center justify-between gap-4 w-full min-w-0">
        <div className="flex items-center space-x-3 min-w-0">
          <div className="p-3 rounded-xl bg-sky-500/15 text-sky-300 border border-sky-500/30 shrink-0">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div className="min-w-0">
            <h2 className="text-base font-bold text-white">Pre-Flight Safety & Scope Guardian Engine</h2>
            <p className="text-xs text-slate-300">Deterministic boundary interceptor protecting out-of-scope targets & third-party services</p>
          </div>
        </div>
        <div className="px-3.5 py-1.5 rounded-xl bg-emerald-950/80 border border-emerald-800 text-emerald-300 font-mono text-xs font-bold flex items-center space-x-2 shrink-0">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span>100% GUARDED • ACTIVE FIREWALL</span>
        </div>
      </div>

      {/* Interactive Scope Policy Live Tester */}
      <div className="bg-[#071326]/90 border border-[#162f55] rounded-2xl p-5 shadow-lg shadow-black/30 backdrop-blur-md space-y-4 w-full min-w-0">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-100 flex items-center space-x-2">
            <Sliders className="w-4 h-4 text-sky-400 shrink-0" />
            <span>Interactive Scope Boundary Tester</span>
          </h3>
          <span className="text-[11px] text-sky-300 font-mono">Test how the AI firewall handles any URL</span>
        </div>

        <p className="text-xs text-slate-300 leading-relaxed">
          Type any URL below (e.g. an external third-party site like <span className="font-mono text-cyan-300">https://google.com</span> or an authorized endpoint like <span className="font-mono text-emerald-300">http://localhost:8080/search</span>) to see how Scope Guardian verifies or blocks it in real time.
        </p>

        <div className="flex flex-col sm:flex-row gap-2.5 w-full min-w-0">
          <input
            type="text"
            value={testUrl}
            onChange={(e) => setTestUrl(e.target.value)}
            placeholder="https://example.com/api/test"
            className="flex-1 min-w-0 w-full bg-[#030915] border border-[#183561] focus:border-sky-400 rounded-xl px-4 py-2.5 text-xs font-mono text-sky-200 focus:outline-none shadow-inner placeholder-slate-500 transition-colors"
          />
          <button
            onClick={handleTestUrl}
            className="shrink-0 px-5 py-2.5 bg-gradient-to-r from-sky-500 via-cyan-500 to-blue-600 hover:from-sky-400 hover:to-cyan-400 text-white text-xs font-bold rounded-xl shadow-md shadow-sky-500/25 ring-1 ring-sky-300/40 transition-all flex items-center justify-center space-x-2 cursor-pointer active:scale-98"
          >
            <span>Test URL Rule</span>
            <ArrowRight className="w-3.5 h-3.5 shrink-0" />
          </button>
        </div>

        {/* Test Result Box */}
        {testResult && (
          <div className={`p-4 rounded-xl border text-xs space-y-1.5 transition-all min-w-0 ${
            testResult.allowed
              ? 'bg-emerald-950/30 border-emerald-800/60 text-emerald-200'
              : 'bg-rose-950/30 border-rose-800/60 text-rose-200'
          }`}>
            <div className="flex flex-wrap items-center space-x-2 font-bold uppercase tracking-wider">
              {testResult.allowed ? (
                <>
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span className="text-emerald-400">PASSED: In-Scope Target Allowed</span>
                </>
              ) : (
                <>
                  <Ban className="w-4 h-4 text-rose-400 shrink-0" />
                  <span className="text-rose-400">BLOCKED: Out-of-Scope Target Dropped</span>
                </>
              )}
              <span className="text-[10px] font-mono opacity-80 break-all">({testResult.rule})</span>
            </div>
            <p className="text-slate-300 font-mono text-[11px] break-words [overflow-wrap:anywhere]">{testResult.reason}</p>
          </div>
        )}
      </div>

      {/* Scope Rules Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 w-full min-w-0">
        
        {/* Allowed Domain Boundaries */}
        <div className="bg-[#0a1832] border border-[#162f59] rounded-2xl p-5 shadow-sm space-y-3 min-w-0">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-100 flex items-center space-x-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>Authorized Target Domains & Hostnames</span>
          </h3>
          <p className="text-xs text-slate-400">
            Every HTTP request and network probe must match an authorized domain before dispatch.
          </p>
          <div className="space-y-1.5 font-mono text-xs">
            {scopeConfig.allowed_domains.map((dom, i) => (
              <div key={i} className="p-2.5 rounded-lg bg-[#061021] border border-[#162f59] text-emerald-300 flex items-center justify-between gap-2 min-w-0">
                <span className="truncate min-w-0 break-all">{dom}</span>
                <span className="shrink-0 text-[10px] px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-800 text-emerald-400 font-semibold uppercase">
                  WHITELISTED
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Authorized Ports & Protocol Limits */}
        <div className="bg-[#0a1832] border border-[#162f59] rounded-2xl p-5 shadow-sm space-y-3 min-w-0">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-100 flex items-center space-x-2">
            <Sliders className="w-4 h-4 text-cyan-300 shrink-0" />
            <span>Port Boundaries & Rate Limits</span>
          </h3>
          <p className="text-xs text-slate-400">
            Prevents unexpected service disruptions or scanning of internal sensitive ports.
          </p>
          <div className="space-y-2 text-xs">
            <div className="flex items-center justify-between p-2.5 rounded-lg bg-[#061021] border border-[#162f59] font-mono min-w-0 gap-2">
              <span className="text-slate-400 shrink-0">Allowed Ports:</span>
              <span className="text-cyan-300 font-bold break-all text-right">{scopeConfig.allowed_ports.join(', ')}</span>
            </div>
            <div className="flex items-center justify-between p-2.5 rounded-lg bg-[#061021] border border-[#162f59] font-mono min-w-0 gap-2">
              <span className="text-slate-400 shrink-0">Max Request Rate:</span>
              <span className="text-cyan-300 font-bold break-all text-right">{scopeConfig.max_requests_per_minute} req/min</span>
            </div>
            <div className="flex items-center justify-between p-2.5 rounded-lg bg-[#061021] border border-[#162f59] font-mono min-w-0 gap-2">
              <span className="text-slate-400 shrink-0">Destructive Payloads (DoS):</span>
              <span className="text-rose-400 font-bold shrink-0">DISABLED / BLOCKED</span>
            </div>
          </div>
        </div>

      </div>

      {/* Safety Policy Guarantee */}
      <div className="bg-[#0a1832] border border-[#162f59] rounded-2xl p-5 text-xs text-slate-300 space-y-2 w-full min-w-0">
        <h4 className="font-bold text-sky-400 uppercase tracking-wider flex items-center space-x-2">
          <AlertOctagon className="w-4 h-4 text-sky-400 shrink-0" />
          <span>Core Safety Guarantees</span>
        </h4>
        <ul className="list-disc list-inside space-y-1 text-slate-400 pl-1 leading-relaxed [overflow-wrap:anywhere]">
          <li><strong>Zero Out-of-Scope Requests:</strong> Out-of-scope targets trigger an immediate <code className="break-all">ScopeViolationError</code> and are dropped before hitting the network stack.</li>
          <li><strong>No Jailbreak or Provider Bypass:</strong> The system strictly adheres to LLM provider safety guidelines and never attempts prompt injection bypasses.</li>
          <li><strong>Empirical PoC Requirement:</strong> No vulnerability is promoted to verified status without an executable, safe reproduction test.</li>
        </ul>
      </div>

    </div>
  );
};
export default ScopeGuardianView;
