import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import {
  Shield,
  ArrowRight,
  Terminal,
  Zap,
  CheckCircle2,
  ChevronRight,
  Bug,
  Eye,
  Key,
  Layers,
  FileText,
  Lock,
  Compass,
  Cpu,
  Sparkles,
  AlertTriangle,
  Menu,
  X,
  Database,
  Activity,
  Network,
  Crosshair,
  FileCode,
  Check,
} from 'lucide-react';
import { LandingHeroBackground } from './LandingHeroBackground';
import { AIAttackersVisual } from './AIAttackersVisual';
import { LandingProductPreview } from './LandingProductPreview';
import { LandingRiskCalculator } from './LandingRiskCalculator';

interface LandingPageProps {
  onGetStarted: () => void;
}

export const LandingPage: React.FC<LandingPageProps> = ({ onGetStarted }) => {
  const [scrolled, setScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 30);
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const scrollToSection = (id: string) => {
    setMobileMenuOpen(false);
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const fadeInUpVariants = {
    hidden: { opacity: 0, y: 30 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.6, ease: 'easeOut' } },
  };

  return (
    <div className="min-h-screen bg-[#030712] text-slate-100 font-sans selection:bg-sky-500 selection:text-white overflow-x-hidden relative">
      {/* ============================================================ */}
      {/* 1. FLOATING / TRANSPARENT NAVBAR                             */}
      {/* ============================================================ */}
      <header
        className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
          scrolled
            ? 'bg-[#040c1c]/85 backdrop-blur-xl border-b border-[#132747]/80 py-3.5 shadow-2xl shadow-sky-950/40'
            : 'bg-transparent py-5'
        }`}
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-between">
          {/* Brand Logo */}
          <div
            onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
            className="flex items-center space-x-3 cursor-pointer group"
          >
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-sky-400 via-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-sky-500/30 ring-1 ring-sky-300/40 transition-transform group-hover:scale-105">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div className="flex flex-col">
              <span className="font-black text-xl tracking-tight bg-gradient-to-r from-white via-sky-100 to-sky-400 bg-clip-text text-transparent font-sans">
                RED TEAM
              </span>
              <span className="text-[9px] font-mono text-sky-400/90 tracking-widest uppercase font-semibold">
                Autonomous Risk Assessment
              </span>
            </div>
          </div>

          {/* Desktop Navigation Links */}
          <nav className="hidden md:flex items-center space-x-8 text-sm font-medium text-slate-300">
            <button
              onClick={() => scrollToSection('features')}
              className="hover:text-sky-300 transition-colors cursor-pointer"
            >
              Features
            </button>
            <button
              onClick={() => scrollToSection('how-it-works')}
              className="hover:text-sky-300 transition-colors cursor-pointer"
            >
              How It Works
            </button>
            <button
              onClick={() => scrollToSection('swarm')}
              className="hover:text-sky-300 transition-colors cursor-pointer"
            >
              AI Swarm
            </button>
            <button
              onClick={() => scrollToSection('calculator')}
              className="hover:text-sky-300 transition-colors cursor-pointer"
            >
              Risk Simulator
            </button>
            <button
              onClick={() => scrollToSection('platform')}
              className="hover:text-sky-300 transition-colors cursor-pointer"
            >
              SOC Live
            </button>
          </nav>

          {/* Right Action Button (No Auth Required) */}
          <div className="hidden md:flex items-center space-x-4">
            <button
              onClick={onGetStarted}
              className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-sky-500 via-cyan-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 text-white text-xs font-bold font-mono tracking-wide transition-all shadow-lg shadow-sky-500/25 ring-1 ring-sky-300/40 hover:scale-105 active:scale-95 cursor-pointer flex items-center gap-2"
            >
              <span>Get Started</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Mobile Menu Button */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="md:hidden p-2 rounded-xl bg-[#09152b] border border-[#162d52] text-slate-300 hover:text-white"
          >
            {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>

        {/* Mobile Dropdown Drawer */}
        {mobileMenuOpen && (
          <div className="md:hidden px-4 pt-3 pb-6 bg-[#061124]/95 border-b border-[#152a4e] backdrop-blur-2xl flex flex-col space-y-3 animate-in fade-in slide-in-from-top-4">
            <button
              onClick={() => scrollToSection('features')}
              className="text-left px-3 py-2 text-sm text-slate-200 hover:bg-[#0c1e3d] rounded-lg font-medium"
            >
              Features
            </button>
            <button
              onClick={() => scrollToSection('how-it-works')}
              className="text-left px-3 py-2 text-sm text-slate-200 hover:bg-[#0c1e3d] rounded-lg font-medium"
            >
              How It Works
            </button>
            <button
              onClick={() => scrollToSection('swarm')}
              className="text-left px-3 py-2 text-sm text-slate-200 hover:bg-[#0c1e3d] rounded-lg font-medium"
            >
              AI Swarm
            </button>
            <button
              onClick={() => scrollToSection('calculator')}
              className="text-left px-3 py-2 text-sm text-slate-200 hover:bg-[#0c1e3d] rounded-lg font-medium"
            >
              Risk Simulator
            </button>
            <button
              onClick={() => scrollToSection('platform')}
              className="text-left px-3 py-2 text-sm text-slate-200 hover:bg-[#0c1e3d] rounded-lg font-medium"
            >
              SOC Live
            </button>
            <button
              onClick={() => {
                setMobileMenuOpen(false);
                onGetStarted();
              }}
              className="w-full py-3 rounded-xl bg-gradient-to-r from-sky-500 to-blue-600 text-white font-bold text-sm shadow-lg flex items-center justify-center gap-2"
            >
              <span>Get Started</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        )}
      </header>

      {/* ============================================================ */}
      {/* 2. HERO SECTION (Massive High-Impact Typography & Entrance)  */}
      {/* ============================================================ */}
      <section className="relative min-h-[94vh] flex items-center justify-center pt-28 pb-20 px-4 sm:px-6 lg:px-8 overflow-hidden">
        {/* Animated Cyber Background Canvas */}
        <LandingHeroBackground />

        {/* Ambient Top Glow Spheres */}
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[650px] h-[380px] bg-sky-500/15 rounded-full blur-[140px] pointer-events-none" />
        <div className="absolute top-1/3 left-1/4 w-[350px] h-[220px] bg-cyan-500/10 rounded-full blur-[100px] pointer-events-none" />

        <div className="relative z-10 max-w-5xl mx-auto text-center flex flex-col items-center">
          {/* Entrance Animated Top Pill / Badge */}
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#08172e]/80 border border-sky-500/30 text-sky-300 text-xs font-mono mb-8 backdrop-blur-md shadow-lg shadow-sky-950/40"
          >
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
            <span className="font-semibold tracking-wide">Next-Gen Autonomous Pentesting & Risk Audit</span>
            <span className="text-slate-500">|</span>
            <span className="text-emerald-400 font-semibold">Zero False Positives</span>
          </motion.div>

          {/* Huge Main Typography: RED TEAM */}
          <motion.div
            initial={{ opacity: 0, scale: 0.92 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.7, delay: 0.2, ease: 'easeOut' }}
            className="relative select-none my-2"
          >
            <h1 className="text-6xl sm:text-8xl md:text-9xl lg:text-[10.5rem] font-black tracking-tighter leading-none text-transparent bg-clip-text bg-gradient-to-b from-white via-sky-100 to-sky-400 drop-shadow-[0_0_40px_rgba(56,189,248,0.38)]">
              RED TEAM
            </h1>

            {/* Subtle cyber scanlines overlay */}
            <div className="absolute inset-0 bg-gradient-to-b from-transparent via-sky-400/5 to-transparent pointer-events-none mix-blend-overlay" />
          </motion.div>

          {/* Primary Tagline */}
          <motion.h2
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.35 }}
            className="text-xl sm:text-2xl md:text-3xl font-bold tracking-tight text-sky-200 font-sans mt-4 max-w-3xl"
          >
            Know your app’s risk <span className="text-white underline decoration-sky-400 decoration-2 underline-offset-8">before someone else finds it</span>.
          </motion.h2>

          {/* Description */}
          <motion.p
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.45 }}
            className="text-slate-400 text-base sm:text-lg max-w-2xl mt-5 leading-relaxed"
          >
            Deploy intelligent AI attackers to probe your endpoints, trace AST taint sinks, calculate CVSS risk scores, and simulate real-world exploits — without noise or false alarms.
          </motion.p>

          {/* Action Buttons */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.55 }}
            className="flex flex-col sm:flex-row items-center gap-4 mt-9"
          >
            <button
              onClick={onGetStarted}
              className="w-full sm:w-auto px-9 py-4 rounded-2xl bg-gradient-to-r from-sky-500 via-cyan-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 text-white font-bold text-base tracking-wide shadow-xl shadow-sky-500/30 ring-1 ring-sky-300/50 hover:scale-105 active:scale-95 transition-all duration-200 cursor-pointer flex items-center justify-center gap-3 group font-mono"
            >
              <span>Get Started</span>
              <ArrowRight className="w-5 h-5 transition-transform group-hover:translate-x-1" />
            </button>

            <button
              onClick={() => scrollToSection('calculator')}
              className="w-full sm:w-auto px-7 py-4 rounded-2xl bg-[#09152b]/90 hover:bg-[#112445] border border-[#1d3b6b] text-slate-200 font-semibold text-base transition-all duration-200 cursor-pointer flex items-center justify-center gap-2 hover:border-sky-400/60 shadow-lg"
            >
              <Crosshair className="w-5 h-5 text-sky-400" />
              <span>Simulate Risk</span>
            </button>
          </motion.div>

          {/* Quick Metrics Bar */}
          <motion.div
            initial={{ opacity: 0, y: 25 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.65 }}
            className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-16 max-w-3xl w-full text-left"
          >
            <div className="p-4 rounded-2xl bg-[#071326]/70 border border-[#142849] backdrop-blur-sm">
              <div className="text-2xl font-black text-white font-mono">100%</div>
              <div className="text-xs text-slate-400 mt-0.5">Empirical PoC Proofs</div>
            </div>
            <div className="p-4 rounded-2xl bg-[#071326]/70 border border-[#142849] backdrop-blur-sm">
              <div className="text-2xl font-black text-sky-400 font-mono">12-Stage</div>
              <div className="text-xs text-slate-400 mt-0.5">Deterministic Audit</div>
            </div>
            <div className="p-4 rounded-2xl bg-[#071326]/70 border border-[#142849] backdrop-blur-sm">
              <div className="text-2xl font-black text-cyan-400 font-mono">SHA-256</div>
              <div className="text-xs text-slate-400 mt-0.5">Snapshot Fingerprint</div>
            </div>
            <div className="p-4 rounded-2xl bg-[#071326]/70 border border-[#142849] backdrop-blur-sm">
              <div className="text-2xl font-black text-emerald-400 font-mono">Word .docx</div>
              <div className="text-xs text-slate-400 mt-0.5">Automated Export</div>
            </div>
          </motion.div>
        </div>
      </section>

      {/* ============================================================ */}
      {/* 3. CORE FEATURE HIGHLIGHTS (Scroll-Triggered)                */}
      {/* ============================================================ */}
      <section id="features" className="py-24 px-4 sm:px-6 lg:px-8 relative border-t border-[#10203a] bg-[#040a17]">
        <div className="max-w-7xl mx-auto">
          <motion.div
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: '-60px' }}
            variants={fadeInUpVariants}
            className="max-w-3xl mx-auto text-center mb-16"
          >
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sky-500/10 border border-sky-500/30 text-sky-400 text-xs font-mono uppercase tracking-widest mb-4">
              <Sparkles className="w-3.5 h-3.5" />
              <span>Core Vulnerability & Risk Capabilities</span>
            </div>
            <h2 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
              An AI Red Team in Your Browser.
            </h2>
            <p className="text-slate-400 text-base sm:text-lg mt-4 leading-relaxed">
              Unlike static scanners that flood you with theoretical warnings, Red Team applies adversarial reasoning to discover, validate, and score real exploitable risks.
            </p>
          </motion.div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 max-w-6xl mx-auto">
            {[
              {
                icon: Bug,
                title: 'Autonomous Vulnerability Probing',
                desc: 'Specialized attack agents simulate SQL injection, IDOR, SSRF, and authentication bypass workflows against your live endpoints and code AST.',
                tag: 'Adversarial Probing',
                accent: 'border-rose-500/40 text-rose-400',
              },
              {
                icon: Activity,
                title: 'Dynamic CVSS Risk Scoring',
                desc: 'Compute realistic CVSS 3.1 severity scores based on exploitability, impact blast radius, asset criticality, and affirmative defense posture.',
                tag: 'Risk Telemetry',
                accent: 'border-amber-500/40 text-amber-400',
              },
              {
                icon: Eye,
                title: 'Endpoint & Route Discovery',
                desc: 'Extract full attack surfaces across Express, Next.js, and FastAPI routes, mapping parameters, headers, and authentication gates automatically.',
                tag: 'Surface Mapping',
                accent: 'border-sky-500/40 text-sky-400',
              },
              {
                icon: CheckCircle2,
                title: 'Zero-False-Positive Validation',
                desc: 'Every finding must be empirically verified through AST code inspection and live payload execution before being marked as confirmed.',
                tag: 'Verified PoC',
                accent: 'border-emerald-500/40 text-emerald-400',
              },
              {
                icon: FileCode,
                title: 'AST Source Taint Analysis',
                desc: 'Trace untrusted input from request handlers directly into sensitive sinks (e.g. raw SQL strings, exec calls) with exact file line mapping.',
                tag: 'Source Line Tracing',
                accent: 'border-cyan-500/40 text-cyan-400',
              },
              {
                icon: FileText,
                title: 'Executive Word (.docx) Reporting',
                desc: 'Download publication-grade Word documents containing executive risk summaries, severity metrics, code patches, and verified defense postures.',
                tag: 'One-Click Export',
                accent: 'border-blue-500/40 text-blue-400',
              },
            ].map((feat, i) => {
              const Icon = feat.icon;
              return (
                <motion.div
                  key={i}
                  initial="hidden"
                  whileInView="visible"
                  viewport={{ once: true, margin: '-40px' }}
                  variants={fadeInUpVariants}
                  className="group relative p-6 rounded-3xl bg-[#061021] border border-[#142849] hover:border-sky-400/60 transition-all duration-300 hover:-translate-y-1.5 hover:shadow-xl hover:shadow-sky-500/10 flex flex-col justify-between"
                >
                  <div>
                    <div className="flex items-center justify-between mb-4">
                      <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-[#0c1f3d] to-[#061224] border border-[#1b3b6e] flex items-center justify-center text-sky-400 group-hover:text-cyan-300 group-hover:scale-110 group-hover:border-sky-400 transition-all shadow-md">
                        <Icon className="w-6 h-6" />
                      </div>
                      <span className="text-[10px] font-mono font-semibold px-2.5 py-1 rounded-full bg-[#0a1830] text-sky-300 border border-[#18345e]">
                        {feat.tag}
                      </span>
                    </div>

                    <h3 className="text-lg font-bold text-white group-hover:text-sky-200 transition-colors">
                      {feat.title}
                    </h3>
                    <p className="text-slate-400 text-xs sm:text-sm mt-2.5 leading-relaxed">{feat.desc}</p>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </div>
      </section>

      {/* ============================================================ */}
      {/* 4. HOW THE PLATFORM WORKS (5-Stage Linear Pipeline)         */}
      {/* ============================================================ */}
      <section id="how-it-works" className="py-24 px-4 sm:px-6 lg:px-8 relative border-t border-[#10203a] bg-[#030814]">
        <div className="max-w-7xl mx-auto">
          <motion.div
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: '-60px' }}
            variants={fadeInUpVariants}
            className="max-w-3xl mx-auto text-center mb-16"
          >
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono uppercase tracking-widest mb-4">
              <Layers className="w-3.5 h-3.5" />
              <span>Deterministic Security Audit</span>
            </div>
            <h2 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
              From Target to Attack Surface.
            </h2>
            <p className="text-slate-400 text-base sm:text-lg mt-4 leading-relaxed">
              A transparent, 5-stage automated attack process that maps, probes, validates, and reports security weaknesses with surgical precision.
            </p>
          </motion.div>

          <div className="grid grid-cols-1 md:grid-cols-5 gap-4 relative max-w-6xl mx-auto">
            {[
              {
                num: '01',
                title: 'TARGET',
                desc: 'Connect or provide the application to be tested via live URL, GitHub repository, or source archive.',
                icon: Shield,
              },
              {
                num: '02',
                title: 'RECON',
                desc: 'AI agents analyze the target, map endpoints, detect frameworks, and identify potential attack surfaces.',
                icon: Eye,
              },
              {
                num: '03',
                title: 'ATTACK',
                desc: 'Agents simulate relevant adversarial techniques and test assumptions in a safe, strictly scoped environment.',
                icon: Bug,
              },
              {
                num: '04',
                title: 'VALIDATE',
                desc: 'Potential findings are tested and validated with AST inspection and live proof-of-concept verification.',
                icon: CheckCircle2,
              },
              {
                num: '05',
                title: 'REPORT',
                desc: 'Generate understandable security findings with empirical evidence, severity ranking, and Word (.docx) export.',
                icon: FileText,
              },
            ].map((stage) => {
              const Icon = stage.icon;
              return (
                <motion.div
                  key={stage.num}
                  initial="hidden"
                  whileInView="visible"
                  viewport={{ once: true, margin: '-40px' }}
                  variants={fadeInUpVariants}
                  className="group relative p-6 rounded-3xl bg-[#061224] border border-[#142849] hover:border-sky-400/60 transition-all duration-300 hover:-translate-y-2 hover:shadow-2xl hover:shadow-sky-500/15 flex flex-col justify-between"
                >
                  <div className="absolute top-0 right-0 w-16 h-16 bg-sky-500/5 rounded-tr-3xl group-hover:bg-sky-500/15 transition-colors pointer-events-none" />

                  <div>
                    <div className="flex items-center justify-between mb-4">
                      <span className="text-2xl font-black font-mono text-sky-400 tracking-tight">
                        {stage.num}
                      </span>
                      <div className="w-9 h-9 rounded-xl bg-[#0b1b36] border border-[#1a3866] flex items-center justify-center text-sky-300 group-hover:scale-110 group-hover:text-cyan-300 transition-all">
                        <Icon className="w-4 h-4" />
                      </div>
                    </div>

                    <h3 className="text-base font-extrabold text-white font-mono tracking-wide uppercase">
                      {stage.title}
                    </h3>
                    <p className="text-xs text-slate-400 mt-2.5 leading-relaxed">{stage.desc}</p>
                  </div>

                  <div className="mt-6 pt-3 border-t border-[#122340] flex items-center text-[10px] font-mono text-slate-500 group-hover:text-sky-300 transition-colors">
                    <span>STAGE {stage.num} COMPLIANT</span>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </div>
      </section>

      {/* ============================================================ */}
      {/* 5. MULTI-AGENT SWARM VISUAL ("One Target. Multiple Attackers.") */}
      {/* ============================================================ */}
      <section id="swarm" className="py-24 px-4 sm:px-6 lg:px-8 relative border-t border-[#10203a] bg-[#040a17] overflow-hidden">
        <div className="max-w-7xl mx-auto">
          <motion.div
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: '-60px' }}
            variants={fadeInUpVariants}
            className="max-w-3xl mx-auto text-center mb-6"
          >
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono uppercase tracking-widest mb-4">
              <Cpu className="w-3.5 h-3.5" />
              <span>Multi-Agent Swarm</span>
            </div>
            <h2 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
              One Target. Multiple Attackers.
            </h2>
            <p className="text-slate-400 text-base sm:text-lg mt-4 leading-relaxed">
              Our orchestrator mobilizes dedicated AI security specialists in parallel. Each agent focuses on its tactical domain, discovering vulnerabilities, validating exploitability, and correlating defense signals.
            </p>
          </motion.div>

          {/* Interactive Multi-Agent Orbit Visual */}
          <AIAttackersVisual />
        </div>
      </section>

      {/* ============================================================ */}
      {/* 6. INTERACTIVE RISK SIMULATOR WIDGET                         */}
      {/* ============================================================ */}
      <section id="calculator" className="py-24 px-4 sm:px-6 lg:px-8 relative border-t border-[#10203a] bg-[#030814]">
        <div className="max-w-7xl mx-auto">
          <motion.div
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: '-60px' }}
            variants={fadeInUpVariants}
            className="max-w-3xl mx-auto text-center mb-12"
          >
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sky-500/10 border border-sky-500/30 text-sky-300 text-xs font-mono uppercase tracking-widest mb-4">
              <Crosshair className="w-3.5 h-3.5" />
              <span>Risk Modeling & CVSS Math</span>
            </div>
            <h2 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
              Live Threat Radius Calculator.
            </h2>
            <p className="text-slate-400 text-base sm:text-lg mt-4 leading-relaxed">
              Experience our risk evaluation heuristics in real time. Select simulated vulnerability configurations to compute live exposure scores and see how verified defensive mitigations drive risk to zero.
            </p>
          </motion.div>

          {/* Interactive Risk Calculator */}
          <LandingRiskCalculator onGetStarted={onGetStarted} />
        </div>
      </section>

      {/* ============================================================ */}
      {/* 7. PHILOSOPHY: THINK LIKE AN ATTACKER                        */}
      {/* ============================================================ */}
      <section className="py-24 px-4 sm:px-6 lg:px-8 relative border-t border-[#10203a] bg-[#040a17]">
        <div className="max-w-5xl mx-auto">
          <motion.div
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: '-60px' }}
            variants={fadeInUpVariants}
            className="p-8 sm:p-12 rounded-3xl bg-gradient-to-br from-[#07152b] via-[#040d1c] to-[#02060f] border border-sky-500/30 shadow-2xl relative overflow-hidden"
          >
            <div className="absolute top-0 right-0 w-96 h-96 bg-sky-500/10 rounded-full blur-3xl pointer-events-none" />

            <div className="relative z-10 max-w-3xl">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono uppercase tracking-widest mb-6">
                <Lock className="w-3.5 h-3.5" />
                <span>Security Philosophy</span>
              </div>

              <h2 className="text-2xl sm:text-4xl font-extrabold text-white tracking-tight">
                Built to Find What Automated Scanners Miss.
              </h2>

              <div className="my-8 py-6 border-y border-[#18315a]">
                <p className="text-2xl sm:text-3xl md:text-4xl font-black font-sans leading-tight text-transparent bg-clip-text bg-gradient-to-r from-sky-200 via-cyan-100 to-sky-400">
                  "Don't just scan the application.
                  <br />
                  <span className="text-white">Attack the assumptions."</span>
                </p>
              </div>

              <p className="text-slate-300 text-sm sm:text-base leading-relaxed">
                Conventional static scanners check regex patterns and known CVE dictionaries. Real threat actors chain minor logic slips, exploit subtle tenant boundaries, and bypass token assumptions. Red Team brings cognitive reasoning to security validation.
              </p>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-8">
                <div className="p-4 rounded-2xl bg-[#09172e]/80 border border-[#162d52]">
                  <div className="text-xs font-bold text-rose-400 font-mono mb-1">TRADITIONAL SCANNERS</div>
                  <div className="text-xs text-slate-400">Static signature matching, high noise ratio, unverified assumptions.</div>
                </div>

                <div className="p-4 rounded-2xl bg-[#09172e]/80 border border-sky-500/40">
                  <div className="text-xs font-bold text-sky-300 font-mono mb-1">AI RED TEAM PLATFORM</div>
                  <div className="text-xs text-slate-300">Hypothesis-driven adversarial simulation with affirmative reproduction proof.</div>
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </section>

      {/* ============================================================ */}
      {/* 8. PRODUCT PREVIEW SECTION (Live SOC Console)               */}
      {/* ============================================================ */}
      <section id="platform" className="py-24 px-4 sm:px-6 lg:px-8 relative border-t border-[#10203a] bg-[#030814]">
        <div className="max-w-7xl mx-auto">
          <motion.div
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: '-60px' }}
            variants={fadeInUpVariants}
            className="max-w-3xl mx-auto text-center mb-16"
          >
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono uppercase tracking-widest mb-4">
              <Terminal className="w-3.5 h-3.5" />
              <span>Interactive SOC Console</span>
            </div>
            <h2 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
              Your Security Operations Layer.
            </h2>
            <p className="text-slate-400 text-base sm:text-lg mt-4 leading-relaxed">
              Experience the live command center. Track active attacking agents, monitor real-time telemetry, verify empirical evidence, and view AST source traces in one unified console.
            </p>
          </motion.div>

          {/* Interactive Live Product Preview Mockup */}
          <LandingProductPreview onGetStarted={onGetStarted} />
        </div>
      </section>

      {/* ============================================================ */}
      {/* 9. CLOSING CTA SECTION (Direct No-Auth Entry)               */}
      {/* ============================================================ */}
      <section className="py-24 px-4 sm:px-6 lg:px-8 relative border-t border-[#10203a] bg-gradient-to-b from-[#040a17] to-[#02050c] overflow-hidden text-center">
        {/* Glow Spheres */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[350px] bg-sky-500/15 rounded-full blur-[140px] pointer-events-none" />

        <motion.div
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: '-40px' }}
          variants={fadeInUpVariants}
          className="relative z-10 max-w-4xl mx-auto flex flex-col items-center"
        >
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-sky-400 to-blue-600 flex items-center justify-center shadow-xl shadow-sky-500/30 mb-8 ring-2 ring-sky-300/40">
            <Shield className="w-8 h-8 text-white" />
          </div>

          <h2 className="text-4xl sm:text-6xl font-black text-white tracking-tight">
            Ready to Think Like an Attacker?
          </h2>

          <p className="text-slate-400 text-base sm:text-xl max-w-2xl mt-5 leading-relaxed">
            Start assessing your application’s vulnerabilities with an AI-driven red team. No complex configuration, no login walls, and zero simulation delays.
          </p>

          <div className="mt-9">
            <button
              onClick={onGetStarted}
              className="px-10 py-5 rounded-2xl bg-gradient-to-r from-sky-500 via-cyan-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 text-white font-extrabold text-lg tracking-wide shadow-2xl shadow-sky-500/40 ring-2 ring-sky-300/60 hover:scale-105 active:scale-95 transition-all duration-200 cursor-pointer flex items-center gap-3 group font-mono"
            >
              <span>Get Started</span>
              <ArrowRight className="w-6 h-6 transition-transform group-hover:translate-x-1.5" />
            </button>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-6 mt-8 text-xs font-mono text-slate-500">
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" /> No Sign-In Required
            </span>
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Instant In-Browser Execution
            </span>
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" /> 100% Deterministic Scope
            </span>
          </div>
        </motion.div>
      </section>

      {/* ============================================================ */}
      {/* 10. MINIMAL FOOTER                                           */}
      {/* ============================================================ */}
      <footer className="border-t border-[#0e1c33] bg-[#02050c] py-12 px-4 sm:px-6 lg:px-8 text-xs text-slate-400 font-sans">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-6">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 rounded-lg bg-sky-500/20 border border-sky-400/40 flex items-center justify-center text-sky-400">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <span className="font-extrabold text-white tracking-wider font-mono">RED TEAM</span>
              <span className="text-slate-400 ml-2">Autonomous AI vulnerability & risk assessment.</span>
            </div>
          </div>

          <div className="flex items-center space-x-6 text-slate-400 font-medium">
            <button onClick={() => scrollToSection('features')} className="hover:text-sky-300 transition-colors cursor-pointer">
              Features
            </button>
            <button onClick={() => scrollToSection('how-it-works')} className="hover:text-sky-300 transition-colors cursor-pointer">
              How It Works
            </button>
            <button onClick={() => scrollToSection('calculator')} className="hover:text-sky-300 transition-colors cursor-pointer">
              Risk Simulator
            </button>
            <button onClick={onGetStarted} className="text-sky-400 hover:text-sky-300 font-bold cursor-pointer font-mono">
              Launch App →
            </button>
          </div>
        </div>

        <div className="max-w-7xl mx-auto mt-8 pt-6 border-t border-[#091322] flex flex-col sm:flex-row items-center justify-between text-[11px] text-slate-400 font-mono">
          <div>© {new Date().getFullYear()} Red Team Autonomous Security Testing. All rights reserved.</div>
          <div className="flex items-center gap-2 mt-2 sm:mt-0">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Risk Analysis Engine: ONLINE</span>
          </div>
        </div>
      </footer>
    </div>
  );
};
