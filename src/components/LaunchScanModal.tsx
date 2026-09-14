import React, { useState } from 'react';
import { X, Play, Globe, Shield, Code, Zap, Layers, Github, Upload, FileCode, CheckCircle, AlertCircle, Loader2, Star, GitBranch, RefreshCw, Archive } from 'lucide-react';
import { ScanMode, ScanDepth, ScopeConfig, RepoMetadata, SourceFile } from '../types';
import { safeFetchJson } from '../lib/safeFetch';
import { isZipArchive, extractZipArchive, getFileLanguage } from '../lib/zipExtractor';

interface LaunchScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onLaunch: (
    target: string,
    mode: ScanMode,
    depth: ScanDepth,
    instruction: string,
    scope: ScopeConfig,
    options?: {
      targetType?: 'url' | 'github_repo' | 'uploaded_code';
      repoMetadata?: RepoMetadata;
      sourceFiles?: SourceFile[];
    }
  ) => void;
}

type TargetType = 'url' | 'github_repo' | 'uploaded_code';

interface ModeConfig {
  id: ScanMode;
  label: string;
  badge: string;
  icon: typeof Globe;
  defaultTarget: string;
  defaultInstruction: string;
  allowedDomains: string;
  desc: string;
}

const MODES: ModeConfig[] = [
  {
    id: 'white_box',
    label: 'White Box (SAST)',
    badge: 'Deep Source Audit',
    icon: Code,
    defaultTarget: 'https://github.com/expressjs/express',
    defaultInstruction: 'Conduct deep inside-out source code SAST audit: detect raw SQL injection sinks, IDOR/BOLA authorization flaws, hardcoded secrets, SSRF, RCE, and vulnerable dependencies.',
    allowedDomains: 'github.com, localhost',
    desc: 'Deep code audit: AST taint analysis, SQLi sinks, IDOR & hardcoded secrets'
  },
  {
    id: 'black_box',
    label: 'Black Box',
    badge: 'Perimeter & Web',
    icon: Globe,
    defaultTarget: 'http://localhost:8080',
    defaultInstruction: 'Perform focused black-box perimeter assessment: real-world business logic flaws, session fixation, broken access control, and API authorization bypasses.',
    allowedDomains: 'localhost, 127.0.0.1, demo-target',
    desc: 'Outside-in testing: Web routes, API endpoints, auth security & business logic'
  },
  {
    id: 'grey_box',
    label: 'Grey Box',
    badge: 'Hybrid & API',
    icon: Shield,
    defaultTarget: 'http://localhost:8080/api/v1',
    defaultInstruction: 'Execute hybrid Red Team assessment: cloud metadata SSRF, tenant superadmin privilege escalation, and BOLA/IDOR user leaks.',
    allowedDomains: 'localhost, 127.0.0.1, demo-target',
    desc: 'Authenticated hybrid: Cloud SSRF, BFLA superadmin & BOLA/IDOR'
  }
];

export const LaunchScanModal: React.FC<LaunchScanModalProps> = ({ isOpen, onClose, onLaunch }) => {
  const [targetType, setTargetType] = useState<TargetType>('github_repo');
  const [mode, setMode] = useState<ScanMode>('white_box');
  const [depth, setDepth] = useState<ScanDepth>('deep_technical');
  const [target, setTarget] = useState('https://github.com/expressjs/express');
  const [githubBranch, setGithubBranch] = useState('');
  const [githubToken, setGithubToken] = useState('');
  const [isInspectingRepo, setIsInspectingRepo] = useState(false);
  const [inspectError, setInspectError] = useState<string | null>(null);
  const [inspectedRepo, setInspectedRepo] = useState<{ metadata: RepoMetadata; files: SourceFile[] } | null>(null);

  const [uploadedFiles, setUploadedFiles] = useState<SourceFile[]>([]);
  const [archiveInfo, setArchiveInfo] = useState<{
    archiveName: string;
    summary: string;
    extractedCount: number;
    totalLines: number;
    languages: string[];
    skippedBinary: number;
  } | null>(null);
  const [isExtractingArchive, setIsExtractingArchive] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [instruction, setInstruction] = useState(
    'Conduct deep inside-out source code SAST audit: detect raw SQL injection sinks, IDOR/BOLA authorization flaws, hardcoded secrets, SSRF, RCE, and vulnerable dependencies.'
  );
  const [allowedDomains, setAllowedDomains] = useState('github.com, localhost, 127.0.0.1');
  const [allowedPorts, setAllowedPorts] = useState('80, 443, 3000, 5000, 8080');
  const [maxRpm, setMaxRpm] = useState(120);
  const [allowDestructive, setAllowDestructive] = useState(false);
  const [confirmedAuthorized, setConfirmedAuthorized] = useState(true);

  if (!isOpen) return null;

  const handleTargetTypeChange = (newType: TargetType) => {
    setTargetType(newType);
    setInspectError(null);
    if (newType === 'github_repo') {
      setMode('white_box');
      setTarget(target.includes('http') && !target.includes('github') ? 'https://github.com/expressjs/express' : target);
      setInstruction('Conduct deep inside-out source code SAST audit: detect raw SQL injection sinks, IDOR/BOLA authorization flaws, hardcoded secrets, SSRF, RCE, and vulnerable dependencies.');
    } else if (newType === 'uploaded_code') {
      setMode('white_box');
      setTarget('Uploaded Source Code Package');
      setInstruction('Deeply inspect uploaded codebase for security vulnerabilities, dangerous sinks, AST taint flows, and missing validation.');
    } else {
      setMode('black_box');
      setTarget('http://localhost:8080');
      setInstruction('Perform focused black-box perimeter assessment: real-world business logic flaws, session fixation, broken access control, and API authorization bypasses.');
    }
  };

  const handleInspectGitHubRepo = async (repoToInspect?: string) => {
    const repoUrl = repoToInspect || target;
    if (!repoUrl.trim()) return;

    setIsInspectingRepo(true);
    setInspectError(null);

    try {
      const res = await safeFetchJson<any>('/api/github/inspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repoUrl,
          branch: githubBranch.trim() || undefined,
          token: githubToken.trim() || undefined,
        }),
      });

      const data = res.data || {};
      if (!res.success || !data.success) {
        throw new Error(data.error || res.error || 'Failed to inspect GitHub repository');
      }

      const metadata: RepoMetadata = data.metadata || {
        owner: data.owner || repoUrl.replace('https://github.com/', '').split('/')[0] || 'repository',
        name: data.name || repoUrl.replace('https://github.com/', '').split('/')[1] || 'repo',
        full_name: data.full_name || (data.owner && data.name ? `${data.owner}/${data.name}` : repoUrl),
        branch: data.default_branch || githubBranch || 'main',
        stars: data.stars ?? 0,
        language: data.language || 'Multi-language',
        description: data.description || 'Source code repository for deep security audit.',
        total_files: data.total_files_count || (Array.isArray(data.files) ? data.files.length : 0),
        files: data.tree || [],
      };

      const files: SourceFile[] = Array.isArray(data.files) && data.files.length > 0
        ? data.files
        : Array.isArray(data.security_files)
        ? data.security_files.map((f: any) => ({
            name: f.name || f.path.split('/').pop() || 'file',
            path: f.path,
            content: f.content,
            language: f.language,
            size: f.size,
            lines: (f.content || '').split('\n').length,
          }))
        : [];

      setInspectedRepo({
        metadata,
        files,
      });

      if (metadata.branch && !githubBranch) {
        setGithubBranch(metadata.branch);
      }
    } catch (err: any) {
      setInspectError(err?.message || 'Could not fetch repository source tree');
    } finally {
      setIsInspectingRepo(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const fileList = e.target.files;
    if (!fileList || fileList.length === 0) return;

    setUploadError(null);
    setIsExtractingArchive(true);

    try {
      const filesArray: File[] = Array.from(fileList);
      const allNewFiles: SourceFile[] = [];
      let detectedZipName: string | null = null;
      let archiveTotalFiles = 0;
      let archiveTotalLines = 0;
      let archiveSkipped = 0;
      const archiveLangsSet = new Set<string>();

      for (const file of filesArray) {
        if (isZipArchive(file)) {
          detectedZipName = file.name;
          const extracted = await extractZipArchive(file, file.name);
          allNewFiles.push(...extracted.files);
          archiveTotalFiles += extracted.totalExtractedFiles;
          archiveTotalLines += extracted.totalLines;
          archiveSkipped += extracted.skippedBinaryCount;
          extracted.detectedLanguages.forEach(l => archiveLangsSet.add(l));
        } else {
          const content = await file.text();
          const lines = content.split('\n').length;
          const lang = getFileLanguage(file.name);
          allNewFiles.push({
            name: file.name,
            path: (file as any).webkitRelativePath || file.name,
            content,
            size: file.size,
            language: lang,
            lines,
          });
        }
      }

      if (detectedZipName && archiveTotalFiles > 0) {
        setArchiveInfo({
          archiveName: detectedZipName,
          summary: `Extracted ${archiveTotalFiles} source files (${archiveTotalLines.toLocaleString()} lines)`,
          extractedCount: archiveTotalFiles,
          totalLines: archiveTotalLines,
          languages: Array.from(archiveLangsSet),
          skippedBinary: archiveSkipped,
        });
        setTarget(`${detectedZipName} (${allNewFiles.length} extracted source files)`);
      } else {
        const totalCount = uploadedFiles.length + allNewFiles.length;
        setTarget(`Local Workspace (${totalCount} source files)`);
      }

      setUploadedFiles(prev => [...prev, ...allNewFiles]);
    } catch (err: any) {
      console.error('Failed to process upload:', err);
      setUploadError(err?.message || 'Failed to process uploaded file(s)');
    } finally {
      setIsExtractingArchive(false);
      e.target.value = '';
    }
  };

  const handleRemoveUploadedFile = (index: number) => {
    setUploadedFiles(prev => {
      const next = prev.filter((_, i) => i !== index);
      if (next.length === 0) {
        setArchiveInfo(null);
      }
      return next;
    });
  };

  const handleClearAllFiles = () => {
    setUploadedFiles([]);
    setArchiveInfo(null);
    setUploadError(null);
    setTarget('Uploaded Source Code Package');
  };

  const handleSelectMode = (newMode: ScanMode) => {
    setMode(newMode);
    const selected = MODES.find(m => m.id === newMode);
    if (selected && targetType === 'url') {
      setTarget(selected.defaultTarget);
      setInstruction(selected.defaultInstruction);
      setAllowedDomains(selected.allowedDomains);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!confirmedAuthorized) return;

    const scopeConfig: ScopeConfig = {
      allowed_domains: allowedDomains.split(',').map(s => s.trim()).filter(Boolean),
      allowed_urls: [target],
      allowed_ports: allowedPorts.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n)),
      allowed_local_paths: ['./demo-target', './', ...(uploadedFiles.map(f => f.path))],
      excluded_paths: ['/logout', '/delete-account', '/admin/reset-db', 'node_modules'],
      max_requests_per_minute: maxRpm,
      allow_destructive_payloads: allowDestructive
    };

    let effectiveTarget = target;
    let repoMetadata: RepoMetadata | undefined = undefined;
    let sourceFiles: SourceFile[] | undefined = undefined;

    if (targetType === 'github_repo') {
      effectiveTarget = target;
      if (inspectedRepo) {
        repoMetadata = inspectedRepo.metadata;
        sourceFiles = inspectedRepo.files;
      }
    } else if (targetType === 'uploaded_code') {
      effectiveTarget = 'Local Source Code Project';
      sourceFiles = uploadedFiles;
    }

    onLaunch(effectiveTarget, mode, depth, instruction, scopeConfig, {
      targetType,
      repoMetadata,
      sourceFiles,
    });
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-4 sm:p-6 overflow-y-auto font-sans">
      <div className="bg-[#0a1832] border border-[#162f59] rounded-2xl max-w-3xl w-full shadow-2xl overflow-hidden text-slate-100 animate-in fade-in zoom-in-95 duration-200 my-auto min-w-0">
        
        {/* Modal Header */}
        <div className="bg-[#0d1f3d] px-6 py-5 sm:px-8 border-b border-[#162f59] flex items-center justify-between">
          <div className="flex items-center space-x-3 min-w-0">
            <div className="p-2.5 rounded-xl bg-sky-500/15 border border-sky-400/30 text-sky-300 shrink-0">
              <Shield className="w-5 h-5" />
            </div>
            <div className="min-w-0">
              <h2 className="text-base font-bold text-white truncate">Configure Security Assessment</h2>
              <p className="text-xs text-slate-300 truncate">Scan web domains or inspect GitHub repositories & source files deeply for vulnerabilities</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-[#162f59] transition-colors cursor-pointer shrink-0 ml-2"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <form onSubmit={handleSubmit} className="px-6 py-6 sm:px-8 sm:py-7 space-y-6 max-h-[80vh] overflow-y-auto custom-scrollbar">
          
          {/* Target Type Selector Tabs */}
          <div className="space-y-2">
            <label className="text-xs font-bold uppercase tracking-wider text-sky-400 font-mono flex items-center space-x-1.5">
              <span>TARGET SOURCE TYPE</span>
              <span className="text-sky-400">*</span>
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 bg-[#061021] p-1.5 rounded-xl border border-[#162f59]">
              <button
                type="button"
                onClick={() => handleTargetTypeChange('github_repo')}
                className={`flex items-center justify-center space-x-2 py-2.5 px-3 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  targetType === 'github_repo'
                    ? 'bg-sky-500/20 text-sky-200 border border-sky-400/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#0c1f3d]'
                }`}
              >
                <Github className="w-4 h-4 text-sky-400" />
                <span>GitHub Repository</span>
              </button>

              <button
                type="button"
                onClick={() => handleTargetTypeChange('url')}
                className={`flex items-center justify-center space-x-2 py-2.5 px-3 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  targetType === 'url'
                    ? 'bg-sky-500/20 text-sky-200 border border-sky-400/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#0c1f3d]'
                }`}
              >
                <Globe className="w-4 h-4 text-sky-400" />
                <span>Web URL / Domain</span>
              </button>

              <button
                type="button"
                onClick={() => handleTargetTypeChange('uploaded_code')}
                className={`flex items-center justify-center space-x-2 py-2.5 px-3 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  targetType === 'uploaded_code'
                    ? 'bg-sky-500/20 text-sky-200 border border-sky-400/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#0c1f3d]'
                }`}
              >
                <Upload className="w-4 h-4 text-sky-400" />
                <span>Upload Source Files</span>
              </button>
            </div>
          </div>

          {/* Type 1: GitHub Repository Input */}
          {targetType === 'github_repo' && (
            <div className="space-y-3 bg-[#071328] p-4 rounded-xl border border-[#162f59]">
              <div className="flex items-center justify-between">
                <label className="text-xs font-bold text-sky-300 font-mono flex items-center space-x-1.5">
                  <Github className="w-4 h-4 text-sky-400" />
                  <span>GITHUB REPOSITORY URL OR SLUG</span>
                </label>
                <span className="text-[11px] text-slate-400">e.g. expressjs/express or https://github.com/owner/repo</span>
              </div>

              <div className="flex space-x-2">
                <input
                  type="text"
                  value={target}
                  onChange={(e) => {
                    setTarget(e.target.value);
                    setInspectedRepo(null);
                    setInspectError(null);
                  }}
                  placeholder="https://github.com/owner/repo or owner/repo"
                  className="flex-1 bg-[#061021] border border-[#162f59] rounded-xl px-4 py-2.5 text-sm font-mono text-sky-100 placeholder-slate-500 focus:outline-none focus:border-sky-400 focus:ring-1 focus:ring-sky-400 transition-all"
                  required
                />
                <button
                  type="button"
                  onClick={() => handleInspectGitHubRepo()}
                  disabled={isInspectingRepo || !target.trim()}
                  className="px-4 py-2.5 bg-sky-600/30 hover:bg-sky-600/50 border border-sky-500/50 text-sky-200 rounded-xl text-xs font-bold flex items-center space-x-2 transition-all disabled:opacity-50 cursor-pointer"
                >
                  {isInspectingRepo ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin text-sky-300" />
                      <span>Fetching Tree...</span>
                    </>
                  ) : (
                    <>
                      <RefreshCw className="w-3.5 h-3.5" />
                      <span>Inspect Source</span>
                    </>
                  )}
                </button>
              </div>

              {/* Advanced GitHub Options: Branch & Token */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-[#162f59]/60">
                <div>
                  <label className="text-[11px] text-slate-300 font-mono flex items-center space-x-1 mb-1">
                    <GitBranch className="w-3 h-3 text-sky-400" />
                    <span>Branch / Tag (Optional)</span>
                  </label>
                  <input
                    type="text"
                    value={githubBranch}
                    onChange={(e) => setGithubBranch(e.target.value)}
                    placeholder="main, master, or release"
                    className="w-full bg-[#061021] border border-[#162f59] rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-400"
                  />
                </div>
                <div>
                  <label className="text-[11px] text-slate-300 font-mono flex items-center space-x-1 mb-1">
                    <span>Personal Access Token (Private Repos)</span>
                  </label>
                  <input
                    type="password"
                    value={githubToken}
                    onChange={(e) => setGithubToken(e.target.value)}
                    placeholder="ghp_xxxxxxxxxxxx (Optional)"
                    className="w-full bg-[#061021] border border-[#162f59] rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-400"
                  />
                </div>
              </div>

              {/* Inspected Repo Status Preview */}
              {inspectError && (
                <div className="p-3 rounded-lg bg-red-950/40 border border-red-500/40 flex items-start space-x-2 text-xs text-red-200">
                  <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-bold">Inspection Notice:</span> {inspectError}
                    <div className="text-[11px] text-red-300/80 mt-0.5">The scan will still proceed using neural white-box AST reasoning.</div>
                  </div>
                </div>
              )}

              {inspectedRepo && (
                <div className="p-3.5 rounded-xl bg-sky-950/40 border border-sky-500/40 space-y-2 animate-in fade-in">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-emerald-400" />
                      <span className="text-xs font-bold text-white">
                        {inspectedRepo.metadata?.full_name || inspectedRepo.metadata?.name || target}
                      </span>
                    </div>
                    <div className="flex items-center space-x-3 text-[11px] text-sky-300 font-mono">
                      <span className="flex items-center space-x-1">
                        <Star className="w-3 h-3 text-amber-400" />
                        <span>{inspectedRepo.metadata?.stars ?? 0}</span>
                      </span>
                      <span className="bg-sky-900/60 px-2 py-0.5 rounded border border-sky-700/50">
                        {inspectedRepo.metadata?.language || 'Multi-Language'}
                      </span>
                    </div>
                  </div>

                  <p className="text-[11px] text-slate-300 line-clamp-1">
                    {inspectedRepo.metadata?.description || 'Repository ready for deep security audit.'}
                  </p>

                  <div className="flex items-center justify-between pt-1 text-[11px] text-sky-200/90 font-mono border-t border-sky-800/40">
                    <span>
                      Indexed <strong className="text-emerald-300">{(inspectedRepo.files || []).length}</strong> security-critical source files
                    </span>
                    <span className="text-slate-400">
                      Total Tree Size: {inspectedRepo.metadata?.total_files ?? (inspectedRepo.files || []).length} files
                    </span>
                  </div>

                  <div className="flex flex-wrap gap-1.5 max-h-20 overflow-y-auto pt-1">
                    {(inspectedRepo.files || []).slice(0, 10).map((f) => (
                      <span key={f.path} className="text-[10px] font-mono bg-[#061021] text-sky-300 px-2 py-0.5 rounded border border-[#162f59]">
                        {f.path} {f.lines ? `(${f.lines} lines)` : ''}
                      </span>
                    ))}
                    {(inspectedRepo.files || []).length > 10 && (
                      <span className="text-[10px] font-mono text-slate-400 px-1 py-0.5">
                        +{(inspectedRepo.files || []).length - 10} more files
                      </span>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Type 2: Web URL / Domain Input */}
          {targetType === 'url' && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-bold uppercase tracking-wider text-sky-400 font-mono flex items-center space-x-1.5">
                  <span>TARGET WEBSITE URL OR DOMAIN</span>
                  <span className="text-sky-400">*</span>
                </label>
                <span className="text-[11px] text-sky-300 font-mono">Live perimeter domain or API URL</span>
              </div>
              
              <input
                type="text"
                value={target}
                onChange={(e) => {
                  const val = e.target.value;
                  setTarget(val);
                  try {
                    if (val.startsWith('http://') || val.startsWith('https://')) {
                      const urlObj = new URL(val);
                      if (urlObj.hostname && !allowedDomains.includes(urlObj.hostname)) {
                        setAllowedDomains(`${urlObj.hostname}, localhost, 127.0.0.1`);
                      }
                    }
                  } catch {
                    // Ignore during typing
                  }
                }}
                placeholder="https://your-website.com or http://localhost:8080"
                className="w-full bg-[#061021] border border-[#162f59] rounded-xl px-4 py-3 text-sm font-mono text-sky-100 placeholder-slate-500 focus:outline-none focus:border-sky-400 focus:ring-1 focus:ring-sky-400 transition-all shadow-inner"
                required
              />
            </div>
          )}

          {/* Type 3: Upload Source Files */}
          {targetType === 'uploaded_code' && (
            <div className="space-y-3 bg-[#071328] p-4 rounded-xl border border-[#162f59]">
              <div className="flex items-center justify-between">
                <label className="text-xs font-bold text-sky-300 font-mono flex items-center space-x-1.5">
                  <Upload className="w-4 h-4 text-sky-400" />
                  <span>UPLOAD LOCAL SOURCE FILES OR ZIP ARCHIVE FOR DEEP SAST AUDIT</span>
                </label>
                <span className="text-[11px] text-slate-400 font-mono">.zip, .ts, .js, .py, .go, .java, .sql</span>
              </div>

              <div className="border-2 border-dashed border-[#1d3d70] hover:border-sky-400/60 rounded-xl p-6 text-center bg-[#061021] transition-all cursor-pointer relative">
                <input
                  type="file"
                  multiple
                  accept=".zip,.ts,.tsx,.js,.jsx,.py,.pyw,.go,.java,.json,.env,.sql,.yaml,.yml,.toml,.xml,.html,.css,.sh"
                  onChange={handleFileUpload}
                  disabled={isExtractingArchive}
                  className="absolute inset-0 opacity-0 cursor-pointer w-full h-full disabled:cursor-not-allowed"
                />
                {isExtractingArchive ? (
                  <div className="py-2 flex flex-col items-center justify-center space-y-2">
                    <Loader2 className="w-8 h-8 text-sky-400 animate-spin" />
                    <p className="text-xs font-semibold text-sky-300">Unpacking & indexing archive source files...</p>
                    <p className="text-[11px] text-slate-400">Filtering binaries and mapping source AST locations</p>
                  </div>
                ) : (
                  <>
                    <div className="flex items-center justify-center space-x-3 mb-2 opacity-85">
                      <Archive className="w-7 h-7 text-sky-400" />
                      <FileCode className="w-7 h-7 text-sky-400" />
                    </div>
                    <p className="text-xs font-semibold text-slate-200">
                      Drop a <span className="text-sky-400 font-bold">ZIP archive</span> or source files here, or <span className="text-sky-400 underline">browse workspace</span>
                    </p>
                    <p className="text-[11px] text-slate-400 mt-1">
                      ZIP archives are automatically extracted and indexed into isolated AST source files for taint analysis.
                    </p>
                  </>
                )}
              </div>

              {uploadError && (
                <div className="p-2.5 rounded-lg bg-red-950/40 border border-red-800/60 text-xs text-red-300 flex items-center space-x-2">
                  <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
                  <span>{uploadError}</span>
                </div>
              )}

              {archiveInfo && (
                <div className="bg-[#0b1b36] border border-sky-500/40 rounded-xl p-3 flex items-start space-x-3 text-xs">
                  <Archive className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
                  <div className="space-y-1.5 flex-1">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-sky-200 font-mono text-xs">{archiveInfo.archiveName}</span>
                      <span className="text-[10px] font-mono bg-sky-500/20 text-sky-300 px-2 py-0.5 rounded border border-sky-500/30">
                        ZIP ARCHIVE EXTRACTED
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-300">
                      Indexed <strong className="text-sky-300">{archiveInfo.extractedCount}</strong> source files ({archiveInfo.totalLines.toLocaleString()} total lines of code){archiveInfo.skippedBinary > 0 ? `, filtered ${archiveInfo.skippedBinary} non-source binaries` : ''}.
                    </p>
                    {archiveInfo.languages.length > 0 && (
                      <div className="flex flex-wrap gap-1 pt-0.5">
                        {archiveInfo.languages.map((l, i) => (
                          <span key={i} className="text-[10px] bg-[#162f59] text-sky-300 px-1.5 py-0.5 rounded font-mono border border-sky-800/50">
                            {l}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {uploadedFiles.length > 0 && (
                <div className="space-y-2 pt-1">
                  <div className="flex items-center justify-between text-xs font-bold text-sky-300 font-mono">
                    <span>INDEXED SOURCE FILES ({uploadedFiles.length})</span>
                    <button
                      type="button"
                      onClick={handleClearAllFiles}
                      className="text-[11px] text-red-400 hover:underline cursor-pointer"
                    >
                      Clear All
                    </button>
                  </div>
                  <div className="max-h-40 overflow-y-auto space-y-1.5 pr-1 custom-scrollbar">
                    {uploadedFiles.map((file, idx) => (
                      <div key={idx} className="flex items-center justify-between px-3 py-1.5 rounded-lg bg-[#061021] border border-[#162f59] text-xs font-mono">
                        <div className="flex items-center space-x-2 truncate">
                          <FileCode className="w-3.5 h-3.5 text-sky-400 shrink-0" />
                          <span className="text-sky-100 truncate">{file.path || file.name}</span>
                          <span className="text-[10px] text-sky-400/80 bg-sky-950/60 px-1.5 py-0.5 rounded border border-sky-800/40">
                            {file.language}
                          </span>
                          <span className="text-[10px] text-slate-400">{file.lines} lines</span>
                        </div>
                        <button
                          type="button"
                          onClick={() => handleRemoveUploadedFile(idx)}
                          className="text-slate-400 hover:text-red-400 p-1 cursor-pointer"
                        >
                          <X className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Assessment Mode Selector */}
          <div className="space-y-2.5">
            <div className="flex items-center justify-between">
              <label className="text-xs font-bold uppercase tracking-wider text-sky-400 font-mono flex items-center space-x-1.5">
                <span>ASSESSMENT METHODOLOGY</span>
                <span className="text-sky-400">*</span>
              </label>
              <span className="text-[11px] text-sky-300 font-mono">Select testing scope</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {MODES.map((m) => {
                const IconComponent = m.icon;
                const isSelected = mode === m.id;
                return (
                  <button
                    key={m.id}
                    type="button"
                    onClick={() => handleSelectMode(m.id)}
                    className={`p-4 rounded-xl border text-left transition-all flex flex-col justify-between cursor-pointer ${
                      isSelected
                        ? 'bg-sky-950/70 border-sky-400 text-white ring-1 ring-sky-400/50 shadow-lg shadow-sky-950/50'
                        : 'bg-[#061021] border-[#162f59] text-slate-300 hover:border-sky-500/50 hover:bg-[#0c1f3d]'
                    }`}
                  >
                    <div>
                      <div className="flex items-center justify-between mb-2.5">
                        <IconComponent className={`w-4 h-4 ${isSelected ? 'text-sky-300' : 'text-slate-400'}`} />
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-medium ${
                          isSelected ? 'bg-sky-900/90 text-sky-200 border border-sky-700/70' : 'bg-[#0c1f3d] text-slate-400 border border-[#162f59]'
                        }`}>
                          {m.badge}
                        </span>
                      </div>
                      <div className="text-xs font-bold text-white mb-1">{m.label}</div>
                      <div className="text-[11px] text-slate-400 leading-snug">{m.desc}</div>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Analysis Depth Selector */}
          <div className="space-y-2.5">
            <div className="flex items-center justify-between">
              <label className="text-xs font-bold uppercase tracking-wider text-sky-400 font-mono flex items-center space-x-1.5">
                <span>ANALYSIS DEPTH</span>
                <span className="text-sky-400">*</span>
              </label>
              <span className="text-[11px] text-sky-300 font-mono">Configure scan thoroughness</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => setDepth('quick_surface')}
                className={`p-3.5 rounded-xl border text-left transition-all cursor-pointer flex items-start space-x-3 ${
                  depth === 'quick_surface'
                    ? 'bg-sky-950/70 border-sky-400 text-white ring-1 ring-sky-400/50 shadow-md shadow-sky-950/40'
                    : 'bg-[#061021] border-[#162f59] text-slate-300 hover:border-sky-500/50'
                }`}
              >
                <div className={`p-2 rounded-lg mt-0.5 ${depth === 'quick_surface' ? 'bg-sky-900/80 text-sky-300' : 'bg-[#0c1f3d] text-slate-400'}`}>
                  <Zap className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-bold text-white">Quick Surface Scan</span>
                    <span className="text-[9px] font-mono px-1.5 py-0.2 bg-sky-900/60 text-sky-300 rounded border border-sky-700/50">High-Signal Triage</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
                    Rapid reconnaissance uncovering high-signal perimeter leaks and immediate attack vectors.
                  </p>
                </div>
              </button>

              <button
                type="button"
                onClick={() => setDepth('deep_technical')}
                className={`p-3.5 rounded-xl border text-left transition-all cursor-pointer flex items-start space-x-3 ${
                  depth === 'deep_technical'
                    ? 'bg-sky-950/70 border-sky-400 text-white ring-1 ring-sky-400/50 shadow-md shadow-sky-950/40'
                    : 'bg-[#061021] border-[#162f59] text-slate-300 hover:border-sky-500/50'
                }`}
              >
                <div className={`p-2 rounded-lg mt-0.5 ${depth === 'deep_technical' ? 'bg-sky-900/80 text-sky-300' : 'bg-[#0c1f3d] text-slate-400'}`}>
                  <Layers className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-bold text-white">Deep Technical Audit</span>
                    <span className="text-[9px] font-mono px-1.5 py-0.2 bg-sky-900/60 text-sky-300 rounded border border-sky-700/50">Full Scope (All Logical Risks)</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
                    Comprehensive multi-agent audit examining SQLi sinks, BOLA/BFLA, race conditions, and all genuine vulnerabilities.
                  </p>
                </div>
              </button>
            </div>
          </div>

          {/* Custom Instruction Prompt */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-bold uppercase tracking-wider text-sky-400 font-mono">
                RED TEAM FOCUS INSTRUCTION (OPTIONAL)
              </label>
              <span className="text-[11px] text-slate-400">Guide agents toward specific focus areas</span>
            </div>
            <textarea
              value={instruction}
              onChange={(e) => setInstruction(e.target.value)}
              rows={2}
              className="w-full bg-[#061021] border border-[#162f59] rounded-xl px-4 py-2.5 text-xs text-sky-100 placeholder-slate-500 focus:outline-none focus:border-sky-400 font-mono leading-relaxed"
              placeholder="e.g. Focus on raw SQL queries in routes, IDOR on organization billing, and exposed API keys"
            />
          </div>

          {/* Authorization Checkbox */}
          <div className="bg-[#071328] p-4 rounded-xl border border-[#162f59] space-y-3">
            <label className="flex items-start space-x-3 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={confirmedAuthorized}
                onChange={(e) => setConfirmedAuthorized(e.target.checked)}
                className="mt-1 w-4 h-4 rounded border-slate-700 text-sky-500 focus:ring-sky-500 bg-[#061021]"
              />
              <div className="text-xs">
                <span className="font-bold text-white block">Authorization & Scope Confirmation</span>
                <span className="text-slate-400 text-[11px] leading-relaxed block mt-0.5">
                  I confirm authorization to perform security assessments and static AST code auditing on the designated asset within Scope Guardian boundaries.
                </span>
              </div>
            </label>
          </div>

          {/* Modal Footer Actions */}
          <div className="flex flex-wrap items-center justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-5 py-2.5 rounded-xl border border-[#162f59] text-xs font-medium text-slate-300 hover:text-white hover:bg-[#0c1f3d] transition-colors cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!confirmedAuthorized || (!target.trim() && uploadedFiles.length === 0)}
              className="px-6 py-2.5 bg-gradient-to-r from-sky-500 to-teal-500 hover:from-sky-400 hover:to-teal-400 text-slate-950 font-bold text-xs rounded-xl shadow-lg shadow-sky-500/20 transition-all flex items-center space-x-2 disabled:opacity-50 cursor-pointer"
            >
              <Play className="w-4 h-4 fill-current" />
              <span>Launch Autonomous Assessment</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
export default LaunchScanModal;
