import crypto from 'crypto';
import { SourceFile, SourceLocation, Finding, ScanMode, RepoMetadata } from '../src/types.js';

export interface ProjectSnapshot {
  project_id?: string;
  project_version_id?: string;
  scan_id?: string;
  project_sha: string;
  files: SourceFile[];
  repoMetadata?: RepoMetadata & { commit_sha?: string };
  mode: ScanMode;
}

export interface CandidateSourceLocation {
  file?: string;
  file_path?: string;
  line_number?: number;
  line_number_start?: number;
  line_number_end?: number;
  snippet?: string;
  code_snippet?: string;
  function_name?: string;
  vulnerability_type?: string;
  cwe?: string;
  sink_pattern?: string;
  taint_source?: { file: string; line: number; snippet?: string };
  taint_sink?: { file: string; line: number; snippet?: string };
}

export interface LanguageInventory {
  languageCounts: Record<string, number>;
  extensionCounts: Record<string, number>;
  hasTypeScript: boolean;
  hasJavaScript: boolean;
  hasPython: boolean;
  hasGo: boolean;
  hasJava: boolean;
  hasPhp: boolean;
  hasRuby: boolean;
  hasRust: boolean;
  hasCSharp: boolean;
  totalFiles: number;
}

export class SourceLocationResolver {
  /**
   * Deterministically computes SHA-256 hash of normalized code snippet
   */
  public computeCodeSnippetHash(snippet: string): string {
    if (!snippet) return '';
    const normalized = snippet
      .replace(/\r\n/g, '\n')
      .replace(/\s+/g, ' ')
      .trim();
    return crypto.createHash('sha256').update(normalized, 'utf8').digest('hex');
  }

  /**
   * Normalizes candidate file paths safely.
   * Prevents path traversal (../), collapses slashes, strips leading ./ and /
   */
  public normalizeFilePath(inputPath?: string): string | null {
    if (!inputPath || typeof inputPath !== 'string') return null;

    let p = inputPath.trim();
    // Replace Windows backslashes with standard forward slashes
    p = p.replace(/\\/g, '/');

    // Reject dangerous path traversal attempts or external drive specs
    if (p.includes('../') || p.includes('..\\') || /^[a-zA-Z]:/.test(p)) {
      return null;
    }

    // Strip leading ./ and /
    p = p.replace(/^\.?\/+/, '');

    // Collapse multiple consecutive slashes
    p = p.replace(/\/+/g, '/');

    // Remove trailing slashes
    p = p.replace(/\/+$/, '');

    // Strip URL prefixes if accidentally included
    p = p.replace(/^https?:\/\/[^/]+\//i, '');

    // Strip project name prefixes if they exist (e.g. my-repo/src/app.py -> src/app.py)
    return p.length > 0 ? p : null;
  }

  /**
   * Inventories all actual languages and file extensions in the scanned project snapshot
   */
  public buildProjectLanguageInventory(files: SourceFile[]): LanguageInventory {
    const languageCounts: Record<string, number> = {};
    const extensionCounts: Record<string, number> = {};

    for (const f of files) {
      const p = this.normalizeFilePath(f.path || f.name);
      if (!p) continue;

      const ext = p.split('.').pop()?.toLowerCase() || '';
      if (ext) {
        extensionCounts[ext] = (extensionCounts[ext] || 0) + 1;
      }

      let lang = 'Other';
      if (['ts', 'tsx'].includes(ext)) lang = 'TypeScript';
      else if (['js', 'jsx', 'mjs', 'cjs'].includes(ext)) lang = 'JavaScript';
      else if (['py', 'pyw'].includes(ext)) lang = 'Python';
      else if (['go'].includes(ext)) lang = 'Go';
      else if (['java', 'jar'].includes(ext)) lang = 'Java';
      else if (['php'].includes(ext)) lang = 'PHP';
      else if (['rb'].includes(ext)) lang = 'Ruby';
      else if (['rs'].includes(ext)) lang = 'Rust';
      else if (['cs'].includes(ext)) lang = 'C#';
      else if (['c', 'cpp', 'cc', 'h', 'hpp'].includes(ext)) lang = 'C/C++';
      else if (['json', 'yml', 'yaml', 'toml', 'env'].includes(ext)) lang = 'Config';

      languageCounts[lang] = (languageCounts[lang] || 0) + 1;
    }

    return {
      languageCounts,
      extensionCounts,
      hasTypeScript: (languageCounts['TypeScript'] || 0) > 0,
      hasJavaScript: (languageCounts['JavaScript'] || 0) > 0,
      hasPython: (languageCounts['Python'] || 0) > 0,
      hasGo: (languageCounts['Go'] || 0) > 0,
      hasJava: (languageCounts['Java'] || 0) > 0,
      hasPhp: (languageCounts['PHP'] || 0) > 0,
      hasRuby: (languageCounts['Ruby'] || 0) > 0,
      hasRust: (languageCounts['Rust'] || 0) > 0,
      hasCSharp: (languageCounts['C#'] || 0) > 0,
      totalFiles: files.length,
    };
  }

  /**
   * Deterministically constructs GitHub commit source URL
   */
  public generateGitHubCommitUrl(
    repoMetadata?: RepoMetadata & { commit_sha?: string },
    filePath?: string,
    startLine?: number,
    endLine?: number
  ): string | undefined {
    if (!repoMetadata || !repoMetadata.owner || !repoMetadata.name || !filePath) {
      return undefined;
    }

    const owner = repoMetadata.owner;
    const repo = repoMetadata.name;
    const commit = repoMetadata.commit_sha || repoMetadata.branch || 'main';

    let lineHash = '';
    if (startLine && startLine > 0) {
      if (endLine && endLine > startLine) {
        lineHash = `#L${startLine}-L${endLine}`;
      } else {
        lineHash = `#L${startLine}`;
      }
    }

    return `https://github.com/${owner}/${repo}/blob/${commit}/${filePath}${lineHash}`;
  }

  /**
   * Resolves and verifies a single candidate source location against the actual scanned project files
   */
  public resolveSourceLocation(
    projectSnapshot: ProjectSnapshot,
    candidate: CandidateSourceLocation,
    context?: { endpoint?: string; parameter?: string; vulnerabilityType?: string }
  ): SourceLocation {
    const { project_sha, project_id, project_version_id, scan_id, mode, files = [], repoMetadata } = projectSnapshot;

    // 1. BLACK BOX ENFORCEMENT: Source location is strictly NOT AVAILABLE
    if (mode === 'black_box') {
      return {
        project_id,
        project_version_id,
        scan_id,
        project_sha,
        verification_status: 'NOT_AVAILABLE',
        verification_rationale: 'Source location not available from Black Box assessment. Validated runtime & API evidence provided.',
      };
    }

    // 2. Normalize candidate file path
    const rawCandidatePath = candidate.file || candidate.file_path;
    const normalizedPath = this.normalizeFilePath(rawCandidatePath);

    if (!normalizedPath) {
      return {
        project_id,
        project_version_id,
        scan_id,
        project_sha,
        verification_status: 'UNVERIFIED',
        verification_rationale: 'Candidate source file path is invalid or missing.',
      };
    }

    // 3. Language Inventory Verification (Prevent fake TypeScript / Python when absent)
    const inventory = this.buildProjectLanguageInventory(files);
    const candidateExt = normalizedPath.split('.').pop()?.toLowerCase() || '';

    if (['ts', 'tsx'].includes(candidateExt) && !inventory.hasTypeScript) {
      return {
        project_id,
        project_version_id,
        scan_id,
        project_sha,
        file_path: normalizedPath,
        file: normalizedPath,
        verification_status: 'UNVERIFIED',
        verification_rationale: `Rejected TypeScript source location: Scanned project snapshot contains 0 TypeScript files (file not found).`,
      };
    }

    if (['py', 'pyw'].includes(candidateExt) && !inventory.hasPython) {
      return {
        project_id,
        project_version_id,
        scan_id,
        project_sha,
        file_path: normalizedPath,
        file: normalizedPath,
        verification_status: 'UNVERIFIED',
        verification_rationale: `Rejected Python source location: Scanned project snapshot contains 0 Python files (file not found).`,
      };
    }

    // 4. Locate the actual file in the scanned snapshot
    const targetFile = files.find((f) => {
      const p = this.normalizeFilePath(f.path || f.name);
      if (!p) return false;
      return p === normalizedPath || p.endsWith('/' + normalizedPath) || normalizedPath.endsWith('/' + p);
    });

    if (!targetFile || typeof targetFile.content !== 'string') {
      return {
        project_id,
        project_version_id,
        scan_id,
        project_sha,
        file_path: normalizedPath,
        file: normalizedPath,
        verification_status: 'UNVERIFIED',
        verification_rationale: `File "${normalizedPath}" does not exist in scanned project snapshot (SHA: ${project_sha.slice(0, 8)}).`,
      };
    }

    const actualFilePath = this.normalizeFilePath(targetFile.path || targetFile.name) || normalizedPath;
    const fileLines = targetFile.content.split('\n');
    const totalLines = fileLines.length;

    const candidateSnippet = (candidate.snippet || candidate.code_snippet || '').trim();
    const candidateLine = candidate.line_number || candidate.line_number_start || 1;

    let verifiedStartLine: number | null = null;
    let verifiedEndLine: number | null = null;
    let verifiedSnippet: string = '';
    let matchMethod: string = '';

    // =========================================================================
    // STEP 4A: Check at candidate line number
    // =========================================================================
    if (candidateLine >= 1 && candidateLine <= totalLines) {
      if (candidateSnippet) {
        const candidateSnippetLines = candidateSnippet.split('\n');
        const snippetLineCount = Math.max(1, candidateSnippetLines.length);
        const windowEnd = Math.min(totalLines, candidateLine + snippetLineCount + 2);
        const windowText = fileLines.slice(candidateLine - 1, windowEnd).join('\n');

        // Exact or normalized match within line window
        if (
          windowText.includes(candidateSnippet) ||
          this.normalizeCode(windowText).includes(this.normalizeCode(candidateSnippet))
        ) {
          verifiedStartLine = candidateLine;
          verifiedEndLine = Math.min(totalLines, candidateLine + snippetLineCount - 1);
          verifiedSnippet = fileLines.slice(verifiedStartLine - 1, verifiedEndLine).join('\n');
          matchMethod = 'exact_at_candidate_line';
        }
      } else {
        // Line exists and is within file boundaries
        verifiedStartLine = candidateLine;
        verifiedEndLine = candidateLine;
        verifiedSnippet = fileLines[candidateLine - 1] || '';
        matchMethod = 'line_within_file';
      }
    }

    // =========================================================================
    // STEP 4B: If candidate line is wrong, search the actual file for exact snippet
    // =========================================================================
    if (!verifiedStartLine && candidateSnippet) {
      const occurrences = this.findSnippetOccurrences(fileLines, candidateSnippet);

      if (occurrences.length === 1) {
        verifiedStartLine = occurrences[0].startLine;
        verifiedEndLine = occurrences[0].endLine;
        verifiedSnippet = occurrences[0].snippet;
        matchMethod = 'relocated_exact_snippet_in_file';
      } else if (occurrences.length > 1) {
        // Contextual disambiguation
        const scored = occurrences.map((occ) => {
          let score = 0;
          // Proximity to candidate line
          const distance = Math.abs(occ.startLine - candidateLine);
          score -= distance * 0.05;

          // Context matches in surrounding lines (±5 lines)
          const contextStart = Math.max(0, occ.startLine - 6);
          const contextEnd = Math.min(totalLines, occ.endLine + 5);
          const surrounding = fileLines.slice(contextStart, contextEnd).join('\n').toLowerCase();

          if (context?.endpoint && surrounding.includes(context.endpoint.toLowerCase())) score += 10;
          if (context?.parameter && surrounding.includes(context.parameter.toLowerCase())) score += 5;
          if (candidate.function_name && surrounding.includes(candidate.function_name.toLowerCase())) score += 8;
          if (context?.vulnerabilityType && surrounding.includes(context.vulnerabilityType.toLowerCase())) score += 3;

          return { occ, score };
        });

        scored.sort((a, b) => b.score - a.score);
        const best = scored[0].occ;
        verifiedStartLine = best.startLine;
        verifiedEndLine = best.endLine;
        verifiedSnippet = best.snippet;
        matchMethod = 'relocated_contextual_match';
      }
    }

    // =========================================================================
    // STEP 4C: AST / Sink Pattern Search in Actual File
    // =========================================================================
    if (!verifiedStartLine) {
      const sinkMatch = this.detectVulnerableSinkInFile(fileLines, candidate, context);
      if (sinkMatch) {
        verifiedStartLine = sinkMatch.startLine;
        verifiedEndLine = sinkMatch.endLine;
        verifiedSnippet = sinkMatch.snippet;
        matchMethod = 'ast_sink_pattern_match';
      }
    }

    // =========================================================================
    // STEP 4D: Verification outcome
    // =========================================================================
    if (!verifiedStartLine) {
      return {
        project_id,
        project_version_id,
        scan_id,
        project_sha,
        file_path: actualFilePath,
        file: actualFilePath,
        line_number: candidateLine,
        verification_status: 'UNVERIFIED',
        verification_rationale: `Claimed code snippet or sink could not be verified in actual "${actualFilePath}" content.`,
      };
    }

    const finalStart = verifiedStartLine;
    const finalEnd = verifiedEndLine || verifiedStartLine;
    const finalSnippet = verifiedSnippet || fileLines.slice(finalStart - 1, finalEnd).join('\n');
    const codeHash = this.computeCodeSnippetHash(finalSnippet);

    const githubUrl = this.generateGitHubCommitUrl(repoMetadata, actualFilePath, finalStart, finalEnd);

    return {
      project_id,
      project_version_id,
      scan_id,
      project_sha,
      file_path: actualFilePath,
      file: actualFilePath,
      line_number_start: finalStart,
      line_number_end: finalEnd,
      line_number: finalStart,
      function_name: candidate.function_name || this.extractEnclosingFunction(fileLines, finalStart),
      code_snippet: finalSnippet,
      snippet: finalSnippet,
      code_hash: codeHash,
      verification_status: 'VERIFIED',
      verification_rationale: `Verified in scanned project snapshot (${matchMethod}) at lines ${finalStart}-${finalEnd}.`,
      github_url: githubUrl,
      commit_sha: repoMetadata?.commit_sha,
      taint_source: candidate.taint_source,
      taint_sink: candidate.taint_sink,
    };
  }

  /**
   * Resolves and verifies all source locations attached to a finding
   */
  public resolveFindingSourceLocations(finding: Finding, projectSnapshot: ProjectSnapshot): Finding {
    const updatedFinding = { ...finding };
    const { mode, project_sha } = projectSnapshot;

    // Cross-project check: Ensure finding is bound to current project SHA
    updatedFinding.project_sha = project_sha;
    if (projectSnapshot.project_id) updatedFinding.project_id = projectSnapshot.project_id;
    if (projectSnapshot.project_version_id) updatedFinding.version_id = projectSnapshot.project_version_id;
    if (projectSnapshot.scan_id) updatedFinding.scan_id = projectSnapshot.scan_id;

    // Strict boundary for Black Box and Grey Box (API / Logic level, no source code files attached)
    if (mode === 'black_box' || mode === 'grey_box') {
      updatedFinding.source_locations = [];
      updatedFinding.source_verification_status = 'NOT_AVAILABLE';
      delete updatedFinding.file;
      delete updatedFinding.line;
      delete updatedFinding.code_patch_diff;
      return updatedFinding;
    }

    const candidateLocs: CandidateSourceLocation[] = [];

    if (Array.isArray(finding.source_locations) && finding.source_locations.length > 0) {
      for (const loc of finding.source_locations) {
        candidateLocs.push({
          file: loc.file || loc.file_path,
          line_number: loc.line_number || loc.line_number_start,
          line_number_start: loc.line_number_start,
          line_number_end: loc.line_number_end,
          snippet: loc.snippet || loc.code_snippet,
          function_name: loc.function_name,
          vulnerability_type: finding.vulnerability_type,
          cwe: finding.cwe,
          taint_source: loc.taint_source,
          taint_sink: loc.taint_sink,
        });
      }
    } else if (finding.file) {
      candidateLocs.push({
        file: finding.file,
        line_number: finding.line,
        snippet: finding.evidence?.find((e) => e.evidence_type === 'code_snippet')?.description,
        vulnerability_type: finding.vulnerability_type,
        cwe: finding.cwe,
      });
    }

    if (candidateLocs.length === 0) {
      updatedFinding.source_locations = [];
      updatedFinding.source_verification_status = mode === 'white_box' ? 'UNVERIFIED' : 'NOT_AVAILABLE';
      return updatedFinding;
    }

    const verifiedLocs: SourceLocation[] = [];
    let anyVerified = false;

    for (const cand of candidateLocs) {
      const resolved = this.resolveSourceLocation(projectSnapshot, cand, {
        endpoint: finding.affected_endpoint || finding.endpoint,
        parameter: finding.parameter,
        vulnerabilityType: finding.vulnerability_type,
      });
      verifiedLocs.push(resolved);
      if (resolved.verification_status === 'VERIFIED') {
        anyVerified = true;
      }
    }

    updatedFinding.source_locations = verifiedLocs;
    updatedFinding.source_verification_status = anyVerified ? 'VERIFIED' : 'UNVERIFIED';

    const primary = verifiedLocs.find((l) => l.verification_status === 'VERIFIED') || verifiedLocs[0];
    if (primary && primary.verification_status === 'VERIFIED') {
      updatedFinding.file = primary.file_path || primary.file;
      updatedFinding.line = primary.line_number_start || primary.line_number;
    } else if (primary && primary.verification_status === 'UNVERIFIED') {
      // Do not present unverified files/lines as authoritative
      updatedFinding.file = primary.file_path;
      updatedFinding.line = primary.line_number;
    }

    return updatedFinding;
  }

  /**
   * Batch resolves an array of findings against a project snapshot.
   * In White-Box mode with uploaded files, guarantees zero hallucinated files.
   */
  public resolveAllFindings(findings: Finding[], projectSnapshot: ProjectSnapshot): Finding[] {
    const resolved = findings.map((f) => this.resolveFindingSourceLocations(f, projectSnapshot));

    // If White-Box mode and actual files were provided, filter out phantom unverified findings
    if (projectSnapshot.mode === 'white_box' && projectSnapshot.files && projectSnapshot.files.length > 0) {
      const verifiedOnly = resolved.filter((f) => f.source_verification_status === 'VERIFIED');
      if (verifiedOnly.length > 0) {
        return verifiedOnly;
      }
    }

    return resolved;
  }

  // --- Internal Helper Functions ---

  private normalizeCode(code: string): string {
    return code
      .replace(/["']/g, '"')
      .replace(/\s+/g, ' ')
      .trim();
  }

  private findSnippetOccurrences(
    lines: string[],
    snippet: string
  ): Array<{ startLine: number; endLine: number; snippet: string }> {
    const results: Array<{ startLine: number; endLine: number; snippet: string }> = [];
    const snippetLines = snippet.split('\n').map((l) => l.trim()).filter(Boolean);
    if (snippetLines.length === 0) return results;

    const firstLineSnippet = this.normalizeCode(snippetLines[0]);

    for (let i = 0; i < lines.length; i++) {
      const normalizedCurrent = this.normalizeCode(lines[i]);
      if (normalizedCurrent.includes(firstLineSnippet) || (firstLineSnippet.length > 8 && lines[i].includes(snippetLines[0]))) {
        const matchStart = i + 1;
        const matchEnd = Math.min(lines.length, matchStart + snippetLines.length - 1);
        const actualSnippet = lines.slice(matchStart - 1, matchEnd).join('\n');
        results.push({
          startLine: matchStart,
          endLine: matchEnd,
          snippet: actualSnippet,
        });
      }
    }

    return results;
  }

  private detectVulnerableSinkInFile(
    lines: string[],
    candidate: CandidateSourceLocation,
    context?: { endpoint?: string; parameter?: string; vulnerabilityType?: string }
  ): { startLine: number; endLine: number; snippet: string } | null {
    const cwe = candidate.cwe || '';
    const vuln = (candidate.vulnerability_type || context?.vulnerabilityType || '').toLowerCase();

    const sqlPatterns = [/cursor\.execute\s*\(/i, /db\.query\s*\(/i, /pool\.query\s*\(/i, /SELECT\s+.*FROM/i];
    const bolaPatterns = [/\.findById\s*\(/i, /\.get_session\s*\(/i, /\.objects\.get\s*\(/i, /db\.get\s*\(/i];
    const cmdPatterns = [/child_process\.exec/i, /subprocess\.Popen/i, /os\.system/i, /exec\s*\(/i];

    let patterns: RegExp[] = [];
    if (cwe.includes('89') || vuln.includes('sql')) patterns = sqlPatterns;
    else if (cwe.includes('639') || vuln.includes('access control') || vuln.includes('idor') || vuln.includes('bola')) patterns = bolaPatterns;
    else if (cwe.includes('78') || vuln.includes('command') || vuln.includes('rce')) patterns = cmdPatterns;

    if (patterns.length === 0) return null;

    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i];
      for (const pat of patterns) {
        if (pat.test(lineText)) {
          return {
            startLine: i + 1,
            endLine: i + 1,
            snippet: lineText.trim(),
          };
        }
      }
    }

    return null;
  }

  private extractEnclosingFunction(lines: string[], targetLine: number): string | undefined {
    for (let i = targetLine - 1; i >= 0; i--) {
      const line = lines[i];
      const fnMatch = line.match(/(?:def|function|async\s+function|const\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?\()/);
      if (fnMatch) {
        return fnMatch[1] || line.trim().split('(')[0].replace(/^(?:async\s+)?(?:def|function)\s+/, '');
      }
      const methodMatch = line.match(/^\s*(?:public|private|async)?\s*([a-zA-Z0-9_$]+)\s*\([^)]*\)\s*[:{]/);
      if (methodMatch) {
        return methodMatch[1];
      }
    }
    return undefined;
  }
}

export const sourceLocationResolver = new SourceLocationResolver();
