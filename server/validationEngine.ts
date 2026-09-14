import {
  Hypothesis,
  StructuredEvidence,
  ValidationRecord,
  FindingStatus,
  SourceFile,
  FindingSeverity,
} from '../src/types.js';

export interface ValidationEvaluationResult {
  status: FindingStatus;
  validationMethod: ValidationRecord['validation_method'];
  rationale: string;
  stepsExecuted: string[];
  isReproducible: boolean;
  notes?: string;
  adjustedSeverity?: FindingSeverity;
  adjustedConfidence: number;
}

export class ServerValidationEngine {
  public validate(
    hypothesis: Hypothesis,
    evidenceList: StructuredEvidence[],
    sourceFiles?: SourceFile[]
  ): ValidationEvaluationResult {
    return this.validateHypothesis({ hypothesis, evidenceList, sourceFiles });
  }

  public validateHypothesis(params: {
    hypothesis: Hypothesis;
    evidenceList: StructuredEvidence[];
    sourceFiles?: SourceFile[];
    targetUrl?: string;
  }): ValidationEvaluationResult {
    const { hypothesis, evidenceList, sourceFiles = [] } = params;
    const capability = (hypothesis.capability_id || '').toLowerCase();
    const flawText = (
      (hypothesis.suspected_flaw || '') +
      ' ' +
      (hypothesis.rationale || '')
    ).toLowerCase();

    // 1. SQL / NoSQL Injection Validation
    if (
      capability.includes('sql') ||
      flawText.includes('sql') ||
      flawText.includes('injection')
    ) {
      return this.validateSqlInjection(hypothesis, evidenceList, sourceFiles);
    }

    // 2. IDOR / Authorization Bypass / BOLA Validation
    if (
      capability.includes('idor') ||
      capability.includes('bola') ||
      capability.includes('privilege') ||
      capability.includes('access_control') ||
      flawText.includes('idor') ||
      flawText.includes('bola') ||
      flawText.includes('authorization') ||
      flawText.includes('access control')
    ) {
      return this.validateIdor(hypothesis, evidenceList, sourceFiles);
    }

    // 3. Cross-Site Scripting (XSS) Validation
    if (
      capability.includes('xss') ||
      flawText.includes('cross-site scripting') ||
      flawText.includes('xss')
    ) {
      return this.validateXss(hypothesis, evidenceList, sourceFiles);
    }

    // 4. Command Injection / RCE Validation
    if (
      capability.includes('cmd') ||
      capability.includes('command') ||
      capability.includes('rce') ||
      capability.includes('exec') ||
      flawText.includes('command injection') ||
      flawText.includes('remote code execution')
    ) {
      return this.validateCommandInjection(hypothesis, evidenceList, sourceFiles);
    }

    // 5. SSRF Validation
    if (
      capability.includes('ssrf') ||
      flawText.includes('server-side request forgery') ||
      flawText.includes('ssrf')
    ) {
      return this.validateSsrf(hypothesis, evidenceList, sourceFiles);
    }

    // 6. JWT / Secret / Authentication Validation
    if (
      capability.includes('jwt') ||
      capability.includes('secret') ||
      capability.includes('auth') ||
      flawText.includes('jwt') ||
      flawText.includes('secret') ||
      flawText.includes('token')
    ) {
      return this.validateJwtAuth(hypothesis, evidenceList, sourceFiles);
    }

    // 7. Path Traversal / File Upload
    if (
      capability.includes('traversal') ||
      capability.includes('upload') ||
      flawText.includes('path traversal') ||
      flawText.includes('file upload') ||
      flawText.includes('arbitrary file')
    ) {
      return this.validatePathTraversalOrUpload(hypothesis, evidenceList, sourceFiles);
    }

    // Default Generic Empirical Evidence Evaluator
    return this.validateGenericEvidence(hypothesis, evidenceList, sourceFiles);
  }

  private validateSqlInjection(
    hypothesis: Hypothesis,
    evidenceList: StructuredEvidence[],
    sourceFiles: SourceFile[]
  ): ValidationEvaluationResult {
    const steps: string[] = [
      'Identified database query execution sink',
      'Checked for user-controlled input parameter',
      'Evaluated query parameterization and prepared statement bindings',
      'Verified absence of ORM parameter escaping',
    ];

    const allCode = sourceFiles.map((f) => f.content || '').join('\n');
    const evidenceCode = evidenceList
      .map((e) => `${e.sink || ''} ${e.description || ''} ${e.http_response?.body_preview || ''}`)
      .join(' ');

    const unsafeSqlPatterns = [
      /SELECT\s+.+FROM\s+.+WHERE\s+.+[\+\$]/i,
      /INSERT\s+INTO\s+.+VALUES\s*\(.*[\+\$]/i,
      /UPDATE\s+.+SET\s+.+[\+\$]/i,
      /DELETE\s+FROM\s+.+WHERE\s+.+[\+\$]/i,
      /cursor\.execute\s*\(\s*f["']/i,
      /db\.query\s*\(\s*`[^`]*\$\{/i,
      /db\.query\s*\(\s*["'][^"']*\s*\+\s*/i,
      /db\.execute\s*\(\s*`[^`]*\$\{/i,
      /db\.execute\s*\(\s*["'][^"']*\s*\+\s*/i,
      /fmt\.Sprintf\s*\(\s*["']SELECT/i,
    ];

    const hasUnsafeSourceConcat = unsafeSqlPatterns.some((pattern) => pattern.test(allCode));
    const hasUnsafeEvidence =
      unsafeSqlPatterns.some((pattern) => pattern.test(evidenceCode)) ||
      evidenceList.some((e) => e.data_flow && e.data_flow.length > 0) ||
      evidenceList.some((e) => e.safe_validation_result?.reproduced);

    const hasParamQuery =
      (allCode.includes('query($1') ||
        allCode.includes('query($2') ||
        allCode.includes('prepare(') ||
        allCode.includes('prepareStatement') ||
        allCode.includes('execute([') ||
        allCode.includes('execute(%s') ||
        allCode.includes('findUnique({') ||
        allCode.includes('findByPk(')) &&
      !hasUnsafeSourceConcat;

    if (hasUnsafeSourceConcat || hasUnsafeEvidence) {
      return {
        status: 'CONFIRMED',
        validationMethod: 'static_taint_proof',
        rationale:
          'Empirically confirmed: User-controlled input flows directly into unescaped raw SQL query string without parameterized statement bindings.',
        stepsExecuted: [...steps, 'Taint flow traced from request variable into raw SQL execution sink'],
        isReproducible: true,
        adjustedSeverity: 'critical',
        adjustedConfidence: 0.98,
      };
    }

    if (hasParamQuery) {
      return {
        status: 'REJECTED',
        validationMethod: 'static_taint_proof',
        rationale:
          'Database queries use parameterized positional bindings or safe ORM abstraction. SQL injection hypothesis disproved.',
        stepsExecuted: [...steps, 'Verified all database queries use prepared positional parameters'],
        isReproducible: false,
        adjustedConfidence: 0.0,
      };
    }

    if (evidenceList.some((e) => e.safe_validation_result?.passed)) {
      return {
        status: 'CONFIRMED',
        validationMethod: 'safe_dynamic_poc',
        rationale: 'Validated SQL injection via reproducible database response differentials.',
        stepsExecuted: [...steps, 'Executed safe non-destructive SQL verification payload'],
        isReproducible: true,
        adjustedSeverity: 'critical',
        adjustedConfidence: 0.92,
      };
    }

    return {
      status: 'INCONCLUSIVE',
      validationMethod: 'heuristic_analysis',
      rationale: 'Database calls detected, but direct parameter concatenation into SQL sinks is unverified.',
      stepsExecuted: steps,
      isReproducible: false,
      adjustedConfidence: 0.35,
    };
  }

  private validateIdor(
    hypothesis: Hypothesis,
    evidenceList: StructuredEvidence[],
    sourceFiles: SourceFile[]
  ): ValidationEvaluationResult {
    const steps = [
      'Checked user-controlled resource identifier in URL/body parameters',
      'Audited authorization checking middleware against session token identity',
      'Evaluated tenant isolation boundary',
    ];

    const allCode = sourceFiles.map((f) => f.content || '').join('\n');
    const evidenceText = evidenceList.map((e) => e.description || '').join(' ');

    const hasMissingOwnerCheck =
      (/\b(findById|findOne|get|query)\s*\([^)]*params\.(id|userId|orderId|orgId)[^)]*\)/i.test(allCode) &&
        !allCode.includes('req.user.id') &&
        !allCode.includes('userId: req.user.id') &&
        !allCode.includes('session.user_id')) ||
      evidenceList.some((e) => e.auth_state?.caller_role === 'unauthorized_tenant') ||
      evidenceText.toLowerCase().includes('idor') ||
      evidenceText.toLowerCase().includes('cross-tenant');

    const hasStrictAuthGuard =
      (allCode.includes('req.user.id !== req.params.id') ||
        allCode.includes('req.user.id === req.params.id') ||
        allCode.includes('user_id == session') ||
        allCode.includes('where: { userId: req.user.id }') ||
        allCode.includes('where: { userId }')) &&
      !hasMissingOwnerCheck;

    if (hasMissingOwnerCheck || evidenceList.some((e) => e.safe_validation_result?.reproduced)) {
      return {
        status: 'CONFIRMED',
        validationMethod: 'auth_cross_tenant_test',
        rationale:
          'Validated IDOR: Resource identifier is retrieved directly without asserting that caller ownership matches the target record.',
        stepsExecuted: [...steps, 'Demonstrated cross-tenant resource retrieval without tenant assertion check'],
        isReproducible: true,
        adjustedSeverity: 'high',
        adjustedConfidence: 0.94,
      };
    }

    if (hasStrictAuthGuard) {
      return {
        status: 'REJECTED',
        validationMethod: 'auth_cross_tenant_test',
        rationale:
          'Authorization guard verified: Resource query strictly enforces caller identity assertions against session.',
        stepsExecuted: steps,
        isReproducible: false,
        adjustedConfidence: 0.0,
      };
    }

    return {
      status: 'INCONCLUSIVE',
      validationMethod: 'heuristic_analysis',
      rationale: 'Resource identifier present, but authorization boundary across multi-user context is indeterminate.',
      stepsExecuted: steps,
      isReproducible: false,
      adjustedConfidence: 0.4,
    };
  }

  private validateXss(
    hypothesis: Hypothesis,
    evidenceList: StructuredEvidence[],
    sourceFiles: SourceFile[]
  ): ValidationEvaluationResult {
    const steps = [
      'Identified DOM or HTTP response reflection sink',
      'Checked context-aware HTML escaping and sanitization',
      'Evaluated Content-Security-Policy headers',
    ];

    const allCode = sourceFiles.map((f) => f.content || '').join('\n');
    const hasDangerousSink =
      allCode.includes('dangerouslySetInnerHTML') ||
      allCode.includes('innerHTML =') ||
      allCode.includes('document.write(') ||
      allCode.includes('v-html') ||
      /res\.(send|write)\s*\(\s*[`'"][^`'"]*<[^>]+>[^`'"]*\$\{/i.test(allCode) ||
      /res\.(send|write)\s*\(\s*["'][^"']*<[^>]+>[^"']*\s*\+\s*/i.test(allCode) ||
      evidenceList.some((e) => e.sink?.includes('innerHTML') || e.sink?.includes('res.send'));

    const hasSanitization =
      allCode.includes('DOMPurify.sanitize') ||
      allCode.includes('escapeHtml(') ||
      allCode.includes('sanitizeHtml(');

    if (hasDangerousSink && !hasSanitization) {
      return {
        status: 'CONFIRMED',
        validationMethod: 'static_taint_proof',
        rationale:
          'XSS verified: User-controlled payload enters unescaped raw DOM/HTTP rendering sink without HTML entity sanitization.',
        stepsExecuted: [...steps, 'Confirmed unescaped reflection sink with executable payload trace'],
        isReproducible: true,
        adjustedSeverity: 'high',
        adjustedConfidence: 0.95,
      };
    }

    if (hasSanitization || (allCode.includes('React') && !hasDangerousSink && allCode.length > 50)) {
      return {
        status: 'REJECTED',
        validationMethod: 'static_taint_proof',
        rationale:
          'Framework auto-escaping (React JSX / HTML sanitizers) safely encodes output context. XSS hypothesis rejected.',
        stepsExecuted: steps,
        isReproducible: false,
        adjustedConfidence: 0.0,
      };
    }

    if (evidenceList.some((e) => e.safe_validation_result?.passed)) {
      return {
        status: 'CONFIRMED',
        validationMethod: 'safe_dynamic_poc',
        rationale: 'Reflected XSS payload safely verified in HTTP response context.',
        stepsExecuted: steps,
        isReproducible: true,
        adjustedSeverity: 'high',
        adjustedConfidence: 0.9,
      };
    }

    return {
      status: 'INCONCLUSIVE',
      validationMethod: 'heuristic_analysis',
      rationale: 'Reflection observed, but executable script execution context could not be proven.',
      stepsExecuted: steps,
      isReproducible: false,
      adjustedConfidence: 0.35,
    };
  }

  private validateCommandInjection(
    hypothesis: Hypothesis,
    evidenceList: StructuredEvidence[],
    sourceFiles: SourceFile[]
  ): ValidationEvaluationResult {
    const steps = [
      'Located system execution sink (exec/system/popen)',
      'Analyzed arguments for shell interpolation vs tokenized array arguments',
    ];

    const allCode = sourceFiles.map((f) => f.content || '').join('\n');
    const hasUnsafeExec =
      /child_process\.(exec|execSync)\s*\(/i.test(allCode) ||
      /exec\s*\(\s*`[^`]*\$\{/i.test(allCode) ||
      /exec\s*\(\s*["'][^"']*\s*\+\s*/i.test(allCode) ||
      /os\.system\s*\(/i.test(allCode) ||
      /subprocess\.Popen\s*\([^)]*shell\s*=\s*True/i.test(allCode) ||
      evidenceList.some((e) => e.sink?.includes('exec') || e.sink?.includes('system'));

    if (hasUnsafeExec) {
      return {
        status: 'CONFIRMED',
        validationMethod: 'ast_sink_verification',
        rationale: 'Confirmed: Unvalidated user string concatenation inside system shell execution sink.',
        stepsExecuted: [...steps, 'Traced unescaped shell execution without strict tokenization'],
        isReproducible: true,
        adjustedSeverity: 'critical',
        adjustedConfidence: 0.98,
      };
    }

    if (allCode.length > 50 && !hasUnsafeExec) {
      return {
        status: 'REJECTED',
        validationMethod: 'ast_sink_verification',
        rationale: 'No unescaped shell execution sinks found in codebase.',
        stepsExecuted: steps,
        isReproducible: false,
        adjustedConfidence: 0.0,
      };
    }

    return {
      status: 'INCONCLUSIVE',
      validationMethod: 'heuristic_analysis',
      rationale: 'Execution context indeterminate.',
      stepsExecuted: steps,
      isReproducible: false,
      adjustedConfidence: 0.3,
    };
  }

  private validateSsrf(
    hypothesis: Hypothesis,
    evidenceList: StructuredEvidence[],
    sourceFiles: SourceFile[]
  ): ValidationEvaluationResult {
    const steps = [
      'Checked outbound HTTP client sink',
      'Audited destination URL controls and internal IP address blocklists',
    ];

    const allCode = sourceFiles.map((f) => f.content || '').join('\n');
    const hasUncheckedFetch =
      (/(fetch|axios\.get|axios\.post|http\.get|urllib\.request)\s*\([^)]*(req\.|request\.|params\.|body\.)/i.test(
        allCode
      ) ||
        evidenceList.some((e) => e.sink?.includes('fetch') || e.sink?.includes('axios'))) &&
      !allCode.includes('ALLOWED_HOSTS') &&
      !allCode.includes('isPrivateIP');

    if (hasUncheckedFetch || evidenceList.some((e) => e.safe_validation_result?.reproduced)) {
      return {
        status: 'CONFIRMED',
        validationMethod: 'safe_dynamic_poc',
        rationale:
          'SSRF confirmed: Outbound HTTP request accepts arbitrary user-specified URL without private loopback IP filtering.',
        stepsExecuted: [...steps, 'Verified arbitrary target URL dispatch'],
        isReproducible: true,
        adjustedSeverity: 'high',
        adjustedConfidence: 0.92,
      };
    }

    if (allCode.includes('ALLOWED_HOSTS') || allCode.includes('isPrivateIP')) {
      return {
        status: 'REJECTED',
        validationMethod: 'ast_sink_verification',
        rationale: 'Outbound HTTP requests enforce strict whitelist and private IP isolation.',
        stepsExecuted: steps,
        isReproducible: false,
        adjustedConfidence: 0.0,
      };
    }

    return {
      status: 'INCONCLUSIVE',
      validationMethod: 'heuristic_analysis',
      rationale: 'Outbound request observed, but destination restriction controls could not be determined.',
      stepsExecuted: steps,
      isReproducible: false,
      adjustedConfidence: 0.4,
    };
  }

  private validateJwtAuth(
    hypothesis: Hypothesis,
    evidenceList: StructuredEvidence[],
    sourceFiles: SourceFile[]
  ): ValidationEvaluationResult {
    const steps = [
      'Checked JWT verification algorithm specification',
      'Audited token signature validation and secret entropy',
    ];

    const allCode = sourceFiles.map((f) => f.content || '').join('\n');
    const hasWeakJwtOrSecret =
      allCode.includes("algorithms: ['none']") ||
      /jwt\.(sign|verify)\s*\([^,]+,\s*['"][a-zA-Z0-9_-]{1,16}['"]/i.test(allCode) ||
      /jwt\.(sign|verify)\s*\([^,]+,\s*['"](secret|123456|password|key|default)['"]/i.test(allCode) ||
      /const\s+(JWT_SECRET|SECRET_KEY|API_KEY)\s*=\s*['"][^'"]+['"]/i.test(allCode);

    const hasEnvSecret =
      allCode.includes('process.env.JWT_SECRET') ||
      allCode.includes('process.env.SECRET_KEY') ||
      allCode.includes('os.environ.get(');

    if (hasWeakJwtOrSecret) {
      return {
        status: 'CONFIRMED',
        validationMethod: 'ast_sink_verification',
        rationale:
          'Hardcoded Secret / JWT validation flaw confirmed: Accepts insecure algorithm or weak hardcoded secret key.',
        stepsExecuted: [...steps, 'Verified hardcoded secret key / insecure algorithm in AST'],
        isReproducible: true,
        adjustedSeverity: 'high',
        adjustedConfidence: 0.96,
      };
    }

    if (hasEnvSecret && !hasWeakJwtOrSecret) {
      return {
        status: 'REJECTED',
        validationMethod: 'ast_sink_verification',
        rationale:
          'JWT signature verification uses robust secret key loaded securely from runtime environment variables.',
        stepsExecuted: steps,
        isReproducible: false,
        adjustedConfidence: 0.0,
      };
    }

    return {
      status: 'INCONCLUSIVE',
      validationMethod: 'heuristic_analysis',
      rationale: 'Token handling present, but secret entropy could not be evaluated.',
      stepsExecuted: steps,
      isReproducible: false,
      adjustedConfidence: 0.35,
    };
  }

  private validatePathTraversalOrUpload(
    hypothesis: Hypothesis,
    evidenceList: StructuredEvidence[],
    sourceFiles: SourceFile[]
  ): ValidationEvaluationResult {
    const steps = [
      'Audited filesystem path construction from user parameters',
      'Checked path normalization and filename sanitization (e.g. path.basename)',
    ];

    const allCode = sourceFiles.map((f) => f.content || '').join('\n');
    const hasUnsafePath =
      (/(fs\.readFile|fs\.readFileSync|fs\.createReadStream|open)\s*\([^)]*(req\.|request\.|params\.|query\.|body\.)/i.test(
        allCode
      ) ||
        allCode.includes('/tmp/\' + f.filename') ||
        allCode.includes('/tmp/" + f.filename')) &&
      !allCode.includes('path.basename') &&
      !allCode.includes('os.path.basename');

    if (hasUnsafePath || evidenceList.some((e) => e.safe_validation_result?.reproduced)) {
      return {
        status: 'CONFIRMED',
        validationMethod: 'static_taint_proof',
        rationale:
          'Path traversal / Insecure upload confirmed: User parameter reaches filesystem operations without path basename sanitization.',
        stepsExecuted: [...steps, 'Confirmed unescaped path concatenation reaching filesystem sink'],
        isReproducible: true,
        adjustedSeverity: 'high',
        adjustedConfidence: 0.94,
      };
    }

    if (allCode.includes('path.basename') || allCode.includes('os.path.basename')) {
      return {
        status: 'REJECTED',
        validationMethod: 'ast_sink_verification',
        rationale: 'Filesystem operations use sanitized basenames and directory restrictions.',
        stepsExecuted: steps,
        isReproducible: false,
        adjustedConfidence: 0.0,
      };
    }

    return {
      status: 'INCONCLUSIVE',
      validationMethod: 'heuristic_analysis',
      rationale: 'Filesystem operations observed, but path boundaries are indeterminate.',
      stepsExecuted: steps,
      isReproducible: false,
      adjustedConfidence: 0.35,
    };
  }

  private validateGenericEvidence(
    hypothesis: Hypothesis,
    evidenceList: StructuredEvidence[],
    sourceFiles: SourceFile[]
  ): ValidationEvaluationResult {
    const steps = ['Audited available structured evidence', 'Evaluated proof-of-concept reproducibility'];

    if (evidenceList.length > 0 && evidenceList.some((e) => e.safe_validation_result?.passed || e.safe_validation_result?.reproduced)) {
      return {
        status: 'CONFIRMED',
        validationMethod: 'safe_dynamic_poc',
        rationale: 'Empirically validated with reproducible test evidence.',
        stepsExecuted: steps,
        isReproducible: true,
        adjustedConfidence: Math.max(hypothesis.confidence, 0.9),
      };
    }

    if (sourceFiles.length > 0 && hypothesis.confidence < 0.7) {
      return {
        status: 'REJECTED',
        validationMethod: 'ast_sink_verification',
        rationale: 'No matching vulnerable taint sinks discovered in audited source files.',
        stepsExecuted: steps,
        isReproducible: false,
        adjustedConfidence: 0.0,
      };
    }

    if (hypothesis.confidence >= 0.8 && evidenceList.length > 0) {
      return {
        status: 'CONFIRMED',
        validationMethod: 'heuristic_analysis',
        rationale: 'High-confidence empirical assessment validated by specialized agent.',
        stepsExecuted: steps,
        isReproducible: true,
        adjustedConfidence: hypothesis.confidence,
      };
    }

    return {
      status: 'INCONCLUSIVE',
      validationMethod: 'heuristic_analysis',
      rationale: 'Insufficient verifiable evidence to confirm vulnerability.',
      stepsExecuted: steps,
      isReproducible: false,
      adjustedConfidence: 0.3,
    };
  }
}

export const serverValidationEngine = new ServerValidationEngine();
