import { SourceFile, ApplicationProfile, ScanMode } from '../types';
import { analyzeAuthoritativeTechStack, normalizePath, isIgnoredPath } from './fingerprint';

export function profileApplication(
  files: SourceFile[],
  target: string,
  mode: ScanMode
): ApplicationProfile {
  const dependenciesSet = new Set<string>();
  const dbTechSet = new Set<string>();
  const authMechSet = new Set<string>();
  const authzMechSet = new Set<string>();
  const inputSourcesSet = new Set<string>();
  const outputLocsSet = new Set<string>();
  const sensitiveResourcesSet = new Set<string>();
  const configLocsSet = new Set<string>();
  const endpoints: Array<{
    path: string;
    method: string;
    auth_required: boolean;
    parameters: string[];
  }> = [];

  let hasFileUpload = false;
  let hasExternalRequests = false;
  let hasTemplates = false;
  let templateEngine: string | undefined;
  let hasSessions = false;
  let hasJwt = false;
  let hasCookies = false;
  let hasAdminRoutes = false;
  let hasGraphql = false;
  let hasWebsockets = false;
  let hasRawSql = false;
  let hasDeserialization = false;
  let hasCommandExec = false;
  let packageManager: string | undefined;

  // Filter valid files first
  const validFiles: Array<{ normalizedPath: string; content: string; size: number }> = [];
  for (const file of files || []) {
    const rawPath = file.path || file.name || '';
    const norm = normalizePath(rawPath);
    if (!isIgnoredPath(norm)) {
      validFiles.push({
        normalizedPath: norm,
        content: file.content || '',
        size: typeof file.size === 'number' ? file.size : (file.content || '').length,
      });
    }
  }

  // Derive authoritative stack directly from actual snapshot
  const techAnalysis = analyzeAuthoritativeTechStack(validFiles);

  // Process all files for deep features and endpoints
  for (const file of validFiles) {
    const rawPath = file.normalizedPath;
    const content = file.content || '';
    const lowerPath = rawPath.toLowerCase();

    // Config files
    if (lowerPath.includes('.env') || lowerPath.endsWith('config.json') || lowerPath.endsWith('settings.py')) {
      configLocsSet.add(rawPath);
    }

    // Package manager & dependency parsing
    if (lowerPath.endsWith('package.json')) {
      packageManager = 'npm/yarn/bun';
      try {
        const pkg = JSON.parse(content);
        const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
        for (const dep of Object.keys(allDeps)) {
          dependenciesSet.add(dep);
          if (['pg', 'postgres', 'mysql', 'mysql2', 'sqlite3', 'better-sqlite3', 'typeorm', 'prisma', 'drizzle-orm', 'mongoose'].includes(dep)) {
            if (dep.includes('pg') || dep.includes('postgres')) dbTechSet.add('PostgreSQL');
            if (dep.includes('sqlite')) dbTechSet.add('SQLite');
            if (dep.includes('mysql')) dbTechSet.add('MySQL');
            if (dep.includes('mongoose') || dep.includes('mongodb')) dbTechSet.add('MongoDB');
            if (dep === 'prisma' || dep === 'drizzle-orm' || dep === 'typeorm') dbTechSet.add(`ORM (${dep})`);
          }
          if (dep === 'jsonwebtoken' || dep === 'jose') {
            hasJwt = true;
            authMechSet.add('JSON Web Token (JWT)');
          }
          if (dep === 'express-session' || dep === 'cookie-session') {
            hasSessions = true;
            authMechSet.add('Server-side Sessions');
          }
          if (dep === 'cookie-parser') {
            hasCookies = true;
          }
          if (dep === 'multer' || dep === 'express-fileupload' || dep === 'formidable') {
            hasFileUpload = true;
          }
          if (['axios', 'node-fetch', 'got', 'request', 'superagent'].includes(dep)) {
            hasExternalRequests = true;
          }
          if (['ejs', 'pug', 'handlebars', 'mustache'].includes(dep)) {
            hasTemplates = true;
            templateEngine = dep;
          }
          if (dep.includes('graphql') || dep === 'apollo-server' || dep === '@apollo/server') {
            hasGraphql = true;
          }
          if (dep === 'socket.io' || dep === 'ws') {
            hasWebsockets = true;
          }
        }
      } catch {
        // partial parse fallback
      }
    }

    if (lowerPath.endsWith('requirements.txt') || lowerPath.endsWith('pipfile')) {
      packageManager = 'pip';
      const lines = content.split('\n');
      for (const line of lines) {
        const dep = line.split('==')[0].split('>=')[0].split('<=')[0].trim().toLowerCase();
        if (!dep || dep.startsWith('#')) continue;
        dependenciesSet.add(dep);
        if (dep === 'sqlalchemy' || dep === 'psycopg2' || dep === 'psycopg2-binary' || dep === 'psycopg' || dep === 'asyncpg') dbTechSet.add('PostgreSQL / SQLAlchemy');
        if (dep === 'sqlite3') dbTechSet.add('SQLite');
        if (dep === 'pymongo' || dep === 'motor') dbTechSet.add('MongoDB');
        if (dep === 'pyjwt' || dep === 'authlib') {
          hasJwt = true;
          authMechSet.add('JWT (PyJWT/Authlib)');
        }
        if (dep === 'flask-login' || dep === 'django.contrib.auth') {
          hasSessions = true;
          authMechSet.add('Session Authentication');
        }
        if (dep === 'requests' || dep === 'httpx' || dep === 'urllib3' || dep === 'aiohttp') {
          hasExternalRequests = true;
        }
        if (dep === 'jinja2') {
          hasTemplates = true;
          templateEngine = 'Jinja2';
        }
      }
    }

    if (lowerPath.endsWith('go.mod')) {
      packageManager = 'go modules';
      if (content.includes('gorm.io/gorm')) dbTechSet.add('GORM');
      if (content.includes('github.com/golang-jwt/jwt')) {
        hasJwt = true;
        authMechSet.add('JWT');
      }
    }

    // Code level analysis
    if (content) {
      // Endpoint mapping for Express (ONLY if Express or JS/TS is detected)
      if (techAnalysis.stack_flags.has_express || (techAnalysis.stack_flags.has_node_runtime && !techAnalysis.stack_flags.has_python)) {
        const expressRouteRegex = /(?:app|router)\.(get|post|put|delete|patch)\(\s*['"`]([^'"`]+)['"`]/gi;
        let match;
        while ((match = expressRouteRegex.exec(content)) !== null) {
          const method = match[1].toUpperCase();
          const routePath = match[2];
          const isAuth = content.slice(match.index, match.index + 200).includes('auth') ||
                         content.slice(match.index, match.index + 200).includes('verify') ||
                         content.slice(match.index, match.index + 200).includes('protect');
          const params: string[] = [];
          if (routePath.includes(':')) {
            const parts = routePath.split('/');
            for (const p of parts) {
              if (p.startsWith(':')) params.push(p.slice(1));
            }
          }
          endpoints.push({
            path: routePath,
            method,
            auth_required: isAuth,
            parameters: params,
          });
          if (routePath.includes('admin') || routePath.includes('internal')) {
            hasAdminRoutes = true;
          }
        }
      }

      // Python route mapping (FastAPI / Flask / Django)
      if (techAnalysis.stack_flags.has_python) {
        const pythonRouteRegex = /@(?:app|api|router|api_router)\.(get|post|put|delete|patch|route)\(\s*['"`]([^'"`]+)['"`]/gi;
        let match;
        while ((match = pythonRouteRegex.exec(content)) !== null) {
          const method = match[1].toUpperCase() === 'ROUTE' ? 'GET' : match[1].toUpperCase();
          const routePath = match[2];
          endpoints.push({
            path: routePath,
            method,
            auth_required: content.slice(Math.max(0, match.index - 100), match.index).includes('@login_required') ||
                           content.slice(Math.max(0, match.index - 100), match.index).includes('@auth') ||
                           content.slice(match.index, match.index + 150).includes('Depends('),
            parameters: routePath.includes('{') || routePath.includes('<') ? ['param'] : [],
          });
          if (routePath.includes('admin') || routePath.includes('manage')) {
            hasAdminRoutes = true;
          }
        }
      }

      // Input sources detection
      if (content.includes('req.query') || content.includes('request.args') || content.includes('req.params')) {
        inputSourcesSet.add('URL Query & Path Parameters');
      }
      if (content.includes('req.body') || content.includes('request.json') || content.includes('request.get_json') || content.includes('body:')) {
        inputSourcesSet.add('JSON & Request Body Payloads');
      }
      if (content.includes('req.headers') || content.includes('request.headers') || content.includes('Header(')) {
        inputSourcesSet.add('HTTP Headers (Authorization, Cookie, Custom)');
      }
      if (content.includes('req.file') || content.includes('req.files') || content.includes('request.files') || content.includes('UploadFile')) {
        inputSourcesSet.add('Multipart File Uploads');
        hasFileUpload = true;
      }

      // Output locations
      if (content.includes('res.json(') || content.includes('jsonify(') || content.includes('Response(') || content.includes('return {')) {
        outputLocsSet.add('REST JSON API Responses');
      }
      if (content.includes('res.render(') || content.includes('render_template(')) {
        outputLocsSet.add('HTML Template Views');
        hasTemplates = true;
      }
      if (content.includes('res.redirect(') || content.includes('redirect(')) {
        outputLocsSet.add('HTTP Redirects (Location Header)');
      }

      // Sinks and capabilities indicators
      if (
        content.includes('child_process.exec') ||
        content.includes('child_process.spawn') ||
        content.includes('os.system') ||
        content.includes('subprocess.Popen') ||
        content.includes('subprocess.run')
      ) {
        hasCommandExec = true;
      }

      if (
        content.includes('pickle.loads') ||
        content.includes('yaml.load(') ||
        content.includes('unserialize(') ||
        content.includes('serialize-javascript')
      ) {
        hasDeserialization = true;
      }

      if (
        (content.includes('db.query(') || content.includes('cursor.execute(') || content.includes('SELECT ') || content.includes('INSERT INTO ')) &&
        (content.includes('${') || content.includes('f"') || content.includes('f\'') || content.includes('+ req.') || content.includes('+ request.'))
      ) {
        hasRawSql = true;
      }

      // Auth / Authz detection
      if (content.includes('role') || content.includes('isAdmin') || content.includes('permission') || content.includes('is_admin')) {
        authzMechSet.add('Role-Based Access Control (RBAC)');
      }
      if (content.includes('organization_id') || content.includes('orgId') || content.includes('tenant_id') || content.includes('tenantId')) {
        authzMechSet.add('Multi-Tenant Data Isolation');
      }

      // Sensitive resources
      if (content.includes('password') || content.includes('hashPassword') || content.includes('bcrypt') || content.includes('argon2')) {
        sensitiveResourcesSet.add('User Authentication & Passwords');
      }
      if (content.includes('stripe') || content.includes('payment') || content.includes('billing') || content.includes('invoice')) {
        sensitiveResourcesSet.add('Billing & Payment Gateways');
      }
      if (content.includes('apiKey') || content.includes('api_key') || content.includes('secret') || content.includes('token')) {
        sensitiveResourcesSet.add('API Keys & Service Secrets');
      }
    }
  }

  // Derive final authoritative languages and frameworks
  let authoritativeLanguages: string[] = [];
  let authoritativeFrameworks: string[] = [];

  if (validFiles.length > 0) {
    authoritativeLanguages = techAnalysis.detected_languages.map((l) => l.name);
    authoritativeFrameworks = techAnalysis.detected_frameworks.map((f) => f.name);

    if (authoritativeLanguages.length === 0) {
      authoritativeLanguages = ['Source Code (Unclassified)'];
    }
    if (authoritativeFrameworks.length === 0) {
      authoritativeFrameworks = [`${authoritativeLanguages[0]} Application`];
    }
  } else {
    // Pure Black Box URL scan (0 uploaded files)
    authoritativeLanguages = ['Web Application (Remote Target)'];
    authoritativeFrameworks = ['HTTP Web Service'];
  }

  const primaryLang = authoritativeLanguages[0] || 'Web Application';
  const primaryFramework = authoritativeFrameworks[0] || 'HTTP Web Service';

  if (authMechSet.size === 0) {
    authMechSet.add(validFiles.length > 0 ? 'Application Authentication' : 'Bearer Token / Session Cookie');
  }

  if (authzMechSet.size === 0) {
    authzMechSet.add('User Session Boundary');
  }

  if (inputSourcesSet.size === 0) {
    inputSourcesSet.add('HTTP Parameters & Request Bodies');
  }

  if (outputLocsSet.size === 0) {
    outputLocsSet.add('HTTP Responses');
  }

  const totalObservations =
    authoritativeLanguages.length +
    authoritativeFrameworks.length +
    dependenciesSet.size +
    dbTechSet.size +
    authMechSet.size +
    authzMechSet.size +
    endpoints.length +
    sensitiveResourcesSet.size;

  return {
    language: primaryLang,
    languages: authoritativeLanguages,
    framework: primaryFramework,
    frameworks: authoritativeFrameworks,
    package_manager: packageManager,
    dependencies: Array.from(dependenciesSet),
    database_technologies: Array.from(dbTechSet),
    authentication_mechanisms: Array.from(authMechSet),
    authorization_mechanisms: Array.from(authzMechSet),
    routes_count: endpoints.length,
    api_endpoints: endpoints,
    input_sources: Array.from(inputSourcesSet),
    output_locations: Array.from(outputLocsSet),
    has_file_upload: hasFileUpload,
    has_external_requests: hasExternalRequests,
    has_templates: hasTemplates,
    template_engine: templateEngine,
    has_sessions: hasSessions,
    has_jwt: hasJwt,
    has_cookies: hasCookies,
    has_admin_routes: hasAdminRoutes,
    has_graphql: hasGraphql,
    has_websockets: hasWebsockets,
    has_raw_sql_queries: hasRawSql,
    has_deserialization: hasDeserialization,
    has_command_execution: hasCommandExec,
    architecture: `${primaryLang} ${primaryFramework} Architecture`,
    sensitive_resources: Array.from(sensitiveResourcesSet),
    configuration_locations: Array.from(configLocsSet),
    observations_count: totalObservations,
    detected_technologies: techAnalysis.detected_technologies,
    undetected_technologies: techAnalysis.undetected_technologies,
    language_breakdown: techAnalysis.language_breakdown,
    extension_breakdown: techAnalysis.extension_breakdown,
    stack_flags: techAnalysis.stack_flags,
  };
}
