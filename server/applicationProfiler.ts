import { TechnologyEvidenceItem } from '../src/types.js';
import { analyzeAuthoritativeTechStack, normalizePath, isIgnoredPath } from './fingerprintService.js';

export interface SourceFileItem {
  path?: string;
  name?: string;
  content?: string;
}

export interface ApplicationProfileResult {
  language: string;
  languages: string[];
  framework: string;
  frameworks: string[];
  package_manager?: string;
  dependencies: string[];
  database_technologies: string[];
  authentication_mechanisms: string[];
  authorization_mechanisms: string[];
  routes_count: number;
  api_endpoints: Array<{
    path: string;
    method: string;
    auth_required: boolean;
    parameters: string[];
  }>;
  input_sources: string[];
  output_locations: string[];
  has_file_upload: boolean;
  has_external_requests: boolean;
  has_templates: boolean;
  template_engine?: string;
  has_sessions: boolean;
  has_jwt: boolean;
  has_cookies: boolean;
  has_admin_routes: boolean;
  has_graphql: boolean;
  has_websockets: boolean;
  has_raw_sql_queries: boolean;
  has_deserialization: boolean;
  has_command_execution: boolean;
  architecture: string;
  sensitive_resources: string[];
  configuration_locations: string[];
  observations_count: number;
  detected_technologies?: TechnologyEvidenceItem[];
  undetected_technologies?: TechnologyEvidenceItem[];
  language_breakdown?: Record<string, number>;
  extension_breakdown?: Record<string, number>;
  stack_flags?: any;
}

export function profileApplication(
  files: SourceFileItem[],
  target: string,
  mode: string
): ApplicationProfileResult {
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

  const validFiles: Array<{ normalizedPath: string; content: string; size: number }> = [];
  for (const file of files || []) {
    const rawPath = file.path || file.name || '';
    const norm = normalizePath(rawPath);
    if (!isIgnoredPath(norm)) {
      validFiles.push({
        normalizedPath: norm,
        content: file.content || '',
        size: (file.content || '').length,
      });
    }
  }

  const techAnalysis = analyzeAuthoritativeTechStack(validFiles);

  for (const file of validFiles) {
    const rawPath = file.normalizedPath;
    const content = file.content || '';
    const lowerPath = rawPath.toLowerCase();

    if (lowerPath.includes('.env') || lowerPath.endsWith('config.json') || lowerPath.endsWith('settings.py')) {
      configLocsSet.add(rawPath);
    }

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
          if (dep === 'multer' || dep === 'express-fileupload') {
            hasFileUpload = true;
          }
          if (['axios', 'node-fetch', 'got'].includes(dep)) {
            hasExternalRequests = true;
          }
          if (dep.includes('graphql') || dep === 'apollo-server') {
            hasGraphql = true;
          }
        }
      } catch {}
    }

    if (lowerPath.endsWith('requirements.txt') || lowerPath.endsWith('pipfile')) {
      packageManager = 'pip';
      const lines = content.split('\n');
      for (const line of lines) {
        const dep = line.split('==')[0].split('>=')[0].split('<=')[0].trim().toLowerCase();
        if (!dep || dep.startsWith('#')) continue;
        dependenciesSet.add(dep);
        if (dep === 'sqlalchemy' || dep === 'psycopg2' || dep === 'psycopg2-binary' || dep === 'asyncpg') dbTechSet.add('PostgreSQL / SQLAlchemy');
        if (dep === 'pyjwt') {
          hasJwt = true;
          authMechSet.add('PyJWT');
        }
        if (dep === 'requests' || dep === 'httpx') {
          hasExternalRequests = true;
        }
      }
    }

    if (content) {
      if (techAnalysis.stack_flags.has_express || (techAnalysis.stack_flags.has_node_runtime && !techAnalysis.stack_flags.has_python)) {
        const expressRouteRegex = /(?:app|router)\.(get|post|put|delete|patch)\(\s*['"`]([^'"`]+)['"`]/gi;
        let match;
        while ((match = expressRouteRegex.exec(content)) !== null) {
          const method = match[1].toUpperCase();
          const routePath = match[2];
          endpoints.push({
            path: routePath,
            method,
            auth_required: content.slice(match.index, match.index + 150).includes('auth'),
            parameters: routePath.includes(':') ? ['param'] : [],
          });
          if (routePath.includes('admin')) hasAdminRoutes = true;
        }
      }

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
          if (routePath.includes('admin') || routePath.includes('manage')) hasAdminRoutes = true;
        }
      }

      if (content.includes('req.query') || content.includes('req.params') || content.includes('request.args')) inputSourcesSet.add('URL Parameters');
      if (content.includes('req.body') || content.includes('request.json') || content.includes('request.form') || content.includes('body:')) inputSourcesSet.add('JSON Request Body');
      if (content.includes('req.file') || content.includes('req.files') || content.includes('request.files') || content.includes('multer') || content.includes('.save(')) hasFileUpload = true;
      if (content.includes('jwt') || content.includes('jsonwebtoken') || content.includes('jwt.sign') || content.includes('jwt.verify') || content.includes('pyjwt')) {
        hasJwt = true;
        authMechSet.add('JSON Web Token (JWT)');
      }
      if (content.includes('child_process.exec') || content.includes('os.system') || content.includes('subprocess.')) hasCommandExec = true;
      if (content.includes('yaml.load(') || content.includes('pickle.loads')) hasDeserialization = true;
      if (
        (content.includes('db.query(') || content.includes('SELECT ')) &&
        (content.includes('${') || content.includes('f"') || content.includes('+ req.'))
      ) {
        hasRawSql = true;
      }
    }
  }

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
    authoritativeLanguages = ['Web Application (Remote Target)'];
    authoritativeFrameworks = ['HTTP Web Service'];
  }

  const primaryLang = authoritativeLanguages[0] || 'Web Application';
  const primaryFramework = authoritativeFrameworks[0] || 'HTTP Web Service';

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
    architecture: `${primaryLang} ${primaryFramework}`,
    sensitive_resources: Array.from(sensitiveResourcesSet),
    configuration_locations: Array.from(configLocsSet),
    observations_count: endpoints.length + dependenciesSet.size + authoritativeLanguages.length + authoritativeFrameworks.length,
    detected_technologies: techAnalysis.detected_technologies,
    undetected_technologies: techAnalysis.undetected_technologies,
    language_breakdown: techAnalysis.language_breakdown,
    extension_breakdown: techAnalysis.extension_breakdown,
    stack_flags: techAnalysis.stack_flags,
  };
}
