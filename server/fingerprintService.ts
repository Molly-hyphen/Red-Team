import crypto from 'crypto';
import { TechnologyEvidenceItem } from '../src/types.js';

const IGNORE_PATTERNS = [
  /^node_modules\//i,
  /^\.git\//i,
  /^\.github\//i,
  /^dist\//i,
  /^build\//i,
  /^out\//i,
  /^\.next\//i,
  /^coverage\//i,
  /^__pycache__\//i,
  /^\.pytest_cache\//i,
  /\.DS_Store$/i,
  /Thumbs\.db$/i,
  /\.pyc$/i,
  /\.pyo$/i,
  /\.lock$/i,
  /package-lock\.json$/i,
  /yarn\.lock$/i,
  /bun\.lock$/i,
  /pnpm-lock\.yaml$/i,
  /\.map$/i,
  /\.log$/i,
  /^tmp\//i,
  /^temp\//i,
];

export function normalizePath(filePath: string): string {
  return filePath
    .replace(/\\/g, '/')
    .replace(/^\.\//, '')
    .replace(/^\//, '')
    .trim();
}

export function isIgnoredPath(filePath: string): boolean {
  const norm = normalizePath(filePath);
  return IGNORE_PATTERNS.some((pattern) => pattern.test(norm));
}

export interface FileItem {
  path?: string;
  name?: string;
  content?: string;
  size?: number;
}

export function analyzeAuthoritativeTechStack(
  validFiles: Array<{ normalizedPath: string; content: string; size: number }>
) {
  const extensionCounts: Record<string, number> = {};
  const languageCounts: Record<string, number> = {};

  const detectedLanguages: TechnologyEvidenceItem[] = [];
  const detectedFrameworks: TechnologyEvidenceItem[] = [];
  const detectedTechnologies: TechnologyEvidenceItem[] = [];
  const undetectedTechnologies: TechnologyEvidenceItem[] = [];

  let packageJsonDepNames: string[] = [];
  let pythonDepNames: string[] = [];
  let goDepNames: string[] = [];
  let hasTsConfig = false;
  let hasPyproject = false;
  let hasRequirements = false;
  let hasPackageJson = false;

  for (const f of validFiles) {
    const p = f.normalizedPath;
    const lowerP = p.toLowerCase();
    const ext = lowerP.split('.').pop() || '';
    if (ext) {
      extensionCounts[ext] = (extensionCounts[ext] || 0) + 1;
    }

    if (lowerP.endsWith('tsconfig.json')) hasTsConfig = true;
    if (lowerP.endsWith('pyproject.toml') || lowerP.endsWith('pipfile') || lowerP.endsWith('setup.py')) hasPyproject = true;
    if (lowerP.endsWith('requirements.txt')) hasRequirements = true;
    if (lowerP.endsWith('package.json')) {
      hasPackageJson = true;
      try {
        const parsed = JSON.parse(f.content || '{}');
        const deps = { ...parsed.dependencies, ...parsed.devDependencies };
        packageJsonDepNames = Object.keys(deps).map((d) => d.toLowerCase());
      } catch {
        // partial parse
      }
    }

    if (lowerP.endsWith('requirements.txt') || lowerP.endsWith('pipfile')) {
      const lines = (f.content || '').split('\n');
      for (const line of lines) {
        const dep = line.split('==')[0].split('>=')[0].split('<=')[0].trim().toLowerCase();
        if (dep && !dep.startsWith('#')) {
          pythonDepNames.push(dep);
        }
      }
    }

    if (lowerP.endsWith('go.mod')) {
      const lines = (f.content || '').split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.startsWith('require') || trimmed.includes('/')) {
          goDepNames.push(trimmed.toLowerCase());
        }
      }
    }
  }

  const tsCount = (extensionCounts['ts'] || 0) + (extensionCounts['tsx'] || 0);
  const jsCount =
    (extensionCounts['js'] || 0) +
    (extensionCounts['jsx'] || 0) +
    (extensionCounts['mjs'] || 0) +
    (extensionCounts['cjs'] || 0);
  const pyCount = (extensionCounts['py'] || 0) + (extensionCounts['pyw'] || 0);
  const goCount = extensionCounts['go'] || 0;
  const javaCount = (extensionCounts['java'] || 0) + (extensionCounts['jar'] || 0);
  const phpCount = extensionCounts['php'] || 0;
  const rbCount = extensionCounts['rb'] || 0;
  const rsCount = extensionCounts['rs'] || 0;
  const csCount = extensionCounts['cs'] || 0;

  if (tsCount > 0) languageCounts['TypeScript'] = tsCount;
  if (jsCount > 0) languageCounts['JavaScript'] = jsCount;
  if (pyCount > 0) languageCounts['Python'] = pyCount;
  if (goCount > 0) languageCounts['Go'] = goCount;
  if (javaCount > 0) languageCounts['Java'] = javaCount;
  if (phpCount > 0) languageCounts['PHP'] = phpCount;
  if (rbCount > 0) languageCounts['Ruby'] = rbCount;
  if (rsCount > 0) languageCounts['Rust'] = rsCount;
  if (csCount > 0) languageCounts['C#'] = csCount;

  // 1. Python Language & Frameworks
  if (pyCount > 0) {
    const pyEvidence = [`${pyCount} .py source file(s) present in project snapshot`];
    if (hasRequirements) pyEvidence.push('requirements.txt manifest present');
    if (hasPyproject) pyEvidence.push('Python package manifest (pyproject.toml/setup.py) present');

    detectedLanguages.push({
      name: 'Python',
      category: 'language',
      detected: true,
      file_count: pyCount,
      evidence: pyEvidence,
      confidence: 1.0,
    });

    const hasFastApiDep = pythonDepNames.some((d) => d.includes('fastapi'));
    const hasFastApiImport = validFiles.some((f) => (f.content || '').includes('from fastapi') || (f.content || '').includes('import fastapi') || (f.content || '').includes('FastAPI('));
    if (hasFastApiDep || hasFastApiImport) {
      detectedFrameworks.push({
        name: 'FastAPI',
        category: 'framework',
        detected: true,
        evidence: [
          hasFastApiDep ? 'FastAPI declared in Python dependencies' : '',
          hasFastApiImport ? 'FastAPI application instance/routes found in Python source' : '',
        ].filter(Boolean),
        confidence: 1.0,
      });
    }

    const hasFlaskDep = pythonDepNames.some((d) => d.includes('flask'));
    const hasFlaskImport = validFiles.some((f) => (f.content || '').includes('from flask') || (f.content || '').includes('import flask') || (f.content || '').includes('Flask(__name__)'));
    if (hasFlaskDep || hasFlaskImport) {
      detectedFrameworks.push({
        name: 'Flask',
        category: 'framework',
        detected: true,
        evidence: [
          hasFlaskDep ? 'Flask declared in Python dependencies' : '',
          hasFlaskImport ? 'Flask application instance/routes found in Python source' : '',
        ].filter(Boolean),
        confidence: 1.0,
      });
    }

    const hasDjangoDep = pythonDepNames.some((d) => d.includes('django'));
    const hasDjangoImport = validFiles.some((f) => (f.content || '').includes('import django') || (f.content || '').includes('from django'));
    if (hasDjangoDep || hasDjangoImport) {
      detectedFrameworks.push({
        name: 'Django',
        category: 'framework',
        detected: true,
        evidence: [
          hasDjangoDep ? 'Django declared in Python dependencies' : '',
          hasDjangoImport ? 'Django settings or modules found in Python source' : '',
        ].filter(Boolean),
        confidence: 1.0,
      });
    }
  } else {
    undetectedTechnologies.push({
      name: 'Python',
      category: 'language',
      detected: false,
      file_count: 0,
      evidence: [],
      confidence: 1.0,
      rejection_reason: '0 .py/.pyw files present in scanned snapshot (Zero-File Rule applied)',
    });
  }

  // 2. TypeScript Language
  if (tsCount > 0) {
    const tsEvidence = [`${tsCount} .ts/.tsx source file(s) present in project snapshot`];
    if (hasTsConfig) tsEvidence.push('tsconfig.json configuration present');
    if (packageJsonDepNames.includes('typescript')) tsEvidence.push('TypeScript listed in package.json dependencies');

    detectedLanguages.push({
      name: 'TypeScript',
      category: 'language',
      detected: true,
      file_count: tsCount,
      evidence: tsEvidence,
      confidence: 1.0,
    });
  } else {
    undetectedTechnologies.push({
      name: 'TypeScript',
      category: 'language',
      detected: false,
      file_count: 0,
      evidence: [],
      confidence: 1.0,
      rejection_reason: '0 .ts/.tsx files and 0 tsconfig.json found in project snapshot (Zero-File Rule applied)',
    });
  }

  // 3. JavaScript / Node.js
  if (jsCount > 0 || hasPackageJson) {
    const jsEvidence = [];
    if (jsCount > 0) jsEvidence.push(`${jsCount} .js/.jsx/.mjs/.cjs source file(s) present`);
    if (hasPackageJson) jsEvidence.push('package.json manifest present');

    detectedLanguages.push({
      name: 'JavaScript',
      category: 'language',
      detected: true,
      file_count: jsCount,
      evidence: jsEvidence,
      confidence: 1.0,
    });

    detectedTechnologies.push({
      name: 'Node.js',
      category: 'package_manager',
      detected: true,
      evidence: jsEvidence,
      confidence: 0.95,
    });
  } else {
    undetectedTechnologies.push({
      name: 'JavaScript / Node.js',
      category: 'language',
      detected: false,
      file_count: 0,
      evidence: [],
      confidence: 1.0,
      rejection_reason: '0 .js files and 0 package.json found in project snapshot (Zero-File Rule applied)',
    });
  }

  // 4. Express.js Framework
  const hasExpressDep = packageJsonDepNames.includes('express');
  const hasExpressImport = validFiles.some(
    (f) =>
      (f.content || '').includes("require('express')") ||
      (f.content || '').includes('require("express")') ||
      (f.content || '').includes("from 'express'") ||
      (f.content || '').includes('from "express"')
  );

  if (hasExpressDep || hasExpressImport) {
    detectedFrameworks.push({
      name: 'Express.js',
      category: 'framework',
      detected: true,
      evidence: [
        hasExpressDep ? 'express declared in package.json' : '',
        hasExpressImport ? 'Express import and router handlers found in JavaScript/TypeScript source' : '',
      ].filter(Boolean),
      confidence: 1.0,
    });
  } else {
    undetectedTechnologies.push({
      name: 'Express.js',
      category: 'framework',
      detected: false,
      file_count: 0,
      evidence: [],
      confidence: 1.0,
      rejection_reason: 'No express dependency in package.json and 0 Express import/router references found',
    });
  }

  // 5. Go Language & Frameworks
  if (goCount > 0) {
    detectedLanguages.push({
      name: 'Go',
      category: 'language',
      detected: true,
      file_count: goCount,
      evidence: [`${goCount} .go source file(s) found in project snapshot`],
      confidence: 1.0,
    });

    const hasGin = goDepNames.some((d) => d.includes('gin-gonic/gin')) || validFiles.some((f) => (f.content || '').includes('github.com/gin-gonic/gin'));
    if (hasGin) {
      detectedFrameworks.push({
        name: 'Gin',
        category: 'framework',
        detected: true,
        evidence: ['Gin web framework imported in Go source or go.mod'],
        confidence: 1.0,
      });
    }

    const hasFiber = goDepNames.some((d) => d.includes('gofiber/fiber')) || validFiles.some((f) => (f.content || '').includes('github.com/gofiber/fiber'));
    if (hasFiber) {
      detectedFrameworks.push({
        name: 'Fiber',
        category: 'framework',
        detected: true,
        evidence: ['Fiber web framework imported in Go source or go.mod'],
        confidence: 1.0,
      });
    }
  }

  // 6. Java Language & Frameworks
  if (javaCount > 0) {
    detectedLanguages.push({
      name: 'Java',
      category: 'language',
      detected: true,
      file_count: javaCount,
      evidence: [`${javaCount} Java source file(s) found in project snapshot`],
      confidence: 1.0,
    });

    const hasSpring = validFiles.some((f) => (f.content || '').includes('org.springframework') || (f.content || '').includes('@RestController') || (f.content || '').includes('@SpringBootApplication'));
    if (hasSpring) {
      detectedFrameworks.push({
        name: 'Spring Boot',
        category: 'framework',
        detected: true,
        evidence: ['Spring Boot annotations and framework imports found in Java source'],
        confidence: 1.0,
      });
    }
  }

  for (const lang of detectedLanguages) {
    if (!detectedTechnologies.some((t) => t.name === lang.name)) {
      detectedTechnologies.push(lang);
    }
  }
  for (const fw of detectedFrameworks) {
    if (!detectedTechnologies.some((t) => t.name === fw.name)) {
      detectedTechnologies.push(fw);
    }
  }

  const stack_flags = {
    has_typescript: tsCount > 0,
    has_javascript: jsCount > 0 || hasPackageJson,
    has_python: pyCount > 0,
    has_go: goCount > 0,
    has_java: javaCount > 0,
    has_php: phpCount > 0,
    has_ruby: rbCount > 0,
    has_rust: rsCount > 0,
    has_csharp: csCount > 0,
    has_express: hasExpressDep || hasExpressImport,
    has_fastapi: detectedFrameworks.some((f) => f.name === 'FastAPI'),
    has_flask: detectedFrameworks.some((f) => f.name === 'Flask'),
    has_django: detectedFrameworks.some((f) => f.name === 'Django'),
    has_nextjs: packageJsonDepNames.includes('next') || validFiles.some((f) => (f.content || '').includes('next/router')),
    has_nestjs: packageJsonDepNames.some((d) => d.includes('@nestjs')) || validFiles.some((f) => (f.content || '').includes('@nestjs/core')),
    has_gin: detectedFrameworks.some((f) => f.name === 'Gin'),
    has_fiber: detectedFrameworks.some((f) => f.name === 'Fiber'),
    has_spring: detectedFrameworks.some((f) => f.name === 'Spring Boot'),
    has_node_runtime: jsCount > 0 || tsCount > 0 || hasPackageJson,
  };

  return {
    extension_breakdown: extensionCounts,
    language_breakdown: languageCounts,
    detected_languages: detectedLanguages,
    detected_frameworks: detectedFrameworks,
    detected_technologies: detectedTechnologies,
    undetected_technologies: undetectedTechnologies,
    stack_flags,
  };
}

export function computeProjectHash(
  files: FileItem[],
  fallbackTarget?: string,
  mode?: string
): {
  project_hash: string;
  normalized_files_count: number;
  included_files: string[];
  ignored_files: string[];
  total_bytes: number;
  extension_breakdown: Record<string, number>;
  language_breakdown: Record<string, number>;
  detected_languages: TechnologyEvidenceItem[];
  detected_frameworks: TechnologyEvidenceItem[];
  detected_technologies: TechnologyEvidenceItem[];
  undetected_technologies: TechnologyEvidenceItem[];
  stack_flags: any;
} {
  const included_files: string[] = [];
  const ignored_files: string[] = [];
  const validFiles: Array<{ normalizedPath: string; content: string; size: number }> = [];

  for (const file of files || []) {
    const rawPath = file.path || file.name || 'unnamed';
    const norm = normalizePath(rawPath);
    if (isIgnoredPath(norm)) {
      ignored_files.push(norm);
      continue;
    }
    included_files.push(norm);
    const content = file.content || '';
    validFiles.push({
      normalizedPath: norm,
      content,
      size: typeof file.size === 'number' ? file.size : Buffer.byteLength(content, 'utf8'),
    });
  }

  validFiles.sort((a, b) => a.normalizedPath.localeCompare(b.normalizedPath));

  const hash = crypto.createHash('sha256');
  let totalBytes = 0;

  if (validFiles.length > 0) {
    for (const f of validFiles) {
      totalBytes += f.size;
      hash.update(`${f.normalizedPath}\0${f.content}\n`, 'utf8');
    }
  } else {
    const targetPayload = `target_url:${normalizePath(fallbackTarget || 'default')}\0mode:${mode || 'black_box'}\n`;
    totalBytes = Buffer.byteLength(targetPayload, 'utf8');
    hash.update(targetPayload, 'utf8');
    included_files.push(fallbackTarget || 'default');
  }

  const project_hash = hash.digest('hex');
  const techAnalysis = analyzeAuthoritativeTechStack(validFiles);

  return {
    project_hash,
    normalized_files_count: validFiles.length,
    included_files: included_files.sort(),
    ignored_files: ignored_files.sort(),
    total_bytes: totalBytes,
    extension_breakdown: techAnalysis.extension_breakdown,
    language_breakdown: techAnalysis.language_breakdown,
    detected_languages: techAnalysis.detected_languages,
    detected_frameworks: techAnalysis.detected_frameworks,
    detected_technologies: techAnalysis.detected_technologies,
    undetected_technologies: techAnalysis.undetected_technologies,
    stack_flags: techAnalysis.stack_flags,
  };
}
