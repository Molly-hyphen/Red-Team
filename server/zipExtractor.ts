import JSZip from 'jszip';
import { SourceFile } from '../src/types.js';

export interface ExtractedArchiveResult {
  isArchive: boolean;
  archiveName: string;
  files: SourceFile[];
  totalExtractedFiles: number;
  totalLines: number;
  detectedLanguages: string[];
  skippedBinaryCount: number;
  archiveSummary: string;
}

const IGNORED_PATH_PREFIXES = [
  '__macosx/',
  '.git/',
  '.github/',
  '.vscode/',
  '.idea/',
  'node_modules/',
  '.next/',
  'dist/',
  'build/',
  'out/',
  'coverage/',
  '__pycache__/',
  '.pytest_cache/',
  '.mypy_cache/',
];

const IGNORED_FILENAMES = [
  '.ds_store',
  'thumbs.db',
  'desktop.ini',
];

const BINARY_EXTENSIONS = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'ico', 'webp', 'bmp', 'tiff',
  'woff', 'woff2', 'ttf', 'eot', 'otf',
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
  'zip', 'tar', 'gz', 'bz2', '7z', 'rar', 'xz', 'bin', 'iso', 'exe', 'dll', 'so', 'dylib',
  'mp3', 'mp4', 'wav', 'mov', 'avi', 'mkv', 'flac', 'ogg',
  'pyc', 'pyo', 'pyd', 'class', 'o', 'obj', 'a', 'lib'
]);

export function getFileLanguage(fileName: string): string {
  const lower = fileName.toLowerCase();
  const ext = lower.split('.').pop() || '';
  const baseName = lower.split('/').pop() || '';

  if (baseName === 'dockerfile' || baseName.startsWith('dockerfile.')) return 'Dockerfile';
  if (baseName === 'makefile') return 'Makefile';
  if (baseName.startsWith('.env')) return 'Environment Variables';
  if (baseName === 'requirements.txt' || baseName === 'pipfile') return 'Python Dependencies';
  if (baseName === 'package.json') return 'Node.js Package Manifest';
  if (baseName === 'go.mod' || baseName === 'go.sum') return 'Go Module';
  if (baseName === 'cargo.toml') return 'Rust Cargo Manifest';
  if (baseName === 'pom.xml') return 'Maven POM';

  switch (ext) {
    case 'ts':
      return 'TypeScript';
    case 'tsx':
      return 'TypeScript (React)';
    case 'js':
    case 'mjs':
    case 'cjs':
      return 'JavaScript';
    case 'jsx':
      return 'JavaScript (React)';
    case 'py':
    case 'pyw':
      return 'Python';
    case 'go':
      return 'Go';
    case 'java':
      return 'Java';
    case 'rb':
      return 'Ruby';
    case 'php':
      return 'PHP';
    case 'rs':
      return 'Rust';
    case 'cs':
      return 'C#';
    case 'c':
    case 'h':
      return 'C';
    case 'cpp':
    case 'hpp':
    case 'cc':
    case 'cxx':
      return 'C++';
    case 'sql':
      return 'SQL';
    case 'json':
      return 'JSON';
    case 'yml':
    case 'yaml':
      return 'YAML';
    case 'toml':
      return 'TOML';
    case 'xml':
      return 'XML';
    case 'html':
    case 'htm':
      return 'HTML';
    case 'css':
    case 'scss':
    case 'sass':
    case 'less':
      return 'CSS';
    case 'sh':
    case 'bash':
    case 'zsh':
      return 'Shell Script';
    case 'md':
    case 'markdown':
      return 'Markdown';
    default:
      return 'Source Code';
  }
}

export function isZipBufferOrName(name: string, buffer?: Buffer | ArrayBuffer | Uint8Array | string): boolean {
  if (name.toLowerCase().endsWith('.zip')) return true;
  if (buffer) {
    if (typeof buffer === 'string') {
      if (buffer.startsWith('data:application/zip;base64,') || buffer.startsWith('UEsDB')) {
        return true;
      }
    } else {
      const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer || buffer);
      if (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04) {
        return true;
      }
    }
  }
  return false;
}

export async function extractZipArchiveServer(
  archiveData: Buffer | ArrayBuffer | Uint8Array | string,
  archiveName: string = 'project.zip'
): Promise<ExtractedArchiveResult> {
  const zip = new JSZip();
  let dataToLoad: any = archiveData;

  if (typeof archiveData === 'string' && archiveData.startsWith('data:')) {
    const base64Part = archiveData.split(',')[1] || archiveData;
    dataToLoad = Buffer.from(base64Part, 'base64');
  } else if (typeof archiveData === 'string' && /^[A-Za-z0-9+/=]+$/.test(archiveData.trim()) && archiveData.length > 50) {
    dataToLoad = Buffer.from(archiveData, 'base64');
  }

  let loadedZip: JSZip;
  try {
    loadedZip = await zip.loadAsync(dataToLoad);
  } catch (err: any) {
    throw new Error(`Failed to unpack ZIP archive "${archiveName}": ${err?.message || 'Invalid ZIP'}`);
  }

  const rawEntries: Array<{ relativePath: string; entry: JSZip.JSZipObject }> = [];
  loadedZip.forEach((relativePath, entry) => {
    if (entry.dir) return;
    const normPath = relativePath.replace(/\\/g, '/');
    const lower = normPath.toLowerCase();

    if (IGNORED_PATH_PREFIXES.some(prefix => lower.startsWith(prefix) || lower.includes('/' + prefix))) {
      return;
    }
    const fileName = normPath.split('/').pop() || '';
    if (IGNORED_FILENAMES.includes(fileName.toLowerCase())) {
      return;
    }
    rawEntries.push({ relativePath: normPath, entry });
  });

  let commonPrefix = '';
  if (rawEntries.length > 0) {
    const firstParts = rawEntries[0].relativePath.split('/');
    if (firstParts.length > 1) {
      const candidatePrefix = firstParts[0] + '/';
      const allSharePrefix = rawEntries.every(e => e.relativePath.startsWith(candidatePrefix));
      if (allSharePrefix) {
        commonPrefix = candidatePrefix;
      }
    }
  }

  const extractedFiles: SourceFile[] = [];
  let skippedBinary = 0;
  let totalLinesCount = 0;
  const languagesSet = new Set<string>();

  for (const { relativePath, entry } of rawEntries) {
    const cleanPath = commonPrefix ? relativePath.substring(commonPrefix.length) : relativePath;
    const ext = cleanPath.split('.').pop()?.toLowerCase() || '';

    if (BINARY_EXTENSIONS.has(ext)) {
      skippedBinary++;
      continue;
    }

    try {
      const content = await entry.async('text');
      if (content.includes('\0\0\0') || content.includes('\ufffd\ufffd')) {
        skippedBinary++;
        continue;
      }

      const lines = content.split('\n').length;
      totalLinesCount += lines;
      const lang = getFileLanguage(cleanPath);
      languagesSet.add(lang);

      extractedFiles.push({
        name: cleanPath.split('/').pop() || cleanPath,
        path: cleanPath,
        content,
        size: content.length,
        language: lang,
        lines,
      });
    } catch {
      skippedBinary++;
    }
  }

  const detectedLanguages = Array.from(languagesSet);
  const archiveSummary = `ZIP Archive "${archiveName}": Extracted ${extractedFiles.length} source files (${totalLinesCount.toLocaleString()} lines across ${detectedLanguages.length} languages${skippedBinary > 0 ? `, skipped ${skippedBinary} binary assets` : ''})`;

  return {
    isArchive: true,
    archiveName,
    files: extractedFiles,
    totalExtractedFiles: extractedFiles.length,
    totalLines: totalLinesCount,
    detectedLanguages,
    skippedBinaryCount: skippedBinary,
    archiveSummary,
  };
}
