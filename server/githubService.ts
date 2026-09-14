export interface GitHubRepoFile {
  path: string;
  name: string;
  size: number;
  type: 'file' | 'dir';
  content?: string;
  language?: string;
}

export interface GitHubInspectResult {
  success: boolean;
  owner: string;
  name: string;
  full_name: string;
  description: string;
  stars: number;
  forks: number;
  default_branch: string;
  commit_sha?: string;
  language: string;
  topics: string[];
  total_files_count: number;
  security_files: GitHubRepoFile[];
  tree: Array<{ path: string; size?: number; type: string }>;
  error?: string;
}

export function parseGitHubUrl(input: string): { owner: string; repo: string } | null {
  if (!input) return null;
  let clean = input.trim();
  clean = clean.replace(/\.git$/i, '');
  clean = clean.replace(/^git@github\.com:/i, 'https://github.com/');

  // Match https://github.com/owner/repo or github.com/owner/repo
  const matchUrl = clean.match(/(?:https?:\/\/)?(?:www\.)?github\.com\/([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)/i);
  if (matchUrl) {
    return { owner: matchUrl[1], repo: matchUrl[2] };
  }

  // Match owner/repo
  const matchShort = clean.match(/^([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)$/);
  if (matchShort && !clean.includes('http') && !clean.includes('.')) {
    return { owner: matchShort[1], repo: matchShort[2] };
  }

  return null;
}

const SECURITY_RELEVANT_PATTERNS = [
  /(?:routes?|controllers?|handlers?|api|services?|middleware|auth|security|models?|db|database|queries|schema|utils?|helpers?|lib)/i,
  /(?:server\.(?:ts|js|py|go|java)|app\.(?:ts|js|py|go|java)|main\.(?:ts|js|py|go|java|rs)|index\.(?:ts|js|py))/i,
  /(?:package\.json|requirements\.txt|pom\.xml|build\.gradle|go\.mod|Cargo\.toml|Gemfile|composer\.json)/i,
  /(?:Dockerfile|docker-compose\.ya?ml|\.env\.example|config\.(?:json|ya?ml|ts|js|py))/i,
];

function isSecurityRelevantFile(filePath: string): boolean {
  return SECURITY_RELEVANT_PATTERNS.some(pattern => pattern.test(filePath));
}

function detectFileLanguage(filePath: string): string {
  const ext = filePath.split('.').pop()?.toLowerCase() || '';
  switch (ext) {
    case 'ts':
    case 'tsx':
      return 'TypeScript';
    case 'js':
    case 'jsx':
    case 'mjs':
    case 'cjs':
      return 'JavaScript';
    case 'py':
      return 'Python';
    case 'go':
      return 'Go';
    case 'java':
      return 'Java';
    case 'php':
      return 'PHP';
    case 'rb':
      return 'Ruby';
    case 'rs':
      return 'Rust';
    case 'cs':
      return 'C#';
    case 'c':
    case 'cpp':
    case 'h':
      return 'C/C++';
    case 'sol':
      return 'Solidity';
    case 'sql':
      return 'SQL';
    case 'json':
      return 'JSON';
    case 'yml':
    case 'yaml':
      return 'YAML';
    case 'dockerfile':
      return 'Docker';
    default:
      return 'Text';
  }
}

export async function inspectGitHubRepository(
  input: string,
  branch?: string,
  token = process.env.GITHUB_TOKEN || ''
): Promise<GitHubInspectResult> {
  const parsed = parseGitHubUrl(input);
  if (!parsed) {
    throw new Error(`Invalid GitHub repository format: "${input}". Expected "https://github.com/owner/repo" or "owner/repo".`);
  }

  const { owner, repo } = parsed;
  const headers: Record<string, string> = {
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'aistudio-build-pentest-sast-engine',
  };
  if (token) {
    headers['Authorization'] = `token ${token}`;
  }

  // 1. Fetch Repository Metadata
  let repoData: any = {};
  try {
    const repoRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers });
    if (repoRes.ok) {
      repoData = await repoRes.json();
    } else if (repoRes.status === 404) {
      throw new Error(`GitHub repository "${owner}/${repo}" was not found (or is private).`);
    } else if (repoRes.status === 403) {
      console.warn('[GitHub SAST] Rate limit exceeded or forbidden on repo info, continuing with best effort.');
    }
  } catch (e: any) {
    if (e.message.includes('not found')) throw e;
    console.warn('[GitHub SAST] Repo metadata fetch error:', e.message);
  }

  const targetBranch = branch || repoData.default_branch || 'main';

  // 2. Fetch Git Tree recursively & commit SHA
  let rawTree: any[] = [];
  let commitSha = '';
  try {
    const treeRes = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/git/trees/${targetBranch}?recursive=1`,
      { headers }
    );
    if (treeRes.ok) {
      const treeJson: any = await treeRes.json();
      commitSha = treeJson.sha || '';
      if (Array.isArray(treeJson.tree)) {
        rawTree = treeJson.tree;
      }
    } else {
      // Try 'master' if 'main' was not found
      if (targetBranch === 'main') {
        const fallbackRes = await fetch(
          `https://api.github.com/repos/${owner}/${repo}/git/trees/master?recursive=1`,
          { headers }
        );
        if (fallbackRes.ok) {
          const fbJson: any = await fallbackRes.json();
          commitSha = fbJson.sha || '';
          if (Array.isArray(fbJson.tree)) {
            rawTree = fbJson.tree;
          }
        }
      }
    }
  } catch (err: any) {
    console.warn('[GitHub SAST] Error fetching git tree:', err.message);
  }

  // If no commitSha from tree, fetch latest commit on branch
  if (!commitSha) {
    try {
      const commitRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/commits/${targetBranch}`, { headers });
      if (commitRes.ok) {
        const cJson: any = await commitRes.json();
        commitSha = cJson.sha || '';
      }
    } catch {
      // ignore
    }
  }

  const treeFiles = rawTree
    .filter(item => item.type === 'blob')
    .map(item => ({
      path: item.path,
      size: item.size || 0,
      type: 'file',
    }));

  // 3. Filter high-value source files for SAST security analysis
  const candidateFiles = treeFiles.filter(item => {
    // Exclude images, binary, minified, test suites, locks
    if (/\.(png|jpg|jpeg|gif|svg|ico|pdf|zip|tar|gz|woff|woff2|ttf|eot|min\.js|min\.css|lock)$/i.test(item.path)) {
      return false;
    }
    if (/(node_modules|dist|build|vendor|\.git|\.next|\.nuxt)/i.test(item.path)) {
      return false;
    }
    return isSecurityRelevantFile(item.path);
  });

  // Pick the top 10 most security-critical files to fetch contents
  const selectedToFetch = candidateFiles.slice(0, 10);
  const securityFiles: GitHubRepoFile[] = [];

  for (const item of selectedToFetch) {
    try {
      const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${targetBranch}/${item.path}`;
      const fileRes = await fetch(rawUrl, { headers: { 'User-Agent': 'aistudio-build-pentest-sast-engine' } });
      if (fileRes.ok) {
        const text = await fileRes.text();
        // Truncate to first 25KB per file if very large
        const truncated = text.length > 25000 ? text.slice(0, 25000) + '\n// ... [truncated for SAST scan]' : text;
        securityFiles.push({
          path: item.path,
          name: item.path.split('/').pop() || item.path,
          size: item.size || text.length,
          type: 'file',
          content: truncated,
          language: detectFileLanguage(item.path),
        });
      }
    } catch (e: any) {
      console.warn(`[GitHub SAST] Could not fetch raw content for ${item.path}:`, e.message);
    }
  }

  return {
    success: true,
    owner,
    name: repo,
    full_name: repoData.full_name || `${owner}/${repo}`,
    description: repoData.description || `Source code repository for ${repo}`,
    stars: repoData.stargazers_count || 0,
    forks: repoData.forks_count || 0,
    default_branch: targetBranch,
    commit_sha: commitSha || undefined,
    language: repoData.language || 'Multi-language',
    topics: repoData.topics || [],
    total_files_count: treeFiles.length,
    security_files: securityFiles,
    tree: treeFiles.slice(0, 150),
  };
}
