import { GoogleGenAI } from '@google/genai';

export interface AIProviderStatus {
  status: 'ok' | 'degraded' | 'offline';
  active_provider: 'gemini' | 'ollama' | 'heuristic_engine';
  is_local: boolean;
  model: string;
  base_url?: string;
  ollama_installed_models?: string[];
  ollama_reachable?: boolean;
  has_gemini_key: boolean;
  recommended_model: string;
  details: string;
  timestamp: string;
}

// Global Gemini client singleton
let geminiClient: GoogleGenAI | null = null;

function getGeminiKey(): string {
  return (
    process.env.GEMINI_API_KEY ||
    process.env.GOOGLE_GENAI_API_KEY ||
    process.env.GOOGLE_API_KEY ||
    process.env.API_KEY ||
    ''
  ).trim();
}

export function getGeminiClient(): GoogleGenAI | null {
  const apiKey = getGeminiKey();
  if (!apiKey) return null;

  if (!geminiClient) {
    try {
      geminiClient = new GoogleGenAI({
        apiKey,
        httpOptions: {
          headers: {
            'User-Agent': 'aistudio-build',
          },
        },
      });
    } catch {
      geminiClient = null;
    }
  }
  return geminiClient;
}

/**
 * Resilient Gemini Content Generator with multi-model rotation & 503/429/network fallback
 */
export async function generateGeminiContentWithFallback(
  contents: string | any,
  options?: {
    config?: Record<string, any>;
    preferredModel?: string;
  }
): Promise<{ text: string; model_used: string } | null> {
  const gemini = getGeminiClient();
  if (!gemini) return null;

  const envModel = process.env.GEMINI_MODEL;
  const userPreferred = options?.preferredModel || envModel;

  // Candidate models prioritized by standard availability and throughput
  const candidateModels = [
    userPreferred,
    'gemini-3.7-flash',
    'gemini-3.1-flash-lite',
    'gemini-flash-latest',
  ].filter(Boolean) as string[];

  const uniqueModels = Array.from(new Set(candidateModels));

  for (let i = 0; i < uniqueModels.length; i++) {
    const modelName = uniqueModels[i];
    try {
      const response = await gemini.models.generateContent({
        model: modelName,
        contents,
        config: options?.config,
      });

      const text = response.text || '';
      if (text) {
        return { text, model_used: modelName };
      }
    } catch (err: any) {
      const errMsg = err?.message || String(err);
      const is503OrRateLimit = errMsg.includes('503') || errMsg.includes('UNAVAILABLE') || errMsg.includes('high demand') || errMsg.includes('429');
      const isNetworkIssue = errMsg.includes('fetch failed') || errMsg.includes('ENOTFOUND') || errMsg.includes('ECONNREFUSED') || errMsg.includes('ETIMEDOUT');
      
      const nextModel = uniqueModels[i + 1];
      if (is503OrRateLimit && nextModel) {
        console.info(`[AI Engine] Model ${modelName} experiencing temporary demand (503), switching to ${nextModel}...`);
      } else if (isNetworkIssue) {
        console.info(`[AI Engine] Cloud API connectivity notice for ${modelName}; checking next model or local heuristic.`);
      }
    }
  }

  return null;
}

export function extractAndParseJSON(rawText: string): any {
  if (!rawText) return null;
  let text = rawText.trim();

  // Strip markdown code fences if present (```json ... ``` or ``` ...)
  text = text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim();

  // Attempt direct parse first
  try {
    return JSON.parse(text);
  } catch {
    // If direct parse fails, isolate JSON between first { and last }
    const firstBrace = text.indexOf('{');
    const lastBrace = text.lastIndexOf('}');
    if (firstBrace !== -1 && lastBrace !== -1 && lastBrace >= firstBrace) {
      const jsonSub = text.substring(firstBrace, lastBrace + 1);
      try {
        return JSON.parse(jsonSub);
      } catch {
        const cleaned = jsonSub
          .replace(/,\s*([}\]])/g, '$1')
          .replace(/[\u0000-\u001F]+/g, ' ');
        return JSON.parse(cleaned);
      }
    }
    throw new Error('Could not parse valid JSON from AI response: ' + text.slice(0, 120));
  }
}

/**
 * Check if local Ollama server is reachable and fetch list of models
 */
export async function checkOllamaReachability(
  baseUrl = process.env.OLLAMA_BASE_URL || 'http://localhost:11434'
): Promise<{ reachable: boolean; models: string[] }> {
  try {
    const cleanUrl = baseUrl.replace(/\/+$/, '');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 1500);

    const response = await fetch(`${cleanUrl}/api/tags`, {
      method: 'GET',
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (response.ok) {
      const data: any = await response.json();
      const models = Array.isArray(data?.models)
        ? data.models.map((m: any) => m.name || m.model || String(m))
        : [];
      return { reachable: true, models };
    }
  } catch {
    // Ollama not reachable on this host/port
  }
  return { reachable: false, models: [] };
}

/**
 * Query Ollama /api/generate for local inference
 */
export async function queryOllama(
  prompt: string,
  systemPrompt?: string,
  model = process.env.OLLAMA_MODEL || 'llama3.2',
  baseUrl = process.env.OLLAMA_BASE_URL || 'http://localhost:11434'
): Promise<string> {
  const cleanUrl = baseUrl.replace(/\/+$/, '');
  const controller = new AbortController();
  // 60-second timeout for local LLM inference
  const timeoutId = setTimeout(() => controller.abort(), 60000);

  const payload: Record<string, any> = {
    model: model,
    prompt: prompt,
    stream: false,
    format: 'json',
    options: {
      temperature: 0.2,
      num_predict: 4096,
    },
  };

  if (systemPrompt) {
    payload.system = systemPrompt;
  }

  try {
    const response = await fetch(`${cleanUrl}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`Ollama returned HTTP ${response.status}: ${await response.text()}`);
    }

    const data: any = await response.json();
    return data.response || '';
  } catch (err: any) {
    clearTimeout(timeoutId);
    throw err;
  }
}

/**
 * Assess overall AI provider status and active configuration
 */
export async function getComprehensiveAIStatus(): Promise<AIProviderStatus> {
  const configuredProvider = (process.env.LLM_PROVIDER || 'auto').toLowerCase();
  const ollamaBaseUrl = process.env.OLLAMA_BASE_URL || 'http://localhost:11434';
  const ollamaModel = process.env.OLLAMA_MODEL || 'llama3.2';
  const hasGeminiKey = Boolean(getGeminiKey());
  const customGeminiModel = process.env.GEMINI_MODEL || 'gemini-3.7-flash';

  const ollamaCheck = await checkOllamaReachability(ollamaBaseUrl);

  // Determine active provider based on preference & availability
  let activeProvider: 'gemini' | 'ollama' | 'heuristic_engine' = 'heuristic_engine';
  let activeModel = 'Domain Heuristic Matrix (Offline)';
  let isLocal = false;
  let details = '';

  if (configuredProvider === 'ollama' || (configuredProvider === 'auto' && ollamaCheck.reachable)) {
    if (ollamaCheck.reachable) {
      activeProvider = 'ollama';
      activeModel = `Ollama: ${ollamaModel}`;
      isLocal = true;
      details = `Connected to local Ollama on ${ollamaBaseUrl} with ${ollamaCheck.models.length} model(s) available.`;
    } else if (hasGeminiKey) {
      activeProvider = 'gemini';
      activeModel = customGeminiModel;
      isLocal = false;
      details = `Ollama unreachable on ${ollamaBaseUrl}; fell back to Google Gemini (${customGeminiModel}).`;
    }
  } else if (hasGeminiKey) {
    activeProvider = 'gemini';
    activeModel = customGeminiModel;
    isLocal = false;
    details = `Using Google Gemini Cloud API (${customGeminiModel}) via backend secret environment variable.`;
  } else if (ollamaCheck.reachable) {
    activeProvider = 'ollama';
    activeModel = `Ollama: ${ollamaModel}`;
    isLocal = true;
    details = `Auto-detected local Ollama instance on ${ollamaBaseUrl}.`;
  } else {
    activeProvider = 'heuristic_engine';
    activeModel = 'Real-World Heuristics & Deterministic Rules';
    isLocal = true;
    details = 'Zero-dependency standalone mode. Add GEMINI_API_KEY or start Ollama locally for neural reasoning.';
  }

  return {
    status: activeProvider !== 'heuristic_engine' ? 'ok' : 'degraded',
    active_provider: activeProvider,
    is_local: isLocal,
    model: activeModel,
    base_url: isLocal ? (activeProvider === 'ollama' ? ollamaBaseUrl : undefined) : undefined,
    ollama_installed_models: ollamaCheck.models,
    ollama_reachable: ollamaCheck.reachable,
    has_gemini_key: hasGeminiKey,
    recommended_model: customGeminiModel,
    details,
    timestamp: new Date().toISOString(),
  };
}
