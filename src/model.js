/**
 * Ollama client.
 *
 * One provider, no abstraction layer. Veil only claims local inference, so the
 * only thing it knows how to talk to is a base URL on localhost. If you point
 * OLLAMA_HOST at a remote box, that is your call and the app says so in the UI.
 */

const DEFAULT_HOST = 'http://127.0.0.1:11434';

/**
 * Small models wrap JSON in markdown fences even when the API asks for raw
 * JSON, and a truncated response can end mid-object. Try the obvious repair
 * before giving up: strip fences, then take the widest {…} pair.
 *
 * @param {string} raw
 * @returns {unknown | undefined}
 */
export function parseJsonLoosely(raw) {
  const attempts = [raw];

  const fenced = raw.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fenced) attempts.push(fenced[1].trim());

  const first = raw.indexOf('{');
  const last = raw.lastIndexOf('}');
  if (first !== -1 && last > first) attempts.push(raw.slice(first, last + 1));

  for (const attempt of attempts) {
    try {
      return JSON.parse(attempt);
    } catch {
      // try the next shape
    }
  }

  return undefined;
}

export class ModelUnavailable extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'ModelUnavailable';
    this.cause = cause;
  }
}

/**
 * @param {{host?: string, model?: string}} [config]
 */
export function createClient(config = {}) {
  const host = (config.host ?? process.env.OLLAMA_HOST ?? DEFAULT_HOST).replace(/\/$/, '');
  const model = config.model ?? process.env.VEIL_MODEL ?? 'gemma3:4b';

  /**
   * @param {string} path
   * @param {object} body
   * @param {number} timeoutMs
   */
  async function post(path, body, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(`${host}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (!res.ok) {
        const detail = await res.text().catch(() => '');
        throw new ModelUnavailable(
          `Ollama returned ${res.status} for ${path}${detail ? `: ${detail.slice(0, 200)}` : ''}`,
        );
      }
      return await res.json();
    } catch (error) {
      if (error instanceof ModelUnavailable) throw error;
      if (error?.name === 'AbortError') {
        throw new ModelUnavailable(
          `The model did not answer within ${Math.round(timeoutMs / 1000)}s. A cold model load on CPU can take a while; try again.`,
          error,
        );
      }
      throw new ModelUnavailable(
        `Cannot reach Ollama at ${host}. Start it with \`ollama serve\` and pull a model, for example \`ollama pull ${model}\`.`,
        error,
      );
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    host,
    model,

    /** @returns {Promise<{reachable: boolean, models: string[], error?: string}>} */
    async health() {
      try {
        const res = await fetch(`${host}/api/tags`, { signal: AbortSignal.timeout(2000) });
        if (!res.ok) return { reachable: false, models: [], error: `HTTP ${res.status}` };
        const data = await res.json();
        return { reachable: true, models: (data.models ?? []).map((m) => m.name) };
      } catch (error) {
        return { reachable: false, models: [], error: error.message };
      }
    },

    /**
     * Structured JSON completion. Ollama's `format: 'json'` constrains decoding
     * to valid JSON, which is the only reason this is reliable on small models.
     *
     * @param {{system: string, prompt: string, timeoutMs?: number, temperature?: number}} args
     */
    async json({ system, prompt, timeoutMs = 120_000, temperature = 0 }) {
      const data = await post(
        '/api/generate',
        {
          model,
          system,
          prompt,
          stream: false,
          format: 'json',
          options: { temperature, top_p: 0.9, num_predict: 1024 },
        },
        timeoutMs,
      );
      const raw = String(data.response ?? '').trim();
      const parsed = parseJsonLoosely(raw);
      if (parsed === undefined) {
        throw new ModelUnavailable(
          `Model returned text that was not JSON: ${raw.slice(0, 160)}`,
        );
      }
      return parsed;
    },

    /**
     * Free-form completion, used for the "explain this risk" panel.
     * @param {{system: string, prompt: string, timeoutMs?: number}} args
     */
    async text({ system, prompt, timeoutMs = 120_000 }) {
      const data = await post(
        '/api/generate',
        { model, system, prompt, stream: false, options: { temperature: 0.2, num_predict: 320 } },
        timeoutMs,
      );
      return String(data.response ?? '').trim();
    },
  };
}
