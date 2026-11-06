/**
 * ClinePass streaming with fallbacks.
 *
 * The gateway can reject a paid model for this account (missing
 * subscription, zero credits, or a product-surface gate). Instead of leaving
 * the turn dead, retry through the working Cline free route. Paid models are
 * never relabeled as free in the catalog; only the request path falls back.
 */

import { streamSimple as openaiStreamSimple } from "@earendil-works/pi-ai/api/openai-completions";
import { createAssistantMessageEventStream } from "@earendil-works/pi-ai";

const CLINE_FREE_HEADERS = {
  "HTTP-Referer": "https://cline.bot",
  "X-Title": "Cline",
  "User-Agent": "Cline/3.0.68",
  "X-IS-MULTIROOT": "false",
  "X-CLIENT-TYPE": "cline-cli",
  "X-CLIENT-VERSION": "3.0.68",
  "X-PLATFORM": "cli",
  "X-PLATFORM-VERSION": "3.0.68",
  "X-CORE-VERSION": "0.0.90",
  "X-Response-Format": "openai",
} as const;

const FREE_FALLBACK_MODEL_IDS = [
  "reflection/beam-free",
  "cline-free/nemotron-3.5-super-vl",
  "nvidia/nemotron-3.5-lightning-free",
  "cline-free/solar-mini4",
];

const ZERO_USAGE = {
  input: 0,
  output: 0,
  cacheRead: 0,
  cacheWrite: 0,
  totalTokens: 0,
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
};

function errorMessage(error: unknown): string {
  if (error && typeof error === "object") {
    const anyError = error as { errorMessage?: unknown; message?: unknown };
    if (typeof anyError.errorMessage === "string" && anyError.errorMessage) return anyError.errorMessage;
    if (typeof anyError.message === "string" && anyError.message) return anyError.message;
  }
  return String(error ?? "ClinePass request failed");
}

function assistantError(model: any, error: unknown): any {
  if (error && typeof error === "object" && (error as { role?: unknown }).role === "assistant") {
    return error;
  }
  return {
    role: "assistant",
    content: [],
    api: model?.api ?? "openai-completions",
    provider: model?.provider ?? "clinepass",
    model: model?.id ?? "unknown",
    usage: ZERO_USAGE,
    stopReason: "error",
    errorMessage: errorMessage(error),
    timestamp: Date.now(),
  };
}

export function clinePassStreamSimple(model: any, context: any, options?: any): any {
  const outer = createAssistantMessageEventStream();

  void (async () => {
    let lastError: unknown = null;

    // Primary attempt: the selected ClinePass model.
    try {
      const primary = openaiStreamSimple(model, context, options);
      const iterator = primary[Symbol.asyncIterator]();
      const first = await iterator.next();
      if (first.done) {
        try {
          outer.end(await primary.result());
        } catch {
          outer.end();
        }
        return;
      }
      if (first.value?.type !== "error") {
        outer.push(first.value);
        while (true) {
          const next = await iterator.next();
          if (next.done) break;
          outer.push(next.value);
        }
        try {
          outer.end(await primary.result());
        } catch {
          outer.end();
        }
        return;
      }
      lastError = first.value.error ?? first.value;
    } catch (error) {
      lastError = error;
    }

    console.warn(`[pi-clinepass] primary model failed (${errorMessage(lastError)}); trying free fallback`);

    // Fallback attempts: known working Cline free routes.
    for (const fallbackId of FREE_FALLBACK_MODEL_IDS) {
      const fallbackModel = {
        ...model,
        id: fallbackId,
        name: `${model?.name ?? "ClinePass model"} (free fallback)`,
        provider: "cline-free",
        headers: { ...(model?.headers ?? {}), ...CLINE_FREE_HEADERS },
      };
      try {
        const stream = openaiStreamSimple(fallbackModel, context, {
          ...options,
          apiKey: options?.apiKey,
          headers: { ...(options?.headers ?? {}), ...CLINE_FREE_HEADERS },
        });
        const iterator = stream[Symbol.asyncIterator]();
        const first = await iterator.next();
        if (first.done) continue;
        if (first.value?.type === "error") {
          lastError = first.value.error ?? first.value;
          continue;
        }
        outer.push(first.value);
        while (true) {
          const next = await iterator.next();
          if (next.done) break;
          outer.push(next.value);
        }
        try {
          outer.end(await stream.result());
        } catch {
          outer.end();
        }
        return;
      } catch (error) {
        lastError = error;
        continue;
      }
    }

    // Everything failed: surface the last real error instead of a generic one.
    outer.push({ type: "error", reason: "error", error: assistantError(model, lastError) });
  })().catch((error) => {
    outer.push({ type: "error", reason: "error", error: assistantError(model, error) });
  });

  return outer;
}
