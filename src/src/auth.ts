/**
 * ClinePass authentication: credential resolution and the /login flow.
 *
 * Login presents a chooser (reuse existing credentials / device flow /
 * paste API key); the user picks explicitly every time.
 */

import type { OAuthCredentials, OAuthLoginCallbacks } from "@earendil-works/pi-ai";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  DEFAULT_API_BASE,
  WORKOS_REFRESH_MARGIN_MS,
  isWorkosToken,
  pollDeviceAuthorization,
  refreshWorkosToken,
  registerWorkOSTokens,
  startDeviceAuthorization,
  type ClineAuthCredentials,
} from "./workos.js";

export const DASHBOARD_URL = "https://app.cline.bot/dashboard/account?tab=api-keys";
export const TEN_YEARS_MS = 10 * 365 * 24 * 60 * 60 * 1000;

export interface AuthOptions {
  homeDir?: () => string;
  readFile?: (path: string) => string;
  fileExists?: (path: string) => boolean;
  writeFile?: (path: string, data: string) => void;
  fetch?: typeof globalThis.fetch;
  apiBase?: string;
}

function defaultHomeDir(): string {
  return homedir();
}

function resolveOptions(
  options: AuthOptions,
): Required<Pick<AuthOptions, "homeDir" | "readFile" | "fileExists" | "writeFile">> {
  return {
    homeDir: options.homeDir ?? defaultHomeDir,
    readFile: options.readFile ?? ((p) => readFileSync(p, "utf8")),
    fileExists: options.fileExists ?? ((p) => existsSync(p)),
    writeFile: options.writeFile ?? defaultWriteFile,
  };
}

/** Atomic-ish write matching pi's auth.json conventions (JSON, 0600 on create). */
function defaultWriteFile(path: string, data: string): void {
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, data, { encoding: "utf8", mode: 0o600 });
  try {
    // rename replaces atomically on POSIX; on Windows it may fail if the
    // target is open — fall back to a direct write in that case.
    renameSync(tmp, path);
  } catch {
    writeFileSync(path, data, { encoding: "utf8", mode: 0o600 });
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function numberValue(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  return undefined;
}

function isMissingFileError(error: unknown): boolean {
  if (typeof error === "object" && error !== null && "code" in error) {
    if ((error as { code?: unknown }).code === "ENOENT") return true;
  }
  const msg = error instanceof Error ? error.message : String(error);
  return msg.includes("ENOENT") || msg.includes("not found");
}

function parseJson(path: string, options: AuthOptions): Record<string, unknown> | undefined {
  const { readFile, fileExists } = resolveOptions(options);
  try {
    if (!fileExists(path)) return undefined;
    const parsed: unknown = JSON.parse(readFile(path));
    return isRecord(parsed) ? parsed : undefined;
  } catch (error) {
    if (!isMissingFileError(error)) {
      console.warn(`[pi-clinepass] failed to read ${path}: ${error instanceof Error ? error.message : String(error)}`);
    }
    return undefined;
  }
}

// ─── Credential extraction ────────────────────────────────────────────────

function extractWorkosAuth(auth: Record<string, unknown>): ClineAuthCredentials | undefined {
  const accessToken = stringValue(auth.accessToken);
  const refreshToken = stringValue(auth.refreshToken);
  if (!accessToken || !refreshToken || !isWorkosToken(accessToken)) return undefined;
  return {
    accessToken,
    refreshToken,
    expiresAt: numberValue(auth.expiresAt) ?? 0,
  };
}

/**
 * Read credentials a Cline CLI login left on this machine
 * (`~/.cline/data/settings/providers.json`) — offered as the "reuse"
 * option in /login.
 */
export function resolveClineCliCredential(options: AuthOptions = {}): ClineAuthCredentials | undefined {
  const home = resolveOptions(options).homeDir();
  const parsed = parseJson(join(home, ".cline", "data", "settings", "providers.json"), options);
  if (!parsed) return undefined;

  const providers = isRecord(parsed.providers) ? parsed.providers : undefined;
  const candidates: ClineAuthCredentials[] = [];
  for (const key of ["cline-pass", "cline"] as const) {
    const provider = isRecord(providers?.[key]) ? providers[key] : undefined;
    const settings = isRecord(provider?.settings) ? provider.settings : undefined;
    const auth = isRecord(settings?.auth) ? settings.auth : undefined;
    if (auth) {
      const cred = extractWorkosAuth(auth);
      if (cred) candidates.push(cred);
    }
  }
  if (candidates.length > 0) {
    return candidates.reduce((best, current) => (current.expiresAt > best.expiresAt ? current : best));
  }
  return undefined;
}

/**
 * Read pi's OWN stored credential for the `clinepass` provider
 * (`~/.pi/agent/auth.json` → `clinepass` field). This is the identity pi
 * itself uses for chat requests after /login — the meter must match it.
 * Handles: plain string key, `{type:"api_key", key}`, and OAuth objects.
 */
export async function clearPiStoredCredential(options: AuthOptions = {}): Promise<void> {
  const { homeDir, readFile, fileExists, writeFile } = resolveOptions(options);
  const authPath = join(homeDir(), ".pi", "agent", "auth.json");
  try {
    if (!fileExists(authPath)) return;
    const current = readFile(authPath);
    const parsed: unknown = current.trim() ? JSON.parse(current) : {};
    if (!isRecord(parsed)) return;
    if (!("clinepass" in parsed)) return;
    const { clinepass: _removed, ...rest } = parsed as Record<string, unknown>;
    writeFile(authPath, JSON.stringify(rest, null, 2));
  } catch {
    // Best-effort: never throw from cleanup.
  }
}

export function resolvePiStoredCredential(options: AuthOptions = {}): ClineAuthCredentials | undefined {
  const home = resolveOptions(options).homeDir();
  const parsed = parseJson(join(home, ".pi", "agent", "auth.json"), options);
  if (!parsed) return undefined;

  const cp = parsed.clinepass;
  if (typeof cp === "string" && cp.trim()) {
    return { accessToken: cp.trim(), refreshToken: cp.trim(), expiresAt: Number.MAX_SAFE_INTEGER };
  }
  if (!isRecord(cp)) return undefined;

  if (cp.type === "api_key") {
    const key = stringValue(cp.key);
    return key ? { accessToken: key, refreshToken: key, expiresAt: Number.MAX_SAFE_INTEGER } : undefined;
  }

  const access = stringValue(cp.access);
  const refresh = stringValue(cp.refresh);
  if (!access) return undefined;
  const isOAuth = isWorkosToken(access);
  return {
    accessToken: access,
    refreshToken: refresh ?? access,
    // Bare non-prefixed access from pi's store is a static key; WorkOS
    // tokens with no expiry are treated as stale so they get refreshed.
    expiresAt: numberValue(cp.expires) ?? (isOAuth ? 0 : Number.MAX_SAFE_INTEGER),
  };
}

// ─── Live account existence check ───────────────────────────────────────

/**
 * Live check: does the signed-in Cline account still exist?
 *
 * Reads pi's stored `clinepass` credential, calls `/api/v1/users/me`, and
 * returns `true` when the account is reachable. A deleted account clears the
 * stored credential and returns `false`; transport/other failures default to
 * `true` so a flaky connection never masquerades as a deleted account.
 */
export async function checkAccountExists(options: AuthOptions = {}): Promise<boolean> {
  let credential = resolvePiStoredCredential(options);
  if (!credential) return true;
  const fetchFn = options.fetch ?? globalThis.fetch;
  const apiBase = options.apiBase ?? DEFAULT_API_BASE;

  const check = async (accessToken: string): Promise<Response> =>
    fetchFn(`${apiBase}/api/v1/users/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
      signal: AbortSignal.timeout(10_000),
    });

  try {
    // Refresh expired WorkOS tokens before deciding the account is gone; an
    // expired token is not a deleted account.
    if (isWorkosToken(credential.accessToken) && credential.expiresAt <= Date.now() + WORKOS_REFRESH_MARGIN_MS) {
      try {
        const refreshed = await refreshToken(credential, undefined, options);
        await persistOAuthCredential(refreshed, options).catch(() => {});
        credential = {
          accessToken: refreshed.access,
          refreshToken: refreshed.refresh,
          expiresAt: refreshed.expires,
        };
      } catch {
        // Fall through and let the endpoint response decide.
      }
    }

    let response = await check(credential.accessToken);
    if (response.status === 401 && isWorkosToken(credential.accessToken)) {
      try {
        const refreshed = await refreshToken(credential, undefined, options);
        await persistOAuthCredential(refreshed, options).catch(() => {});
        credential = {
          accessToken: refreshed.access,
          refreshToken: refreshed.refresh,
          expiresAt: refreshed.expires,
        };
        response = await check(credential.accessToken);
      } catch {
        // Keep the original 401 response for classification.
      }
    }

    if (response.ok) return true;
    const text = await response.text().catch(() => "");
    const deleted =
      response.status === 404 ||
      response.status === 410 ||
      /user account has been deleted|account has been deleted|account deleted/i.test(text);
    if (deleted) {
      await clearPiStoredCredential(options).catch(() => {});
      return false;
    }
    // 401/403/etc. are auth/entitlement problems, not proof of deletion.
    return true;
  } catch {
    return true;
  }
}

/**
 * Strict HTTPS verification used by the login flow: the credential must
 * resolve to a live `/api/v1/users/me` response. Throws on a deleted or
 * invalid account so callers can clear credentials and prompt again.
 */
export async function verifyAccountLogin(
  credential: ClineAuthCredentials,
  options: AuthOptions = {},
): Promise<boolean> {
  const fetchFn = options.fetch ?? globalThis.fetch;
  const apiBase = options.apiBase ?? DEFAULT_API_BASE;
  let response: Response;
  try {
    response = await fetchFn(`${apiBase}/api/v1/users/me`, {
      headers: { Authorization: `Bearer ${credential.accessToken}` },
      signal: AbortSignal.timeout(10_000),
    });
  } catch (err) {
    throw new Error(
      `Could not verify Cline account over HTTPS: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (response.ok) return true;
  const text = await response.text().catch(() => "");
  const deleted =
    response.status === 404 ||
    response.status === 410 ||
    /user account has been deleted|account has been deleted|account deleted/i.test(text);
  if (deleted) {
    await clearPiStoredCredential(options).catch(() => {});
    throw new Error("Cline account has been deleted. Run `pi /login` to sign in with a valid account.");
  }
  throw new Error(
    `Cline account verification failed (${response.status}): ${text.slice(0, 200) || "unauthorized"}`,
  );
}

// ─── Credential persistence ─────────────────────────────────────
/**
 * Persist an OAuth credential for the `clinepass` provider back into pi's
 * auth.json (`~/.pi/agent/auth.json`). Used after a meter-triggered refresh
 * produced rotated tokens — if the server rotates single-use refresh
 * tokens, discarding the new one would leave pi's stored credential dead
 * and force a re-login. Waits for pi's lock file (`<auth.json>.lock`, held
 * by proper-lockfile while pi writes) to clear before merging, then verifies
 * after writing: the meter refresh and pi's own chat-path refresh can fire at
 * the same near-expiry moment, so if pi rewrote the file in between, the
 * merge is redone once on top of the newer content instead of dropping it.
 */
export async function persistOAuthCredential(
  credential: OAuthCredentials,
  options: AuthOptions = {},
): Promise<void> {
  const { homeDir, readFile, fileExists, writeFile } = resolveOptions(options);
  const authPath = join(homeDir(), ".pi", "agent", "auth.json");
  const lockPath = `${authPath}.lock`;
  const entry = {
    type: "oauth",
    access: credential.access,
    refresh: credential.refresh,
    expires: credential.expires,
  };

  for (let pass = 0; pass < 2; pass++) {
    for (let attempt = 0; attempt < 20 && fileExists(lockPath); attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }

    const current = fileExists(authPath) ? readFile(authPath) : "{}";
    const parsed: unknown = current.trim() ? JSON.parse(current) : {};
    if (!isRecord(parsed)) {
      throw new Error("auth.json is not a JSON object");
    }
    const serialized = JSON.stringify({ ...parsed, clinepass: entry }, null, 2);
    writeFile(authPath, serialized);

    let contended = false;
    for (let attempt = 0; attempt < 20 && fileExists(lockPath); attempt++) {
      contended = true;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    // Done only when pi never contended and the file still holds exactly what
    // we wrote; otherwise loop once more and merge over the newer content.
    if (!contended && (!fileExists(authPath) || readFile(authPath) === serialized)) return;
  }
}

// ─── Login chain ──────────────────────────────────────────────────────────

function credentialsFromApiKey(apiKey: string): OAuthCredentials {
  return { refresh: apiKey, access: apiKey, expires: Date.now() + TEN_YEARS_MS };
}

async function loginWithWorkosCredentials(
  clineAuth: ClineAuthCredentials,
  options: AuthOptions,
): Promise<OAuthCredentials> {
  if (clineAuth.expiresAt <= Date.now() + WORKOS_REFRESH_MARGIN_MS) {
    return refreshWorkosToken(
      { access: clineAuth.accessToken, refresh: clineAuth.refreshToken, expires: clineAuth.expiresAt },
      { fetch: options.fetch, apiBase: options.apiBase ?? DEFAULT_API_BASE },
    );
  }
  return {
    access: clineAuth.accessToken,
    refresh: clineAuth.refreshToken,
    expires: clineAuth.expiresAt,
  };
}

async function loginWithDeviceFlow(
  callbacks: OAuthLoginCallbacks,
  options: AuthOptions,
): Promise<OAuthCredentials> {
  const device = await startDeviceAuthorization({ fetch: options.fetch });
  callbacks.onDeviceCode({
    userCode: device.userCode,
    verificationUri: device.verificationUri,
    intervalSeconds: device.intervalSeconds,
    expiresInSeconds: device.expiresInSeconds,
  });
  callbacks.onAuth({ url: device.verificationUriComplete ?? device.verificationUri });
  const tokens = await pollDeviceAuthorization(
    {
      deviceCode: device.deviceCode,
      expiresInSeconds: device.expiresInSeconds,
      intervalSeconds: device.intervalSeconds,
    },
    { fetch: options.fetch },
  );
  return registerWorkOSTokens(tokens, { fetch: options.fetch, apiBase: options.apiBase ?? DEFAULT_API_BASE });
}

async function loginWithManualApiKey(
  callbacks: OAuthLoginCallbacks,
  options: AuthOptions,
  reason?: string,
): Promise<OAuthCredentials> {
  const apiKey = sanitizeApiKey(
    await callbacks.onPrompt({
      message:
        (reason ? `${reason} ` : "") +
        `Enter your ClinePass API key (get one at ${DASHBOARD_URL}):`,
    }),
  );
  if (!apiKey) throw new Error("No ClinePass API key provided");
  if (apiKey.length < 20) {
    console.warn(
      `[pi-clinepass] Warning: API key looks unusually short (${apiKey.length} chars). ` +
        "Verify you copied the full key from app.cline.bot.",
    );
  }
  return credentialsFromApiKey(apiKey);
}

/** Strip terminal paste wrappers and control chars from pasted key input. */
export function sanitizeApiKey(input: string): string {
  const esc = "\x1b";
  return input
    .replaceAll(`${esc}[200~`, "")
    .replaceAll(`${esc}[201~`, "")
    .replaceAll("[200~", "")
    .replaceAll("[201~", "")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim();
}

export async function login(callbacks: OAuthLoginCallbacks, options: AuthOptions = {}): Promise<OAuthCredentials> {
  // Reuse candidate comes from a Cline CLI login only — never pi's own
  // stored credential.
  const reusable = resolveClineCliCredential(options);

  const optionsList: { id: string; label: string }[] = [
    { id: "device", label: "Sign in with browser" },
    { id: "paste", label: "Enter API key" },
  ];
  if (reusable) {
    optionsList.unshift({ id: "reuse", label: "Use existing sign-in (Cline CLI)" });
  }

  const selected = await callbacks.onSelect({
    message: "Choose how to sign in to ClinePass",
    options: optionsList,
  });
  if (!selected) throw new Error("ClinePass login cancelled");

  switch (selected) {
    case "reuse": {
      if (!reusable) throw new Error("ClinePass login cancelled");
      let refreshed: OAuthCredentials;
      try {
        refreshed = await loginWithWorkosCredentials(reusable, options);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (/account has been deleted|account deleted/i.test(msg)) {
          await clearPiStoredCredential(options).catch(() => {});
          throw new Error("Cline account has been deleted. Run `pi /login` to sign in with a valid account.");
        }
        console.warn(`[pi-clinepass] Cline CLI sign-in failed: ${msg}`);
        return loginWithManualApiKey(callbacks, options, "Cline CLI sign-in failed (refresh token may be expired).");
      }
      try {
        await verifyAccountLogin(
          { accessToken: refreshed.access, refreshToken: refreshed.refresh, expiresAt: refreshed.expires },
          options,
        );
        callbacks.onProgress?.("Verified Cline account via HTTPS");
        return refreshed;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (/account has been deleted|account deleted/i.test(msg)) {
          await clearPiStoredCredential(options).catch(() => {});
          throw new Error("Cline account has been deleted. Run `pi /login` to sign in with a valid account.");
        }
        console.warn(`[pi-clinepass] Cline CLI account check failed: ${msg}`);
        return loginWithManualApiKey(callbacks, options, "Cline CLI account check failed; enter an API key instead.");
      }
    }
    case "paste": {
      const cred = await loginWithManualApiKey(callbacks, options);
      await verifyAccountLogin(
        { accessToken: cred.access, refreshToken: cred.refresh, expiresAt: cred.expires },
        options,
      );
      callbacks.onProgress?.("Verified Cline account via HTTPS");
      return cred;
    }
    case "device": {
      let cred: OAuthCredentials;
      try {
        cred = await loginWithDeviceFlow(callbacks, options);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (/account has been deleted|account deleted/i.test(msg)) {
          await clearPiStoredCredential(options).catch(() => {});
          throw new Error("Cline account has been deleted. Run `pi /login` to sign in with a valid account.");
        }
        console.warn(`[pi-clinepass] Device login failed: ${msg}`);
        return loginWithManualApiKey(callbacks, options, "Device login failed or was cancelled.");
      }
      try {
        await verifyAccountLogin(
          { accessToken: cred.access, refreshToken: cred.refresh, expiresAt: cred.expires },
          options,
        );
        callbacks.onProgress?.("Verified Cline account via HTTPS");
        return cred;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (/account has been deleted|account deleted/i.test(msg)) {
          await clearPiStoredCredential(options).catch(() => {});
          throw new Error("Cline account has been deleted. Run `pi /login` to sign in with a valid account.");
        }
        console.warn(`[pi-clinepass] Device-flow account check failed: ${msg}`);
        return loginWithManualApiKey(callbacks, options, "Account verification failed; enter an API key instead.");
      }
    }
    default:
      throw new Error("ClinePass login cancelled");
  }
}
/**
 * Refresh ClinePass credentials. WorkOS tokens (workos: prefix) go through
 * Cline's server endpoint; static API keys never expire and pass through.
 */
export async function refreshToken(
  credentials: OAuthCredentials,
  _signal?: AbortSignal,
  options: AuthOptions = {},
): Promise<OAuthCredentials> {
  if (isWorkosToken(credentials.access)) {
    return refreshWorkosToken(credentials, { fetch: options.fetch, apiBase: options.apiBase ?? DEFAULT_API_BASE });
  }
  return credentialsFromApiKey(credentials.refresh);
}

/**
 * Return the bearer token. OAuth flows already store the `workos:` prefix
 * (refresh/register ensure it); static API keys are used as-is.
 */
export function getApiKey(credentials: OAuthCredentials): string {
  return credentials.access;
}
