/**
 * Punto 2 y Punto 4: Interceptor de Red con Cola Silenciosa (Silent Refresh Queue)
 * y Gestión de Tokens en Memoria Volátil (RAM)
 *
 * - access_token (5 min) y elevated_token (10 min): Viven exclusivamente en variables de memoria RAM.
 * - Cuando cualquier petición responde 401 Unauthorized:
 *   1. Pausa las llamadas subsecuentes y encola las peticiones en vuelo en `refreshSubscribers`.
 *   2. Dispara UNA ÚNICA petición POST /auth/refresh con el refresh_token de SecureStore.
 *   3. Si tiene éxito, actualiza el access_token en RAM, desbloquea la cola y reintenta todas las peticiones.
 *   4. Si falla (refresh_token vencido o revocado), limpia SecureStore y redirige al login.
 */

import Constants from 'expo-constants';
import { Platform } from 'react-native';

import {
  clearRefreshTokenFromHardware,
  getRefreshTokenFromHardware,
  saveRefreshTokenToHardware,
} from '@/services/secure-storage';

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  category: 'PKCE' | 'STORAGE' | 'SILENT_REFRESH' | 'TOTP' | 'STEP_UP' | 'ANTI_REPLAY';
  status: 'INFO' | 'SUCCESS' | 'WARNING' | 'ERROR';
  title: string;
  detail: string;
  httpStatus?: number;
}

export interface StepUpRequiredError extends Error {
  status: 403;
  code: 'mfa_required';
  stepUpToken: string;
}

export interface ReplayAttackError extends Error {
  status: 409;
  code: 'Replay Attack Detected';
  ttlRemainingSeconds?: number;
}

// ============================================================================
// MEMORIA VOLÁTIL (RAM) — Se destruye al cerrar/matar el proceso de la app
// ============================================================================
let volatileAccessToken: string | null = null;
let volatileAccessTokenExp: number | null = null;
let volatileElevatedToken: string | null = null;
let volatileElevatedTokenExp: number | null = null;

// Listeners para sincronizar el estado de React con la memoria volátil
type TokenChangeListener = () => void;
const tokenListeners = new Set<TokenChangeListener>();

type SessionExpiredListener = (reason: string) => void;
let onSessionExpiredCallback: SessionExpiredListener | null = null;

// ============================================================================
// COLA DE PROMESAS PARA SILENT REFRESH (Evita Race Conditions en 401 Concurrentes)
// ============================================================================
interface QueuedRequestSubscriber {
  id: string;
  endpoint: string;
  resolve: (newAccessToken: string) => void;
  reject: (error: Error) => void;
}

let isRefreshingToken = false;
let refreshQueue: QueuedRequestSubscriber[] = [];

// Registro de auditoría en memoria para inspección durante la sustentación
let auditLogs: AuditLogEntry[] = [];
const auditListeners = new Set<() => void>();

export function addAuditLog(
  entry: Omit<AuditLogEntry, 'id' | 'timestamp'>
): AuditLogEntry {
  const now = new Date();
  const timeStr = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');
  const fullEntry: AuditLogEntry = {
    ...entry,
    id: `${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    timestamp: timeStr,
  };
  auditLogs = [fullEntry, ...auditLogs].slice(0, 80);
  auditListeners.forEach((cb) => cb());
  return fullEntry;
}

export function getAuditLogs(): AuditLogEntry[] {
  return auditLogs;
}

export function clearAuditLogs(): void {
  auditLogs = [];
  auditListeners.forEach((cb) => cb());
}

export function subscribeAuditLogs(listener: () => void): () => void {
  auditListeners.add(listener);
  return () => {
    auditListeners.delete(listener);
  };
}

function notifyTokenListeners(): void {
  tokenListeners.forEach((cb) => cb());
}

export function subscribeVolatileTokens(listener: TokenChangeListener): () => void {
  tokenListeners.add(listener);
  return () => {
    tokenListeners.delete(listener);
  };
}

export function setOnSessionExpired(callback: SessionExpiredListener | null): void {
  onSessionExpiredCallback = callback;
}

/**
 * Resuelve automáticamente la URL del backend según el entorno (Emulador Android, Simulador iOS, Dispositivo LAN o Web)
 */
function detectDefaultBackendUrl(): string {
  if (process.env.EXPO_PUBLIC_BACKEND_URL) {
    return process.env.EXPO_PUBLIC_BACKEND_URL;
  }

  const hostUri = Constants.expoConfig?.hostUri;
  if (hostUri) {
    const host = hostUri.split(':')[0];
    if (host && host !== 'localhost' && host !== '127.0.0.1') {
      return `http://${host}:4000`;
    }
  }

  if (Platform.OS === 'android') {
    return 'http://10.0.2.2:4000';
  }

  return 'http://localhost:4000';
}

let backendBaseUrl = detectDefaultBackendUrl();

export function getBackendBaseUrl(): string {
  return backendBaseUrl;
}

export function setBackendBaseUrl(url: string): void {
  const cleaned = url.trim().replace(/\/+$/, '');
  if (cleaned) {
    backendBaseUrl = cleaned;
    notifyTokenListeners();
  }
}

/**
 * Lee el estado actual de los tokens en memoria volátil (RAM)
 */
export function getVolatileTokenState() {
  return {
    accessToken: volatileAccessToken,
    accessTokenExp: volatileAccessTokenExp,
    elevatedToken: volatileElevatedToken,
    elevatedTokenExp: volatileElevatedTokenExp,
    isRefreshing: isRefreshingToken,
    queuedCount: refreshQueue.length,
  };
}

/**
 * Guarda el access_token (5 min) exclusivamente en memoria RAM
 */
export function setVolatileAccessToken(token: string | null, expiresInSeconds = 300): void {
  volatileAccessToken = token;
  volatileAccessTokenExp = token ? Math.floor(Date.now() / 1000) + expiresInSeconds : null;
  notifyTokenListeners();
}

/**
 * Guarda el elevated_token (10 min, mfa_verified: true) exclusivamente en memoria RAM
 */
export function setVolatileElevatedToken(token: string | null, expiresInSeconds = 600): void {
  volatileElevatedToken = token;
  volatileElevatedTokenExp = token ? Math.floor(Date.now() / 1000) + expiresInSeconds : null;
  notifyTokenListeners();
}

/**
 * Limpia todos los tokens volátiles en RAM
 */
export function clearAllVolatileTokens(): void {
  volatileAccessToken = null;
  volatileAccessTokenExp = null;
  volatileElevatedToken = null;
  volatileElevatedTokenExp = null;
  notifyTokenListeners();
}

/**
 * Corrompe/expira intencionalmente el access_token en memoria RAM (y en el backend)
 * para demostrar en vivo el funcionamiento del Interceptor 401 y la Silent Refresh Queue.
 */
export async function forceExpireVolatileAccessToken(): Promise<void> {
  if (volatileAccessToken) {
    try {
      await fetch(`${backendBaseUrl}/auth/debug/expire-access`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${volatileAccessToken}`,
          'Content-Type': 'application/json',
        },
      });
    } catch {
      // Si no hay red o el token ya expiró, igual reemplazamos en RAM por un JWT vencido
    }
  }
  volatileAccessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.EXPIRED_PAYLOAD.EXPIRED_SIG';
  volatileAccessTokenExp = Math.floor(Date.now() / 1000) - 60;
  volatileElevatedToken = null;
  volatileElevatedTokenExp = null;

  addAuditLog({
    category: 'SILENT_REFRESH',
    status: 'WARNING',
    title: 'Access Token Expirado en RAM',
    detail:
      'El access_token en memoria volátil fue marcado como expirado. Las próximas llamadas a la API recibirán 401 Unauthorized y activarán la Silent Refresh Queue.',
  });
  notifyTokenListeners();
}

/**
 * Ejecuta la renovación única POST /auth/refresh y resuelve o rechaza toda la cola de peticiones en espera
 */
async function performSingleSilentRefresh(): Promise<string> {
  const { refreshToken, meta } = await getRefreshTokenFromHardware();

  if (!refreshToken) {
    throw new Error('No existe refresh_token en SecureStore (Keychain / Keystore).');
  }

  addAuditLog({
    category: 'SILENT_REFRESH',
    status: 'INFO',
    title: 'Disparando POST /auth/refresh único',
    detail: `Leyendo refresh_token desde ${
      meta?.storageEngine || 'SecureStore'
    } (${refreshQueue.length} peticiones encoladas esperando resolución).`,
  });

  const response = await fetch(`${backendBaseUrl}/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });

  if (!response.ok) {
    const errBody = await response.json().catch(() => ({}));
    throw new Error(
      errBody.message || `Refresh token rechazado o expirado (HTTP ${response.status})`
    );
  }

  const data = await response.json();
  const newAccessToken: string = data.access_token;
  const newRefreshToken: string = data.refresh_token || refreshToken;

  // Actualizar access_token en memoria volátil (RAM)
  setVolatileAccessToken(newAccessToken, data.expires_in || 300);

  // Actualizar refresh_token en SecureStore si fue rotado
  if (newRefreshToken) {
    await saveRefreshTokenToHardware(newRefreshToken, meta?.userEmail, meta?.userName);
  }

  addAuditLog({
    category: 'SILENT_REFRESH',
    status: 'SUCCESS',
    title: 'Silent Refresh Exitoso (200 OK)',
    detail: `Nuevo access_token cargado en RAM (TTL 5 min). Desbloqueando ${refreshQueue.length} peticiones encoladas.`,
    httpStatus: 200,
  });

  return newAccessToken;
}

export interface ApiRequestOptions extends RequestInit {
  useElevatedTokenIfAvailable?: boolean;
  skipAuth?: boolean;
  _isRetry?: boolean;
}

/**
 * Wrapper HTTP con Interceptor 401 y Cola Silenciosa (Silent Refresh Queue)
 */
export async function apiFetch<T = unknown>(
  endpoint: string,
  options: ApiRequestOptions = {}
): Promise<T> {
  const url = endpoint.startsWith('http') ? endpoint : `${backendBaseUrl}${endpoint}`;
  const {
    useElevatedTokenIfAvailable = false,
    skipAuth = false,
    _isRetry = false,
    headers: customHeaders,
    ...restOptions
  } = options;

  // Si ya hay un Silent Refresh en curso y esta es una petición autenticada,
  // la encolamos inmediatamente para no disparar múltiples llamadas fallidas ni múltiples /auth/refresh.
  if (!skipAuth && isRefreshingToken && !_isRetry) {
    const queuedToken = await new Promise<string>((resolve, reject) => {
      const subId = Math.random().toString(36).slice(2, 7);
      refreshQueue.push({ id: subId, endpoint, resolve, reject });
      notifyTokenListeners();
      addAuditLog({
        category: 'SILENT_REFRESH',
        status: 'INFO',
        title: `Petición Encolada (${endpoint})`,
        detail: `Refresh en curso. Petición #${refreshQueue.length} pausada en la cola de promesas.`,
      });
    });

    return apiFetch<T>(endpoint, {
      ...options,
      _isRetry: true,
      headers: {
        ...(customHeaders as Record<string, string>),
        Authorization: `Bearer ${queuedToken}`,
      },
    });
  }

  // Seleccionar el token de memoria volátil (elevated_token si aplica, o access_token estándar)
  const activeToken =
    useElevatedTokenIfAvailable && volatileElevatedToken
      ? volatileElevatedToken
      : volatileAccessToken;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(customHeaders as Record<string, string>),
  };

  if (!skipAuth && activeToken && !headers.Authorization) {
    headers.Authorization = `Bearer ${activeToken}`;
  }

  const response = await fetch(url, {
    ...restOptions,
    headers,
  });

  // ==========================================================================
  // INTERCEPTOR 401 UNAUTHORIZED -> SILENT REFRESH QUEUE
  // ==========================================================================
  if (response.status === 401 && !skipAuth && !_isRetry) {
    addAuditLog({
      category: 'SILENT_REFRESH',
      status: 'WARNING',
      title: `Interceptado 401 Unauthorized en ${endpoint}`,
      detail: isRefreshingToken
        ? 'Un proceso de renovación ya está activo; encolando esta petición en refreshQueue.'
        : 'Iniciando bloqueo de cola y renovación silenciosa con refresh_token de SecureStore.',
      httpStatus: 401,
    });

    // Crear promesa en la cola para esta petición
    const retryPromise = new Promise<string>((resolve, reject) => {
      const subId = Math.random().toString(36).slice(2, 7);
      refreshQueue.push({ id: subId, endpoint, resolve, reject });
      notifyTokenListeners();
    });

    if (!isRefreshingToken) {
      isRefreshingToken = true;
      notifyTokenListeners();

      performSingleSilentRefresh()
        .then((freshToken) => {
          const pending = [...refreshQueue];
          refreshQueue = [];
          isRefreshingToken = false;
          notifyTokenListeners();
          pending.forEach((subscriber) => subscriber.resolve(freshToken));
        })
        .catch(async (refreshError: Error) => {
          const pending = [...refreshQueue];
          refreshQueue = [];
          isRefreshingToken = false;
          // Limpiar almacenamiento seguro y memoria volátil
          clearAllVolatileTokens();
          await clearRefreshTokenFromHardware();
          notifyTokenListeners();

          addAuditLog({
            category: 'SILENT_REFRESH',
            status: 'ERROR',
            title: 'Refresh Token Vencido o Revocado',
            detail: `${refreshError.message}. Se limpió SecureStore y se cerró la sesión.`,
            httpStatus: 401,
          });

          pending.forEach((subscriber) => subscriber.reject(refreshError));
          if (onSessionExpiredCallback) {
            onSessionExpiredCallback(refreshError.message);
          }
        });
    }

    const newAccessToken = await retryPromise;

    addAuditLog({
      category: 'SILENT_REFRESH',
      status: 'SUCCESS',
      title: `Reintentando ${endpoint} tras Silent Refresh`,
      detail: 'Petición original reanudada transparentemente con el nuevo access_token.',
    });

    return apiFetch<T>(endpoint, {
      ...options,
      _isRetry: true,
      headers: {
        ...(customHeaders as Record<string, string>),
        Authorization: `Bearer ${newAccessToken}`,
      },
    });
  }

  const body = await response.json().catch(() => ({}));

  // ==========================================================================
  // INTERCEPTOR 403 FORBIDDEN (mfa_required -> Step-Up Authentication)
  // ==========================================================================
  if (response.status === 403 && body.error === 'mfa_required') {
    addAuditLog({
      category: 'STEP_UP',
      status: 'WARNING',
      title: '403 Forbidden: Step-Up 2FA Requerido',
      detail: `El recurso ${endpoint} exige mfa_verified: true. Recibido step_up_token temporal para desafío TOTP.`,
      httpStatus: 403,
    });

    const stepUpErr = new Error(
      body.message || 'Se requiere verificación de segundo factor (Step-Up 2FA).'
    ) as StepUpRequiredError;
    stepUpErr.status = 403;
    stepUpErr.code = 'mfa_required';
    stepUpErr.stepUpToken = body.step_up_token;
    throw stepUpErr;
  }

  // ==========================================================================
  // INTERCEPTOR 409 CONFLICT (Replay Attack Detected)
  // ==========================================================================
  if (response.status === 409) {
    addAuditLog({
      category: 'ANTI_REPLAY',
      status: 'ERROR',
      title: '409 Conflict: Replay Attack Detected',
      detail:
        body.message ||
        'El código TOTP enviado ya fue utilizado dentro de la ventana de validez (TTL 90s).',
      httpStatus: 409,
    });

    const replayErr = new Error(
      body.message || '409 Conflict: Replay Attack Detected'
    ) as ReplayAttackError;
    replayErr.status = 409;
    replayErr.code = 'Replay Attack Detected';
    replayErr.ttlRemainingSeconds = body.ttl_remaining_seconds;
    throw replayErr;
  }

  if (!response.ok) {
    throw new Error(body.message || `Error HTTP ${response.status} en ${endpoint}`);
  }

  return body as T;
}

