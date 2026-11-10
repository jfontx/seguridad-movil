/**
 * Contexto Global de Seguridad Móvil:
 * Coordina OAuth 2.0 + PKCE (RFC 7636), Almacenamiento Seguro (SecureStore vs RAM),
 * Silent Refresh Queue, Authenticator TOTP (RFC 6238) y Step-Up 2FA + Anti-Replay.
 */

import * as Linking from 'expo-linking';
import * as WebBrowser from 'expo-web-browser';
import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';

import {
  addAuditLog,
  apiFetch,
  AuditLogEntry,
  clearAllVolatileTokens,
  clearAuditLogs,
  forceExpireVolatileAccessToken,
  getAuditLogs,
  getBackendBaseUrl,
  getVolatileTokenState,
  ReplayAttackError,
  setBackendBaseUrl,
  setOnSessionExpired,
  setVolatileAccessToken,
  setVolatileElevatedToken,
  StepUpRequiredError,
  subscribeAuditLogs,
  subscribeVolatileTokens,
} from '@/services/api-client';
import {
  clearRefreshTokenFromHardware,
  getRefreshTokenFromHardware,
  loadTotpConfigFromHardware,
  RefreshTokenMetadata,
  saveRefreshTokenToHardware,
  saveTotpConfigToHardware,
} from '@/services/secure-storage';
import { createPkceChallengeBundle, PkceSessionBundle } from '@/utils/pkce';
import { OtpAuthConfig, parseOtpAuthUri } from '@/utils/totp';

WebBrowser.maybeCompleteAuthSession();

export interface UserProfile {
  id: string;
  email: string;
  name: string;
  role: string;
}

export interface VaultSecretItem {
  id: string;
  title: string;
  value: string;
  updatedAt: string;
}

export interface VaultDataResponse {
  status: string;
  vault_id: string;
  classification: string;
  accessed_by: string;
  mfa_verified: boolean;
  elevated_exp: number;
  secrets: VaultSecretItem[];
}

interface AuthContextValue {
  user: UserProfile | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  // Estado de tokens (RAM vs Hardware)
  accessToken: string | null;
  accessTokenExp: number | null;
  elevatedToken: string | null;
  elevatedTokenExp: number | null;
  refreshTokenPreview: string | null;
  refreshTokenMeta: RefreshTokenMetadata | null;
  isRefreshing: boolean;
  queuedRequestsCount: number;
  // Ultimo bundle PKCE generado (para mostrar telemetría en UI)
  lastPkceBundle: PkceSessionBundle | null;
  lastAuthError: string | null;
  // TOTP Config
  totpConfig: OtpAuthConfig;
  updateTotpFromUriOrSecret: (rawInput: string) => Promise<OtpAuthConfig>;
  // Acciones Fase 1: OAuth 2.0 + PKCE
  loginWithOAuthPkce: (options?: { simulateCsrfMismatch?: boolean }) => Promise<void>;
  logout: () => Promise<void>;
  // Acciones Fase 2: Silent Refresh Queue
  expireAccessTokenForDemo: () => Promise<void>;
  runConcurrentSilentRefreshDemo: () => Promise<string[]>;
  // Acciones Fase 4: Step-Up & Bóveda Crítica & Anti-Replay
  vaultData: VaultDataResponse | null;
  pendingStepUpToken: string | null;
  stepUpModalVisible: boolean;
  setStepUpModalVisible: (visible: boolean) => void;
  requestVaultAccess: () => Promise<void>;
  verifyStepUpTotp: (code: string) => Promise<void>;
  simulateReplayAttackWithLastCode: (codeOverride?: string) => Promise<{
    blocked: boolean;
    status: number;
    message: string;
  }>;
  lastUsedStepUpInfo: { stepUpToken: string; code: string } | null;
  // Configuración de red y logs
  backendUrl: string;
  updateBackendUrl: (url: string) => void;
  auditLogs: AuditLogEntry[];
  clearLogs: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [volatileState, setVolatileState] = useState(getVolatileTokenState());
  const [refreshTokenPreview, setRefreshTokenPreview] = useState<string | null>(null);
  const [refreshTokenMeta, setRefreshTokenMeta] = useState<RefreshTokenMetadata | null>(null);
  const [lastPkceBundle, setLastPkceBundle] = useState<PkceSessionBundle | null>(null);
  const [lastAuthError, setLastAuthError] = useState<string | null>(null);

  const [totpConfig, setTotpConfig] = useState<OtpAuthConfig>({
    secret: 'JBSWY3DPEHPK3PXP',
    issuer: 'UniSabana',
    account: 'estudiante@unisabana.edu.co',
    period: 30,
    digits: 6,
  });

  const [vaultData, setVaultData] = useState<VaultDataResponse | null>(null);
  const [pendingStepUpToken, setPendingStepUpToken] = useState<string | null>(null);
  const [stepUpModalVisible, setStepUpModalVisible] = useState<boolean>(false);
  const [lastUsedStepUpInfo, setLastUsedStepUpInfo] = useState<{
    stepUpToken: string;
    code: string;
  } | null>(null);

  const [backendUrl, setBackendUrlState] = useState<string>(getBackendBaseUrl());
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>(getAuditLogs());

  const syncHardwareStorageState = useCallback(async () => {
    const { refreshToken, meta } = await getRefreshTokenFromHardware();
    if (refreshToken) {
      setRefreshTokenPreview(
        `${refreshToken.slice(0, 14)}...${refreshToken.slice(-8)}`
      );
      setRefreshTokenMeta(meta);
    } else {
      setRefreshTokenPreview(null);
      setRefreshTokenMeta(null);
    }
  }, []);

  // Suscripción a cambios en memoria volátil y bitácora de auditoría
  useEffect(() => {
    const unsubTokens = subscribeVolatileTokens(() => {
      setVolatileState(getVolatileTokenState());
      setBackendUrlState(getBackendBaseUrl());
    });
    const unsubLogs = subscribeAuditLogs(() => {
      setAuditLogs([...getAuditLogs()]);
    });
    setOnSessionExpired((reason) => {
      setUser(null);
      setVaultData(null);
      setRefreshTokenPreview(null);
      setRefreshTokenMeta(null);
      setLastAuthError(`Sesión finalizada: ${reason}`);
    });

    return () => {
      unsubTokens();
      unsubLogs();
      setOnSessionExpired(null);
    };
  }, []);

  // Carga inicial de configuración TOTP y verificación de refresh_token en SecureStore
  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const savedTotp = await loadTotpConfigFromHardware();
        if (mounted) {
          setTotpConfig(savedTotp);
        }
        const { refreshToken, meta } = await getRefreshTokenFromHardware();
        if (mounted && refreshToken) {
          setRefreshTokenPreview(
            `${refreshToken.slice(0, 14)}...${refreshToken.slice(-8)}`
          );
          setRefreshTokenMeta(meta);
          addAuditLog({
            category: 'STORAGE',
            status: 'INFO',
            title: 'Refresh Token detectado en SecureStore',
            detail: `Enclave: ${meta?.storageEngine}. El access_token en RAM está vacío tras reinicio hasta renovar o iniciar sesión.`,
          });
        }
      } finally {
        if (mounted) {
          setIsLoading(false);
        }
      }
    })();
    return () => {
      mounted = false;
    };
  }, []);

  /**
   * Punto 1: Flujo Completo OAuth 2.0 con PKCE (RFC 7636) + Navegador del Sistema
   */
  const loginWithOAuthPkce = useCallback(
    async (options?: { simulateCsrfMismatch?: boolean }) => {
      setLastAuthError(null);
      setIsLoading(true);

      try {
        // 1. Generar code_verifier, code_challenge (SHA-256 Base64URL) y state anti-CSRF
        const pkceBundle = await createPkceChallengeBundle();
        setLastPkceBundle(pkceBundle);

        const redirectUri = Linking.createURL('oauth/callback');

        addAuditLog({
          category: 'PKCE',
          status: 'INFO',
          title: 'PKCE Generado (RFC 7636)',
          detail: `verifier (${pkceBundle.codeVerifier.length} chars) -> SHA256 challenge: ${pkceBundle.codeChallenge.slice(
            0,
            20
          )}... | state: ${pkceBundle.state.slice(0, 12)}...`,
        });

        // 2. Construir URL de autorización hacia /oauth/authorize
        const authUrl =
          `${getBackendBaseUrl()}/oauth/authorize` +
          `?response_type=code` +
          `&client_id=${encodeURIComponent('unisabana-mobile-app')}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&code_challenge=${encodeURIComponent(pkceBundle.codeChallenge)}` +
          `&code_challenge_method=S256` +
          `&state=${encodeURIComponent(pkceBundle.state)}`;

        addAuditLog({
          category: 'PKCE',
          status: 'INFO',
          title: 'Abriendo Navegador Seguro del Sistema',
          detail: `WebBrowser.openAuthSessionAsync -> ${redirectUri}`,
        });

        // 3. Abrir navegador nativo del sistema (ASWebAuthenticationSession / Chrome Custom Tabs)
        const result = await WebBrowser.openAuthSessionAsync(authUrl, redirectUri);

        if (result.type !== 'success' || !result.url) {
          addAuditLog({
            category: 'PKCE',
            status: 'WARNING',
            title: 'Autenticación Cancelada en Navegador',
            detail: `El navegador retornó estado: ${result.type}`,
          });
          return;
        }

        // 4. Extraer code y state del Deep Link de retorno
        const parsedCallback = Linking.parse(result.url);
        const returnedCode =
          typeof parsedCallback.queryParams?.code === 'string'
            ? parsedCallback.queryParams.code
            : '';
        const rawReturnedState =
          typeof parsedCallback.queryParams?.state === 'string'
            ? parsedCallback.queryParams.state
            : '';

        const returnedState = options?.simulateCsrfMismatch
          ? `${rawReturnedState}_LOCAL_TAMPER`
          : rawReturnedState;

        // 5. Validación estricta Anti-CSRF del parámetro state
        if (!returnedState || returnedState !== pkceBundle.state) {
          const csrfMsg = `Alerta de Seguridad Anti-CSRF: El parámetro state recibido (${returnedState.slice(
            0,
            16
          )}...) NO coincide con el state generado en memoria (${pkceBundle.state.slice(
            0,
            16
          )}...). Intercambio OAuth abortado.`;

          addAuditLog({
            category: 'PKCE',
            status: 'ERROR',
            title: 'Ataque CSRF Detectado (State Mismatch)',
            detail: csrfMsg,
          });
          setLastAuthError(csrfMsg);
          throw new Error(csrfMsg);
        }

        if (!returnedCode) {
          throw new Error('El callback OAuth no incluyó un authorization_code válido.');
        }

        addAuditLog({
          category: 'PKCE',
          status: 'SUCCESS',
          title: 'Deep Link y State Anti-CSRF Validados',
          detail: `code recibido: ${returnedCode.slice(0, 18)}... Canjeando por tokens con code_verifier.`,
        });

        // 6. Token Exchange: Enviar authorization_code + code_verifier a POST /auth/oauth/token
        const tokenResponse = await apiFetch<{
          access_token: string;
          refresh_token: string;
          expires_in: number;
          user: UserProfile;
          totp_provisioning?: {
            otpauth_uri: string;
          };
        }>('/auth/oauth/token', {
          method: 'POST',
          skipAuth: true,
          body: JSON.stringify({
            grant_type: 'authorization_code',
            client_id: 'unisabana-mobile-app',
            redirect_uri: redirectUri,
            code: returnedCode,
            code_verifier: pkceBundle.codeVerifier,
          }),
        });

        // 7. Separación de Memoria:
        // - access_token SOLO en RAM volátil (5 min)
        // - refresh_token en SecureStore cifrado por hardware (30 días)
        setVolatileAccessToken(tokenResponse.access_token, tokenResponse.expires_in || 300);
        setVolatileElevatedToken(null);
        setVaultData(null);

        const meta = await saveRefreshTokenToHardware(
          tokenResponse.refresh_token,
          tokenResponse.user.email,
          tokenResponse.user.name
        );

        await syncHardwareStorageState();
        setUser(tokenResponse.user);

        addAuditLog({
          category: 'STORAGE',
          status: 'SUCCESS',
          title: 'Separación Criptográfica de Tokens Completada',
          detail: `access_token guardado en RAM volátil (5m). refresh_token cifrado en ${meta.storageEngine} (30d).`,
          httpStatus: 200,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Error en flujo OAuth 2.0 + PKCE';
        setLastAuthError(message);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [syncHardwareStorageState]
  );

  /**
   * Cierre de sesión limpiando RAM volátil y SecureStore nativo
   */
  const logout = useCallback(async () => {
    clearAllVolatileTokens();
    await clearRefreshTokenFromHardware();
    await syncHardwareStorageState();
    setUser(null);
    setVaultData(null);
    setPendingStepUpToken(null);
    setStepUpModalVisible(false);

    addAuditLog({
      category: 'STORAGE',
      status: 'INFO',
      title: 'Sesión Cerrada y Almacenamiento Limpio',
      detail: 'Se destruyó access_token/elevated_token de RAM y se eliminó refresh_token de SecureStore.',
    });
  }, [syncHardwareStorageState]);

  /**
   * Punto 2: Demostración de expiración y Silent Refresh Queue con 3 peticiones simultáneas
   */
  const expireAccessTokenForDemo = useCallback(async () => {
    await forceExpireVolatileAccessToken();
  }, []);

  const runConcurrentSilentRefreshDemo = useCallback(async (): Promise<string[]> => {
    // 1. Forzar expiración del access_token actual para provocar 401 Unauthorized real
    await forceExpireVolatileAccessToken();

    addAuditLog({
      category: 'SILENT_REFRESH',
      status: 'INFO',
      title: 'Lanzando 3 Peticiones Concurrentes en Vuelo',
      detail: 'Disparando simultáneamente GET /api/perfil, GET /api/auditoria y GET /api/recursos con token expirado.',
    });

    // 2. Disparar 3 llamadas en paralelo
    const [perfilRes, auditoriaRes, recursosRes] = await Promise.all([
      apiFetch<{ endpoint: string; token_jti: string }>('/api/perfil'),
      apiFetch<{ endpoint: string; token_jti: string }>('/api/auditoria'),
      apiFetch<{ endpoint: string; token_jti: string }>('/api/recursos'),
    ]);

    await syncHardwareStorageState();

    if (!user) {
      setUser({
        id: 'usr_unisabana_001',
        email: 'estudiante@unisabana.edu.co',
        name: 'Estudiante Ingeniería UniSabana',
        role: 'student_researcher',
      });
    }

    return [
      `1. ${perfilRes.endpoint} -> 200 OK (jti: ${perfilRes.token_jti.slice(0, 8)})`,
      `2. ${auditoriaRes.endpoint} -> 200 OK (jti: ${auditoriaRes.token_jti.slice(0, 8)})`,
      `3. ${recursosRes.endpoint} -> 200 OK (jti: ${recursosRes.token_jti.slice(0, 8)})`,
    ];
  }, [syncHardwareStorageState, user]);

  /**
   * Punto 3: Actualizar semilla TOTP desde escaneo QR (otpauth://) o entrada manual Base32
   */
  const updateTotpFromUriOrSecret = useCallback(
    async (rawInput: string): Promise<OtpAuthConfig> => {
      const parsed = parseOtpAuthUri(rawInput);
      await saveTotpConfigToHardware(parsed);
      setTotpConfig(parsed);

      addAuditLog({
        category: 'TOTP',
        status: 'SUCCESS',
        title: 'Semilla TOTP Configurada en Enclave Local',
        detail: `Emisor: ${parsed.issuer} | Cuenta: ${parsed.account} | Semilla Base32 (${parsed.secret.length} chars) lista para Modo Avión.`,
      });

      return parsed;
    },
    []
  );

  /**
   * Punto 4 (Fase 2): Solicitar acceso a GET /api/boveda-critica.
   * Si responde 403 Forbidden (mfa_required), atrapa el step_up_token y abre el modal de 2FA.
   */
  const requestVaultAccess = useCallback(async () => {
    setLastAuthError(null);
    try {
      const data = await apiFetch<VaultDataResponse>('/api/boveda-critica', {
        method: 'GET',
        useElevatedTokenIfAvailable: true,
      });
      setVaultData(data);
      addAuditLog({
        category: 'STEP_UP',
        status: 'SUCCESS',
        title: 'Acceso Autorizado a Bóveda Crítica (200 OK)',
        detail: `Clasificación: ${data.classification}. Secretos desbloqueados con elevated_token.`,
        httpStatus: 200,
      });
    } catch (err) {
      const maybeStepUp = err as StepUpRequiredError;
      if (maybeStepUp && maybeStepUp.status === 403 && maybeStepUp.stepUpToken) {
        setPendingStepUpToken(maybeStepUp.stepUpToken);
        setStepUpModalVisible(true);
        return;
      }
      throw err;
    }
  }, []);

  /**
   * Punto 4 (Fase 3): Enviar step_up_token + código TOTP de 6 dígitos a POST /auth/mfa/verify
   */
  const verifyStepUpTotp = useCallback(
    async (code: string) => {
      if (!pendingStepUpToken) {
        throw new Error(
          'No hay un step_up_token activo. Solicita primero el acceso a la Bóveda Crítica.'
        );
      }

      const cleanCode = code.replace(/\s+/g, '');
      const response = await apiFetch<{
        status: string;
        elevated_token: string;
        mfa_verified: boolean;
        expires_in: number;
        matched_window: string;
      }>('/auth/mfa/verify', {
        method: 'POST',
        body: JSON.stringify({
          step_up_token: pendingStepUpToken,
          code: cleanCode,
          secret_override: totpConfig.secret,
        }),
      });

      // Guardar el par (step_up_token, code) recién usado para permitir demostrar el ataque Anti-Replay (Prueba #5)
      setLastUsedStepUpInfo({
        stepUpToken: pendingStepUpToken,
        code: cleanCode,
      });

      // Guardar elevated_token en RAM volátil (10 minutos)
      setVolatileElevatedToken(response.elevated_token, response.expires_in || 600);
      setStepUpModalVisible(false);

      addAuditLog({
        category: 'STEP_UP',
        status: 'SUCCESS',
        title: `2FA TOTP Verificado (Ventana ${response.matched_window})`,
        detail:
          'Recibido elevated_token con claim mfa_verified: true (TTL 10 min). Código registrado en caché Anti-Replay (TTL 90s).',
        httpStatus: 200,
      });

      // Reintentar inmediatamente la apertura de la Bóveda Crítica con el elevated_token
      const unlockedVault = await apiFetch<VaultDataResponse>('/api/boveda-critica', {
        method: 'GET',
        useElevatedTokenIfAvailable: true,
        headers: {
          Authorization: `Bearer ${response.elevated_token}`,
        },
      });
      setVaultData(unlockedVault);
    },
    [pendingStepUpToken, totpConfig.secret]
  );

  /**
   * Prueba de Aceptación #5: Ataque de Repetición (Anti-Replay)
   * Reenvía inmediatamente el mismo código TOTP dentro de la ventana de validez
   * para demostrar que el backend rechaza la solicitud con 409 Conflict.
   */
  const simulateReplayAttackWithLastCode = useCallback(
    async (
      codeOverride?: string
    ): Promise<{ blocked: boolean; status: number; message: string }> => {
      const tokenToUse = lastUsedStepUpInfo?.stepUpToken || pendingStepUpToken;
      const codeToUse = (codeOverride || lastUsedStepUpInfo?.code || '').replace(/\s+/g, '');

      if (!tokenToUse || !codeToUse) {
        throw new Error(
          'Primero verifica un código TOTP en la Bóveda Crítica para poder repetir ese mismo código.'
        );
      }

      try {
        await apiFetch('/auth/mfa/verify', {
          method: 'POST',
          body: JSON.stringify({
            step_up_token: tokenToUse,
            code: codeToUse,
            secret_override: totpConfig.secret,
          }),
        });
        return {
          blocked: false,
          status: 200,
          message: 'El código fue aceptado (no estaba en caché Anti-Replay).',
        };
      } catch (err) {
        const replayErr = err as ReplayAttackError;
        if (replayErr && replayErr.status === 409) {
          return {
            blocked: true,
            status: 409,
            message: replayErr.message,
          };
        }
        throw err;
      }
    },
    [lastUsedStepUpInfo, pendingStepUpToken, totpConfig.secret]
  );

  const updateBackendUrl = useCallback((url: string) => {
    setBackendBaseUrl(url);
    setBackendUrlState(getBackendBaseUrl());
  }, []);

  const clearLogs = useCallback(() => {
    clearAuditLogs();
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      isAuthenticated: Boolean(volatileState.accessToken || refreshTokenPreview),
      isLoading,
      accessToken: volatileState.accessToken,
      accessTokenExp: volatileState.accessTokenExp,
      elevatedToken: volatileState.elevatedToken,
      elevatedTokenExp: volatileState.elevatedTokenExp,
      refreshTokenPreview,
      refreshTokenMeta,
      isRefreshing: volatileState.isRefreshing,
      queuedRequestsCount: volatileState.queuedCount,
      lastPkceBundle,
      lastAuthError,
      totpConfig,
      updateTotpFromUriOrSecret,
      loginWithOAuthPkce,
      logout,
      expireAccessTokenForDemo,
      runConcurrentSilentRefreshDemo,
      vaultData,
      pendingStepUpToken,
      stepUpModalVisible,
      setStepUpModalVisible,
      requestVaultAccess,
      verifyStepUpTotp,
      simulateReplayAttackWithLastCode,
      lastUsedStepUpInfo,
      backendUrl,
      updateBackendUrl,
      auditLogs,
      clearLogs,
    }),
    [
      user,
      volatileState,
      refreshTokenPreview,
      refreshTokenMeta,
      isLoading,
      lastPkceBundle,
      lastAuthError,
      totpConfig,
      updateTotpFromUriOrSecret,
      loginWithOAuthPkce,
      logout,
      expireAccessTokenForDemo,
      runConcurrentSilentRefreshDemo,
      vaultData,
      pendingStepUpToken,
      stepUpModalVisible,
      requestVaultAccess,
      verifyStepUpTotp,
      simulateReplayAttackWithLastCode,
      lastUsedStepUpInfo,
      backendUrl,
      updateBackendUrl,
      auditLogs,
      clearLogs,
    ]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth debe usarse dentro de un <AuthProvider>');
  }
  return ctx;
}

