/**
 * Punto 2: Almacenamiento Seguro Nativo (iOS Keychain / Android Keystore vía expo-secure-store)
 *
 * Estrategia de Separación de Memoria:
 * - access_token y elevated_token: VIVEN ÚNICAMENTE EN MEMORIA VOLÁTIL (RAM).
 *   Prohibido persistirlos en disco, AsyncStorage o SecureStore.
 * - refresh_token: Se persiste en el enclave seguro cifrado por hardware (expo-secure-store).
 * - totp_config: Se persiste en SecureStore para operar 100% offline en Modo Avión.
 */

import * as SecureStore from 'expo-secure-store';
import { Platform } from 'react-native';

import {
  DEFAULT_LAB_OTPAUTH_URI,
  DEFAULT_LAB_SECRET,
  OtpAuthConfig,
  parseOtpAuthUri,
} from '@/utils/totp';

const REFRESH_TOKEN_KEY = 'unisabana_secure_refresh_token';
const REFRESH_META_KEY = 'unisabana_secure_refresh_meta';
const TOTP_CONFIG_KEY = 'unisabana_secure_totp_config';

// Fallback únicamente para entorno Web (donde iOS Keychain / Android Keystore no existen)
const webMemoryVault = new Map<string, string>();

export interface RefreshTokenMetadata {
  savedAt: number;
  expiresAt: number;
  userEmail: string;
  userName: string;
  storageEngine: 'iOS Keychain / Android Keystore (expo-secure-store)' | 'Web Memory Fallback';
}

async function isNativeSecureStoreAvailable(): Promise<boolean> {
  if (Platform.OS === 'web') {
    return false;
  }
  try {
    return await SecureStore.isAvailableAsync();
  } catch {
    return false;
  }
}

const SECURE_STORE_OPTIONS: SecureStore.SecureStoreOptions = {
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

/**
 * Persiste el refresh_token (vida útil 30 días) en el enclave de hardware nativo
 */
export async function saveRefreshTokenToHardware(
  refreshToken: string,
  userEmail = 'estudiante@unisabana.edu.co',
  userName = 'Estudiante Ingeniería UniSabana'
): Promise<RefreshTokenMetadata> {
  const now = Date.now();
  const nativeAvailable = await isNativeSecureStoreAvailable();

  const meta: RefreshTokenMetadata = {
    savedAt: now,
    expiresAt: now + 30 * 24 * 60 * 60 * 1000, // 30 días
    userEmail,
    userName,
    storageEngine: nativeAvailable
      ? 'iOS Keychain / Android Keystore (expo-secure-store)'
      : 'Web Memory Fallback',
  };

  if (nativeAvailable) {
    await SecureStore.setItemAsync(REFRESH_TOKEN_KEY, refreshToken, SECURE_STORE_OPTIONS);
    await SecureStore.setItemAsync(REFRESH_META_KEY, JSON.stringify(meta), SECURE_STORE_OPTIONS);
  } else {
    webMemoryVault.set(REFRESH_TOKEN_KEY, refreshToken);
    webMemoryVault.set(REFRESH_META_KEY, JSON.stringify(meta));
  }

  return meta;
}

/**
 * Lee el refresh_token desde el enclave de seguridad nativo
 */
export async function getRefreshTokenFromHardware(): Promise<{
  refreshToken: string | null;
  meta: RefreshTokenMetadata | null;
}> {
  const nativeAvailable = await isNativeSecureStoreAvailable();
  let refreshToken: string | null = null;
  let rawMeta: string | null = null;

  if (nativeAvailable) {
    refreshToken = await SecureStore.getItemAsync(REFRESH_TOKEN_KEY, SECURE_STORE_OPTIONS);
    rawMeta = await SecureStore.getItemAsync(REFRESH_META_KEY, SECURE_STORE_OPTIONS);
  } else {
    refreshToken = webMemoryVault.get(REFRESH_TOKEN_KEY) ?? null;
    rawMeta = webMemoryVault.get(REFRESH_META_KEY) ?? null;
  }

  let meta: RefreshTokenMetadata | null = null;
  if (rawMeta) {
    try {
      meta = JSON.parse(rawMeta) as RefreshTokenMetadata;
    } catch {
      meta = null;
    }
  }

  return { refreshToken, meta };
}

/**
 * Elimina el refresh_token del enclave seguro (Logout o revocación por expiración de 30 días)
 */
export async function clearRefreshTokenFromHardware(): Promise<void> {
  const nativeAvailable = await isNativeSecureStoreAvailable();
  if (nativeAvailable) {
    await SecureStore.deleteItemAsync(REFRESH_TOKEN_KEY, SECURE_STORE_OPTIONS);
    await SecureStore.deleteItemAsync(REFRESH_META_KEY, SECURE_STORE_OPTIONS);
  } else {
    webMemoryVault.delete(REFRESH_TOKEN_KEY);
    webMemoryVault.delete(REFRESH_META_KEY);
  }
}

/**
 * Guarda la semilla TOTP en el enclave seguro para que el Authenticator opere en Modo Avión
 */
export async function saveTotpConfigToHardware(config: OtpAuthConfig): Promise<void> {
  const nativeAvailable = await isNativeSecureStoreAvailable();
  const serialized = JSON.stringify(config);
  if (nativeAvailable) {
    await SecureStore.setItemAsync(TOTP_CONFIG_KEY, serialized, SECURE_STORE_OPTIONS);
  } else {
    webMemoryVault.set(TOTP_CONFIG_KEY, serialized);
  }
}

/**
 * Recupera la configuración TOTP desde el enclave seguro (o carga la semilla oficial del laboratorio)
 */
export async function loadTotpConfigFromHardware(): Promise<OtpAuthConfig> {
  const nativeAvailable = await isNativeSecureStoreAvailable();
  let raw: string | null = null;

  if (nativeAvailable) {
    raw = await SecureStore.getItemAsync(TOTP_CONFIG_KEY, SECURE_STORE_OPTIONS);
  } else {
    raw = webMemoryVault.get(TOTP_CONFIG_KEY) ?? null;
  }

  if (raw) {
    try {
      const parsed = JSON.parse(raw) as OtpAuthConfig;
      if (parsed && parsed.secret) {
        return parsed;
      }
    } catch {
      // Fallback a configuración por defecto
    }
  }

  return parseOtpAuthUri(DEFAULT_LAB_OTPAUTH_URI || DEFAULT_LAB_SECRET);
}

