/**
 * Punto 1: Generador Criptográfico de PKCE (RFC 7636) y Protección Anti-CSRF
 *
 * - code_verifier: Cadena aleatoria de alta entropía (43 a 128 caracteres, URL-safe: [A-Z], [a-z], [0-9], -, ., _, ~)
 * - code_challenge: Hash SHA-256 del code_verifier, codificado en Base64URL sin relleno (unpadded)
 * - state: Parámetro aleatorio único por solicitud para protección Anti-CSRF
 */

import * as Crypto from 'expo-crypto';

const PKCE_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export interface PkceSessionBundle {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
  state: string;
  createdAt: number;
}

/**
 * Codifica un Uint8Array en Base64URL sin relleno (unpadded) según RFC 4648 §5 y RFC 7636
 */
export function uint8ArrayToBase64Url(bytes: Uint8Array): string {
  let result = '';
  const len = bytes.length;

  for (let i = 0; i < len; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < len ? bytes[i + 1] : 0;
    const b2 = i + 2 < len ? bytes[i + 2] : 0;

    const triplet = (b0 << 16) | (b1 << 8) | b2;

    result += BASE64_CHARS[(triplet >>> 18) & 0x3f];
    result += BASE64_CHARS[(triplet >>> 12) & 0x3f];
    if (i + 1 < len) {
      result += BASE64_CHARS[(triplet >>> 6) & 0x3f];
    }
    if (i + 2 < len) {
      result += BASE64_CHARS[triplet & 0x3f];
    }
  }

  return result.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Convierte Base64 estándar a Base64URL sin relleno (unpadded)
 */
export function base64ToBase64Url(base64: string): string {
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Genera un code_verifier de alta entropía (por defecto 64 caracteres, dentro del rango RFC 7636 de 43..128)
 */
export function generateCodeVerifier(length = 64): string {
  const safeLength = Math.max(43, Math.min(128, length));
  const randomBytes = Crypto.getRandomBytes(safeLength);
  let verifier = '';
  for (let i = 0; i < safeLength; i++) {
    verifier += PKCE_CHARSET[randomBytes[i] % PKCE_CHARSET.length];
  }
  return verifier;
}

/**
 * Calcula code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) sin padding '='
 */
export async function generateCodeChallenge(codeVerifier: string): Promise<string> {
  try {
    const base64Digest = await Crypto.digestStringAsync(
      Crypto.CryptoDigestAlgorithm.SHA256,
      codeVerifier,
      { encoding: Crypto.CryptoEncoding.BASE64 }
    );
    return base64ToBase64Url(base64Digest);
  } catch {
    const asciiBytes = new Uint8Array(codeVerifier.length);
    for (let i = 0; i < codeVerifier.length; i++) {
      asciiBytes[i] = codeVerifier.charCodeAt(i) & 0x7f;
    }
    const digestBuffer = await Crypto.digest(Crypto.CryptoDigestAlgorithm.SHA256, asciiBytes);
    return uint8ArrayToBase64Url(new Uint8Array(digestBuffer));
  }
}

/**
 * Genera un token state aleatorio único por solicitud para mitigar ataques CSRF en el callback OAuth
 */
export function generateAntiCsrfState(byteLength = 24): string {
  const randomBytes = Crypto.getRandomBytes(byteLength);
  return uint8ArrayToBase64Url(randomBytes);
}

/**
 * Construye el paquete completo PKCE + Anti-CSRF para iniciar el flujo OAuth 2.0
 */
export async function createPkceChallengeBundle(): Promise<PkceSessionBundle> {
  const codeVerifier = generateCodeVerifier(64);
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const state = generateAntiCsrfState(24);

  return {
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: 'S256',
    state,
    createdAt: Date.now(),
  };
}

