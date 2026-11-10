/**
 * Punto 3: Módulo Authenticator Propio — TOTP desde Cero en Modo Avión (RFC 6238)
 *
 * REGLA INVIOLABLE:
 * Prohibido el uso de librerías de alto nivel de TOTP (otplib, speakeasy, etc.).
 * Implementación matemática directa de:
 * - Decodificador Base32 (RFC 4648)
 * - Ventana de tiempo T = floor(UnixTimestamp / 30) en entero de 64 bits Big-Endian (8 bytes)
 * - HMAC-SHA1 (RFC 2104) sobre primitiva de hashing SHA-1 (expo-crypto + RFC 3174)
 * - Dynamic Truncation (RFC 4226 / RFC 6238) -> 6 dígitos con ceros a la izquierda
 */

import * as Crypto from 'expo-crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export const DEFAULT_LAB_SECRET = 'JBSWY3DPEHPK3PXP';
export const DEFAULT_LAB_OTPAUTH_URI =
  'otpauth://totp/UniSabana:estudiante@unisabana.edu.co?secret=JBSWY3DPEHPK3PXP&issuer=UniSabana';

export interface OtpAuthConfig {
  secret: string;
  issuer: string;
  account: string;
  period: number;
  digits: number;
}

export interface TotpComputationResult {
  otp: string;
  formattedOtp: string;
  unixSeconds: number;
  timeWindow: number;
  timeWindowHex: string;
  remainingSeconds: number;
  progress: number;
  hmacHex: string;
  offset: number;
  binCode: number;
}

/**
 * Valida si una cadena es una semilla Base32 válida (RFC 4648)
 */
export function isValidBase32(input: string): boolean {
  const cleaned = input.toUpperCase().replace(/[\s=-]+/g, '');
  if (cleaned.length < 8) {
    return false;
  }
  for (let i = 0; i < cleaned.length; i++) {
    if (!BASE32_ALPHABET.includes(cleaned[i])) {
      return false;
    }
  }
  return true;
}

/**
 * Decodificador Base32 (RFC 4648) desde cero a Uint8Array
 */
export function decodeBase32(base32Input: string): Uint8Array {
  const cleaned = base32Input.toUpperCase().replace(/[\s=-]+/g, '');
  if (!cleaned) {
    throw new Error('La semilla Base32 no puede estar vacía.');
  }

  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (let i = 0; i < cleaned.length; i++) {
    const char = cleaned[i];
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) {
      throw new Error(`Carácter inválido en semilla Base32: "${char}"`);
    }
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return new Uint8Array(bytes);
}

/**
 * Parsea tanto una URI otpauth://totp/... como una semilla Base32 pegada manualmente
 */
export function parseOtpAuthUri(rawInput: string): OtpAuthConfig {
  const trimmed = rawInput.trim();

  if (trimmed.toLowerCase().startsWith('otpauth://')) {
    try {
      const url = new URL(trimmed);
      if (url.protocol !== 'otpauth:' || url.host.toLowerCase() !== 'totp') {
        throw new Error('El código QR debe tener el esquema otpauth://totp/...');
      }

      const rawLabel = decodeURIComponent(url.pathname.replace(/^\/+/, ''));
      let issuer = url.searchParams.get('issuer') || 'UniSabana';
      let account = rawLabel || 'estudiante@unisabana.edu.co';

      if (rawLabel.includes(':')) {
        const [labelIssuer, ...rest] = rawLabel.split(':');
        if (!url.searchParams.get('issuer') && labelIssuer) {
          issuer = labelIssuer.trim();
        }
        account = rest.join(':').trim() || account;
      }

      const secret = (url.searchParams.get('secret') || '')
        .toUpperCase()
        .replace(/[\s=-]+/g, '');

      if (!isValidBase32(secret)) {
        throw new Error('La URI otpauth:// no contiene un parámetro secret Base32 válido.');
      }

      const period = Number(url.searchParams.get('period') || '30') || 30;
      const digits = Number(url.searchParams.get('digits') || '6') || 6;

      return {
        secret,
        issuer,
        account,
        period,
        digits,
      };
    } catch (err) {
      if (err instanceof Error) throw err;
      throw new Error('Formato de URI otpauth:// inválido.');
    }
  }

  const cleanedSecret = trimmed.toUpperCase().replace(/[\s=-]+/g, '');
  if (!isValidBase32(cleanedSecret)) {
    throw new Error(
      'Semilla Base32 inválida. Solo se permiten caracteres A-Z y dígitos 2-7 (mínimo 8 caracteres).'
    );
  }

  return {
    secret: cleanedSecret,
    issuer: 'UniSabana',
    account: 'estudiante@unisabana.edu.co',
    period: 30,
    digits: 6,
  };
}

/**
 * Paso 1 del Algoritmo RFC 6238:
 * Ventana de Tiempo T = floor(UnixTimestamp / 30)
 * Formateada como entero de 64 bits en formato Big-Endian (buffer de 8 bytes).
 */
export function buildTimeBufferBigEndian(
  unixSeconds: number,
  period = 30
): { timeWindow: number; buffer: Uint8Array; hex: string } {
  const timeWindow = Math.floor(unixSeconds / period);
  const buffer = new Uint8Array(8);

  let temp = timeWindow;
  for (let i = 7; i >= 0; i--) {
    buffer[i] = temp & 0xff;
    temp = Math.floor(temp / 256);
  }

  const hex = Array.from(buffer)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  return { timeWindow, buffer, hex };
}

/**
 * Implementación pura de SHA-1 (RFC 3174) sobre Uint8Array.
 * Garantiza operación síncrona inmediata sin parpadeos de UI y 100% offline en Modo Avión,
 * complementando el motor nativo de expo-crypto.
 */
export function sha1BytesSync(message: Uint8Array): Uint8Array {
  const ml = message.length * 8;
  const withOne = message.length + 1;
  const zeroPadBytes = (64 - ((withOne + 8) % 64)) % 64;
  const totalLength = withOne + zeroPadBytes + 8;

  const padded = new Uint8Array(totalLength);
  padded.set(message, 0);
  padded[message.length] = 0x80;

  // Longitud en bits como entero de 64 bits Big-Endian al final
  const highBits = Math.floor(ml / 0x100000000);
  const lowBits = ml >>> 0;
  const view = new DataView(padded.buffer);
  view.setUint32(totalLength - 8, highBits, false);
  view.setUint32(totalLength - 4, lowBits, false);

  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;

  const w = new Uint32Array(80);

  for (let offset = 0; offset < totalLength; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 80; i++) {
      const n = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
      w[i] = ((n << 1) | (n >>> 31)) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;

    for (let i = 0; i < 80; i++) {
      let f = 0;
      let k = 0;
      if (i < 20) {
        f = (b & c) | (~b & d);
        k = 0x5a827999;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6;
      }

      const temp = ((((a << 5) | (a >>> 27)) >>> 0) + (f >>> 0) + e + k + w[i]) >>> 0;
      e = d;
      d = c;
      c = ((b << 30) | (b >>> 2)) >>> 0;
      b = a;
      a = temp;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
  }

  const out = new Uint8Array(20);
  const outView = new DataView(out.buffer);
  outView.setUint32(0, h0, false);
  outView.setUint32(4, h1, false);
  outView.setUint32(8, h2, false);
  outView.setUint32(12, h3, false);
  outView.setUint32(16, h4, false);
  return out;
}

/**
 * Hash SHA-1 usando la utilidad nativa expo-crypto (con fallback a RFC 3174 si aplica)
 */
async function sha1BytesNative(data: Uint8Array): Promise<Uint8Array> {
  try {
    const copy = new Uint8Array(data.byteLength);
    copy.set(data);
    const digestBuffer = await Crypto.digest(Crypto.CryptoDigestAlgorithm.SHA1, copy);
    return new Uint8Array(digestBuffer);
  } catch {
    return sha1BytesSync(data);
  }
}

/**
 * Paso 2 del Algoritmo RFC 6238:
 * H = HMAC-SHA1(ClaveSecretaEnBytes, T) según RFC 2104:
 * HMAC(K, m) = SHA1((K' XOR opad) || SHA1((K' XOR ipad) || m))
 */
export function hmacSha1Sync(keyBytes: Uint8Array, messageBytes: Uint8Array): Uint8Array {
  const blockSize = 64;
  const normalizedKey = keyBytes.length > blockSize ? sha1BytesSync(keyBytes) : keyBytes;

  const keyBlock = new Uint8Array(blockSize);
  keyBlock.set(normalizedKey, 0);

  const ipad = new Uint8Array(blockSize);
  const opad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    ipad[i] = keyBlock[i] ^ 0x36;
    opad[i] = keyBlock[i] ^ 0x5c;
  }

  const innerInput = new Uint8Array(blockSize + messageBytes.length);
  innerInput.set(ipad, 0);
  innerInput.set(messageBytes, blockSize);
  const innerHash = sha1BytesSync(innerInput);

  const outerInput = new Uint8Array(blockSize + innerHash.length);
  outerInput.set(opad, 0);
  outerInput.set(innerHash, blockSize);
  return sha1BytesSync(outerInput);
}

export async function hmacSha1Async(
  keyBytes: Uint8Array,
  messageBytes: Uint8Array
): Promise<Uint8Array> {
  const blockSize = 64;
  const normalizedKey =
    keyBytes.length > blockSize ? await sha1BytesNative(keyBytes) : keyBytes;

  const keyBlock = new Uint8Array(blockSize);
  keyBlock.set(normalizedKey, 0);

  const ipad = new Uint8Array(blockSize);
  const opad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    ipad[i] = keyBlock[i] ^ 0x36;
    opad[i] = keyBlock[i] ^ 0x5c;
  }

  const innerInput = new Uint8Array(blockSize + messageBytes.length);
  innerInput.set(ipad, 0);
  innerInput.set(messageBytes, blockSize);
  const innerHash = await sha1BytesNative(innerInput);

  const outerInput = new Uint8Array(blockSize + innerHash.length);
  outerInput.set(opad, 0);
  outerInput.set(innerHash, blockSize);
  return sha1BytesNative(outerInput);
}

/**
 * Paso 3 del Algoritmo RFC 6238:
 * Dynamic Truncation (Truncamiento Dinámico):
 * - Leer último byte de H: offset = H[19] & 0x0F
 * - Extraer 4 bytes consecutivos desde offset enmascarando el bit de signo (0x7F)
 * - TOTP = bin_code % 1000000 (formateado a 6 dígitos con ceros a la izquierda)
 */
export function dynamicTruncation(hmac: Uint8Array): {
  offset: number;
  binCode: number;
  otp: string;
} {
  const offset = hmac[19] & 0x0f;
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = (binCode % 1_000_000).toString().padStart(6, '0');
  return { offset, binCode, otp };
}

/**
 * Cálculo TOTP completo (Síncrono para renderizado instantáneo sin parpadeos en el temporizador)
 */
export function computeTotpSync(
  secretBase32: string,
  unixSeconds = Math.floor(Date.now() / 1000),
  period = 30
): TotpComputationResult {
  const secretBytes = decodeBase32(secretBase32);
  const { timeWindow, buffer: timeBuffer, hex: timeWindowHex } = buildTimeBufferBigEndian(
    unixSeconds,
    period
  );

  const hmac = hmacSha1Sync(secretBytes, timeBuffer);
  const { offset, binCode, otp } = dynamicTruncation(hmac);

  const hmacHex = Array.from(hmac)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  const elapsedInWindow = unixSeconds % period;
  const remainingSeconds = period - elapsedInWindow;
  const progress = remainingSeconds / period;

  return {
    otp,
    formattedOtp: `${otp.slice(0, 3)} ${otp.slice(3, 6)}`,
    unixSeconds,
    timeWindow,
    timeWindowHex,
    remainingSeconds,
    progress,
    hmacHex,
    offset,
    binCode,
  };
}

/**
 * Cálculo TOTP asíncrono empleando expo-crypto (CryptoDigestAlgorithm.SHA1)
 */
export async function computeTotpAsync(
  secretBase32: string,
  unixSeconds = Math.floor(Date.now() / 1000),
  period = 30
): Promise<TotpComputationResult> {
  const secretBytes = decodeBase32(secretBase32);
  const { timeWindow, buffer: timeBuffer, hex: timeWindowHex } = buildTimeBufferBigEndian(
    unixSeconds,
    period
  );

  const hmac = await hmacSha1Async(secretBytes, timeBuffer);
  const { offset, binCode, otp } = dynamicTruncation(hmac);

  const hmacHex = Array.from(hmac)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  const elapsedInWindow = unixSeconds % period;
  const remainingSeconds = period - elapsedInWindow;
  const progress = remainingSeconds / period;

  return {
    otp,
    formattedOtp: `${otp.slice(0, 3)} ${otp.slice(3, 6)}`,
    unixSeconds,
    timeWindow,
    timeWindowHex,
    remainingSeconds,
    progress,
    hmacHex,
    offset,
    binCode,
  };
}

