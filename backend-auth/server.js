/**
 * Universidad de La Sabana — Facultad de Ingeniería
 * Guía de Laboratorio (Sesión 14): Seguridad Móvil
 * Backend OAuth 2.0 con PKCE (RFC 7636), Silent Refresh, Step-Up 2FA (TOTP RFC 6238) y Anti-Replay
 */

const express = require('express');
const cors = require('cors');
const crypto = require('node:crypto');

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'unisabana-compass-secret-key-2026-hmac-sha256';

// Semilla Base32 oficial del laboratorio (RFC 4648)
const DEFAULT_TOTP_SECRET = 'JBSWY3DPEHPK3PXP';
const DEFAULT_OTPAUTH_URI =
  'otpauth://totp/UniSabana:estudiante@unisabana.edu.co?secret=JBSWY3DPEHPK3PXP&issuer=UniSabana';

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================================================
// 1. ALMACENAMIENTO EN MEMORIA (Sesiones, Códigos PKCE y Caché Anti-Replay)
// ============================================================================

/**
 * authorizationCodes: Map<code, {
 *   clientId: string,
 *   redirectUri: string,
 *   codeChallenge: string,
 *   codeChallengeMethod: string,
 *   user: { id: string, email: string, name: string, role: string, totpSecret: string },
 *   expiresAt: number
 * }>
 */
const authorizationCodes = new Map();

/**
 * refreshTokens: Map<token, {
 *   userId: string,
 *   user: object,
 *   createdAt: number,
 *   expiresAt: number,
 *   revoked: boolean
 * }>
 */
const refreshTokens = new Map();

/**
 * revokedAccessJtis: Set<string> para permitir simular expiración inmediata en sustentación
 */
const revokedAccessJtis = new Set();

/**
 * replayCache: Map<cacheKey, { code: string, usedAt: number, expiresAt: number, window: string }>
 * Registra códigos TOTP validados por usuario con TTL de 90 segundos (3 ventanas de 30s)
 */
const replayCache = new Map();

// Limpieza periódica de cachés expirados
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of authorizationCodes.entries()) {
    if (val.expiresAt < now) authorizationCodes.delete(key);
  }
  for (const [key, val] of replayCache.entries()) {
    if (val.expiresAt < now) replayCache.delete(key);
  }
}, 15_000).unref();

// ============================================================================
// 2. UTILIDADES CRIPTOGRÁFICAS: JWT, PKCE (RFC 7636) y TOTP (RFC 6238)
// ============================================================================

function base64UrlEncode(buffer) {
  return Buffer.from(buffer)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64');
}

/**
 * Firma un token JWT compacto (HS256) sin librerías externas
 */
function signJwt(payload, expiresInSeconds) {
  const nowSec = Math.floor(Date.now() / 1000);
  const header = { alg: 'HS256', typ: 'JWT' };
  const fullPayload = {
    ...payload,
    jti: crypto.randomUUID(),
    iat: nowSec,
    exp: nowSec + expiresInSeconds,
  };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(fullPayload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(signingInput)
    .digest();
  return {
    token: `${signingInput}.${base64UrlEncode(signature)}`,
    payload: fullPayload,
  };
}

/**
 * Verifica un JWT firmado con HS256
 */
function verifyJwt(token) {
  if (!token || typeof token !== 'string') {
    throw new Error('Token ausente o malformado');
  }
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Estructura JWT inválida');
  }
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const expectedSig = base64UrlEncode(
    crypto.createHmac('sha256', JWT_SECRET).update(signingInput).digest()
  );
  if (expectedSig !== encodedSignature) {
    throw new Error('Firma criptográfica JWT inválida');
  }
  const payload = JSON.parse(base64UrlDecode(encodedPayload).toString('utf8'));
  const nowSec = Math.floor(Date.now() / 1000);
  if (payload.exp && nowSec >= payload.exp) {
    const err = new Error('Token expirado');
    err.code = 'TOKEN_EXPIRED';
    throw err;
  }
  if (payload.jti && revokedAccessJtis.has(payload.jti)) {
    const err = new Error('Token revocado o expirado forzosamente');
    err.code = 'TOKEN_EXPIRED';
    throw err;
  }
  return payload;
}

/**
 * Decodificador Base32 (RFC 4648) desde cero
 */
function decodeBase32(base32Str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = String(base32Str)
    .toUpperCase()
    .replace(/[\s=-]+/g, '');

  let bits = 0;
  let value = 0;
  const output = [];

  for (let i = 0; i < cleaned.length; i++) {
    const idx = alphabet.indexOf(cleaned[i]);
    if (idx === -1) {
      throw new Error(`Carácter Base32 inválido: ${cleaned[i]}`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

/**
 * Algoritmo TOTP (RFC 6238 / RFC 4226) desde cero:
 * 1. T = floor(UnixTimestamp / 30) en entero de 64 bits Big-Endian (8 bytes)
 * 2. H = HMAC-SHA1(SecretBytes, T)
 * 3. Dynamic Truncation: offset = H[19] & 0x0f, extrae 4 bytes (31 bits)
 * 4. TOTP = (bin_code % 1_000_000) con ceros a la izquierda (6 dígitos)
 */
function generateTotpAtTime(secretBase32, unixSeconds, period = 30) {
  const secretBytes = decodeBase32(secretBase32);
  const timeCounter = Math.floor(unixSeconds / period);

  // Buffer de 8 bytes Big-Endian (64-bit integer)
  const timeBuffer = Buffer.alloc(8);
  let temp = timeCounter;
  for (let i = 7; i >= 0; i--) {
    timeBuffer[i] = temp & 0xff;
    temp = Math.floor(temp / 256);
  }

  // HMAC-SHA1
  const hmac = crypto.createHmac('sha1', secretBytes).update(timeBuffer).digest();

  // Dynamic Truncation
  const offset = hmac[19] & 0x0f;
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = (binCode % 1_000_000).toString().padStart(6, '0');
  return {
    otp,
    counter: timeCounter,
    offset,
    binCode,
  };
}

/**
 * Verifica TOTP con tolerancia a desfase de reloj (Clock Skew):
 * Ventanas C-1 (t - 30s), C (t) y C+1 (t + 30s)
 */
function verifyTotpWithSkew(secretBase32, candidateCode, nowSeconds = Math.floor(Date.now() / 1000)) {
  const sanitizedCode = String(candidateCode).trim();
  if (!/^\d{6}$/.test(sanitizedCode)) {
    return { valid: false, window: null };
  }

  const windows = [
    { label: 'C-1', time: nowSeconds - 30 },
    { label: 'C', time: nowSeconds },
    { label: 'C+1', time: nowSeconds + 30 },
  ];

  for (const w of windows) {
    const { otp, counter } = generateTotpAtTime(secretBase32, w.time, 30);
    if (otp === sanitizedCode) {
      return { valid: true, window: w.label, counter };
    }
  }

  return { valid: false, window: null };
}

// ============================================================================
// 3. MIDDLEWARE DE AUTENTICACIÓN BEARER
// ============================================================================

function authenticateBearer(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'unauthorized',
      message: 'Header Authorization Bearer requerido.',
    });
  }

  const token = authHeader.slice('Bearer '.length).trim();
  try {
    const claims = verifyJwt(token);
    req.user = claims;
    req.rawToken = token;
    return next();
  } catch (err) {
    return res.status(401).json({
      error: 'token_expired',
      message: err.message || 'Access token expirado o inválido',
    });
  }
}

// ============================================================================
// 4. ENDPOINTS FASE 1: OAUTH 2.0 CON PKCE (RFC 7636)
// ============================================================================

/**
 * GET /oauth/authorize
 * Se abre en el navegador seguro del sistema operativo (ASWebAuthenticationSession / Custom Tabs).
 */
app.get('/oauth/authorize', (req, res) => {
  const {
    response_type = 'code',
    client_id = 'unisabana-mobile-app',
    redirect_uri = 'unisabana-auth://oauth/callback',
    code_challenge = '',
    code_challenge_method = 'S256',
    state = '',
  } = req.query;

  if (!code_challenge || code_challenge_method !== 'S256') {
    return res.status(400).send(`
      <!DOCTYPE html>
      <html lang="es">
      <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Error PKCE</title></head>
      <body style="font-family: -apple-system, sans-serif; padding: 24px; background: #0f172a; color: #f8fafc;">
        <h2 style="color: #f87171;">Error RFC 7636 (PKCE Requerido)</h2>
        <p>El cliente público debe enviar <code>code_challenge</code> y <code>code_challenge_method=S256</code>.</p>
      </body>
      </html>
    `);
  }

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`
    <!DOCTYPE html>
    <html lang="es">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
      <title>UniSabana Compass SSO — OAuth 2.0 + PKCE</title>
      <style>
        * { box-sizing: border-box; }
        body {
          margin: 0;
          padding: 20px;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          background: linear-gradient(160deg, #0a192f 0%, #112240 100%);
          color: #e6f1ff;
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .card {
          width: 100%;
          max-width: 420px;
          background: rgba(17, 34, 64, 0.95);
          border: 1px solid rgba(100, 255, 218, 0.25);
          border-radius: 18px;
          padding: 24px;
          box-shadow: 0 16px 40px rgba(2, 12, 27, 0.7);
        }
        .badge {
          display: inline-block;
          background: rgba(100, 255, 218, 0.12);
          color: #64ffda;
          font-size: 11px;
          font-weight: 700;
          padding: 4px 10px;
          border-radius: 999px;
          letter-spacing: 0.6px;
          text-transform: uppercase;
          margin-bottom: 12px;
        }
        h1 {
          font-size: 20px;
          margin: 0 0 6px 0;
          color: #ffffff;
        }
        p.sub {
          margin: 0 0 18px 0;
          font-size: 13px;
          color: #8892b0;
          line-height: 1.45;
        }
        .pkce-box {
          background: #0a192f;
          border: 1px solid #233554;
          border-radius: 10px;
          padding: 10px 12px;
          margin-bottom: 16px;
          font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
          font-size: 11px;
          color: #a8b2d1;
          word-break: break-all;
        }
        .pkce-box strong {
          color: #64ffda;
          display: block;
          margin-bottom: 2px;
        }
        label {
          display: block;
          font-size: 12px;
          font-weight: 600;
          margin-bottom: 6px;
          color: #ccd6f6;
        }
        input[type="email"], input[type="password"] {
          width: 100%;
          padding: 11px 12px;
          border-radius: 10px;
          border: 1px solid #233554;
          background: #0a192f;
          color: #ffffff;
          font-size: 14px;
          margin-bottom: 12px;
        }
        .btn-primary {
          width: 100%;
          padding: 14px;
          border: none;
          border-radius: 12px;
          background: #10b981;
          color: #042f2e;
          font-weight: 800;
          font-size: 15px;
          cursor: pointer;
          margin-top: 4px;
        }
        .btn-Secondary {
          width: 100%;
          padding: 10px;
          border: 1px solid rgba(248, 113, 113, 0.45);
          border-radius: 10px;
          background: rgba(248, 113, 113, 0.1);
          color: #fca5a5;
          font-weight: 600;
          font-size: 12px;
          cursor: pointer;
          margin-top: 10px;
        }
      </style>
    </head>
    <body>
      <div class="card">
        <span class="badge">Navegador Seguro del Sistema • RFC 7636</span>
        <h1>Universidad de La Sabana SSO</h1>
        <p class="sub">Proveedor de Identidad OAuth 2.0 con PKCE. La aplicación móvil nunca toca tu contraseña.</p>

        <div class="pkce-box">
          <strong>PKCE Challenge (${code_challenge_method}):</strong>
          ${String(code_challenge).slice(0, 28)}...<br/>
          <strong>Anti-CSRF State:</strong> ${state}<br/>
          <strong>Redirect URI:</strong> ${redirect_uri}
        </div>

        <form method="POST" action="/oauth/authorize/decision">
          <input type="hidden" name="client_id" value="${client_id}" />
          <input type="hidden" name="redirect_uri" value="${redirect_uri}" />
          <input type="hidden" name="code_challenge" value="${code_challenge}" />
          <input type="hidden" name="code_challenge_method" value="${code_challenge_method}" />
          <input type="hidden" name="state" value="${state}" />
          <input type="hidden" name="response_type" value="${response_type}" />

          <label>Correo Institucional</label>
          <input type="email" name="email" value="estudiante@unisabana.edu.co" required />

          <label>Contraseña SSO</label>
          <input type="password" name="password" value="Sabana2026!" required />

          <button type="submit" name="action" value="allow" class="btn-primary">
            Autorizar e Iniciar Sesión
          </button>
          <button type="submit" name="action" value="tamper_state" class="btn-Secondary">
            Simular Ataque CSRF (Alterar State en Callback)
          </button>
        </form>
      </div>
    </body>
    </html>
  `);
});

/**
 * POST /oauth/authorize/decision
 * Procesa el consentimiento del usuario y redirige mediante Deep Link a la app móvil.
 */
app.post('/oauth/authorize/decision', (req, res) => {
  const {
    client_id = 'unisabana-mobile-app',
    redirect_uri,
    code_challenge,
    code_challenge_method = 'S256',
    state,
    email = 'estudiante@unisabana.edu.co',
    action = 'allow',
  } = req.body;

  if (!redirect_uri || !code_challenge) {
    return res.status(400).send('Parámetros OAuth incompletos');
  }

  const authCode = `usab_code_${base64UrlEncode(crypto.randomBytes(24))}`;
  authorizationCodes.set(authCode, {
    clientId: client_id,
    redirectUri: redirect_uri,
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method,
    user: {
      id: 'usr_unisabana_001',
      email,
      name: 'Estudiante Ingeniería UniSabana',
      role: 'student_researcher',
      totpSecret: DEFAULT_TOTP_SECRET,
    },
    expiresAt: Date.now() + 2 * 60 * 1000, // 2 minutos
  });

  const returnedState = action === 'tamper_state' ? `${state}_TAMPERED_CSRF` : state;
  const separator = redirect_uri.includes('?') ? '&' : '?';
  const callbackUrl = `${redirect_uri}${separator}code=${encodeURIComponent(
    authCode
  )}&state=${encodeURIComponent(returnedState)}`;

  return res.redirect(302, callbackUrl);
});

/**
 * POST /auth/oauth/token
 * Canjea authorization_code + code_verifier validando SHA256(code_verifier) === code_challenge.
 * Retorna access_token (5 min, RAM) y refresh_token (30 días, Keychain/Keystore).
 */
app.post('/auth/oauth/token', (req, res) => {
  const { code, code_verifier, client_id } = req.body;

  if (!code || !code_verifier) {
    return res.status(400).json({
      error: 'invalid_request',
      message: 'Se requieren code y code_verifier (RFC 7636).',
    });
  }

  const record = authorizationCodes.get(code);
  if (!record) {
    return res.status(400).json({
      error: 'invalid_grant',
      message: 'El código de autorización no existe, ya fue usado o expiró.',
    });
  }

  // Un authorization_code es de un solo uso
  authorizationCodes.delete(code);

  if (Date.now() > record.expiresAt) {
    return res.status(400).json({
      error: 'invalid_grant',
      message: 'El authorization_code ha expirado.',
    });
  }

  // Validación matemática PKCE (RFC 7636): BASE64URL(SHA256(code_verifier)) === code_challenge
  const computedChallenge = base64UrlEncode(
    crypto.createHash('sha256').update(String(code_verifier), 'ascii').digest()
  );

  if (computedChallenge !== record.codeChallenge) {
    return res.status(401).json({
      error: 'invalid_grant',
      message: 'Fallo de verificación PKCE: SHA256(code_verifier) !== code_challenge.',
      debug: {
        expected: record.codeChallenge,
        computed: computedChallenge,
      },
    });
  }

  // Emitir access_token (vida corta: 5 minutos = 300s, mfa_verified: false)
  const { token: accessToken, payload: accessPayload } = signJwt(
    {
      sub: record.user.id,
      email: record.user.email,
      name: record.user.name,
      role: record.user.role,
      mfa_verified: false,
      client_id: client_id || record.clientId,
    },
    5 * 60 // 5 minutos
  );

  // Emitir refresh_token (vida larga: 30 días = 2,592,000s)
  const refreshToken = `usab_rt_${base64UrlEncode(crypto.randomBytes(36))}`;
  const now = Date.now();
  refreshTokens.set(refreshToken, {
    userId: record.user.id,
    user: record.user,
    createdAt: now,
    expiresAt: now + 30 * 24 * 60 * 60 * 1000, // 30 días
    revoked: false,
  });

  return res.status(200).json({
    token_type: 'Bearer',
    access_token: accessToken,
    refresh_token: refreshToken,
    expires_in: 300, // 5 minutos
    refresh_expires_in: 30 * 24 * 60 * 60, // 30 días
    mfa_verified: false,
    user: {
      id: record.user.id,
      email: record.user.email,
      name: record.user.name,
      role: record.user.role,
    },
    totp_provisioning: {
      issuer: 'UniSabana',
      account: record.user.email,
      secret: record.user.totpSecret,
      otpauth_uri: DEFAULT_OTPAUTH_URI,
    },
    pkce_verified: true,
    issued_at: accessPayload.iat,
  });
});

// ============================================================================
// 5. ENDPOINTS FASE 2: SILENT REFRESH & GESTIÓN DE CICLO DE VIDA DE TOKENS
// ============================================================================

/**
 * POST /auth/refresh
 * Renueva silenciosamente el access_token usando el refresh_token guardado en SecureStore.
 */
app.post('/auth/refresh', (req, res) => {
  const { refresh_token } = req.body;

  if (!refresh_token) {
    return res.status(401).json({
      error: 'invalid_token',
      message: 'refresh_token no proporcionado.',
    });
  }

  const stored = refreshTokens.get(refresh_token);
  if (!stored || stored.revoked || Date.now() > stored.expiresAt) {
    refreshTokens.delete(refresh_token);
    return res.status(401).json({
      error: 'refresh_token_expired',
      message: 'El refresh_token es inválido, fue revocado o ha expirado. Inicie sesión nuevamente.',
    });
  }

  // Rotación opcional o mantenimiento del refresh_token + nuevo access_token de 5 minutos
  const { token: newAccessToken, payload } = signJwt(
    {
      sub: stored.user.id,
      email: stored.user.email,
      name: stored.user.name,
      role: stored.user.role,
      mfa_verified: false,
    },
    5 * 60
  );

  return res.status(200).json({
    token_type: 'Bearer',
    access_token: newAccessToken,
    refresh_token: refresh_token,
    expires_in: 300,
    mfa_verified: false,
    refreshed_at: new Date().toISOString(),
    jti: payload.jti,
  });
});

/**
 * POST /auth/debug/expire-access
 * Invalida inmediatamente el access_token actual en el backend para demostrar en vivo
 * cómo el interceptor HTTP atrapa el 401 Unauthorized y dispara la Silent Refresh Queue.
 */
app.post('/auth/debug/expire-access', authenticateBearer, (req, res) => {
  if (req.user && req.user.jti) {
    revokedAccessJtis.add(req.user.jti);
  }
  return res.status(200).json({
    status: 'expired',
    message:
      'El access_token actual fue marcado como expirado en el backend. La próxima llamada a la API responderá 401 Unauthorized.',
  });
});

// ============================================================================
// 6. ENDPOINTS FASE 3 y 4: STEP-UP AUTHENTICATION, BÓVEDA CRÍTICA Y ANTI-REPLAY
// ============================================================================

/**
 * Handler compartido para GET /api/boveda y GET /api/boveda-critica
 * Requiere un token con mfa_verified: true. Si mfa_verified es false, retorna 403 Forbidden
 * con error: "mfa_required" y un step_up_token temporal.
 */
function handleBovedaCritica(req, res) {
  const userClaims = req.user;

  if (!userClaims.mfa_verified) {
    const { token: stepUpToken } = signJwt(
      {
        sub: userClaims.sub,
        email: userClaims.email,
        purpose: 'step_up_mfa',
      },
      5 * 60 // 5 minutos para completar el desafío 2FA
    );

    return res.status(403).json({
      error: 'mfa_required',
      message:
        'Acceso denegado a Bóveda Crítica: Se requiere elevación de privilegios Step-Up 2FA (TOTP RFC 6238).',
      step_up_token: stepUpToken,
      required_acr: 'urn:unisabana:acr:mfa-totp',
    });
  }

  return res.status(200).json({
    status: 'authorized',
    vault_id: 'VAULT-USAB-2026-CRITICA',
    classification: 'CONFIDENCIAL // NIVEL 4 (STEP-UP MFA VERIFICADO)',
    accessed_by: userClaims.email,
    mfa_verified: true,
    elevated_exp: userClaims.exp,
    secrets: [
      {
        id: 'SEC-01',
        title: 'Llave Maestra HSM Producción',
        value: 'USAB-HSM-9941-A8F3-E210-77C9',
        updatedAt: '2026-11-09T18:30:00Z',
      },
      {
        id: 'SEC-02',
        title: 'Certificado Raíz Firma Académica',
        value: 'SHA256:4f:8a:99:1c:02:eb:71:3d:cc:91:08:aa',
        updatedAt: '2026-11-09T19:00:00Z',
      },
      {
        id: 'SEC-03',
        title: 'Token de Despliegue Clúster Financiero',
        value: 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.BOVEDA_UNLOCKED',
        updatedAt: '2026-11-09T19:15:00Z',
      },
    ],
  });
}

app.get('/api/boveda', authenticateBearer, handleBovedaCritica);
app.get('/api/boveda-critica', authenticateBearer, handleBovedaCritica);

/**
 * POST /auth/mfa/verify
 * Recibe step_up_token y el código TOTP de 6 dígitos.
 * - Verifica Caché Anti-Replay (TTL 90 segundos) -> 409 Conflict: Replay Attack Detected
 * - Verifica ventanas temporales C-1 (t-30s), C (t), C+1 (t+30s)
 * - Retorna elevated_token con mfa_verified: true (expiración corta: 10 minutos)
 */
app.post('/auth/mfa/verify', (req, res) => {
  const { step_up_token, code, secret_override } = req.body;

  if (!step_up_token || !code) {
    return res.status(400).json({
      error: 'invalid_request',
      message: 'Se requieren step_up_token y el código TOTP de 6 dígitos.',
    });
  }

  let stepUpClaims;
  try {
    stepUpClaims = verifyJwt(step_up_token);
    if (stepUpClaims.purpose !== 'step_up_mfa') {
      throw new Error('El token proporcionado no es un step_up_token válido.');
    }
  } catch (err) {
    return res.status(401).json({
      error: 'invalid_step_up_token',
      message: err.message || 'step_up_token inválido o expirado.',
    });
  }

  const sanitizedCode = String(code).trim();
  const userId = stepUpClaims.sub || 'usr_unisabana_001';
  const replayKey = `${userId}:${sanitizedCode}`;
  const now = Date.now();

  // 1. Verificar Caché Anti-Replay (TTL 90s)
  const existingReplay = replayCache.get(replayKey);
  if (existingReplay && existingReplay.expiresAt > now) {
    const remainingSec = Math.ceil((existingReplay.expiresAt - now) / 1000);
    return res.status(409).json({
      error: 'Replay Attack Detected',
      message: `409 Conflict: Replay Attack Detected. El código TOTP ${sanitizedCode} ya fue consumido hace ${Math.floor(
        (now - existingReplay.usedAt) / 1000
      )}s. Bloqueado en caché Anti-Replay por ${remainingSec}s adicionales.`,
      code_reused: sanitizedCode,
      ttl_remaining_seconds: remainingSec,
    });
  }

  // 2. Validar TOTP en ventanas C-1, C y C+1
  const secretToUse = secret_override || DEFAULT_TOTP_SECRET;
  const verification = verifyTotpWithSkew(secretToUse, sanitizedCode);

  if (!verification.valid) {
    return res.status(401).json({
      error: 'invalid_totp',
      message:
        'Código TOTP inválido. No coincide con las ventanas temporales C-1 (-30s), C (actual) ni C+1 (+30s).',
    });
  }

  // 3. Registrar en Caché Anti-Replay con TTL de 90 segundos
  replayCache.set(replayKey, {
    code: sanitizedCode,
    usedAt: now,
    expiresAt: now + 90 * 1000, // 90 segundos
    window: verification.window,
  });

  // 4. Emitir elevated_token con claim mfa_verified: true (expiración: 10 minutos = 600s)
  const { token: elevatedToken, payload: elevatedPayload } = signJwt(
    {
      sub: userId,
      email: stepUpClaims.email || 'estudiante@unisabana.edu.co',
      name: 'Estudiante Ingeniería UniSabana',
      role: 'student_researcher',
      mfa_verified: true,
      amr: ['pwd', 'otp'],
      matched_window: verification.window,
    },
    10 * 60 // 10 minutos
  );

  return res.status(200).json({
    status: 'mfa_verified',
    elevated_token: elevatedToken,
    mfa_verified: true,
    expires_in: 600, // 10 minutos
    matched_window: verification.window,
    anti_replay_ttl_seconds: 90,
    issued_at: elevatedPayload.iat,
  });
});

// ============================================================================
// 7. ENDPOINTS DE RECURSOS ESTÁNDAR (Para probar Silent Refresh Queue en paralelo)
// ============================================================================

app.get('/api/perfil', authenticateBearer, (req, res) => {
  res.json({
    endpoint: '/api/perfil',
    user: {
      id: req.user.sub,
      email: req.user.email,
      name: req.user.name || 'Estudiante Ingeniería UniSabana',
      mfa_verified: Boolean(req.user.mfa_verified),
    },
    token_jti: req.user.jti,
    timestamp: new Date().toISOString(),
  });
});

app.get('/api/auditoria', authenticateBearer, (req, res) => {
  res.json({
    endpoint: '/api/auditoria',
    active_refresh_sessions: refreshTokens.size,
    replay_cache_entries: replayCache.size,
    token_jti: req.user.jti,
    timestamp: new Date().toISOString(),
  });
});

app.get('/api/recursos', authenticateBearer, (req, res) => {
  res.json({
    endpoint: '/api/recursos',
    resources: ['Horario Académico', 'Notas Parciales', 'Certificados Activos'],
    token_jti: req.user.jti,
    timestamp: new Date().toISOString(),
  });
});

app.get('/health', (_req, res) => {
  const nowSec = Math.floor(Date.now() / 1000);
  res.json({
    status: 'ok',
    service: 'unisabana-security-lab-backend',
    server_unix_time: nowSec,
    totp_period: 30,
    totp_remaining_seconds: 30 - (nowSec % 30),
    otpauth_uri: DEFAULT_OTPAUTH_URI,
  });
});

if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n==================================================================`);
    console.log(`🛡️  Backend Seguridad Móvil UniSabana corriendo en puerto ${PORT}`);
    console.log(`🔗 OAuth Authorize: http://localhost:${PORT}/oauth/authorize`);
    console.log(`🔑 Semilla TOTP Base32: ${DEFAULT_TOTP_SECRET}`);
    console.log(`📱 URI QR TOTP: ${DEFAULT_OTPAUTH_URI}`);
    console.log(`==================================================================\n`);
  });
}

module.exports = {
  app,
  generateTotpAtTime,
  verifyTotpWithSkew,
  decodeBase32,
};

