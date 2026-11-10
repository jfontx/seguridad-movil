# Guía de Laboratorio (Sesión 14): Seguridad Móvil — OAuth 2.0 con PKCE, Almacenamiento Criptográfico y Step-Up 2FA (TOTP)

**Curso:** Desarrollo Móvil (React Native / Expo)  
**Institución:** Universidad de La Sabana — Facultad de Ingeniería  
**Sesión:** Sesión 14 (Compass: Autenticación Móvil, Tokens y Seguridad de Recursos)

---

## 📁 Estructura del Repositorio

* `/` (`src/`): Aplicación móvil en **React Native + Expo (SDK 58) + Expo Router** con TypeScript estricto (`strict: true`).
  * [`src/utils/pkce.ts`](./src/utils/pkce.ts): Generador criptográfico OAuth 2.0 con PKCE (**RFC 7636**) (`code_verifier`, `code_challenge` SHA-256 Base64URL sin padding y `state` Anti-CSRF).
  * [`src/utils/totp.ts`](./src/utils/totp.ts): Implementación matemática **TOTP desde cero (RFC 6238 / RFC 4226 / RFC 4648)** sin librerías externas de TOTP (decodificador Base32, ventana `T = floor(UnixTimestamp / 30)` en entero de 64 bits Big-Endian de 8 bytes, `HMAC-SHA1` y Truncamiento Dinámico a 6 dígitos). Opera **100% en Modo Avión** y con paridad exacta frente a **Google Authenticator**.
  * [`src/services/secure-storage.ts`](./src/services/secure-storage.ts): Almacenamiento seguro cifrado por hardware mediante `expo-secure-store` (iOS Keychain / Android Keystore) para el `refresh_token` (30 días) y la semilla TOTP.
  * [`src/services/api-client.ts`](./src/services/api-client.ts): Separación estricta de memoria (`access_token` de 5 min y `elevated_token` de 10 min viven **exclusivamente en memoria RAM volátil**) e **Interceptor HTTP con Cola Silenciosa (`Silent Refresh Queue`)** ante respuestas `401 Unauthorized`.
  * [`src/context/auth-context.tsx`](./src/context/auth-context.tsx): Orquestador de OAuth 2.0 + PKCE con `expo-web-browser` (`openAuthSessionAsync`), Deep Linking (`unisabana-auth://oauth/callback`), Step-Up 2FA y pruebas Anti-Replay.
  * [`src/app/index.tsx`](./src/app/index.tsx): **Pestaña 1** — Login OAuth 2.0 + PKCE, Separación RAM vs Hardware y Demostración de Cola Silenciosa (`Silent Refresh Queue`).
  * [`src/app/explore.tsx`](./src/app/explore.tsx): **Pestaña 2** — Módulo Authenticator TOTP Propio (Modo Avión), Escáner QR con `expo-camera`, entrada manual Base32 y desglose matemático en tiempo real.
  * [`src/app/boveda.tsx`](./src/app/boveda.tsx): **Pestaña 3** — Bóveda Crítica (`GET /api/boveda-critica`), Modal Step-Up 2FA (`403 Forbidden -> POST /auth/mfa/verify`) y Simulador de Ataque de Repetición (`409 Conflict: Replay Attack Detected`).
* [`/backend-auth`](./backend-auth): Servidor de autenticación ligero en **Node.js + Express** ([`backend-auth/server.js`](./backend-auth/server.js)).

---

## 🚀 Instrucciones Paso a Paso de Ejecución

### 1. Iniciar el Backend de Autenticación (`/backend-auth`)

En una terminal, instala las dependencias e inicia el servidor en el puerto `4000`:

```bash
cd backend-auth
npm install
npm start
```

El servidor quedará escuchando en `http://0.0.0.0:4000`:
* `GET /oauth/authorize`: Portal SSO OAuth 2.0 + PKCE para navegador nativo del sistema.
* `POST /auth/oauth/token`: Validación matemática `SHA256(code_verifier) === code_challenge` y emisión de `access_token` (5m) + `refresh_token` (30d).
* `POST /auth/refresh`: Renovación silenciosa de `access_token`.
* `GET /api/boveda` y `GET /api/boveda-critica`: Recurso crítico protegido por Step-Up MFA (`403 Forbidden` con `step_up_token` si `mfa_verified === false`).
* `POST /auth/mfa/verify`: Verificación TOTP con tolerancia Clock Skew (`C-1`, `C`, `C+1`), **Caché Anti-Replay (TTL 90s)** (`409 Conflict: Replay Attack Detected`) y emisión de `elevated_token` (`mfa_verified: true`, 10m).

---

### 2. Configurar Variables de Entorno / Red y Ejecutar la App Móvil

En otra terminal, desde la raíz del proyecto:

```bash
npm install
npx expo start
```

> **Nota para Dispositivos Físicos vs Emuladores:**
> * La aplicación detecta automáticamente la IP LAN de tu computador a través de `Constants.expoConfig.hostUri`.
> * También puedes cambiar la URL del backend en cualquier momento tocando el chip **`API: http://...`** en la esquina superior derecha de la primera pantalla (`http://localhost:4000` para iOS Simulator / Web, `http://10.0.2.2:4000` para Android Emulator, o `http://TU_IP_LAN:4000` para dispositivo físico).

---

## 🧪 Guía Rápida para las 5 Pruebas

| # | Prueba de Aceptación | Cómo demostrarla en la App |
| :--- | :--- | :--- |
| **1** | **Flujo OAuth + PKCE con Navegador del Sistema** | En la **Pestaña 1 (OAuth & Tokens)**, presiona **"Iniciar Sesión con OAuth 2.0 + PKCE"**. Se abre el navegador nativo del sistema (`ASWebAuthenticationSession` / Custom Tabs). Presiona **"Autorizar e Iniciar Sesión"**; regresa por Deep Link, verifica `state` y guarda `refresh_token` en `SecureStore` y `access_token` en RAM. |
| **2** | **Paridad Estándar TOTP** | En la **Pestaña 2 (TOTP Offline)**, escanea el QR con formato `otpauth://totp/UniSabana:estudiante@unisabana.edu.co?secret=JBSWY3DPEHPK3PXP&issuer=UniSabana` o carga la semilla `JBSWY3DPEHPK3PXP` en la app y en Google Authenticator. Ambas muestran exactamente los mismos 6 dígitos al mismo tiempo. |
| **3** | **Cálculo Offline en Modo Avión** | Activa el **Modo Avión** del teléfono en la **Pestaña 2**. Espera a que el contador visual regresivo de 30s llegue a `0s` y observa cómo se calcula matemáticamente el nuevo código de 6 dígitos sin conexión a internet. |
| **4** | **Step-Up Authentication & Bóveda** | En la **Pestaña 3 (Bóveda 2FA)**, presiona **"Intentar Abrir Bóveda Crítica"**. La app atrapa el `403 Forbidden (mfa_required)`, abre el modal 2FA, ingresa el código TOTP de 6 dígitos, obtiene el `elevated_token` y desbloquea los secretos de la Bóveda Crítica. |
| **5** | **Ataque de Repetición (Anti-Replay)** | En la **Pestaña 3 (Bóveda 2FA)**, inmediatamente después de abrir la bóveda, presiona **"Reenviar Mismo Código TOTP -> Probar 409 Conflict"**. El backend rechaza el reuso del código con **`409 Conflict: Replay Attack Detected`**. |
