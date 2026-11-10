import { router } from 'expo-router';
import React, { useState } from 'react';
import {
  ActivityIndicator,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { useAuth } from '@/context/auth-context';

export default function OAuthAndTokensScreen() {
  const {
    user,
    isAuthenticated,
    isLoading,
    accessToken,
    accessTokenExp,
    elevatedToken,
    refreshTokenPreview,
    refreshTokenMeta,
    isRefreshing,
    queuedRequestsCount,
    lastPkceBundle,
    lastAuthError,
    loginWithOAuthPkce,
    logout,
    expireAccessTokenForDemo,
    runConcurrentSilentRefreshDemo,
    backendUrl,
    updateBackendUrl,
    auditLogs,
    clearLogs,
  } = useAuth();

  const [urlInput, setUrlInput] = useState(backendUrl);
  const [showUrlEditor, setShowUrlEditor] = useState(false);
  const [concurrencyResults, setConcurrencyResults] = useState<string[]>([]);
  const [runningQueueDemo, setRunningQueueDemo] = useState(false);

  const handleLogin = async (simulateCsrfMismatch = false) => {
    try {
      await loginWithOAuthPkce({ simulateCsrfMismatch });
    } catch {
      // El error queda registrado en lastAuthError y en la bitácora de auditoría
    }
  };

  const handleRunQueueDemo = async () => {
    setRunningQueueDemo(true);
    setConcurrencyResults([]);
    try {
      const results = await runConcurrentSilentRefreshDemo();
      setConcurrencyResults(results);
    } catch {
      // Registrado en bitácora
    } finally {
      setRunningQueueDemo(false);
    }
  };

  const handleSaveBackendUrl = () => {
    updateBackendUrl(urlInput);
    setShowUrlEditor(false);
  };

  return (
    <SafeAreaView style={styles.safeArea} edges={['top']}>
      <ScrollView
        style={styles.scroll}
        contentContainerStyle={styles.contentContainer}
        showsVerticalScrollIndicator={false}>
        {/* ENCABEZADO */}
        <View style={styles.headerCard}>
          <View style={styles.headerTopRow}>
            <View style={styles.badge}>
              <Text style={styles.badgeText}>SESIÓN 14 • COMPASS SEGURIDAD MÓVIL</Text>
            </View>
            <Pressable
              onPress={() => {
                setUrlInput(backendUrl);
                setShowUrlEditor((prev) => !prev);
              }}
              style={styles.serverChip}>
              <Text style={styles.serverChipText}>API: {backendUrl}</Text>
            </Pressable>
          </View>

          <Text style={styles.headerTitle}>
            OAuth 2.0 con PKCE & Silent Refresh Queue
          </Text>
          <Text style={styles.headerSubtitle}>
            {user
              ? `Sesión activa: ${user.name} (${user.email})`
              : 'Universidad de La Sabana • Cliente Público (RFC 7636) sin client_secret ni WebViews'}
          </Text>

          {showUrlEditor && (
            <View style={styles.urlEditorBox}>
              <Text style={styles.urlEditorLabel}>
                URL del Backend (Usa la IP LAN de tu Mac si pruebas en celular físico):
              </Text>
              <View style={styles.urlInputRow}>
                <TextInput
                  style={styles.urlInput}
                  value={urlInput}
                  onChangeText={setUrlInput}
                  autoCapitalize="none"
                  autoCorrect={false}
                  placeholder="http://192.168.1.X:4000"
                  placeholderTextColor="#64748b"
                />
                <Pressable style={styles.urlSaveBtn} onPress={handleSaveBackendUrl}>
                  <Text style={styles.urlSaveBtnText}>Guardar</Text>
                </Pressable>
              </View>
              <View style={styles.quickUrlRow}>
                <Pressable
                  style={styles.quickUrlBtn}
                  onPress={() => {
                    setUrlInput('http://localhost:4000');
                    updateBackendUrl('http://localhost:4000');
                  }}>
                  <Text style={styles.quickUrlText}>iOS / Web (localhost)</Text>
                </Pressable>
                <Pressable
                  style={styles.quickUrlBtn}
                  onPress={() => {
                    setUrlInput('http://10.0.2.2:4000');
                    updateBackendUrl('http://10.0.2.2:4000');
                  }}>
                  <Text style={styles.quickUrlText}>Android Emu (10.0.2.2)</Text>
                </Pressable>
              </View>
            </View>
          )}
        </View>

        {/* ALERTA DE ERROR DE SEGURIDAD (EJ. CSRF MISMATCH) */}
        {lastAuthError ? (
          <View style={styles.errorBanner}>
            <Text style={styles.errorBannerTitle}>Alerta de Seguridad / Autenticación</Text>
            <Text style={styles.errorBannerBody}>{lastAuthError}</Text>
          </View>
        ) : null}

        {/* PUNTO 1: FLUJO OAUTH 2.0 CON PKCE (RFC 7636) */}
        <View style={styles.sectionCard}>
          <View style={styles.sectionHeader}>
            <Text style={styles.sectionStep}>PUNTO 1 (25%)</Text>
            <Text style={styles.sectionTitle}>OAuth 2.0 + PKCE (RFC 7636)</Text>
          </View>
          <Text style={styles.sectionDescription}>
            Abre el navegador seguro del sistema (`WebBrowser.openAuthSessionAsync`), recibe el
            callback por Deep Link y valida el parámetro `state` anti-CSRF antes de canjear el
            código con `code_verifier`.
          </Text>

          <View style={styles.buttonGroup}>
            <Pressable
              style={({ pressed }) => [
                styles.primaryButton,
                pressed && styles.buttonPressed,
                isLoading && styles.buttonDisabled,
              ]}
              disabled={isLoading}
              onPress={() => handleLogin(false)}>
              {isLoading ? (
                <ActivityIndicator color="#042f2e" />
              ) : (
                <Text style={styles.primaryButtonText}>
                  {isAuthenticated
                    ? 'Re-Autenticar con Navegador del Sistema (PKCE)'
                    : 'Iniciar Sesión con OAuth 2.0 + PKCE'}
                </Text>
              )}
            </Pressable>

            <Pressable
              style={({ pressed }) => [
                styles.outlineWarningButton,
                pressed && styles.buttonPressed,
              ]}
              disabled={isLoading}
              onPress={() => handleLogin(true)}>
              <Text style={styles.outlineWarningButtonText}>
                Probar Defensa Anti-CSRF (Simular State Adulterado)
              </Text>
            </Pressable>
          </View>

          {lastPkceBundle && (
            <View style={styles.telemetryBox}>
              <Text style={styles.telemetryHeading}>
                Último Par Criptográfico PKCE Generado en App:
              </Text>
              <Text style={styles.monoLine}>
                <Text style={styles.monoKey}>code_verifier ({lastPkceBundle.codeVerifier.length} chars): </Text>
                {lastPkceBundle.codeVerifier.slice(0, 28)}...
              </Text>
              <Text style={styles.monoLine}>
                <Text style={styles.monoKey}>code_challenge (S256 Base64URL): </Text>
                {lastPkceBundle.codeChallenge}
              </Text>
              <Text style={styles.monoLine}>
                <Text style={styles.monoKey}>state (Anti-CSRF): </Text>
                {lastPkceBundle.state}
              </Text>
            </View>
          )}
        </View>

        {/* PUNTO 2: ALMACENAMIENTO SEGURO NATIVO Y SILENT REFRESH QUEUE */}
        <View style={styles.sectionCard}>
          <View style={styles.sectionHeader}>
            <Text style={styles.sectionStep}>PUNTO 2 (20%)</Text>
            <Text style={styles.sectionTitle}>
              Separación de Memoria & Silent Refresh Queue
            </Text>
          </View>

          <View style={styles.storageGrid}>
            {/* TARJETA RAM VOLÁTIL */}
            <View style={styles.storageBoxRam}>
              <View style={styles.storageHeaderRow}>
                <Text style={styles.storageTagRam}>MEMORIA VOLÁTIL (RAM)</Text>
                <Text style={styles.storageTtl}>TTL: 5 min</Text>
              </View>
              <Text style={styles.storageTokenName}>access_token</Text>
              <Text style={styles.storageTokenValue} numberOfLines={2}>
                {accessToken
                  ? `${accessToken.slice(0, 26)}...${accessToken.slice(-12)}`
                  : 'Vacío (Se destruye al cerrar la app)'}
              </Text>
              <Text style={styles.storageMetaText}>
                {accessTokenExp
                  ? `Expira unix: ${accessTokenExp} | MFA Elevado: ${
                      elevatedToken ? 'SÍ (10m)' : 'NO'
                    }`
                  : 'Nunca toca AsyncStorage ni el disco'}
              </Text>
            </View>

            {/* TARJETA ENCLAVE DE HARDWARE (SECURESTORE) */}
            <View style={styles.storageBoxHardware}>
              <View style={styles.storageHeaderRow}>
                <Text style={styles.storageTagHardware}>HARDWARE ENCLAVE</Text>
                <Text style={styles.storageTtl}>TTL: 30 días</Text>
              </View>
              <Text style={styles.storageTokenName}>refresh_token (expo-secure-store)</Text>
              <Text style={styles.storageTokenValue} numberOfLines={2}>
                {refreshTokenPreview || 'Sin token en Keychain / Keystore'}
              </Text>
              <Text style={styles.storageMetaText}>
                {refreshTokenMeta
                  ? `${refreshTokenMeta.storageEngine} (${refreshTokenMeta.userEmail})`
                  : 'Respaldado por iOS Keychain / Android Keystore'}
              </Text>
            </View>
          </View>

          {/* CONTROLES DE PRUEBA DE SILENT REFRESH QUEUE */}
          <View style={styles.queueDemoBox}>
            <Text style={styles.queueDemoTitle}>
              Demostración de Cola Silenciosa (Interceptor 401)
            </Text>
            <Text style={styles.queueDemoSubtitle}>
              Al expirar el `access_token`, las 3 llamadas concurrentes se pausan en `refreshQueue`,
              se ejecuta UN SOLO `POST /auth/refresh` con el `refresh_token` de SecureStore y se
              reanudan todas sin cerrar la sesión.
            </Text>

            <View style={styles.queueStatusBanner}>
              <Text style={styles.queueStatusText}>
                Estado Cola: {isRefreshing ? 'RENOVANDO TOKEN...' : 'INACTIVA'} • Peticiones en
                espera: {queuedRequestsCount}
              </Text>
            </View>

            <View style={styles.buttonGroup}>
              <Pressable
                style={({ pressed }) => [
                  styles.secondaryActionBtn,
                  pressed && styles.buttonPressed,
                  (!refreshTokenPreview || runningQueueDemo) && styles.buttonDisabled,
                ]}
                disabled={!refreshTokenPreview || runningQueueDemo}
                onPress={handleRunQueueDemo}>
                {runningQueueDemo ? (
                  <ActivityIndicator color="#e2e8f0" />
                ) : (
                  <Text style={styles.secondaryActionBtnText}>
                    Expirar Access Token + Disparar 3 Peticiones Concurrentes
                  </Text>
                )}
              </Pressable>

              <View style={styles.splitBtnRow}>
                <Pressable
                  style={({ pressed }) => [
                    styles.smallGhostBtn,
                    pressed && styles.buttonPressed,
                    !accessToken && styles.buttonDisabled,
                  ]}
                  disabled={!accessToken}
                  onPress={expireAccessTokenForDemo}>
                  <Text style={styles.smallGhostBtnText}>Forzar 401 en RAM</Text>
                </Pressable>

                <Pressable
                  style={({ pressed }) => [
                    styles.smallDangerBtn,
                    pressed && styles.buttonPressed,
                    !isAuthenticated && styles.buttonDisabled,
                  ]}
                  disabled={!isAuthenticated}
                  onPress={logout}>
                  <Text style={styles.smallDangerBtnText}>Cerrar Sesión (Limpiar Todo)</Text>
                </Pressable>
              </View>
            </View>

            {concurrencyResults.length > 0 && (
              <View style={styles.resultsBox}>
                <Text style={styles.resultsTitle}>
                  Resultado de las 3 Peticiones Tras Silent Refresh Único:
                </Text>
                {concurrencyResults.map((line) => (
                  <Text key={line} style={styles.resultLine}>
                    ✅ {line}
                  </Text>
                ))}
              </View>
            )}
          </View>
        </View>

        {/* ACCESO RÁPIDO A LOS OTROS MÓDULOS DE SUSTENTACIÓN */}
        <View style={styles.quickNavRow}>
          <Pressable
            style={styles.quickNavCard}
            onPress={() => router.push('/explore')}>
            <Text style={styles.quickNavStep}>PRUEBAS 2 Y 3</Text>
            <Text style={styles.quickNavTitle}>Ir a Authenticator TOTP (Modo Avión) →</Text>
          </Pressable>
          <Pressable
            style={styles.quickNavCard}
            onPress={() => router.push('/boveda')}>
            <Text style={styles.quickNavStep}>PRUEBAS 4 Y 5</Text>
            <Text style={styles.quickNavTitle}>Ir a Bóveda Crítica & Anti-Replay →</Text>
          </Pressable>
        </View>

        {/* BITÁCORA DE AUDITORÍA EN VIVO */}
        <View style={styles.sectionCard}>
          <View style={styles.logHeaderRow}>
            <Text style={styles.sectionTitle}>Bitácora Criptográfica en Vivo</Text>
            <Pressable onPress={clearLogs}>
              <Text style={styles.clearLogsText}>Limpiar</Text>
            </Pressable>
          </View>
          {auditLogs.length === 0 ? (
            <Text style={styles.emptyLogsText}>
              Inicia sesión con OAuth 2.0 + PKCE para observar la traza de seguridad en tiempo real.
            </Text>
          ) : (
            auditLogs.slice(0, 12).map((log) => (
              <View key={log.id} style={styles.logItem}>
                <View style={styles.logTopLine}>
                  <Text style={styles.logCategory}>[{log.category}]</Text>
                  <Text style={styles.logTitle}>{log.title}</Text>
                  <Text style={styles.logTime}>{log.timestamp}</Text>
                </View>
                <Text style={styles.logDetail}>{log.detail}</Text>
              </View>
            ))
          )}
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: '#070f1e',
  },
  scroll: {
    flex: 1,
  },
  contentContainer: {
    padding: 16,
    paddingBottom: 110,
    gap: 16,
  },
  headerCard: {
    backgroundColor: '#0f1d36',
    borderRadius: 18,
    padding: 18,
    borderWidth: 1,
    borderColor: '#1e3a5f',
  },
  headerTopRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: 8,
    marginBottom: 10,
  },
  badge: {
    backgroundColor: 'rgba(16, 185, 129, 0.15)',
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 999,
  },
  badgeText: {
    color: '#34d399',
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 0.6,
  },
  serverChip: {
    backgroundColor: '#1e293b',
    paddingHorizontal: 10,
    paddingVertical: 5,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#334155',
  },
  serverChipText: {
    color: '#93c5fd',
    fontSize: 11,
    fontFamily: 'monospace',
  },
  headerTitle: {
    color: '#f8fafc',
    fontSize: 21,
    fontWeight: '800',
    marginBottom: 4,
  },
  headerSubtitle: {
    color: '#94a3b8',
    fontSize: 13,
    lineHeight: 18,
  },
  urlEditorBox: {
    marginTop: 14,
    paddingTop: 12,
    borderTopWidth: 1,
    borderTopColor: '#1e293b',
    gap: 8,
  },
  urlEditorLabel: {
    color: '#cbd5e1',
    fontSize: 12,
  },
  urlInputRow: {
    flexDirection: 'row',
    gap: 8,
  },
  urlInput: {
    flex: 1,
    backgroundColor: '#070f1e',
    borderWidth: 1,
    borderColor: '#334155',
    borderRadius: 10,
    paddingHorizontal: 12,
    paddingVertical: 8,
    color: '#f8fafc',
    fontFamily: 'monospace',
    fontSize: 13,
  },
  urlSaveBtn: {
    backgroundColor: '#3b82f6',
    paddingHorizontal: 14,
    justifyContent: 'center',
    borderRadius: 10,
  },
  urlSaveBtnText: {
    color: '#ffffff',
    fontWeight: '700',
    fontSize: 13,
  },
  quickUrlRow: {
    flexDirection: 'row',
    gap: 8,
  },
  quickUrlBtn: {
    backgroundColor: '#1e293b',
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: 8,
  },
  quickUrlText: {
    color: '#cbd5e1',
    fontSize: 11,
  },
  errorBanner: {
    backgroundColor: 'rgba(239, 68, 68, 0.14)',
    borderWidth: 1,
    borderColor: '#ef4444',
    borderRadius: 14,
    padding: 14,
  },
  errorBannerTitle: {
    color: '#fca5a5',
    fontWeight: '800',
    fontSize: 14,
    marginBottom: 4,
  },
  errorBannerBody: {
    color: '#fecaca',
    fontSize: 12,
    lineHeight: 17,
  },
  sectionCard: {
    backgroundColor: '#0f172a',
    borderRadius: 16,
    padding: 16,
    borderWidth: 1,
    borderColor: '#1e293b',
    gap: 12,
  },
  sectionHeader: {
    gap: 2,
  },
  sectionStep: {
    color: '#38bdf8',
    fontSize: 11,
    fontWeight: '800',
    letterSpacing: 0.7,
  },
  sectionTitle: {
    color: '#f1f5f9',
    fontSize: 17,
    fontWeight: '800',
  },
  sectionDescription: {
    color: '#94a3b8',
    fontSize: 13,
    lineHeight: 18,
  },
  buttonGroup: {
    gap: 10,
  },
  primaryButton: {
    backgroundColor: '#10b981',
    paddingVertical: 14,
    paddingHorizontal: 16,
    borderRadius: 12,
    alignItems: 'center',
    justifyContent: 'center',
  },
  primaryButtonText: {
    color: '#042f2e',
    fontWeight: '800',
    fontSize: 14,
  },
  outlineWarningButton: {
    backgroundColor: 'rgba(245, 158, 11, 0.1)',
    borderWidth: 1,
    borderColor: 'rgba(245, 158, 11, 0.45)',
    paddingVertical: 11,
    paddingHorizontal: 14,
    borderRadius: 12,
    alignItems: 'center',
  },
  outlineWarningButtonText: {
    color: '#fbbf24',
    fontWeight: '700',
    fontSize: 12,
  },
  buttonPressed: {
    opacity: 0.75,
  },
  buttonDisabled: {
    opacity: 0.45,
  },
  telemetryBox: {
    backgroundColor: '#070f1e',
    borderRadius: 12,
    padding: 12,
    borderWidth: 1,
    borderColor: '#1e293b',
    gap: 4,
  },
  telemetryHeading: {
    color: '#34d399',
    fontSize: 12,
    fontWeight: '700',
    marginBottom: 2,
  },
  monoLine: {
    color: '#cbd5e1',
    fontFamily: 'monospace',
    fontSize: 11,
  },
  monoKey: {
    color: '#64748b',
    fontWeight: '700',
  },
  storageGrid: {
    gap: 10,
  },
  storageBoxRam: {
    backgroundColor: 'rgba(56, 189, 248, 0.08)',
    borderWidth: 1,
    borderColor: 'rgba(56, 189, 248, 0.35)',
    borderRadius: 12,
    padding: 12,
    gap: 4,
  },
  storageBoxHardware: {
    backgroundColor: 'rgba(16, 185, 129, 0.08)',
    borderWidth: 1,
    borderColor: 'rgba(16, 185, 129, 0.35)',
    borderRadius: 12,
    padding: 12,
    gap: 4,
  },
  storageHeaderRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  storageTagRam: {
    color: '#38bdf8',
    fontSize: 10,
    fontWeight: '800',
  },
  storageTagHardware: {
    color: '#34d399',
    fontSize: 10,
    fontWeight: '800',
  },
  storageTtl: {
    color: '#94a3b8',
    fontSize: 11,
    fontWeight: '700',
  },
  storageTokenName: {
    color: '#f8fafc',
    fontSize: 14,
    fontWeight: '700',
  },
  storageTokenValue: {
    color: '#cbd5e1',
    fontFamily: 'monospace',
    fontSize: 11,
  },
  storageMetaText: {
    color: '#64748b',
    fontSize: 11,
    marginTop: 2,
  },
  queueDemoBox: {
    backgroundColor: '#070f1e',
    borderRadius: 12,
    padding: 12,
    borderWidth: 1,
    borderColor: '#1e293b',
    gap: 10,
  },
  queueDemoTitle: {
    color: '#e2e8f0',
    fontSize: 14,
    fontWeight: '700',
  },
  queueDemoSubtitle: {
    color: '#94a3b8',
    fontSize: 12,
    lineHeight: 17,
  },
  queueStatusBanner: {
    backgroundColor: '#0f172a',
    paddingVertical: 8,
    paddingHorizontal: 10,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#334155',
  },
  queueStatusText: {
    color: '#38bdf8',
    fontFamily: 'monospace',
    fontSize: 11,
    fontWeight: '700',
  },
  secondaryActionBtn: {
    backgroundColor: '#2563eb',
    paddingVertical: 12,
    paddingHorizontal: 14,
    borderRadius: 10,
    alignItems: 'center',
  },
  secondaryActionBtnText: {
    color: '#ffffff',
    fontWeight: '700',
    fontSize: 13,
    textAlign: 'center',
  },
  splitBtnRow: {
    flexDirection: 'row',
    gap: 8,
  },
  smallGhostBtn: {
    flex: 1,
    backgroundColor: '#1e293b',
    paddingVertical: 10,
    borderRadius: 10,
    alignItems: 'center',
  },
  smallGhostBtnText: {
    color: '#cbd5e1',
    fontSize: 12,
    fontWeight: '600',
  },
  smallDangerBtn: {
    flex: 1,
    backgroundColor: 'rgba(239, 68, 68, 0.15)',
    borderWidth: 1,
    borderColor: 'rgba(239, 68, 68, 0.4)',
    paddingVertical: 10,
    borderRadius: 10,
    alignItems: 'center',
  },
  smallDangerBtnText: {
    color: '#fca5a5',
    fontSize: 12,
    fontWeight: '700',
  },
  resultsBox: {
    backgroundColor: 'rgba(16, 185, 129, 0.1)',
    borderRadius: 10,
    padding: 10,
    borderWidth: 1,
    borderColor: 'rgba(16, 185, 129, 0.35)',
    gap: 4,
  },
  resultsTitle: {
    color: '#34d399',
    fontSize: 12,
    fontWeight: '700',
  },
  resultLine: {
    color: '#e2e8f0',
    fontFamily: 'monospace',
    fontSize: 11,
  },
  quickNavRow: {
    flexDirection: 'row',
    gap: 10,
  },
  quickNavCard: {
    flex: 1,
    backgroundColor: '#112240',
    borderRadius: 14,
    padding: 12,
    borderWidth: 1,
    borderColor: '#233554',
    gap: 4,
  },
  quickNavStep: {
    color: '#64ffda',
    fontSize: 10,
    fontWeight: '800',
  },
  quickNavTitle: {
    color: '#e6f1ff',
    fontSize: 12,
    fontWeight: '700',
  },
  logHeaderRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  clearLogsText: {
    color: '#38bdf8',
    fontSize: 12,
    fontWeight: '600',
  },
  emptyLogsText: {
    color: '#64748b',
    fontSize: 12,
    fontStyle: 'italic',
  },
  logItem: {
    backgroundColor: '#070f1e',
    borderRadius: 10,
    padding: 10,
    borderLeftWidth: 3,
    borderLeftColor: '#38bdf8',
    gap: 3,
  },
  logTopLine: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
  },
  logCategory: {
    color: '#34d399',
    fontFamily: 'monospace',
    fontSize: 10,
    fontWeight: '700',
  },
  logTitle: {
    color: '#f1f5f9',
    fontSize: 12,
    fontWeight: '700',
    flex: 1,
  },
  logTime: {
    color: '#64748b',
    fontFamily: 'monospace',
    fontSize: 10,
  },
  logDetail: {
    color: '#94a3b8',
    fontSize: 11,
    lineHeight: 15,
  },
});
