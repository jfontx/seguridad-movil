import { router } from 'expo-router';
import React, { useEffect, useState } from 'react';
import {
  ActivityIndicator,
  Modal,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { useAuth } from '@/context/auth-context';
import { setVolatileElevatedToken } from '@/services/api-client';
import { computeTotpSync } from '@/utils/totp';

export default function BovedaStepUpScreen() {
  const {
    isAuthenticated,
    accessToken,
    elevatedToken,
    elevatedTokenExp,
    totpConfig,
    vaultData,
    pendingStepUpToken,
    stepUpModalVisible,
    setStepUpModalVisible,
    requestVaultAccess,
    verifyStepUpTotp,
    simulateReplayAttackWithLastCode,
    lastUsedStepUpInfo,
  } = useAuth();

  const [otpInput, setOtpInput] = useState<string>('');
  const [liveLocalOtp, setLiveLocalOtp] = useState<string>(() =>
    computeTotpSync(totpConfig.secret).otp
  );
  const [liveRemaining, setLiveRemaining] = useState<number>(30);

  const [busy, setBusy] = useState<boolean>(false);
  const [modalError, setModalError] = useState<string | null>(null);
  const [replayBanner, setReplayBanner] = useState<{
    blocked: boolean;
    status: number;
    message: string;
  } | null>(null);

  useEffect(() => {
    const tick = () => {
      const res = computeTotpSync(totpConfig.secret, Math.floor(Date.now() / 1000), totpConfig.period);
      setLiveLocalOtp(res.otp);
      setLiveRemaining(res.remainingSeconds);
    };
    tick();
    const id = setInterval(tick, 500);
    return () => clearInterval(id);
  }, [totpConfig.secret, totpConfig.period]);

  const handleOpenBoveda = async () => {
    setModalError(null);
    setReplayBanner(null);
    setBusy(true);
    try {
      await requestVaultAccess();
    } catch (err) {
      setModalError(err instanceof Error ? err.message : 'Error al consultar la Bóveda Crítica');
    } finally {
      setBusy(false);
    }
  };

  const handleVerify2FA = async () => {
    setModalError(null);
    setReplayBanner(null);
    setBusy(true);
    try {
      await verifyStepUpTotp(otpInput);
      setOtpInput('');
    } catch (err) {
      setModalError(err instanceof Error ? err.message : 'Código TOTP rechazado');
    } finally {
      setBusy(false);
    }
  };

  const handleSimulateReplay = async () => {
    setModalError(null);
    setBusy(true);
    try {
      const res = await simulateReplayAttackWithLastCode(lastUsedStepUpInfo?.code || liveLocalOtp);
      setReplayBanner(res);
    } catch (err) {
      setModalError(err instanceof Error ? err.message : 'Error al probar Anti-Replay');
    } finally {
      setBusy(false);
    }
  };

  const handleResetElevation = () => {
    setVolatileElevatedToken(null);
    setReplayBanner(null);
  };

  return (
    <SafeAreaView style={styles.safeArea} edges={['top']}>
      <ScrollView
        style={styles.scroll}
        contentContainerStyle={styles.contentContainer}
        showsVerticalScrollIndicator={false}>
        {/* ENCABEZADO */}
        <View style={styles.headerCard}>
          <View style={styles.badgeRow}>
            <View style={styles.stepUpBadge}>
              <Text style={styles.stepUpBadgeText}>PUNTO 4 • STEP-UP 2FA & ANTI-REPLAY</Text>
            </View>
            <View
              style={[
                styles.statusPill,
                elevatedToken ? styles.statusPillElevated : styles.statusPillStandard,
              ]}>
              <Text
                style={[
                  styles.statusPillText,
                  elevatedToken ? styles.statusPillTextElevated : styles.statusPillTextStandard,
                ]}>
                {elevatedToken ? '🔓 mfa_verified: true' : '🔒 mfa_verified: false'}
              </Text>
            </View>
          </View>
          <Text style={styles.headerTitle}>Bóveda Crítica & Caché Anti-Replay</Text>
          <Text style={styles.headerSubtitle}>
            Protección de ruta crítica (`GET /api/boveda-critica`) mediante elevación dinámica de
            privilegios y ventana de tolerancia Clock Skew (`C-1`, `C`, `C+1`).
          </Text>
        </View>

        {!isAuthenticated && (
          <View style={styles.warningCard}>
            <Text style={styles.warningTitle}>Sesión OAuth 2.0 Requerida</Text>
            <Text style={styles.warningBody}>
              Primero inicia sesión con OAuth 2.0 + PKCE en la pestaña 1 para obtener un
              `access_token` estándar (`mfa_verified: false`).
            </Text>
            <Pressable
              style={styles.goLoginBtn}
              onPress={() => router.push('/')}>
              <Text style={styles.goLoginBtnText}>Ir a Iniciar Sesión (OAuth + PKCE) →</Text>
            </Pressable>
          </View>
        )}

        {/* PRUEBA #4: ACCESO A BÓVEDA CRÍTICA (STEP-UP AUTHENTICATION) */}
        <View style={styles.sectionCard}>
          <Text style={styles.sectionStep}>PRUEBA DE ACEPTACIÓN #4</Text>
          <Text style={styles.sectionTitle}>
            Step-Up Authentication (`GET /api/boveda-critica`)
          </Text>
          <Text style={styles.sectionDescription}>
            Si intentas abrir la Bóveda con un `access_token` estándar (`mfa_verified: false`), la
            API responde `403 Forbidden (mfa_required)` con un `step_up_token` y abre el modal de
            verificación 2FA TOTP.
          </Text>

          <View style={styles.tokenStateBox}>
            <Text style={styles.tokenStateLine}>
              • Access Token Estándar:{' '}
              <Text style={styles.monoHighlight}>
                {accessToken ? 'Presente en RAM (mfa_verified: false)' : 'No disponible'}
              </Text>
            </Text>
            <Text style={styles.tokenStateLine}>
              • Elevated Token (2FA):{' '}
              <Text style={styles.monoHighlight}>
                {elevatedToken
                  ? `Activo en RAM (exp: ${elevatedTokenExp})`
                  : 'No elevado (Disparará 403 Forbidden)'}
              </Text>
            </Text>
          </View>

          <View style={styles.actionsColumn}>
            <Pressable
              style={({ pressed }) => [
                styles.primaryVaultBtn,
                pressed && styles.buttonPressed,
                (!isAuthenticated || busy) && styles.buttonDisabled,
              ]}
              disabled={!isAuthenticated || busy}
              onPress={handleOpenBoveda}>
              {busy ? (
                <ActivityIndicator color="#042f2e" />
              ) : (
                <Text style={styles.primaryVaultBtnText}>
                  {elevatedToken
                    ? 'Consultar Bóveda Crítica (Con Elevated Token)'
                    : 'Intentar Abrir Bóveda Crítica (Disparar 403 -> Modal 2FA)'}
                </Text>
              )}
            </Pressable>

            {elevatedToken && (
              <Pressable
                style={({ pressed }) => [
                  styles.downgradeBtn,
                  pressed && styles.buttonPressed,
                ]}
                onPress={handleResetElevation}>
                <Text style={styles.downgradeBtnText}>
                  Revocar Elevated Token en RAM (Volver a mfa_verified: false)
                </Text>
              </Pressable>
            )}
          </View>

          {modalError && !stepUpModalVisible ? (
            <View style={styles.errorAlert}>
              <Text style={styles.errorAlertText}>{modalError}</Text>
            </View>
          ) : null}
        </View>

        {/* PRUEBA #5: ATAQUE DE REPETICIÓN (ANTI-REPLAY CACHE TTL 90S) */}
        <View style={styles.sectionCard}>
          <Text style={styles.sectionStep}>PRUEBA DE ACEPTACIÓN #5</Text>
          <Text style={styles.sectionTitle}>
            Defensa Contra Ataque de Repetición (Anti-Replay 409 Conflict)
          </Text>
          <Text style={styles.sectionDescription}>
            Una vez que un código TOTP de 6 dígitos es validado en `POST /auth/mfa/verify`, el
            backend lo registra en su caché Anti-Replay por 90 segundos. Si se reenvía el mismo
            código en la misma ventana, responde `409 Conflict: Replay Attack Detected`.
          </Text>

          <Pressable
            style={({ pressed }) => [
              styles.replayTestBtn,
              pressed && styles.buttonPressed,
              (!lastUsedStepUpInfo || busy) && styles.buttonDisabled,
            ]}
            disabled={!lastUsedStepUpInfo || busy}
            onPress={handleSimulateReplay}>
            <Text style={styles.replayTestBtnText}>
              {lastUsedStepUpInfo
                ? `Reenviar Mismo Código TOTP (${lastUsedStepUpInfo.code}) -> Probar 409 Conflict`
                : 'Verifica primero el 2FA arriba para habilitar la prueba Anti-Replay'}
            </Text>
          </Pressable>

          {replayBanner && (
            <View
              style={[
                styles.replayResultBox,
                replayBanner.blocked ? styles.replayBlockedBox : styles.replayAllowedBox,
              ]}>
              <Text style={styles.replayResultTitle}>
                {replayBanner.blocked
                  ? `🛡️ BLOQUEADO CON ÉXITO — HTTP ${replayBanner.status}`
                  : `HTTP ${replayBanner.status}`}
              </Text>
              <Text style={styles.replayResultMessage}>{replayBanner.message}</Text>
            </View>
          )}
        </View>

        {/* CONTENIDO DESBLOQUEADO DE LA BÓVEDA CRÍTICA */}
        {vaultData && (
          <View style={styles.vaultUnlockedCard}>
            <View style={styles.vaultHeaderRow}>
              <Text style={styles.vaultUnlockedTag}>✓ BÓVEDA CRÍTICA DESBLOQUEADA</Text>
              <Text style={styles.vaultIdText}>{vaultData.vault_id}</Text>
            </View>
            <Text style={styles.vaultClassification}>{vaultData.classification}</Text>
            <Text style={styles.vaultMeta}>
              Autorizado para: {vaultData.accessed_by} • MFA Verificado:{' '}
              {String(vaultData.mfa_verified)}
            </Text>

            <View style={styles.secretsList}>
              {vaultData.secrets.map((sec) => (
                <View key={sec.id} style={styles.secretItem}>
                  <Text style={styles.secretTitle}>
                    [{sec.id}] {sec.title}
                  </Text>
                  <Text style={styles.secretValue}>{sec.value}</Text>
                </View>
              ))}
            </View>
          </View>
        )}
      </ScrollView>

      {/* MODAL DE ELEVACIÓN DE PRIVILEGIOS (STEP-UP 2FA TOTP) */}
      <Modal
        visible={stepUpModalVisible}
        transparent
        animationType="slide"
        onRequestClose={() => setStepUpModalVisible(false)}>
        <View style={styles.modalBackdrop}>
          <View style={styles.modalCard}>
            <View style={styles.modalBadge}>
              <Text style={styles.modalBadgeText}>
                HTTP 403 FORBIDDEN • MFA_REQUIRED
              </Text>
            </View>

            <Text style={styles.modalTitle}>Elevación de Privilegios Step-Up 2FA</Text>
            <Text style={styles.modalSubtitle}>
              El recurso `/api/boveda-critica` exige verificación TOTP (RFC 6238). Ingresa los 6
              dígitos actuales para obtener un `elevated_token`.
            </Text>

            {pendingStepUpToken && (
              <View style={styles.stepUpTokenPreview}>
                <Text style={styles.stepUpTokenLabel}>step_up_token recibido:</Text>
                <Text style={styles.stepUpTokenMono} numberOfLines={1}>
                  {pendingStepUpToken}
                </Text>
              </View>
            )}

            <TextInput
              style={styles.otpNumericInput}
              value={otpInput}
              onChangeText={(txt) => setOtpInput(txt.replace(/[^0-9]/g, '').slice(0, 6))}
              keyboardType="number-pad"
              maxLength={6}
              placeholder="000000"
              placeholderTextColor="#475569"
            />

            <Pressable
              style={styles.autofillChip}
              onPress={() => setOtpInput(liveLocalOtp)}>
              <Text style={styles.autofillChipText}>
                ⚡ Autocompletar desde mi Authenticator Local: {liveLocalOtp} ({liveRemaining}s)
              </Text>
            </Pressable>

            {modalError ? (
              <View style={styles.modalErrorBox}>
                <Text style={styles.modalErrorText}>{modalError}</Text>
              </View>
            ) : null}

            <View style={styles.modalButtonsRow}>
              <Pressable
                style={styles.modalCancelBtn}
                onPress={() => {
                  setStepUpModalVisible(false);
                  setModalError(null);
                }}>
                <Text style={styles.modalCancelBtnText}>Cancelar</Text>
              </Pressable>

              <Pressable
                style={[
                  styles.modalVerifyBtn,
                  (otpInput.length !== 6 || busy) && styles.buttonDisabled,
                ]}
                disabled={otpInput.length !== 6 || busy}
                onPress={handleVerify2FA}>
                {busy ? (
                  <ActivityIndicator color="#042f2e" />
                ) : (
                  <Text style={styles.modalVerifyBtnText}>Verificar 2FA y Abrir</Text>
                )}
              </Pressable>
            </View>
          </View>
        </View>
      </Modal>
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
    gap: 6,
  },
  badgeRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: 8,
    marginBottom: 4,
  },
  stepUpBadge: {
    backgroundColor: 'rgba(56, 189, 248, 0.15)',
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 999,
  },
  stepUpBadgeText: {
    color: '#38bdf8',
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 0.5,
  },
  statusPill: {
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 999,
    borderWidth: 1,
  },
  statusPillElevated: {
    backgroundColor: 'rgba(16, 185, 129, 0.15)',
    borderColor: '#10b981',
  },
  statusPillStandard: {
    backgroundColor: 'rgba(245, 158, 11, 0.15)',
    borderColor: '#f59e0b',
  },
  statusPillText: {
    fontSize: 11,
    fontWeight: '800',
    fontFamily: 'monospace',
  },
  statusPillTextElevated: {
    color: '#34d399',
  },
  statusPillTextStandard: {
    color: '#fbbf24',
  },
  headerTitle: {
    color: '#f8fafc',
    fontSize: 21,
    fontWeight: '800',
  },
  headerSubtitle: {
    color: '#94a3b8',
    fontSize: 13,
    lineHeight: 18,
  },
  warningCard: {
    backgroundColor: 'rgba(245, 158, 11, 0.12)',
    borderWidth: 1,
    borderColor: '#f59e0b',
    borderRadius: 14,
    padding: 14,
    gap: 8,
  },
  warningTitle: {
    color: '#fbbf24',
    fontSize: 15,
    fontWeight: '800',
  },
  warningBody: {
    color: '#fde68a',
    fontSize: 12,
    lineHeight: 17,
  },
  goLoginBtn: {
    backgroundColor: '#f59e0b',
    paddingVertical: 10,
    paddingHorizontal: 14,
    borderRadius: 10,
    alignSelf: 'flex-start',
  },
  goLoginBtnText: {
    color: '#0f172a',
    fontWeight: '800',
    fontSize: 12,
  },
  sectionCard: {
    backgroundColor: '#0f172a',
    borderRadius: 16,
    padding: 16,
    borderWidth: 1,
    borderColor: '#1e293b',
    gap: 12,
  },
  sectionStep: {
    color: '#38bdf8',
    fontSize: 11,
    fontWeight: '800',
    letterSpacing: 0.7,
  },
  sectionTitle: {
    color: '#f1f5f9',
    fontSize: 16,
    fontWeight: '800',
  },
  sectionDescription: {
    color: '#94a3b8',
    fontSize: 13,
    lineHeight: 18,
  },
  tokenStateBox: {
    backgroundColor: '#070f1e',
    borderRadius: 10,
    padding: 12,
    borderWidth: 1,
    borderColor: '#1e293b',
    gap: 4,
  },
  tokenStateLine: {
    color: '#cbd5e1',
    fontSize: 12,
  },
  monoHighlight: {
    color: '#34d399',
    fontFamily: 'monospace',
    fontWeight: '700',
  },
  actionsColumn: {
    gap: 8,
  },
  primaryVaultBtn: {
    backgroundColor: '#10b981',
    paddingVertical: 14,
    paddingHorizontal: 16,
    borderRadius: 12,
    alignItems: 'center',
  },
  primaryVaultBtnText: {
    color: '#042f2e',
    fontWeight: '800',
    fontSize: 13,
    textAlign: 'center',
  },
  downgradeBtn: {
    backgroundColor: '#1e293b',
    paddingVertical: 10,
    paddingHorizontal: 14,
    borderRadius: 10,
    alignItems: 'center',
  },
  downgradeBtnText: {
    color: '#cbd5e1',
    fontSize: 12,
    fontWeight: '600',
  },
  replayTestBtn: {
    backgroundColor: 'rgba(239, 68, 68, 0.16)',
    borderWidth: 1,
    borderColor: '#ef4444',
    paddingVertical: 13,
    paddingHorizontal: 14,
    borderRadius: 12,
    alignItems: 'center',
  },
  replayTestBtnText: {
    color: '#fca5a5',
    fontWeight: '800',
    fontSize: 13,
    textAlign: 'center',
  },
  replayResultBox: {
    borderRadius: 12,
    padding: 12,
    borderWidth: 1,
    gap: 4,
  },
  replayBlockedBox: {
    backgroundColor: 'rgba(239, 68, 68, 0.15)',
    borderColor: '#ef4444',
  },
  replayAllowedBox: {
    backgroundColor: 'rgba(16, 185, 129, 0.15)',
    borderColor: '#10b981',
  },
  replayResultTitle: {
    color: '#fca5a5',
    fontSize: 13,
    fontWeight: '800',
  },
  replayResultMessage: {
    color: '#fecaca',
    fontSize: 12,
    lineHeight: 17,
  },
  vaultUnlockedCard: {
    backgroundColor: 'rgba(16, 185, 129, 0.08)',
    borderWidth: 1.5,
    borderColor: '#10b981',
    borderRadius: 16,
    padding: 16,
    gap: 10,
  },
  vaultHeaderRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  vaultUnlockedTag: {
    color: '#34d399',
    fontSize: 11,
    fontWeight: '900',
    letterSpacing: 0.6,
  },
  vaultIdText: {
    color: '#94a3b8',
    fontFamily: 'monospace',
    fontSize: 11,
  },
  vaultClassification: {
    color: '#f8fafc',
    fontSize: 15,
    fontWeight: '800',
  },
  vaultMeta: {
    color: '#94a3b8',
    fontSize: 12,
  },
  secretsList: {
    gap: 8,
    marginTop: 4,
  },
  secretItem: {
    backgroundColor: '#070f1e',
    borderRadius: 10,
    padding: 12,
    borderWidth: 1,
    borderColor: '#1e293b',
    gap: 4,
  },
  secretTitle: {
    color: '#38bdf8',
    fontSize: 12,
    fontWeight: '700',
  },
  secretValue: {
    color: '#f1f5f9',
    fontFamily: 'monospace',
    fontSize: 12,
  },
  errorAlert: {
    backgroundColor: 'rgba(239, 68, 68, 0.14)',
    borderRadius: 10,
    padding: 10,
    borderWidth: 1,
    borderColor: '#ef4444',
  },
  errorAlertText: {
    color: '#fca5a5',
    fontSize: 12,
  },
  buttonPressed: {
    opacity: 0.75,
  },
  buttonDisabled: {
    opacity: 0.45,
  },
  modalBackdrop: {
    flex: 1,
    backgroundColor: 'rgba(2, 6, 23, 0.82)',
    justifyContent: 'center',
    padding: 20,
  },
  modalCard: {
    backgroundColor: '#0f172a',
    borderRadius: 20,
    padding: 20,
    borderWidth: 1,
    borderColor: '#334155',
    gap: 12,
  },
  modalBadge: {
    backgroundColor: 'rgba(245, 158, 11, 0.16)',
    alignSelf: 'flex-start',
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 999,
  },
  modalBadgeText: {
    color: '#fbbf24',
    fontSize: 10,
    fontWeight: '800',
  },
  modalTitle: {
    color: '#f8fafc',
    fontSize: 19,
    fontWeight: '800',
  },
  modalSubtitle: {
    color: '#94a3b8',
    fontSize: 13,
    lineHeight: 18,
  },
  stepUpTokenPreview: {
    backgroundColor: '#070f1e',
    padding: 10,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: '#1e293b',
  },
  stepUpTokenLabel: {
    color: '#64748b',
    fontSize: 11,
  },
  stepUpTokenMono: {
    color: '#38bdf8',
    fontFamily: 'monospace',
    fontSize: 11,
  },
  otpNumericInput: {
    backgroundColor: '#070f1e',
    borderWidth: 1.5,
    borderColor: '#10b981',
    borderRadius: 14,
    paddingVertical: 14,
    color: '#ffffff',
    fontFamily: 'monospace',
    fontSize: 32,
    fontWeight: '900',
    textAlign: 'center',
    letterSpacing: 8,
  },
  autofillChip: {
    backgroundColor: 'rgba(16, 185, 129, 0.12)',
    borderWidth: 1,
    borderColor: 'rgba(16, 185, 129, 0.4)',
    paddingVertical: 10,
    paddingHorizontal: 12,
    borderRadius: 10,
    alignItems: 'center',
  },
  autofillChipText: {
    color: '#34d399',
    fontSize: 12,
    fontWeight: '700',
  },
  modalErrorBox: {
    backgroundColor: 'rgba(239, 68, 68, 0.15)',
    borderRadius: 10,
    padding: 10,
    borderWidth: 1,
    borderColor: '#ef4444',
  },
  modalErrorText: {
    color: '#fca5a5',
    fontSize: 12,
  },
  modalButtonsRow: {
    flexDirection: 'row',
    gap: 10,
    marginTop: 4,
  },
  modalCancelBtn: {
    flex: 1,
    backgroundColor: '#1e293b',
    paddingVertical: 13,
    borderRadius: 12,
    alignItems: 'center',
  },
  modalCancelBtnText: {
    color: '#cbd5e1',
    fontWeight: '700',
    fontSize: 14,
  },
  modalVerifyBtn: {
    flex: 1.4,
    backgroundColor: '#10b981',
    paddingVertical: 13,
    borderRadius: 12,
    alignItems: 'center',
  },
  modalVerifyBtnText: {
    color: '#042f2e',
    fontWeight: '800',
    fontSize: 14,
  },
});

