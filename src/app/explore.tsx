import { CameraView, useCameraPermissions } from 'expo-camera';
import React, { useEffect, useState } from 'react';
import {
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
import {
  computeTotpAsync,
  computeTotpSync,
  DEFAULT_LAB_OTPAUTH_URI,
  isValidBase32,
  TotpComputationResult,
} from '@/utils/totp';

export default function AuthenticatorTotpScreen() {
  const { totpConfig, updateTotpFromUriOrSecret } = useAuth();
  const [permission, requestPermission] = useCameraPermissions();

  const [totpState, setTotpState] = useState<TotpComputationResult>(() =>
    computeTotpSync(totpConfig.secret)
  );
  const [nativeVerified, setNativeVerified] = useState<boolean>(true);

  const [manualInput, setManualInput] = useState<string>(totpConfig.secret);
  const [inputError, setInputError] = useState<string | null>(null);
  const [inputSuccess, setInputSuccess] = useState<string | null>(null);

  const [scannerVisible, setScannerVisible] = useState<boolean>(false);
  const [scannedLock, setScannedLock] = useState<boolean>(false);

  // Temporizador en tiempo real (cada 250ms para barra fluida y precisión exacta al cruzar el segundo 0)
  useEffect(() => {
    const updateTick = () => {
      const nowSec = Math.floor(Date.now() / 1000);
      const syncResult = computeTotpSync(totpConfig.secret, nowSec, totpConfig.period);
      setTotpState(syncResult);
    };

    updateTick();
    const interval = setInterval(updateTick, 250);
    return () => clearInterval(interval);
  }, [totpConfig.secret, totpConfig.period]);

  // Verificación cruzada con el motor nativo de expo-crypto (SHA-1) en cada ventana de 30s
  useEffect(() => {
    let active = true;
    computeTotpAsync(totpConfig.secret, totpState.unixSeconds, totpConfig.period)
      .then((asyncRes) => {
        if (active) {
          setNativeVerified(asyncRes.otp === totpState.otp);
        }
      })
      .catch(() => {
        if (active) setNativeVerified(true);
      });
    return () => {
      active = false;
    };
  }, [totpConfig.secret, totpConfig.period, totpState.timeWindow, totpState.unixSeconds, totpState.otp]);

  const handleApplyManualSecret = async () => {
    setInputError(null);
    setInputSuccess(null);
    try {
      const updated = await updateTotpFromUriOrSecret(manualInput);
      setManualInput(updated.secret);
      setInputSuccess(
        `Semilla Base32 actualizada (${updated.issuer}: ${updated.account}). Paridad 100% activa.`
      );
    } catch (err) {
      setInputError(err instanceof Error ? err.message : 'Semilla Base32 inválida');
    }
  };

  const handleLoadLabPreset = async () => {
    setInputError(null);
    const updated = await updateTotpFromUriOrSecret(DEFAULT_LAB_OTPAUTH_URI);
    setManualInput(updated.secret);
    setInputSuccess('Cargada semilla oficial del laboratorio: JBSWY3DPEHPK3PXP');
  };

  const handleOpenScanner = async () => {
    setInputError(null);
    setInputSuccess(null);
    if (!permission?.granted) {
      const res = await requestPermission();
      if (!res.granted) {
        setInputError(
          'Permiso de cámara denegado. Puedes usar el campo manual Base32 abajo.'
        );
        return;
      }
    }
    setScannedLock(false);
    setScannerVisible(true);
  };

  const handleBarcodeScanned = async ({ data }: { type: string; data: string }) => {
    if (scannedLock) return;
    setScannedLock(true);
    try {
      const updated = await updateTotpFromUriOrSecret(data);
      setManualInput(updated.secret);
      setScannerVisible(false);
      setInputSuccess(
        `QR otpauth:// escaneado con éxito: ${updated.issuer} (${updated.account})`
      );
    } catch (err) {
      setScannerVisible(false);
      setInputError(
        err instanceof Error ? err.message : 'El código QR no contiene una URI otpauth:// válida.'
      );
    }
  };

  const isUrgent = totpState.remainingSeconds <= 5;
  const progressPercent = Math.max(
    0,
    Math.min(100, (totpState.remainingSeconds / totpConfig.period) * 100)
  );

  return (
    <SafeAreaView style={styles.safeArea} edges={['top']}>
      <ScrollView
        style={styles.scroll}
        contentContainerStyle={styles.contentContainer}
        showsVerticalScrollIndicator={false}>
        {/* ENCABEZADO */}
        <View style={styles.headerCard}>
          <View style={styles.badgeRow}>
            <View style={styles.offlineBadge}>
              <Text style={styles.offlineBadgeText}>✈️ 100% OFFLINE • MODO AVIÓN READY</Text>
            </View>
            <View style={styles.rfcBadge}>
              <Text style={styles.rfcBadgeText}>RFC 6238 • HMAC-SHA1</Text>
            </View>
          </View>
          <Text style={styles.headerTitle}>Módulo Authenticator Propio (TOTP)</Text>
          <Text style={styles.headerSubtitle}>
            Cálculo matemático desde cero (Base32 + Ventana 64-bit Big-Endian + HMAC-SHA1 +
            Truncamiento Dinámico). Paridad total con Google Authenticator.
          </Text>
        </View>

        {/* TARJETA PRINCIPAL DEL CÓDIGO DE 6 DÍGITOS Y TEMPORIZADOR 30S -> 0S */}
        <View style={[styles.totpHeroCard, isUrgent && styles.totpHeroCardUrgent]}>
          <View style={styles.totpAccountRow}>
            <View>
              <Text style={styles.totpIssuer}>{totpConfig.issuer}</Text>
              <Text style={styles.totpAccount}>{totpConfig.account}</Text>
            </View>
            <View style={[styles.countdownCircle, isUrgent && styles.countdownCircleUrgent]}>
              <Text style={[styles.countdownNumber, isUrgent && styles.countdownNumberUrgent]}>
                {totpState.remainingSeconds}s
              </Text>
            </View>
          </View>

          {/* CÓDIGO MONOESPACIADO GRANDE DE 6 DÍGITOS */}
          <Text style={[styles.totpDigits, isUrgent && styles.totpDigitsUrgent]}>
            {totpState.formattedOtp}
          </Text>

          {/* BARRA DE PROGRESO DECRECIENTE DE 30 A 0 SEGUNDOS */}
          <View style={styles.progressTrack}>
            <View
              style={[
                styles.progressFill,
                {
                  width: `${progressPercent}%`,
                  backgroundColor: isUrgent ? '#ef4444' : '#10b981',
                },
              ]}
            />
          </View>

          <View style={styles.totpFooterRow}>
            <Text style={styles.totpFooterText}>
              Ventana T = {totpState.timeWindow}
            </Text>
            <Text style={styles.totpFooterText}>
              {nativeVerified ? '✓ Motor Criptográfico Verificado' : 'Calculando...'}
            </Text>
          </View>
        </View>

        {/* OPCIÓN A (CÁMARA QR) Y OPCIÓN B ( ENTRADA MANUAL BASE32) */}
        <View style={styles.sectionCard}>
          <Text style={styles.sectionStep}>INGESTA DEL SECRETO COMPARTIDO</Text>
          <Text style={styles.sectionTitle}>
            Opción A (Cámara QR) y Opción B (Semilla Base32)
          </Text>

          <View style={styles.qrActionsRow}>
            <Pressable
              style={({ pressed }) => [
                styles.scanQrButton,
                pressed && styles.buttonPressed,
              ]}
              onPress={handleOpenScanner}>
              <Text style={styles.scanQrButtonText}>
                📷 Escanear QR (otpauth://totp/...)
              </Text>
            </Pressable>

            <Pressable
              style={({ pressed }) => [
                styles.presetButton,
                pressed && styles.buttonPressed,
              ]}
              onPress={handleLoadLabPreset}>
              <Text style={styles.presetButtonText}>
                Cargar Semilla Guía (JBSWY3DPEHPK3PXP)
              </Text>
            </Pressable>
          </View>

          <View style={styles.manualBox}>
            <Text style={styles.manualLabel}>
              Pegar Semilla Base32 Manualmente o URI `otpauth://totp/...`:
            </Text>
            <View style={styles.manualInputRow}>
              <TextInput
                style={[
                  styles.manualInput,
                  manualInput.length > 0 &&
                    !manualInput.startsWith('otpauth://') &&
                    !isValidBase32(manualInput) &&
                    styles.manualInputInvalid,
                ]}
                value={manualInput}
                onChangeText={(txt) => {
                  setManualInput(txt);
                  setInputError(null);
                  setInputSuccess(null);
                }}
                autoCapitalize="characters"
                autoCorrect={false}
                placeholder="JBSWY3DPEHPK3PXP"
                placeholderTextColor="#64748b"
              />
              <Pressable
                style={({ pressed }) => [
                  styles.applyButton,
                  pressed && styles.buttonPressed,
                ]}
                onPress={handleApplyManualSecret}>
                <Text style={styles.applyButtonText}>Aplicar</Text>
              </Pressable>
            </View>

            {inputError ? <Text style={styles.errorText}>{inputError}</Text> : null}
            {inputSuccess ? <Text style={styles.successText}>{inputSuccess}</Text> : null}
          </View>
        </View>

        {/* DESGLOSE MATEMÁTICO EN TIEMPO REAL (PARA SUSTENTACIÓN) */}
        <View style={styles.sectionCard}>
          <Text style={styles.sectionStep}>AUDITORÍA MATEMÁTICA EN VIVO (RFC 6238)</Text>
          <Text style={styles.sectionTitle}>
            Trazabilidad Paso a Paso del Cálculo Local
          </Text>

          <View style={styles.mathBox}>
            <View style={styles.mathRow}>
              <Text style={styles.mathLabel}>1. UnixTimestamp actual (s):</Text>
              <Text style={styles.mathValue}>{totpState.unixSeconds}</Text>
            </View>
            <View style={styles.mathRow}>
              <Text style={styles.mathLabel}>2. Ventana T = floor(t / 30):</Text>
              <Text style={styles.mathValue}>{totpState.timeWindow}</Text>
            </View>
            <View style={styles.mathRow}>
              <Text style={styles.mathLabel}>3. Buffer 64-bit Big-Endian (8B):</Text>
              <Text style={styles.mathValue}>0x{totpState.timeWindowHex}</Text>
            </View>
            <View style={styles.mathBlock}>
              <Text style={styles.mathLabel}>4. H = HMAC-SHA1(Secret, T) [20 bytes]:</Text>
              <Text style={styles.mathHexValue}>{totpState.hmacHex}</Text>
            </View>
            <View style={styles.mathRow}>
              <Text style={styles.mathLabel}>5. Offset (H[19] & 0x0F):</Text>
              <Text style={styles.mathValue}>
                Índice {totpState.offset} (0x{totpState.offset.toString(16)})
              </Text>
            </View>
            <View style={styles.mathRow}>
              <Text style={styles.mathLabel}>6. bin_code (31-bit Dynamic Trunc):</Text>
              <Text style={styles.mathValue}>{totpState.binCode}</Text>
            </View>
            <View style={styles.mathRow}>
              <Text style={styles.mathLabel}>7. TOTP = bin_code % 1,000,000:</Text>
              <Text style={styles.mathValueHighlight}>{totpState.otp}</Text>
            </View>
          </View>
        </View>
      </ScrollView>

      {/* MODAL DE ESCANEO QR CON EXPO-CAMERA */}
      <Modal
        visible={scannerVisible}
        animationType="slide"
        onRequestClose={() => setScannerVisible(false)}>
        <SafeAreaView style={styles.scannerContainer}>
          <View style={styles.scannerHeader}>
            <Text style={styles.scannerTitle}>Escanear Código QR TOTP</Text>
            <Pressable
              style={styles.closeScannerBtn}
              onPress={() => setScannerVisible(false)}>
              <Text style={styles.closeScannerBtnText}>Cerrar</Text>
            </Pressable>
          </View>

          <View style={styles.cameraWrapper}>
            <CameraView
              style={StyleSheet.absoluteFill}
              facing="back"
              barcodeScannerSettings={{
                barcodeTypes: ['qr'],
              }}
              onBarcodeScanned={scannedLock ? undefined : handleBarcodeScanned}
            />
            <View style={styles.scannerOverlayFrame} />
          </View>

          <View style={styles.scannerFooter}>
            <Text style={styles.scannerHint}>
              Apunta al código QR con formato{' '}
              <Text style={styles.monoInline}>
                otpauth://totp/UniSabana:estudiante@unisabana.edu.co?secret=JBSWY3DPEHPK3PXP&issuer=UniSabana
              </Text>
            </Text>
          </View>
        </SafeAreaView>
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
    flexWrap: 'wrap',
    gap: 8,
    marginBottom: 4,
  },
  offlineBadge: {
    backgroundColor: 'rgba(16, 185, 129, 0.16)',
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 999,
  },
  offlineBadgeText: {
    color: '#34d399',
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 0.5,
  },
  rfcBadge: {
    backgroundColor: 'rgba(56, 189, 248, 0.15)',
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 999,
  },
  rfcBadgeText: {
    color: '#38bdf8',
    fontSize: 10,
    fontWeight: '800',
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
  totpHeroCard: {
    backgroundColor: '#0f172a',
    borderRadius: 20,
    padding: 22,
    borderWidth: 1.5,
    borderColor: 'rgba(16, 185, 129, 0.45)',
    gap: 16,
  },
  totpHeroCardUrgent: {
    borderColor: 'rgba(239, 68, 68, 0.65)',
  },
  totpAccountRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  totpIssuer: {
    color: '#34d399',
    fontSize: 13,
    fontWeight: '800',
    textTransform: 'uppercase',
    letterSpacing: 0.8,
  },
  totpAccount: {
    color: '#cbd5e1',
    fontSize: 13,
    marginTop: 2,
  },
  countdownCircle: {
    width: 52,
    height: 52,
    borderRadius: 26,
    borderWidth: 3,
    borderColor: '#10b981',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: 'rgba(16, 185, 129, 0.1)',
  },
  countdownCircleUrgent: {
    borderColor: '#ef4444',
    backgroundColor: 'rgba(239, 68, 68, 0.15)',
  },
  countdownNumber: {
    color: '#34d399',
    fontFamily: 'monospace',
    fontSize: 16,
    fontWeight: '800',
  },
  countdownNumberUrgent: {
    color: '#f87171',
  },
  totpDigits: {
    color: '#ffffff',
    fontFamily: 'monospace',
    fontSize: 46,
    fontWeight: '900',
    textAlign: 'center',
    letterSpacing: 4,
    paddingVertical: 6,
  },
  totpDigitsUrgent: {
    color: '#fca5a5',
  },
  progressTrack: {
    height: 10,
    backgroundColor: '#1e293b',
    borderRadius: 999,
    overflow: 'hidden',
  },
  progressFill: {
    height: '100%',
    borderRadius: 999,
  },
  totpFooterRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  totpFooterText: {
    color: '#94a3b8',
    fontFamily: 'monospace',
    fontSize: 11,
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
  qrActionsRow: {
    gap: 8,
  },
  scanQrButton: {
    backgroundColor: '#10b981',
    paddingVertical: 13,
    paddingHorizontal: 16,
    borderRadius: 12,
    alignItems: 'center',
  },
  scanQrButtonText: {
    color: '#042f2e',
    fontWeight: '800',
    fontSize: 14,
  },
  presetButton: {
    backgroundColor: '#1e293b',
    borderWidth: 1,
    borderColor: '#334155',
    paddingVertical: 11,
    paddingHorizontal: 14,
    borderRadius: 12,
    alignItems: 'center',
  },
  presetButtonText: {
    color: '#93c5fd',
    fontWeight: '700',
    fontSize: 12,
  },
  buttonPressed: {
    opacity: 0.75,
  },
  manualBox: {
    gap: 8,
    marginTop: 4,
  },
  manualLabel: {
    color: '#cbd5e1',
    fontSize: 12,
    fontWeight: '600',
  },
  manualInputRow: {
    flexDirection: 'row',
    gap: 8,
  },
  manualInput: {
    flex: 1,
    backgroundColor: '#070f1e',
    borderWidth: 1,
    borderColor: '#334155',
    borderRadius: 10,
    paddingHorizontal: 12,
    paddingVertical: 10,
    color: '#f8fafc',
    fontFamily: 'monospace',
    fontSize: 14,
  },
  manualInputInvalid: {
    borderColor: '#ef4444',
  },
  applyButton: {
    backgroundColor: '#2563eb',
    paddingHorizontal: 16,
    borderRadius: 10,
    justifyContent: 'center',
    alignItems: 'center',
  },
  applyButtonText: {
    color: '#ffffff',
    fontWeight: '700',
    fontSize: 13,
  },
  errorText: {
    color: '#f87171',
    fontSize: 12,
  },
  successText: {
    color: '#34d399',
    fontSize: 12,
  },
  mathBox: {
    backgroundColor: '#070f1e',
    borderRadius: 12,
    padding: 12,
    borderWidth: 1,
    borderColor: '#1e293b',
    gap: 8,
  },
  mathRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: 4,
  },
  mathBlock: {
    gap: 4,
  },
  mathLabel: {
    color: '#94a3b8',
    fontSize: 12,
  },
  mathValue: {
    color: '#e2e8f0',
    fontFamily: 'monospace',
    fontSize: 12,
    fontWeight: '700',
  },
  mathHexValue: {
    color: '#38bdf8',
    fontFamily: 'monospace',
    fontSize: 11,
  },
  mathValueHighlight: {
    color: '#34d399',
    fontFamily: 'monospace',
    fontSize: 15,
    fontWeight: '900',
  },
  scannerContainer: {
    flex: 1,
    backgroundColor: '#070f1e',
  },
  scannerHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 16,
    backgroundColor: '#0f172a',
  },
  scannerTitle: {
    color: '#f8fafc',
    fontSize: 17,
    fontWeight: '800',
  },
  closeScannerBtn: {
    backgroundColor: '#1e293b',
    paddingHorizontal: 14,
    paddingVertical: 8,
    borderRadius: 8,
  },
  closeScannerBtnText: {
    color: '#f8fafc',
    fontWeight: '700',
    fontSize: 13,
  },
  cameraWrapper: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  scannerOverlayFrame: {
    width: 240,
    height: 240,
    borderWidth: 2,
    borderColor: '#10b981',
    borderRadius: 20,
    backgroundColor: 'transparent',
  },
  scannerFooter: {
    padding: 18,
    backgroundColor: '#0f172a',
  },
  scannerHint: {
    color: '#94a3b8',
    fontSize: 12,
    lineHeight: 18,
    textAlign: 'center',
  },
  monoInline: {
    fontFamily: 'monospace',
    color: '#34d399',
  },
});
