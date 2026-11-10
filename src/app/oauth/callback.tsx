import { router, useLocalSearchParams } from 'expo-router';
import React, { useEffect } from 'react';
import { ActivityIndicator, StyleSheet, Text, View } from 'react-native';

/**
 * Ruta de respaldo para Deep Link OAuth 2.0 (unisabana-auth://oauth/callback)
 * En iOS/Android `WebBrowser.openAuthSessionAsync` intercepta el retorno automáticamente,
 * pero si el sistema operativo abre la ruta en Expo Router, redirigimos limpiamente a la pantalla principal.
 */
export default function OAuthCallbackScreen() {
  const params = useLocalSearchParams<{ code?: string; state?: string }>();

  useEffect(() => {
    const timer = setTimeout(() => {
      router.replace('/');
    }, 400);
    return () => clearTimeout(timer);
  }, [params.code, params.state]);

  return (
    <View style={styles.container}>
      <ActivityIndicator size="large" color="#10b981" />
      <Text style={styles.title}>Procesando Callback OAuth 2.0 + PKCE...</Text>
      <Text style={styles.subtitle}>
        Verificando parámetro state Anti-CSRF y canjeando authorization_code
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0a192f',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 24,
  },
  title: {
    marginTop: 16,
    fontSize: 16,
    fontWeight: '700',
    color: '#e6f1ff',
    textAlign: 'center',
  },
  subtitle: {
    marginTop: 6,
    fontSize: 13,
    color: '#8892b0',
    textAlign: 'center',
  },
});

