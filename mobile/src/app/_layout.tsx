import React from 'react';
import { Stack } from 'expo-router';
import { StatusBar } from 'expo-status-bar';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { SessionProvider, useSession } from '../lib/session';
import { color, Loading } from '../components/ui';
function Navigator() {
  const { ready, session } = useSession();
  if (!ready) return <Loading />;
  return <Stack screenOptions={{ headerShown: false, contentStyle: { backgroundColor: color.bg } }}>
    <Stack.Protected guard={!session}><Stack.Screen name="sign-in" /></Stack.Protected>
    <Stack.Protected guard={!!session}><Stack.Screen name="(tabs)" /></Stack.Protected>
    <Stack.Screen name="auth" />
  </Stack>;
}
export default function Layout() {
  return <SafeAreaProvider><SessionProvider><StatusBar style="light" /><Navigator /></SessionProvider></SafeAreaProvider>;
}
