import React from 'react';
import { Stack } from 'expo-router';
import { StatusBar } from 'expo-status-bar';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { SessionProvider } from '../lib/session';
import { color } from '../components/ui';
export default function Layout() {
  return <SafeAreaProvider><SessionProvider><StatusBar style="light" /><Stack screenOptions={{ headerShown: false, contentStyle: { backgroundColor: color.bg } }} /></SessionProvider></SafeAreaProvider>;
}
