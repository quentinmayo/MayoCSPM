import React from 'react';
import { Redirect, Tabs } from 'expo-router';
import { Text } from 'react-native';
import { color, Loading } from '../../components/ui';
import { useSession } from '../../lib/session';
export default function Layout() {
  const { ready, session } = useSession();
  if (!ready) return <Loading />;
  if (!session) return <Redirect href="/" />;
  return <Tabs screenOptions={{ headerStyle: { backgroundColor: color.surface }, headerTintColor: color.ink,
    headerTitle: 'MayoCSPM', tabBarActiveTintColor: color.accent, tabBarInactiveTintColor: color.muted,
    tabBarStyle: { backgroundColor: color.surface, borderTopColor: color.line }, tabBarLabelStyle: { fontSize: 10 } }}>
    {[['index', 'Overview', '◈'], ['inventory', 'Inventory', '▤'], ['risks', 'Risks', '△'], ['exposure', 'Exposure', '◇'], ['scans', 'Scans', '↻'], ['account', 'Account', '◎']].map(([name, title, icon]) => <Tabs.Screen key={name} name={name} options={{ title, tabBarIcon: ({ color: tint }) => <Text style={{ color: tint, fontSize: 22 }}>{icon}</Text> }} />)}
  </Tabs>;
}
