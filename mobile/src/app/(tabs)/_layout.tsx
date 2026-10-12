import React from 'react';
import { Tabs } from 'expo-router';
import { Text } from 'react-native';
import { color } from '../../components/ui';
export default function Layout() {
  return <Tabs screenOptions={{ headerStyle: { backgroundColor: color.surface }, headerTintColor: color.ink,
    headerTitle: 'MayoCSPM', tabBarActiveTintColor: color.accent, tabBarInactiveTintColor: color.muted,
    tabBarStyle: { backgroundColor: color.surface, borderTopColor: color.line }, tabBarLabelStyle: { fontSize: 10 } }}>
    {[['index', 'Overview', '◈'], ['inventory', 'Inventory', '▤'], ['risks', 'Risks', '△'], ['exposure', 'Exposure', '◇'], ['scans', 'Scans', '↻'], ['account', 'Account', '◎']].map(([name, title, icon]) => <Tabs.Screen key={name} name={name} options={{ title, tabBarIcon: ({ color: tint }) => <Text style={{ color: tint, fontSize: 22 }}>{icon}</Text> }} />)}
  </Tabs>;
}
