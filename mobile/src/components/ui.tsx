import React from 'react';
import { ActivityIndicator, Pressable, RefreshControl, ScrollView, StyleSheet, Text, TextInput, TextInputProps, View } from 'react-native';
export const color = { bg: '#0b1114', surface: '#111b20', raised: '#16242b', ink: '#edf5f6', muted: '#a3b6bf', accent: '#57e0c5', line: '#2a3c44', amber: '#f4cc76', red: '#ff9797' };
export function Screen({ title, subtitle, children, refreshing = false, onRefresh }: { title: string; subtitle?: string; children: React.ReactNode; refreshing?: boolean; onRefresh?: () => void }) {
  return <ScrollView style={s.screen} contentContainerStyle={s.content} keyboardShouldPersistTaps="handled" refreshControl={onRefresh ? <RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor={color.accent} /> : undefined}>
    <Text accessibilityRole="header" style={s.title}>{title}</Text>{subtitle && <Text style={s.subtitle}>{subtitle}</Text>}{children}
  </ScrollView>;
}
export function Card({ children }: { children: React.ReactNode }) { return <View style={s.card}>{children}</View>; }
export function Label({ children }: { children: React.ReactNode }) { return <Text style={s.label}>{children}</Text>; }
export function Copy({ children, muted = false }: { children: React.ReactNode; muted?: boolean }) { return <Text selectable style={[s.copy, muted && { color: color.muted }]}>{children}</Text>; }
export function Button({ title, onPress, disabled = false, secondary = false, testID }: { title: string; onPress: () => void; disabled?: boolean; secondary?: boolean; testID?: string }) { return <Pressable testID={testID} accessibilityRole="button" accessibilityState={{ disabled }} onPress={onPress} disabled={disabled} style={({ pressed }) => [s.button, secondary && s.secondary, (pressed || disabled) && { opacity: 0.55 }]}><Text style={[s.buttonText, secondary && { color: color.ink }]}>{title}</Text></Pressable>; }
export function Field({ label, ...props }: TextInputProps & { label: string }) { return <View style={{ gap: 7, marginBottom: 16 }}><Label>{label}</Label><TextInput accessibilityLabel={label} placeholderTextColor={color.muted} style={s.field} {...props} /></View>; }
export function Notice({ text }: { text?: string }) { return text ? <Text accessibilityRole="alert" style={s.notice}>{text}</Text> : null; }
export function Loading() { return <ActivityIndicator style={{ padding: 24 }} color={color.accent} />; }
export const s = StyleSheet.create({
  screen: { flex: 1, backgroundColor: color.bg }, content: { padding: 22, paddingBottom: 40, gap: 14 },
  title: { color: color.ink, fontSize: 28, fontWeight: '700', letterSpacing: -0.8 }, subtitle: { color: color.muted, fontSize: 13, lineHeight: 20, marginBottom: 6 },
  card: { borderColor: color.line, borderWidth: 1, borderRadius: 16, backgroundColor: color.surface, padding: 18, gap: 10 },
  label: { color: color.muted, fontSize: 12, fontWeight: '600' }, copy: { color: color.ink, fontSize: 14, lineHeight: 21 },
  button: { backgroundColor: color.accent, padding: 14, borderRadius: 10, alignItems: 'center', minHeight: 48, justifyContent: 'center' },
  buttonText: { color: '#06251f', fontWeight: '700', fontSize: 14 }, secondary: { backgroundColor: color.raised, borderWidth: 1, borderColor: color.line },
  field: { color: color.ink, borderColor: color.line, borderWidth: 1, borderRadius: 10, backgroundColor: color.raised, padding: 13, minHeight: 48, fontSize: 14 },
  notice: { color: color.amber, backgroundColor: '#302a1e', padding: 14, borderWidth: 1, borderColor: '#675637', borderRadius: 10, fontSize: 12, lineHeight: 19 },
  number: { fontSize: 36, fontWeight: '700', color: color.ink, fontVariant: ['tabular-nums'] }, row: { flexDirection: 'row', gap: 12, flexWrap: 'wrap' },
});
