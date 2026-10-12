import React, { useState } from 'react';
import { KeyboardAvoidingView, Platform } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Button, Card, Copy, Field, Label, Loading, Notice, Screen, color } from '../components/ui';
import { useSession } from '../lib/session';
import { serverOrigin } from '../lib/client';
import { request } from '../lib/native-client';
export default function SignIn() {
  const { ready, signIn, signInOkta } = useSession();
  const [base, setBase] = useState('https://mayocspm.com');
  const [email, setEmail] = useState(''); const [password, setPassword] = useState('');
  const [options, setOptions] = useState<{ password_enabled: boolean; oidc_enabled: boolean } | null>(null);
  const [error, setError] = useState(''); const [busy, setBusy] = useState(false);
  if (!ready) return <Loading />;
  const act = async (action: () => Promise<void>) => { setBusy(true); setError(''); try { await action(); } catch (reason) { setError(reason instanceof Error ? reason.message : 'Sign-in failed.'); } finally { setBusy(false); setPassword(''); } };
  return <SafeAreaView style={{ flex: 1, backgroundColor: color.bg }}><KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
    <Screen title="MayoCSPM" subtitle="Your cloud. Your context. On your device.">
      <Card><Label>SELF-HOSTED CLOUD SECURITY</Label><Copy>Connect to your own instance to review inventory, risk evidence, exposure context, and scan results.</Copy></Card>
      <Field testID="instance-url" label="Instance URL" value={base} onChangeText={value => { setBase(value); setOptions(null); }} autoCapitalize="none" autoCorrect={false} keyboardType="url" />
      <Button testID="check-instance" title="Check instance" disabled={busy} secondary onPress={() => act(async () => { const origin = serverOrigin(base, __DEV__); setOptions(await request(origin, '/api/auth/options')); setBase(origin); })} />
      <Notice text={error} />
      {options?.oidc_enabled && <Button title="Continue with Okta" disabled={busy} onPress={() => act(() => signInOkta(base))} />}
      {options?.password_enabled && <Card><Field testID="login-email" label="Email" value={email} onChangeText={setEmail} autoCapitalize="none" autoCorrect={false} keyboardType="email-address" autoComplete="email" textContentType="username" />
        <Field testID="login-password" label="Password" value={password} onChangeText={setPassword} secureTextEntry autoComplete="current-password" textContentType="password" maxLength={256} />
        <Button testID="sign-in" title="Sign in" disabled={busy || !email || !password} onPress={() => act(() => signIn(base, email, password))} /></Card>}
      {busy && <Loading />}<Copy muted>Sessions are stored in the device’s protected credential storage. Cloud inventory is loaded on demand and is not saved for offline use.</Copy>
    </Screen>
  </KeyboardAvoidingView></SafeAreaView>;
}
