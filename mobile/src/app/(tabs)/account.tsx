import React, { useState } from 'react';
import { Button, Card, Copy, Label, Notice, Screen } from '../../components/ui';
import { useSession } from '../../lib/session';
export default function Account() {
  const { session, workspace, workspaces, choose, reloadWorkspaces, signOut } = useSession(); const [error, setError] = useState('');
  const action = async (fn: () => Promise<void>) => { setError(''); try { await fn(); } catch (reason) { setError(reason instanceof Error ? reason.message : 'Request failed.'); } };
  return <Screen title="Your account" subtitle={session?.email}><Notice text={error} /><Card><Label>CONNECTED INSTANCE</Label><Copy>{session?.base}</Copy><Copy muted>Session expires {session && new Date(session.expires_at).toLocaleString()}.</Copy></Card>
    <Label>WORKSPACES</Label>{workspaces.map(row => <Button key={row.id} title={`${workspace?.id === row.id ? '✓ ' : ''}${row.name} · ${row.role}`} secondary={workspace?.id !== row.id} onPress={() => choose(row)} />)}
    <Button title="Refresh workspaces" secondary onPress={() => action(reloadWorkspaces)} />
    <Card><Copy muted>Use Sign-in & devices in the browser to link Okta to your existing account. Workspace permissions come from MayoCSPM memberships.</Copy><Copy muted>Sign out before connecting to a different instance. No inventory is saved for offline use.</Copy></Card>
    <Button title="Sign out" secondary onPress={() => action(() => signOut())} /><Button title="Sign out everywhere" secondary onPress={() => action(() => signOut(true))} />
  </Screen>;
}
