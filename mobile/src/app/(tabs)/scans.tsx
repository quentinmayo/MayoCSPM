import React, { useState } from 'react';
import { Button, Card, Copy, Label, Loading, Notice, Screen } from '../../components/ui';
import { useWorkspaceQuery } from '../../lib/query';
import { useSession } from '../../lib/session';
type Job = { id: number; status: string; resource_count: number; coverage: unknown; error: string | null };
type Connection = { id: number; name: string; kind: string; validated: boolean };
export default function Scans() {
  const { workspace, api } = useSession(); const jobs = useWorkspaceQuery<Job[]>('jobs'); const connections = useWorkspaceQuery<Connection[]>('connections');
  const [notice, setNotice] = useState(''); const [busy, setBusy] = useState(false); const [selected, setSelected] = useState<number | null>(null);
  const scan = async (id: number) => { setBusy(true); setNotice(''); try { await api(`/api/workspaces/${workspace!.id}/connections/${id}/scan`, {}); setNotice('Scan queued. Pull to refresh its status.'); jobs.reload(); } catch (error) { setNotice(error instanceof Error ? error.message : 'Could not queue scan.'); } finally { setBusy(false); } };
  const analyst = workspace && workspace.role !== 'viewer';
  return <Screen title="Scan history" subtitle="Collection budgets and coverage remain visible." refreshing={jobs.loading} onRefresh={() => { jobs.reload(); connections.reload(); }}>
    <Notice text={notice || jobs.error || connections.error} />{jobs.loading && <Loading />}
    {analyst && connections.data?.filter(row => row.kind !== 'sarif').map(row => <Card key={row.id}><Label>{row.kind.toUpperCase()}</Label><Copy>{row.name}</Copy><Button title={row.validated || row.kind !== 'aws' ? 'Queue scan' : 'Validate & scan'} disabled={busy || (!row.validated && row.kind === 'aws' && workspace?.role === 'analyst')} onPress={() => scan(row.id)} /></Card>)}
    {jobs.data?.slice(0, 50).map(job => <Card key={job.id}><Label>SCAN #{job.id} · {job.status.toUpperCase()}</Label><Copy>{job.resource_count} resources</Copy>{job.error && <Notice text={job.error} />}<Button title="Coverage details" secondary onPress={() => setSelected(selected === job.id ? null : job.id)} />{selected === job.id && <Copy>{JSON.stringify(job.coverage, null, 2)}</Copy>}</Card>)}
    <Copy muted>Showing up to 50 recent scans. Viewers can inspect results; analysts can run validated connections. Configure new connections and schedules in the browser.</Copy>
  </Screen>;
}
