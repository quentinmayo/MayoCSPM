import React, { useState } from 'react';
import { Button, Card, Copy, Label, Loading, Notice, Screen } from '../../components/ui';
import { useWorkspaceQuery } from '../../lib/query';
type Finding = { id: number; title: string; resource_uid: string; severity: string; score: number; status: string; remediation: string; evidence: unknown; reasons: string[] };
export default function Risks() {
  const [status, setStatus] = useState('open'); const [offset, setOffset] = useState(0); const [selected, setSelected] = useState<number | null>(null);
  const { data, loading, error, reload } = useWorkspaceQuery<{ total: number; items: Finding[] }>(`findings?status=${status}&limit=50&offset=${offset}`);
  return <Screen title="Risk queue" subtitle="Explainable scores, evidence, and remediation." refreshing={loading} onRefresh={reload}>
    <Button title={'Status: ' + status + ' · Change'} secondary onPress={() => { setStatus(status === 'open' ? 'accepted' : status === 'accepted' ? 'resolved' : 'open'); setOffset(0); setSelected(null); }} />
    <Notice text={error} />{loading && <Loading />}{data && <Label>{data.total} {status} findings</Label>}
    {data?.items.map(row => <Card key={row.id}><Label>{row.severity.toUpperCase()} · SCORE {row.score} · {row.status.toUpperCase()}</Label><Copy>{row.title}</Copy><Copy muted>{row.resource_uid}</Copy><Button title={selected === row.id ? 'Hide evidence' : 'Review evidence'} secondary onPress={() => setSelected(selected === row.id ? null : row.id)} />{selected === row.id && <><Label>WHY THIS PRIORITY</Label><Copy>{row.reasons.join(' · ')}</Copy><Label>EVIDENCE</Label><Copy>{JSON.stringify(row.evidence, null, 2)}</Copy><Label>RECOMMENDED NEXT STEP</Label><Copy>{row.remediation}</Copy></>}</Card>)}
    {data?.total === 0 && <Copy muted>No findings in this status. Review collection coverage separately.</Copy>}
    {offset > 0 && <Button title="Previous 50" secondary onPress={() => setOffset(offset - 50)} />}{data && offset + 50 < data.total && <Button title="Next 50" secondary onPress={() => setOffset(offset + 50)} />}
  </Screen>;
}
