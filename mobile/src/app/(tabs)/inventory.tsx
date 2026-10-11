import React, { useState } from 'react';
import { Button, Card, Copy, Field, Label, Loading, Notice, Screen } from '../../components/ui';
import { useWorkspaceQuery } from '../../lib/query';
type Resource = { id: number; name: string; kind: string; uid: string; region: string; data: unknown; seen: string };
export default function Inventory() {
  const [input, setInput] = useState(''); const [query, setQuery] = useState(''); const [offset, setOffset] = useState(0); const [selected, setSelected] = useState<number | null>(null);
  const { data, loading, error, reload } = useWorkspaceQuery<{ total: number; items: Resource[] }>('resources?' + new URLSearchParams({ q: query, limit: '50', offset: String(offset) }));
  return <Screen title="Cloud inventory" subtitle="Query the stored configuration snapshot." refreshing={loading} onRefresh={reload}>
    <Field label="Search resource name or ID" value={input} onChangeText={setInput} maxLength={120} autoCapitalize="none" autoCorrect={false} />
    <Button title="Apply search" secondary onPress={() => { setQuery(input); setOffset(0); setSelected(null); }} /><Notice text={error} />{loading && <Loading />}
    {data && <Label>{data.total} resources · {Math.min(offset + 1, data.total)}–{Math.min(offset + 50, data.total)}</Label>}
    {data?.items.map(row => <Card key={row.id}><Label>{row.kind} · {row.region}</Label><Copy>{row.name}</Copy><Copy muted>{row.uid}</Copy><Button title={selected === row.id ? 'Hide configuration' : 'Inspect configuration'} secondary onPress={() => setSelected(selected === row.id ? null : row.id)} />{selected === row.id && <Copy>{JSON.stringify(row.data, null, 2)}</Copy>}</Card>)}
    {data?.total === 0 && <Copy muted>No resources match this search.</Copy>}
    {offset > 0 && <Button title="Previous 50" secondary onPress={() => { setOffset(offset - 50); setSelected(null); }} />}
    {data && offset + 50 < data.total && <Button title="Next 50" secondary onPress={() => { setOffset(offset + 50); setSelected(null); }} />}
  </Screen>;
}
