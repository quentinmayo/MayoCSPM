import React from 'react';
import { Card, Copy, Label, Loading, Notice, Screen } from '../../components/ui';
import { useWorkspaceQuery } from '../../lib/query';
type Graph = { nodes: { id: string; label: string; kind: string; exposure: string }[]; edges: { source: string; target: string; relation: string; confidence: string }[]; truncated: boolean; model: string };
export default function Exposure() {
  const { data, loading, error, reload } = useWorkspaceQuery<Graph>('graph');
  const names = new Map(data?.nodes.map(node => [node.id, node.label]));
  return <Screen title="Exposure context" subtitle="Observed and candidate relationships." refreshing={loading} onRefresh={reload}>
    <Notice text={error || data?.model} />{loading && <Loading />}
    {data && <Copy muted>First 50 relationships shown. {data.truncated ? 'The server graph is also truncated.' : 'Routes and application reachability are unverified.'}</Copy>}
    {data?.edges.slice(0, 50).map((edge, index) => <Card key={index}><Label>{edge.confidence.toUpperCase()} · {edge.relation}</Label><Copy>{names.get(edge.source) || edge.source} → {names.get(edge.target) || edge.target}</Copy></Card>)}
    {data && !data.edges.length && <Copy muted>No relationships are recorded in this snapshot.</Copy>}
  </Screen>;
}
