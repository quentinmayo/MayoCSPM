import React from 'react';
import { Text, View } from 'react-native';
import { Card, Copy, Label, Loading, Notice, Screen, s } from '../../components/ui';
import { useWorkspaceQuery } from '../../lib/query';
import { useSession } from '../../lib/session';
type Summary = { resource_count: number; open_findings: number; connection_count: number; synthetic: boolean; severities: Record<string, number>; latest_scans: { id: number; status: string }[] };
export default function Overview() {
  const { workspace } = useSession(); const { data, loading, error, reload } = useWorkspaceQuery<Summary>('summary');
  return <Screen title="Overview" subtitle={workspace ? workspace.name + ' · ' + workspace.role : 'Choose a workspace in Account.'} refreshing={loading} onRefresh={reload}>
    <Notice text={error} />{data?.synthetic && <Notice text="Synthetic demo data. These resources are examples, not AWS observations." />}
    {!workspace && <Card><Copy>Create your first workspace in the browser, then refresh the workspace list in Account.</Copy></Card>}
    {loading && !data && <Loading />}{data && <><View style={s.row}>{[['Resources', data.resource_count], ['Open findings', data.open_findings], ['Sources', data.connection_count]].map(([label, value]) => <View key={label} style={{ flexGrow: 1 }}><Card><Label>{label}</Label><Text style={s.number}>{value}</Text></Card></View>)}</View>
      <Card><Label>RISK DISTRIBUTION</Label>{Object.entries(data.severities).map(([severity, count]) => <Copy key={severity}>{severity.toUpperCase()} · {count}</Copy>)}</Card>
      <Card><Label>LATEST COLLECTIONS</Label>{data.latest_scans.map(job => <Copy key={job.id}>Scan #{job.id} · {job.status}</Copy>)}<Copy muted>Partial, limited, and missing collection remain unknown.</Copy></Card>
      <Card><Label>A DELIBERATE DATA BUDGET</Label><Copy>Configuration metadata only. No disk snapshots or image downloads.</Copy><Copy muted>Inventory and risk are stored on your instance; the app queries the current snapshot.</Copy></Card></>}
  </Screen>;
}
