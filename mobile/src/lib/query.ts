import { useCallback, useEffect, useState } from 'react';
import { useSession } from './session';
export function useWorkspaceQuery<T>(path: string) {
  const { api, workspace, session } = useSession();
  const [result, setResult] = useState<{ key: string; data: T | null; error: string } | null>(null);
  const [revision, refresh] = useState(0);
  // Results from a prior account/workspace are hidden immediately, before effects run.
  const key = `${session?.token}:${workspace?.id}:${path}:${revision}`;
  useEffect(() => {
    let active = true;
    if (!workspace || !session) return;
    api<T>(`/api/workspaces/${workspace.id}/${path}`).then(data => { if (active) setResult({ key, data, error: '' }); })
      .catch(reason => { if (active) setResult({ key, data: null, error: reason instanceof Error ? reason.message : 'Could not load this workspace.' }); });
    return () => { active = false; };
  }, [workspace, session, path, key, api]);
  const current = workspace && session && result?.key === key ? result : null;
  return { data: current?.data || null, loading: Boolean(workspace && session && !current), error: current?.error || '', reload: useCallback(() => refresh(value => value + 1), []) };
}
