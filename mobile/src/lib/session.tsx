import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import * as Crypto from 'expo-crypto';
import * as SecureStore from 'expo-secure-store';
import * as WebBrowser from 'expo-web-browser';
import { ApiError, callbackUri, readCallback, serverOrigin, Session, Workspace } from './client';
import { request } from './native-client';

const key = 'mayocspm.session.v1';
type AuthOptions = { oidc_enabled: boolean; password_enabled: boolean; mobile_redirect_uri: string };
type Context = { session: Session | null; ready: boolean; workspaces: Workspace[]; workspace: Workspace | null;
  choose: (workspace: Workspace) => void; signIn: (base: string, email: string, password: string) => Promise<void>;
  signInOkta: (base: string) => Promise<void>; signOut: (everywhere?: boolean) => Promise<void>;
  api: <T>(path: string, body?: unknown) => Promise<T>; reloadWorkspaces: () => Promise<void> };
const Auth = createContext<Context | null>(null);

function randomProof() { return Array.from(Crypto.getRandomBytes(32), byte => byte.toString(16).padStart(2, '0')).join(''); }
export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const active = useRef<Session | null>(null);
  const [ready, setReady] = useState(false);
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [workspace, choose] = useState<Workspace | null>(null);
  const clear = useCallback(async () => {
    active.current = null; setSession(null); setWorkspaces([]); choose(null);
    await SecureStore.deleteItemAsync(key);
  }, []);
  useEffect(() => { let mounted = true;
    (async () => { try {
      const stored = await SecureStore.getItemAsync(key);
      if (stored) { const value: Session = JSON.parse(stored);
        if (serverOrigin(value.base, __DEV__) !== value.base || !value.token?.startsWith('mc_') || !value.email || !Number.isFinite(Date.parse(value.expires_at)) || Date.parse(value.expires_at) <= Date.now()) throw new Error('Expired session');
        if (mounted) { active.current = value; setSession(value); }
      }
    } catch { await clear(); } finally { if (mounted) setReady(true); } })();
    return () => { mounted = false; };
  }, [clear]);
  const save = async (value: Session) => {
    await SecureStore.setItemAsync(key, JSON.stringify(value), { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY });
    active.current = value; setSession(value);
  };
  const api = useCallback(async <T,>(path: string, body?: unknown): Promise<T> => {
    const current = active.current;
    if (!current) throw new ApiError('Sign in to continue.', 401);
    if (Date.parse(current.expires_at) <= Date.now()) { await clear(); throw new ApiError('Session expired. Sign in again.', 401); }
    try { return await request<T>(current.base, path, current.token, body); }
    catch (error) { if (error instanceof ApiError && error.status === 401 && active.current?.token === current.token) await clear(); throw error; }
  }, [clear]);
  useEffect(() => {
    if (!session) return;
    const timer = setTimeout(() => { if (active.current?.token === session.token) clear().catch(() => {}); }, Math.max(0, Date.parse(session.expires_at) - Date.now()));
    return () => clearTimeout(timer);
  }, [session, clear]);
  const reloadWorkspaces = useCallback(async () => {
    const current = active.current;
    const rows = await api<Workspace[]>('/api/workspaces');
    if (active.current?.token !== current?.token) return;
    setWorkspaces(rows); choose(previous => rows.find(row => row.id === previous?.id) || rows[0] || null);
  }, [api]);
  useEffect(() => { if (session) reloadWorkspaces().catch(() => {}); }, [session, reloadWorkspaces]);
  const signIn = async (value: string, email: string, password: string) => {
    const base = serverOrigin(value, __DEV__);
    const response = await request<Omit<Session, 'base'>>(base, '/api/auth/mobile/login', undefined, { email, password });
    await save({ ...response, base });
  };
  const signInOkta = async (value: string) => {
    const base = serverOrigin(value, __DEV__);
    const options = await request<AuthOptions>(base, '/api/auth/options');
    if (!options.oidc_enabled || options.mobile_redirect_uri !== callbackUri) throw new Error('Okta is not configured for this app on this instance.');
    const verifier = randomProof(), state = randomProof();
    const hash = await Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, verifier, { encoding: Crypto.CryptoEncoding.BASE64 });
    const challenge = hash.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const params = new URLSearchParams({ code_challenge: challenge, state });
    const result = await WebBrowser.openAuthSessionAsync(base + '/api/auth/oidc/start?' + params.toString(), callbackUri);
    if (result.type !== 'success') throw new Error('Sign-in was canceled.');
    const code = readCallback(result.url, state);
    const response = await request<Omit<Session, 'base'>>(base, '/api/auth/mobile/exchange', undefined, { code, verifier });
    await save({ ...response, base });
  };
  const signOut = async (everywhere = false) => {
    try { if (active.current) await api(everywhere ? '/api/auth/sessions/revoke' : '/api/auth/logout', {}); }
    finally { await clear(); }
  };
  return <Auth.Provider value={{ session, ready, workspaces, workspace, choose, signIn, signInOkta, signOut, api, reloadWorkspaces }}>{children}</Auth.Provider>;
}
export function useSession() { const context = useContext(Auth); if (!context) throw new Error('Missing session provider'); return context; }
