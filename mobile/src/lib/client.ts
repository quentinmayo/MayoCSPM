export type Session = { base: string; token: string; email: string; expires_at: string };
export type Workspace = { id: number; name: string; role: 'owner' | 'admin' | 'analyst' | 'viewer' };
export const callbackUri = 'com.quentinmayo.mayocspm://auth';

export function serverOrigin(value: string, development = false): string {
  const url = new URL(value.trim());
  const local = ['localhost', '127.0.0.1', '[::1]', '10.0.2.2'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !(development && local && url.protocol === 'http:')) || url.username || url.password || url.search || url.hash || !['', '/'].includes(url.pathname)) {
    throw new Error('Use an HTTPS instance origin without a path or credentials.');
  }
  return url.origin;
}

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) { super(message); this.status = status; }
}

export async function request<T>(base: string, path: string, token?: string, body?: unknown, transport: typeof fetch = fetch): Promise<T> {
  if (serverOrigin(base, true) !== base) throw new Error('Invalid instance origin');
  if (!path.startsWith('/api/') || path.startsWith('//')) throw new Error('Invalid API path');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await transport(base + path, { method: body === undefined ? 'GET' : 'POST',
      headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(token ? { Authorization: 'Bearer ' + token } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body), credentials: 'omit', redirect: 'error', signal: controller.signal });
    if (response.redirected || response.url && new URL(response.url).origin !== base) throw new Error('Instance redirected an API request.');
    if (Number(response.headers.get('content-length')) > 2 * 1024 * 1024) { controller.abort(); throw new Error('Instance response exceeded the mobile data budget.'); }
    if (!response.body) throw new Error('Instance returned an empty API response.');
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 2 * 1024 * 1024) { await reader.cancel(); throw new Error('Instance response exceeded the mobile data budget.'); }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const text = new TextDecoder().decode(bytes);
    let data: unknown;
    try { data = JSON.parse(text); } catch { throw new Error('Instance returned an invalid API response.'); }
    if (!response.ok) throw new ApiError(data && typeof data === 'object' && 'detail' in data && typeof data.detail === 'string' ? data.detail : 'Request could not be validated.', response.status);
    return data as T;
  } finally { clearTimeout(timer); }
}

export function readCallback(url: string, state: string): string {
  const parsed = new URL(url);
  if (parsed.protocol !== 'com.quentinmayo.mayocspm:' || parsed.hostname !== 'auth' || parsed.username || parsed.password || parsed.port || parsed.pathname || parsed.hash || parsed.searchParams.getAll('state').length !== 1 || parsed.searchParams.getAll('code').length !== 1 || parsed.searchParams.get('state') !== state) throw new Error('Sign-in callback did not match this request.');
  const code = parsed.searchParams.get('code');
  if (!code || !/^[A-Za-z0-9_-]{43,128}$/.test(code)) throw new Error('Sign-in did not return a valid handoff code.');
  return code;
}
