import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ApiError, callbackUri, readCallback, request, serverOrigin } from '../src/lib/client.ts';

test('instance origin requires TLS and does not accept paths or embedded credentials', () => {
  assert.equal(serverOrigin(' https://cloud.example.com/ '), 'https://cloud.example.com');
  for (const value of ['http://cloud.example.com', 'https://user:password@cloud.example.com', 'https://cloud.example.com/path', 'https://cloud.example.com/?token=x', 'https://cloud.example.com/#x', 'file:///tmp/x', 'http://localhost:8010']) assert.throws(() => serverOrigin(value));
  assert.equal(serverOrigin('http://127.0.0.1:8010', true), 'http://127.0.0.1:8010');
  assert.throws(() => serverOrigin('http://192.0.2.10', true));
});

test('native handoff validates the exact app destination, state and one code', () => {
  const code = 'a'.repeat(43), state = 'b'.repeat(64);
  const callback = callbackUri + '?code=' + code + '&state=' + state;
  assert.equal(readCallback(callback, state), code);
  for (const value of [callback.replace('com.quentinmayo.mayocspm', 'attacker'), callback.replace('//auth', '//auth.attacker.example'), callback.replace('//auth', '//user@auth'), callback.replace('//auth', '//auth:443'), callback.replace('//auth?', '//auth/path?'), callback + '#x', callback + '&code=' + code, callback + '&state=' + state, callback.replace(code, 'bad')]) assert.throws(() => readCallback(value, state));
  assert.throws(() => readCallback(callback, 'wrong-state'));
});

test('native API sends bearer credentials only in a header without browser cookies', async t => {
  let captured: { url: string; options: RequestInit } | undefined;
  t.mock.method(globalThis, 'fetch', async (url: string, options: RequestInit) => {
    captured = { url, options }; return new Response('{"ok":true}', { status: 200 });
  });
  assert.deepEqual(await request('https://cloud.example.com', '/api/workspaces', 'fixture-session-token'), { ok: true });
  assert.equal(captured!.url, 'https://cloud.example.com/api/workspaces');
  assert.equal(captured!.options.credentials, 'omit');
  assert.equal(captured!.options.redirect, 'error');
  assert.equal(new Headers(captured!.options.headers).get('authorization'), 'Bearer fixture-session-token');
  await assert.rejects(request('https://cloud.example.com', 'https://attacker.example/api', 'fixture-session-token'));
  await assert.rejects(request('https://cloud.example.com/path', '/api/me', 'fixture-session-token'));
});

test('API rejects redirects, invalid responses and oversized bodies; preserves authorization errors', async t => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => new Response('{"detail":"Sign in again"}', { status: 401 }));
  await assert.rejects(request('https://cloud.example.com', '/api/me'), (error: unknown) => error instanceof ApiError && error.status === 401);
  fetch.mock.mockImplementation(async () => new Response('not-json'));
  await assert.rejects(request('https://cloud.example.com', '/api/me'), /invalid API response/);
  fetch.mock.mockImplementation(async () => new Response(' ', { headers: { 'content-length': String(3 * 1024 * 1024) } }));
  await assert.rejects(request('https://cloud.example.com', '/api/me'), /data budget/);
  fetch.mock.mockImplementation(async () => new Response('x'.repeat(2 * 1024 * 1024 + 1)));
  await assert.rejects(request('https://cloud.example.com', '/api/me'), /data budget/);
  fetch.mock.mockImplementation(async () => { const response = new Response('{}'); Object.defineProperty(response, 'url', { value: 'https://attacker.example/api/me' }); return response; });
  await assert.rejects(request('https://cloud.example.com', '/api/me'), /redirected/);
});
