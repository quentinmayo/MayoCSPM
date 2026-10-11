import { fetch } from 'expo/fetch';
import { request as execute } from './client';

// Explicit import prevents a changed global fetch from weakening native redirect,
// cookie and streaming-response guarantees. The core stays independently testable.
export function request<T>(base: string, path: string, token?: string, body?: unknown): Promise<T> {
  return execute<T>(base, path, token, body, fetch as typeof globalThis.fetch);
}
