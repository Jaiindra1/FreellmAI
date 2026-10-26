import express from 'express';
import type { Server } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { authRouter } from '../../routes/auth.js';
import { keysRouter } from '../../routes/keys.js';
import { findWorkspaceForProxyToken, getAuthDb, getDb, initDb, runInWorkspace } from '../../db/index.js';
import { createSession, createUser } from '../../services/auth.js';
import { requireAuth } from '../../middleware/requireAuth.js';
import { proxyWorkspace } from '../../middleware/proxyWorkspace.js';
import { recordCompressionStats, getCompressionStats } from '../../services/compression/stats.js';
import { computeCacheKey } from '../../services/cache.js';

describe('open registration and isolated user workspaces', () => {
  let server: Server;

  beforeAll(async () => {
    initDb(':memory:');
    const app = express();
    app.use(express.json());
    app.use('/api/auth', authRouter);
    app.use('/api/keys', requireAuth, keysRouter);
    app.use(proxyWorkspace);
    app.get('/v1/private-check', (req, res) => {
      if (!findWorkspaceForProxyToken(req.headers.authorization?.replace(/^Bearer\s+/i, ''))) {
        res.status(401).json({ error: 'Invalid API key' });
        return;
      }
      const setting = getDb().prepare("SELECT value FROM settings WHERE key = 'workspace_marker'").get();
      res.json(setting ?? null);
    });
    server = app.listen(0, '127.0.0.1');
    await new Promise<void>(resolve => server.once('listening', resolve));
  });

  afterAll(() => {
    server.close();
  });

  async function register(email: string) {
    const address = server.address() as { port: number };
    const response = await fetch(`http://127.0.0.1:${address.port}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'password123' }),
    });
    return { status: response.status, body: await response.json() as Record<string, any> };
  }

  async function request(path: string, token: string, method = 'GET', body?: unknown) {
    const address = server.address() as { port: number };
    const response = await fetch(`http://127.0.0.1:${address.port}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: response.status, body: await response.json() as any };
  }

  it('does not let open registration bypass first-run setup', async () => {
    const result = await register('first@example.com');
    expect(result.status).toBe(409);
    expect(result.body.error.type).toBe('setup_required');
    expect(getAuthDb().prepare('SELECT COUNT(*) AS count FROM users').get()).toEqual({ count: 0 });
  });

  it('registers without an activation key after setup and creates clean private data', async () => {
    const owner = createUser('owner@example.com', 'password123');
    getDb().prepare("INSERT INTO settings (key, value) VALUES ('private_test', 'legacy-data')").run();
    getDb().prepare(`
      INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag)
      VALUES ('groq', 'legacy key', 'ciphertext', 'iv', 'tag')
    `).run();

    const result = await register('new-user@example.com');
    expect(result.status).toBe(201);
    expect(result.body.token).toEqual(expect.any(String));
    expect(result.body.email).toBe('new-user@example.com');
    const user = getAuthDb().prepare('SELECT id FROM users WHERE email = ?')
      .get('new-user@example.com') as { id: number };

    expect(runInWorkspace(user.id, () => getDb().prepare(
      "SELECT value FROM settings WHERE key = 'private_test'",
    ).get())).toBeUndefined();
    expect(runInWorkspace(user.id, () => getDb().prepare(
      'SELECT COUNT(*) AS count FROM api_keys',
    ).get())).toEqual({ count: 0 });
    expect(runInWorkspace(owner.userId, () => getDb().prepare(
      "SELECT value FROM settings WHERE key = 'private_test'",
    ).get())).toEqual({ value: 'legacy-data' });
  });

  it('selects the workspace that owns a proxy credential', async () => {
    const ownerId = (getAuthDb().prepare('SELECT id FROM users WHERE email = ?')
      .get('owner@example.com') as { id: number }).id;
    const secondId = (getAuthDb().prepare('SELECT id FROM users WHERE email = ?')
      .get('new-user@example.com') as { id: number }).id;
    runInWorkspace(ownerId, () => getDb().prepare(
      "UPDATE settings SET value = 'owner-proxy-key' WHERE key = 'unified_api_key'",
    ).run());
    runInWorkspace(secondId, () => getDb().prepare(
      "UPDATE settings SET value = 'second-proxy-key' WHERE key = 'unified_api_key'",
    ).run());

    expect(findWorkspaceForProxyToken('owner-proxy-key')).toBe(ownerId);
    expect(findWorkspaceForProxyToken('second-proxy-key')).toBe(secondId);
    expect(findWorkspaceForProxyToken('not-a-key')).toBeNull();

    runInWorkspace(secondId, () => getDb().prepare(
      "UPDATE settings SET value = 'owner-proxy-key' WHERE key = 'unified_api_key'",
    ).run());
    expect((await request('/v1/private-check', 'owner-proxy-key')).status).toBe(401);
    runInWorkspace(secondId, () => getDb().prepare(
      "UPDATE settings SET value = 'second-proxy-key' WHERE key = 'unified_api_key'",
    ).run());

    runInWorkspace(ownerId, () => getDb().prepare(
      "INSERT INTO settings (key, value) VALUES ('workspace_marker', 'owner-only')",
    ).run());
    runInWorkspace(secondId, () => getDb().prepare(
      "INSERT INTO settings (key, value) VALUES ('workspace_marker', 'second-only')",
    ).run());
    const ownerToken = createSession(ownerId);
    const secondToken = createSession(secondId);
    const createdKey = await request('/api/keys', ownerToken, 'POST', {
      platform: 'groq',
      key: 'owner-private-key',
      label: 'owner key',
    });
    expect(createdKey.status).toBe(201);
    const ownerKeys = await request('/api/keys', ownerToken);
    const secondKeys = await request('/api/keys', secondToken);
    expect(ownerKeys.status).toBe(200);
    expect(secondKeys.status).toBe(200);
    expect(ownerKeys.body.map((key: { label: string }) => key.label).sort())
      .toEqual(['legacy key', 'owner key']);
    expect(secondKeys.body).toEqual([]);

    expect((await request('/v1/private-check', 'owner-proxy-key')).body)
      .toEqual({ value: 'owner-only' });
    expect((await request('/v1/private-check', 'second-proxy-key')).body)
      .toEqual({ value: 'second-only' });
    expect((await request('/v1/private-check', 'invalid')).status).toBe(401);
  });

  it('keeps process-local usage and response-cache state private per workspace', () => {
    const ownerId = (getAuthDb().prepare('SELECT id FROM users WHERE email = ?')
      .get('owner@example.com') as { id: number }).id;
    const secondId = (getAuthDb().prepare('SELECT id FROM users WHERE email = ?')
      .get('new-user@example.com') as { id: number }).id;
    const stats = {
      originalChars: 10,
      compressedChars: 5,
      estOriginalTokens: 3,
      estCompressedTokens: 2,
      estSavedTokens: 1,
      enginesApplied: ['dedup'],
      discardedByGate: [],
      durationMs: 1,
      stages: [{ engine: 'dedup', inputChars: 10, outputChars: 5, savedChars: 5, applied: true }],
    };
    const cacheInput = { messages: [{ role: 'user' as const, content: 'private prompt' }] };

    runInWorkspace(ownerId, () => recordCompressionStats('standard', stats));
    runInWorkspace(secondId, () => {
      expect(getCompressionStats().requests).toBe(0);
      expect(computeCacheKey(cacheInput)).not.toBe(
        runInWorkspace(ownerId, () => computeCacheKey(cacheInput)),
      );
    });
    expect(runInWorkspace(ownerId, () => getCompressionStats().requests)).toBe(1);
  });
});
