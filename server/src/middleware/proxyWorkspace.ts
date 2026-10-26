import type { NextFunction, Request, Response } from 'express';
import { resolveWorkspaceForProxyToken, runInWorkspace } from '../db/index.js';

function requestToken(req: Request): string | undefined {
  const authorization = req.headers.authorization;
  const bearer = typeof authorization === 'string'
    ? authorization.replace(/^Bearer\s+/i, '').trim()
    : '';
  if (bearer) return bearer;

  const header = req.headers['x-api-key'] ?? req.headers['x-goog-api-key'];
  const key = Array.isArray(header) ? header[0] : header;
  if (key?.trim()) return key.trim();

  const queryKey = typeof req.query.key === 'string' ? req.query.key.trim() : '';
  if (queryKey) return queryKey;

  const urlToken = /^\/v1\/t\/([^/]+)/.exec(req.path)?.[1];
  if (!urlToken) return undefined;
  try {
    return decodeURIComponent(urlToken);
  } catch {
    return undefined;
  }
}

/** Select the credential owner's DB before any authenticated proxy handler. */
export function proxyWorkspace(req: Request, res: Response, next: NextFunction): void {
  if (!req.path.startsWith('/v1') && !req.path.startsWith('/v1beta') && !req.path.startsWith('/mcp')) {
    next();
    return;
  }
  const resolution = resolveWorkspaceForProxyToken(requestToken(req));
  if ('ambiguous' in resolution) {
    res.status(401).json({ error: { message: 'Invalid API key', type: 'authentication_error' } });
    return;
  }
  if (resolution.userId === null) {
    next();
    return;
  }
  runInWorkspace(resolution.userId, next);
}
