import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { AsyncLocalStorage } from 'node:async_hooks';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'url';
import { runMigrationsSync } from './migrate/runner.js';
import { initEncryptionKey, isEncryptionKeyInitialized, withEncryptionKeyState } from '../lib/crypto.js';
import { restrictAllToOwner, restrictDirToOwner } from '../lib/file-permissions.js';
import { nodeSqliteFactory } from './node-sqlite.js';
import type { Db, DbFactory } from './types.js';

export type { Db, DbFactory } from './types.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = path.resolve(__dirname, '../../data/freeapi.db');
const runtimeRequire = createRequire(import.meta.url);

let db: Db;
const workspaceDbs = new Map<number, Db>();
const workspaceContext = new AsyncLocalStorage<number>();

export function getDb(): Db {
  if (!db) {
    throw new Error('Database not initialized. Call initDb() or connectDb() first.');
  }
  const userId = workspaceContext.getStore();
  return userId === undefined ? db : getWorkspaceDb(userId);
}

/** The shared identity database. Use only for account/session operations. */
export function getAuthDb(): Db {
  if (!db) throw new Error('Database not initialized. Call initDb() or connectDb() first.');
  return db;
}

/** Run one authenticated request against the account's private workspace DB. */
export function runInWorkspace<T>(userId: number, callback: () => T): T {
  return workspaceContext.run(userId, callback);
}

/** Stable namespace for process-local state that must follow a workspace. */
export function getWorkspaceScope(): string {
  const userId = workspaceContext.getStore();
  return userId === undefined ? 'server' : `user:${userId}`;
}

/** Resolve a proxy credential to exactly one private workspace. */
export type ProxyWorkspaceResolution =
  | { userId: number }
  | { userId: null }
  | { ambiguous: true };

export function resolveWorkspaceForProxyToken(token: string | undefined): ProxyWorkspaceResolution {
  if (!token) return { userId: null };
  const users = getAuthDb().prepare('SELECT id FROM users ORDER BY id').all() as Array<{ id: number }>;
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const matches: number[] = [];
  for (const { id } of users) {
    const workspace = getWorkspaceDb(id);
    const unified = workspace.prepare(
      "SELECT value FROM settings WHERE key = 'unified_api_key'",
    ).get() as { value: string } | undefined;
    const profile = workspace.prepare(
      'SELECT id FROM client_profiles WHERE token_hash = ? AND enabled = 1',
    ).get(tokenHash);
    const urlToken = workspace.prepare(
      "SELECT id FROM url_tokens WHERE token_hash = ? AND revoked_at IS NULL",
    ).get(tokenHash);
    if ((unified && constantTimeEqual(token, unified.value)) || profile || urlToken) matches.push(id);
  }

  function constantTimeEqual(provided: string, expected: string): boolean {
    const key = Buffer.alloc(32);
    const a = crypto.createHmac('sha256', key).update(provided).digest();
    const b = crypto.createHmac('sha256', key).update(expected).digest();
    return crypto.timingSafeEqual(a, b);
  }
  // Duplicate credentials must never choose one account nondeterministically.
  if (matches.length > 1) return { ambiguous: true };
  return matches.length === 1 ? { userId: matches[0]! } : { userId: null };
}

export function findWorkspaceForProxyToken(token: string | undefined): number | null {
  const resolution = resolveWorkspaceForProxyToken(token);
  return 'userId' in resolution ? resolution.userId : null;
}

function workspacePath(userId: number): string {
  const row = db.prepare('SELECT workspace_id FROM users WHERE id = ?')
    .get(userId) as { workspace_id: string } | undefined;
  if (!row || !/^user:\d+$/.test(row.workspace_id)) {
    throw new Error(`Invalid workspace identity for account ${userId}`);
  }
  return path.join(workspaceRoot(), 'users', `${row.workspace_id.replace(':', '-')}.db`);
}

function workspaceRoot(): string {
  const currentPath = db.name && db.name !== ':memory:' ? db.name : getDefaultDbPath();
  return path.dirname(currentPath);
}

function getWorkspaceDb(userId: number): Db {
  // The earliest account owns the pre-multitenant database. Its existing rows
  // are deliberately left there and can never be inherited by later signups.
  const firstUser = db.prepare('SELECT id FROM users ORDER BY id LIMIT 1').get() as { id: number } | undefined;
  if (firstUser?.id === userId) return db;
  const cached = workspaceDbs.get(userId);
  if (cached) return cached;

  const inMemory = db.memory === true || db.name === ':memory:';
  const resolvedPath = inMemory ? ':memory:' : workspacePath(userId);
  const dataDir = path.dirname(resolvedPath);
  if (!inMemory) {
    const createdDataDir = !fs.existsSync(dataDir);
    fs.mkdirSync(dataDir, { recursive: true });
    restrictDataDir(dataDir, createdDataDir);

    // All workspaces use the installation's encryption key. In dev, copy the
    // already-created key file before migrations initialize the new database.
    const masterKeyFile = path.join(workspaceRoot(), '.encryption-key');
    const workspaceKeyFile = path.join(dataDir, '.encryption-key');
    if (fs.existsSync(masterKeyFile) && !fs.existsSync(workspaceKeyFile)) {
      fs.copyFileSync(masterKeyFile, workspaceKeyFile);
      restrictAllToOwner([workspaceKeyFile]);
    }
  }

  const workspaceDb = openConnection(resolvedPath, {});
  withEncryptionKeyState(() => runMigrationsSync(workspaceDb, 'up'));
  if (!isEncryptionKeyInitialized()) initEncryptionKey(workspaceDb);
  workspaceDbs.set(userId, workspaceDb);
  return workspaceDb;
}

export function getDefaultDbPath(): string {
  return process.env.FREEAPI_DB_PATH?.trim() || DB_PATH;
}

/** Default factory: opens a better-sqlite3 connection at the given path. */
function betterSqliteFactory(resolvedPath: string): Db {
  let BetterSqlite: new (path: string) => unknown;
  try {
    BetterSqlite = runtimeRequire('better-sqlite3') as new (path: string) => unknown;
  } catch (cause) {
    throw new Error(
      'better-sqlite3 is not installed. Reinstall dependencies, or use Node.js 22.13+ on Android/Termux.',
      { cause },
    );
  }
  return new BetterSqlite(resolvedPath) as Db;
}

export function defaultDbFactory(platform: NodeJS.Platform = process.platform): DbFactory {
  return platform === 'android' ? nodeSqliteFactory : betterSqliteFactory;
}

export function connectDb(
  dbPath?: string,
  opts?: {
    /** Create the parent directory if absent. Default: true. Set false in
     *  environments that do not have a writable local filesystem. */
    ensureDir?: boolean;
    /** Factory that constructs the raw Db connection. Default: better-sqlite3. */
    factory?: DbFactory;
  },
): Db {
  const resolvedPath = dbPath ?? getDefaultDbPath();
  const isMemory = resolvedPath === ':memory:';
  const ensureDir = opts?.ensureDir ?? true;
  const factory = opts?.factory ?? defaultDbFactory();

  // Gated on ensureDir along with the mkdir: that flag means "this process does
  // not shape the filesystem here", and changing a directory's permissions is
  // exactly that kind of change. It also keeps the warning below from firing on
  // every boot in the read-only environments the flag exists for.
  if (!isMemory && ensureDir) {
    const dataDir = path.dirname(resolvedPath);
    let created = false;
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
      created = true;
    }
    // Before the connection, not after: on Windows the restriction is inherited,
    // so hardening first means the database file is born protected instead of
    // spending its first moments with whatever ACL the parent handed down.
    restrictDataDir(dataDir, created);
  }

  for (const workspaceDb of workspaceDbs.values()) workspaceDb.close?.();
  workspaceDbs.clear();
  db = openConnection(resolvedPath, { factory, isMemory });
  console.log(`Database initialized at ${resolvedPath}`);
  return db;
}

function openConnection(
  resolvedPath: string,
  opts: { factory?: DbFactory; isMemory?: boolean },
): Db {
  const isMemory = opts.isMemory ?? resolvedPath === ':memory:';
  const connection = (opts.factory ?? defaultDbFactory())(resolvedPath);
  if (!isMemory) connection.pragma('journal_mode = WAL');
  connection.pragma('foreign_keys = ON');
  connection.pragma('busy_timeout = 5000');
  if (!isMemory) restrictDbFilePermissions(resolvedPath);
  return connection;
}

/**
 * Whether the directory holding the database may be restricted to this account.
 *
 * The sidecars can only be covered by the directory: SQLite creates `-wal` and
 * `-shm` on the first write and deletes them on the last clean close, so at
 * startup there is nothing there to chmod. But the directory is also shared
 * state — FREEAPI_DB_PATH may point anywhere — and locking down a directory
 * that is not ours is a worse outage than the leak it prevents. Pointing the DB
 * at `/tmp/freeapi.db` must not chmod 0700 `/tmp`.
 *
 * So the rule is ownership by construction rather than a guess about what is
 * safe. Two cases qualify, and nothing else does:
 *
 *   1. We just created the directory. Nothing else can be living in a directory
 *      that did not exist a moment ago.
 *   2. It is the built-in default data directory, which ships as ours.
 *
 * Case 2 is what covers the installed base: an existing deployment already has
 * `server/data`, so case 1 alone would harden new installs and quietly leave
 * every upgrade behind.
 *
 * An operator who points FREEAPI_DB_PATH at a dedicated directory can opt in
 * with FREEAPI_DB_DIR_HARDENING=1, and one who dislikes the default can opt out
 * with =0. It is a deliberate default-on-where-safe rather than a flag, because
 * hardening that only runs when someone remembers to ask for it is the same
 * class of failure as hardening nobody noticed had stopped running.
 */
export function shouldHardenDataDir(
  dataDir: string,
  created: boolean,
  platform: NodeJS.Platform = process.platform,
): boolean {
  const override = parseDirHardeningOverride();
  if (override !== undefined) return override;
  if (created) return true;

  // Windows paths are case-insensitive; comparing them case-sensitively would
  // miss `C:\App\Data` vs `c:\app\data` and silently skip the default install.
  const normalize = (p: string): string =>
    platform === 'win32' ? path.resolve(p).toLowerCase() : path.resolve(p);
  return normalize(dataDir) === normalize(path.dirname(DB_PATH));
}

/** Tri-state, matching CSP_UPGRADE_INSECURE_REQUESTS in lib/config.ts: on, off,
 *  or unset to leave the policy above in charge. */
function parseDirHardeningOverride(): boolean | undefined {
  const raw = process.env.FREEAPI_DB_DIR_HARDENING;
  if (raw === undefined || raw.trim() === '') return undefined;
  const lower = raw.trim().toLowerCase();
  if (lower === 'true' || lower === '1' || lower === 'yes') return true;
  if (lower === 'false' || lower === '0' || lower === 'no') return false;
  return undefined;
}

/** Emitted at most once: connectDb runs once in a server, but a test suite
 *  reconnects constantly and does not need the same line each time. */
let warnedUnhardenedDataDir = false;

function restrictDataDir(dataDir: string, created: boolean): void {
  if (!shouldHardenDataDir(dataDir, created)) {
    if (!warnedUnhardenedDataDir) {
      warnedUnhardenedDataDir = true;
      console.log(
        `[db] leaving permissions on ${dataDir} as they are: it is not a directory this server created. ` +
        'The WAL sidecars written there inherit whatever it already grants. ' +
        'Set FREEAPI_DB_DIR_HARDENING=1 if it belongs to this account alone.',
      );
    }
    return;
  }

  if (!restrictDirToOwner(dataDir)) {
    console.warn(
      `[db] could not restrict permissions on ${dataDir}; ` +
      'the database and its WAL sidecars may be readable by other local accounts',
    );
  }
}

/** Restrict the DB and its WAL sidecars to the owner. The file holds encrypted
 *  provider keys plus the dashboard password hash, so it must not be readable by
 *  other local users. Best-effort: a filesystem that cannot express the
 *  restriction must not stop startup — but it now says so instead of failing
 *  silently, because a hardening step nobody can see failing is one nobody
 *  notices is absent.
 *
 *  This pass only ever finds the main file on a clean start; the sidecars do not
 *  exist yet. They are covered by the directory instead — see
 *  shouldHardenDataDir. It still runs for both, because a directory this server
 *  is not allowed to touch can still hold sidecars left behind by an unclean
 *  shutdown, and because the main file predates the directory pass on any
 *  install that upgraded into it. */
function restrictDbFilePermissions(resolvedPath: string): void {
  const failed = restrictAllToOwner(['', '-wal', '-shm'].map(suffix => `${resolvedPath}${suffix}`));
  if (failed.length > 0) {
    console.warn(
      `[db] could not restrict database file permissions (${failed.length} of 3 targets); ` +
      'the database may be readable by other local accounts',
    );
  }
}

export function initDb(
  dbPath?: string,
  opts?: { ensureDir?: boolean; factory?: DbFactory },
): Db {
  const db = connectDb(dbPath, opts);

  if (process.env.NODE_ENV !== 'development') {
    runMigrationsSync(db, 'up');
  } else {
    // In dev, verify the DB has been initialised. If not, give a clear error.
    const ready = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='migrations'"
    ).get();
    if (!ready) {
      console.error(
        '\n  [dev] Database not initialised. Run:\n\n' +
        '    npm run db:migration:up\n\n' +
        '  Then restart the server.\n'
      );
      process.exit(1);
    }
  }

  if (!isEncryptionKeyInitialized()) initEncryptionKey(db);

  return db;
}

export function getUnifiedApiKey(): string {
  const db = getDb();
  const row = db.prepare("SELECT value FROM settings WHERE key = 'unified_api_key'").get() as { value: string };
  return row.value;
}

export function regenerateUnifiedKey(): string {
  const db = getDb();
  const key = `freellmapi-${crypto.randomBytes(24).toString('hex')}`;
  db.prepare("UPDATE settings SET value = ? WHERE key = 'unified_api_key'").run(key);
  return key;
}

// Generic key/value settings accessors (used by routing strategy, etc.).
export function getSetting(key: string): string | undefined {
  const db = getDb();
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key) as { value: string } | undefined;
  return row?.value;
}

export function setSetting(key: string, value: string): void {
  const db = getDb();
  db.prepare(`
    INSERT INTO settings (key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `).run(key, value);
}
