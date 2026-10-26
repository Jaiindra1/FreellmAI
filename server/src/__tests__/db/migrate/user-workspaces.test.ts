import Database from 'better-sqlite3';
import { describe, expect, it } from 'vitest';
import { up as legacyBaseline } from '../../../db/migrations/20260101_000000_legacy_baseline.js';
import { down, up } from '../../../db/migrations/20261026_000001_user_workspaces.js';

describe('user workspace migration', () => {
  it('assigns all pre-existing accounts a stable workspace and new accounts on insert', () => {
    const db = new Database(':memory:');
    legacyBaseline(db);
    db.prepare("INSERT INTO users (email, password_hash) VALUES ('legacy@example.com', 'hash')").run();
    db.prepare("INSERT INTO settings (key, value) VALUES ('owner-setting', 'preserved')").run();

    up(db);
    const legacy = db.prepare('SELECT workspace_id FROM users WHERE id = 1').get();
    expect(legacy).toEqual({ workspace_id: 'user:1' });
    expect(db.prepare("SELECT value FROM settings WHERE key = 'owner-setting'").get())
      .toEqual({ value: 'preserved' });

    db.prepare("INSERT INTO users (email, password_hash) VALUES ('new@example.com', 'hash')").run();
    expect(db.prepare('SELECT workspace_id FROM users WHERE email = ?').get('new@example.com'))
      .toEqual({ workspace_id: 'user:2' });

    down(db);
    expect(db.prepare("PRAGMA table_info(users)").all())
      .not.toEqual(expect.arrayContaining([expect.objectContaining({ name: 'workspace_id' })]));
    db.close();
  });
});
