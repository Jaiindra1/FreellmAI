import type { Db } from '../types.js';

export function up(db: Db): void {
  db.exec(`
    ALTER TABLE users ADD COLUMN workspace_id TEXT;
    UPDATE users SET workspace_id = 'user:' || id WHERE workspace_id IS NULL;
    CREATE UNIQUE INDEX idx_users_workspace_id ON users(workspace_id);
    CREATE TRIGGER users_assign_workspace_id
    AFTER INSERT ON users
    WHEN NEW.workspace_id IS NULL
    BEGIN
      UPDATE users SET workspace_id = 'user:' || NEW.id WHERE id = NEW.id;
    END;
  `);
}

export function down(db: Db): void {
  db.exec(`
    DROP TRIGGER IF EXISTS users_assign_workspace_id;
    DROP INDEX IF EXISTS idx_users_workspace_id;
    ALTER TABLE users DROP COLUMN workspace_id;
  `);
}
