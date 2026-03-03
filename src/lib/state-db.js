import path from 'node:path';
import Database from 'better-sqlite3';

export class RevisionConflictError extends Error {
  constructor(message, { expectedRevision, currentRevision } = {}) {
    super(message);
    this.name = 'RevisionConflictError';
    this.code = 'REVISION_CONFLICT';
    this.expectedRevision = expectedRevision;
    this.currentRevision = currentRevision;
  }
}

function parseJson(raw) {
  if (!raw) return null;
  return JSON.parse(raw);
}

function toInt(value, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.floor(n);
}

export class StateDB {
  constructor({ rootDir, dbPath }) {
    const resolved = dbPath || path.join(rootDir, 'data', 'flockmesh.db');
    this.dbPath = resolved;
    this.db = new Database(resolved);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');
    this.db.pragma('foreign_keys = ON');
  }

  init() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS agents (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS connector_bindings (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL,
        agent_id TEXT,
        status TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS runs (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        status TEXT NOT NULL,
        revision INTEGER NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS idempotency_results (
        idempotency_key TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS environment_sets (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL,
        scope TEXT NOT NULL,
        mode TEXT NOT NULL,
        status TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS role_bindings (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        role TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_agents_workspace ON agents(workspace_id);
      CREATE INDEX IF NOT EXISTS idx_bindings_workspace ON connector_bindings(workspace_id);
      CREATE INDEX IF NOT EXISTS idx_bindings_agent ON connector_bindings(agent_id);
      CREATE INDEX IF NOT EXISTS idx_runs_workspace ON runs(workspace_id);
      CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status);
      CREATE INDEX IF NOT EXISTS idx_runs_updated ON runs(updated_at DESC);
      CREATE INDEX IF NOT EXISTS idx_environment_sets_workspace ON environment_sets(workspace_id);
      CREATE INDEX IF NOT EXISTS idx_environment_sets_updated ON environment_sets(updated_at DESC);
      CREATE INDEX IF NOT EXISTS idx_role_bindings_workspace ON role_bindings(workspace_id);
      CREATE INDEX IF NOT EXISTS idx_role_bindings_actor ON role_bindings(actor_id);
      CREATE UNIQUE INDEX IF NOT EXISTS idx_role_bindings_unique
        ON role_bindings(workspace_id, actor_id, role);
    `);

    this.stmts = {
      upsertAgent: this.db.prepare(`
        INSERT INTO agents (id, workspace_id, payload, created_at, updated_at)
        VALUES (@id, @workspace_id, @payload, @created_at, @updated_at)
        ON CONFLICT(id) DO UPDATE SET
          workspace_id = excluded.workspace_id,
          payload = excluded.payload,
          updated_at = excluded.updated_at
      `),
      getAgent: this.db.prepare('SELECT payload FROM agents WHERE id = ?'),
      listAgents: this.db.prepare(`
        SELECT payload
        FROM agents
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
      `),
      countAgents: this.db.prepare('SELECT COUNT(*) AS total FROM agents'),

      upsertBinding: this.db.prepare(`
        INSERT INTO connector_bindings (id, workspace_id, agent_id, status, payload, created_at, updated_at)
        VALUES (@id, @workspace_id, @agent_id, @status, @payload, @created_at, @updated_at)
        ON CONFLICT(id) DO UPDATE SET
          workspace_id = excluded.workspace_id,
          agent_id = excluded.agent_id,
          status = excluded.status,
          payload = excluded.payload,
          updated_at = excluded.updated_at
      `),
      getBinding: this.db.prepare('SELECT payload FROM connector_bindings WHERE id = ?'),
      listBindings: this.db.prepare(`
        SELECT payload
        FROM connector_bindings
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
      `),
      countBindings: this.db.prepare('SELECT COUNT(*) AS total FROM connector_bindings'),

      getRunRow: this.db.prepare('SELECT revision, payload FROM runs WHERE id = ?'),
      insertRun: this.db.prepare(`
        INSERT INTO runs (id, workspace_id, agent_id, status, revision, payload, created_at, updated_at)
        VALUES (@id, @workspace_id, @agent_id, @status, @revision, @payload, @created_at, @updated_at)
      `),
      updateRun: this.db.prepare(`
        UPDATE runs
        SET status = @status,
            revision = @revision,
            payload = @payload,
            updated_at = @updated_at
        WHERE id = @id
      `),
      getRun: this.db.prepare('SELECT payload FROM runs WHERE id = ?'),
      listRunsBase: this.db.prepare(`
        SELECT payload
        FROM runs
        ORDER BY updated_at DESC
        LIMIT ? OFFSET ?
      `),
      countRunsBase: this.db.prepare('SELECT COUNT(*) AS total FROM runs'),
      listRunsByStatus: this.db.prepare(`
        SELECT payload
        FROM runs
        WHERE status = ?
        ORDER BY updated_at DESC
        LIMIT ? OFFSET ?
      `),
      countRunsByStatus: this.db.prepare('SELECT COUNT(*) AS total FROM runs WHERE status = ?'),
      listRunsByWorkspace: this.db.prepare(`
        SELECT payload
        FROM runs
        WHERE workspace_id = ?
        ORDER BY updated_at DESC
        LIMIT ? OFFSET ?
      `),
      countRunsByWorkspace: this.db.prepare('SELECT COUNT(*) AS total FROM runs WHERE workspace_id = ?'),
      listRunsByWorkspaceAndStatus: this.db.prepare(`
        SELECT payload
        FROM runs
        WHERE workspace_id = ? AND status = ?
        ORDER BY updated_at DESC
        LIMIT ? OFFSET ?
      `),
      countRunsByWorkspaceAndStatus: this.db.prepare(`
        SELECT COUNT(*) AS total
        FROM runs
        WHERE workspace_id = ? AND status = ?
      `),

      getIdempotency: this.db.prepare(
        'SELECT payload FROM idempotency_results WHERE idempotency_key = ?'
      ),
      upsertIdempotency: this.db.prepare(`
        INSERT INTO idempotency_results (idempotency_key, run_id, payload, created_at)
        VALUES (@idempotency_key, @run_id, @payload, @created_at)
        ON CONFLICT(idempotency_key) DO UPDATE SET
          payload = excluded.payload
      `),
      listIdempotency: this.db.prepare(
        'SELECT idempotency_key, payload FROM idempotency_results ORDER BY created_at DESC LIMIT ? OFFSET ?'
      ),

      upsertEnvironmentSet: this.db.prepare(`
        INSERT INTO environment_sets (id, workspace_id, scope, mode, status, payload, created_at, updated_at)
        VALUES (@id, @workspace_id, @scope, @mode, @status, @payload, @created_at, @updated_at)
        ON CONFLICT(id) DO UPDATE SET
          workspace_id = excluded.workspace_id,
          scope = excluded.scope,
          mode = excluded.mode,
          status = excluded.status,
          payload = excluded.payload,
          updated_at = excluded.updated_at
      `),
      getEnvironmentSet: this.db.prepare('SELECT payload FROM environment_sets WHERE id = ?'),
      listEnvironmentSetsBase: this.db.prepare(`
        SELECT payload
        FROM environment_sets
        ORDER BY updated_at DESC
        LIMIT ? OFFSET ?
      `),
      countEnvironmentSetsBase: this.db.prepare('SELECT COUNT(*) AS total FROM environment_sets'),
      listEnvironmentSetsByWorkspace: this.db.prepare(`
        SELECT payload
        FROM environment_sets
        WHERE workspace_id = ?
        ORDER BY updated_at DESC
        LIMIT ? OFFSET ?
      `),
      countEnvironmentSetsByWorkspace: this.db.prepare(
        'SELECT COUNT(*) AS total FROM environment_sets WHERE workspace_id = ?'
      ),
      listActiveEnvironmentSetsByWorkspace: this.db.prepare(`
        SELECT payload
        FROM environment_sets
        WHERE workspace_id = ? AND status = 'active'
        ORDER BY updated_at DESC
        LIMIT ? OFFSET ?
      `),
      countActiveEnvironmentSetsByWorkspace: this.db.prepare(
        "SELECT COUNT(*) AS total FROM environment_sets WHERE workspace_id = ? AND status = 'active'"
      ),
      listActiveEnvironmentSetsByWorkspaceAndMode: this.db.prepare(`
        SELECT payload
        FROM environment_sets
        WHERE workspace_id = ? AND status = 'active' AND mode = ?
        ORDER BY updated_at DESC
        LIMIT ? OFFSET ?
      `),
      countActiveEnvironmentSetsByWorkspaceAndMode: this.db.prepare(`
        SELECT COUNT(*) AS total
        FROM environment_sets
        WHERE workspace_id = ? AND status = 'active' AND mode = ?
      `),

      upsertRoleBinding: this.db.prepare(`
        INSERT INTO role_bindings (id, workspace_id, actor_id, role, payload, created_at, updated_at)
        VALUES (@id, @workspace_id, @actor_id, @role, @payload, @created_at, @updated_at)
        ON CONFLICT(id) DO UPDATE SET
          workspace_id = excluded.workspace_id,
          actor_id = excluded.actor_id,
          role = excluded.role,
          payload = excluded.payload,
          updated_at = excluded.updated_at
      `),
      getRoleBinding: this.db.prepare('SELECT payload FROM role_bindings WHERE id = ?'),
      listRoleBindingsBase: this.db.prepare(`
        SELECT payload
        FROM role_bindings
        ORDER BY updated_at DESC
        LIMIT ? OFFSET ?
      `),
      countRoleBindingsBase: this.db.prepare('SELECT COUNT(*) AS total FROM role_bindings'),
      listRoleBindingsByWorkspace: this.db.prepare(`
        SELECT payload
        FROM role_bindings
        WHERE workspace_id = ?
        ORDER BY updated_at DESC
        LIMIT ? OFFSET ?
      `),
      countRoleBindingsByWorkspace: this.db.prepare(
        'SELECT COUNT(*) AS total FROM role_bindings WHERE workspace_id = ?'
      )
    };
  }

  close() {
    this.db.close();
  }

  saveAgent(agent) {
    this.stmts.upsertAgent.run({
      id: agent.id,
      workspace_id: agent.workspace_id,
      payload: JSON.stringify(agent),
      created_at: agent.created_at,
      updated_at: agent.updated_at
    });
    return agent;
  }

  getAgent(id) {
    const row = this.stmts.getAgent.get(id);
    return parseJson(row?.payload);
  }

  listAgents({ limit = 100, offset = 0 } = {}) {
    const boundedLimit = Math.min(Math.max(toInt(limit, 100), 1), 500);
    const boundedOffset = Math.max(toInt(offset, 0), 0);
    const rows = this.stmts.listAgents.all(boundedLimit, boundedOffset);
    const total = this.stmts.countAgents.get().total;
    return {
      total,
      limit: boundedLimit,
      offset: boundedOffset,
      items: rows.map((row) => parseJson(row.payload))
    };
  }

  saveBinding(binding) {
    this.stmts.upsertBinding.run({
      id: binding.id,
      workspace_id: binding.workspace_id,
      agent_id: binding.agent_id || null,
      status: binding.status,
      payload: JSON.stringify(binding),
      created_at: binding.created_at,
      updated_at: binding.updated_at
    });
    return binding;
  }

  getBinding(id) {
    const row = this.stmts.getBinding.get(id);
    return parseJson(row?.payload);
  }

  listBindings({ limit = 100, offset = 0 } = {}) {
    const boundedLimit = Math.min(Math.max(toInt(limit, 100), 1), 500);
    const boundedOffset = Math.max(toInt(offset, 0), 0);
    const rows = this.stmts.listBindings.all(boundedLimit, boundedOffset);
    const total = this.stmts.countBindings.get().total;
    return {
      total,
      limit: boundedLimit,
      offset: boundedOffset,
      items: rows.map((row) => parseJson(row.payload))
    };
  }

  saveRun(run, { expectedRevision = null } = {}) {
    const writeAt = new Date().toISOString();
    const existing = this.stmts.getRunRow.get(run.id);

    if (!existing) {
      if (expectedRevision !== null && expectedRevision !== undefined && expectedRevision !== 0) {
        throw new RevisionConflictError('Run does not exist for expected revision', {
          expectedRevision,
          currentRevision: 0
        });
      }

      const revision = Number(run.revision) > 0 ? Number(run.revision) : 1;
      const persisted = { ...run, revision };

      this.stmts.insertRun.run({
        id: persisted.id,
        workspace_id: persisted.workspace_id,
        agent_id: persisted.agent_id,
        status: persisted.status,
        revision,
        payload: JSON.stringify(persisted),
        created_at: persisted.started_at,
        updated_at: writeAt
      });

      return persisted;
    }

    const currentRevision = Number(existing.revision);

    if (
      expectedRevision !== null &&
      expectedRevision !== undefined &&
      Number(expectedRevision) !== currentRevision
    ) {
      throw new RevisionConflictError('Run revision mismatch', {
        expectedRevision: Number(expectedRevision),
        currentRevision
      });
    }

    const nextRevision = currentRevision + 1;
    const persisted = { ...run, revision: nextRevision };

    this.stmts.updateRun.run({
      id: persisted.id,
      status: persisted.status,
      revision: nextRevision,
      payload: JSON.stringify(persisted),
      updated_at: writeAt
    });

    return persisted;
  }

  getRun(id) {
    const row = this.stmts.getRun.get(id);
    return parseJson(row?.payload);
  }

  listRuns({ status, workspaceId, limit = 100, offset = 0 } = {}) {
    const boundedLimit = Math.min(Math.max(toInt(limit, 100), 1), 500);
    const boundedOffset = Math.max(toInt(offset, 0), 0);
    const normalizedWorkspaceId = String(workspaceId || '').trim();

    if (normalizedWorkspaceId && status) {
      const rows = this.stmts.listRunsByWorkspaceAndStatus.all(
        normalizedWorkspaceId,
        status,
        boundedLimit,
        boundedOffset
      );
      const total = this.stmts.countRunsByWorkspaceAndStatus
        .get(normalizedWorkspaceId, status)
        .total;
      return {
        total,
        limit: boundedLimit,
        offset: boundedOffset,
        items: rows.map((row) => parseJson(row.payload))
      };
    }

    if (normalizedWorkspaceId) {
      const rows = this.stmts.listRunsByWorkspace.all(
        normalizedWorkspaceId,
        boundedLimit,
        boundedOffset
      );
      const total = this.stmts.countRunsByWorkspace.get(normalizedWorkspaceId).total;
      return {
        total,
        limit: boundedLimit,
        offset: boundedOffset,
        items: rows.map((row) => parseJson(row.payload))
      };
    }

    if (status) {
      const rows = this.stmts.listRunsByStatus.all(status, boundedLimit, boundedOffset);
      const total = this.stmts.countRunsByStatus.get(status).total;
      return {
        total,
        limit: boundedLimit,
        offset: boundedOffset,
        items: rows.map((row) => parseJson(row.payload))
      };
    }

    const rows = this.stmts.listRunsBase.all(boundedLimit, boundedOffset);
    const total = this.stmts.countRunsBase.get().total;

    return {
      total,
      limit: boundedLimit,
      offset: boundedOffset,
      items: rows.map((row) => parseJson(row.payload))
    };
  }

  summarizeRunsByWorkspace({ workspaceId } = {}) {
    const normalizedWorkspaceId = String(workspaceId || '').trim();
    if (!normalizedWorkspaceId) {
      return {
        total: 0,
        by_status: {}
      };
    }

    const statuses = ['accepted', 'running', 'waiting_approval', 'completed', 'failed', 'cancelled'];
    const byStatus = {};
    for (const status of statuses) {
      byStatus[status] = Number(
        this.stmts.countRunsByWorkspaceAndStatus.get(normalizedWorkspaceId, status)?.total || 0
      );
    }

    return {
      total: Number(this.stmts.countRunsByWorkspace.get(normalizedWorkspaceId)?.total || 0),
      by_status: byStatus
    };
  }

  getIdempotencyResult(key) {
    const row = this.stmts.getIdempotency.get(key);
    return parseJson(row?.payload);
  }

  saveIdempotencyResult({ key, runId, payload, createdAt }) {
    this.stmts.upsertIdempotency.run({
      idempotency_key: key,
      run_id: runId,
      payload: JSON.stringify(payload),
      created_at: createdAt
    });
    return payload;
  }

  listIdempotencyResults({ limit = 1000, offset = 0 } = {}) {
    const boundedLimit = Math.min(Math.max(toInt(limit, 1000), 1), 5000);
    const boundedOffset = Math.max(toInt(offset, 0), 0);
    const rows = this.stmts.listIdempotency.all(boundedLimit, boundedOffset);

    return rows.map((row) => ({
      key: row.idempotency_key,
      payload: parseJson(row.payload)
    }));
  }

  saveEnvironmentSet(environmentSet) {
    this.stmts.upsertEnvironmentSet.run({
      id: environmentSet.id,
      workspace_id: environmentSet.workspace_id,
      scope: environmentSet.scope,
      mode: environmentSet.mode,
      status: environmentSet.status,
      payload: JSON.stringify(environmentSet),
      created_at: environmentSet.created_at,
      updated_at: environmentSet.updated_at
    });
    return environmentSet;
  }

  getEnvironmentSet(id) {
    const row = this.stmts.getEnvironmentSet.get(id);
    return parseJson(row?.payload);
  }

  listEnvironmentSets({ workspaceId, limit = 100, offset = 0 } = {}) {
    const boundedLimit = Math.min(Math.max(toInt(limit, 100), 1), 500);
    const boundedOffset = Math.max(toInt(offset, 0), 0);
    const normalizedWorkspaceId = String(workspaceId || '').trim();

    if (normalizedWorkspaceId) {
      const rows = this.stmts.listEnvironmentSetsByWorkspace.all(
        normalizedWorkspaceId,
        boundedLimit,
        boundedOffset
      );
      const total = this.stmts.countEnvironmentSetsByWorkspace.get(normalizedWorkspaceId).total;
      return {
        total,
        limit: boundedLimit,
        offset: boundedOffset,
        items: rows.map((row) => parseJson(row.payload))
      };
    }

    const rows = this.stmts.listEnvironmentSetsBase.all(boundedLimit, boundedOffset);
    const total = this.stmts.countEnvironmentSetsBase.get().total;
    return {
      total,
      limit: boundedLimit,
      offset: boundedOffset,
      items: rows.map((row) => parseJson(row.payload))
    };
  }

  listActiveEnvironmentSets({ workspaceId, mode, limit = 100, offset = 0 } = {}) {
    const boundedLimit = Math.min(Math.max(toInt(limit, 100), 1), 500);
    const boundedOffset = Math.max(toInt(offset, 0), 0);
    const normalizedWorkspaceId = String(workspaceId || '').trim();
    const normalizedMode = String(mode || '').trim();

    if (!normalizedWorkspaceId) {
      return {
        total: 0,
        limit: boundedLimit,
        offset: boundedOffset,
        items: []
      };
    }

    if (normalizedMode) {
      const rows = this.stmts.listActiveEnvironmentSetsByWorkspaceAndMode.all(
        normalizedWorkspaceId,
        normalizedMode,
        boundedLimit,
        boundedOffset
      );
      const total = Number(
        this.stmts.countActiveEnvironmentSetsByWorkspaceAndMode
          .get(normalizedWorkspaceId, normalizedMode)
          ?.total || 0
      );
      return {
        total,
        limit: boundedLimit,
        offset: boundedOffset,
        items: rows.map((row) => parseJson(row.payload))
      };
    }

    const rows = this.stmts.listActiveEnvironmentSetsByWorkspace.all(
      normalizedWorkspaceId,
      boundedLimit,
      boundedOffset
    );
    const total = Number(
      this.stmts.countActiveEnvironmentSetsByWorkspace
        .get(normalizedWorkspaceId)
        ?.total || 0
    );
    return {
      total,
      limit: boundedLimit,
      offset: boundedOffset,
      items: rows.map((row) => parseJson(row.payload))
    };
  }

  saveRoleBinding(roleBinding) {
    this.stmts.upsertRoleBinding.run({
      id: roleBinding.id,
      workspace_id: roleBinding.workspace_id,
      actor_id: roleBinding.actor_id,
      role: roleBinding.role,
      payload: JSON.stringify(roleBinding),
      created_at: roleBinding.created_at,
      updated_at: roleBinding.updated_at
    });
    return roleBinding;
  }

  getRoleBinding(id) {
    const row = this.stmts.getRoleBinding.get(id);
    return parseJson(row?.payload);
  }

  listRoleBindings({ workspaceId, limit = 200, offset = 0 } = {}) {
    const boundedLimit = Math.min(Math.max(toInt(limit, 200), 1), 1000);
    const boundedOffset = Math.max(toInt(offset, 0), 0);
    const normalizedWorkspaceId = String(workspaceId || '').trim();

    if (normalizedWorkspaceId) {
      const rows = this.stmts.listRoleBindingsByWorkspace.all(
        normalizedWorkspaceId,
        boundedLimit,
        boundedOffset
      );
      const total = this.stmts.countRoleBindingsByWorkspace.get(normalizedWorkspaceId).total;
      return {
        total,
        limit: boundedLimit,
        offset: boundedOffset,
        items: rows.map((row) => parseJson(row.payload))
      };
    }

    const rows = this.stmts.listRoleBindingsBase.all(boundedLimit, boundedOffset);
    const total = this.stmts.countRoleBindingsBase.get().total;
    return {
      total,
      limit: boundedLimit,
      offset: boundedOffset,
      items: rows.map((row) => parseJson(row.payload))
    };
  }
}
