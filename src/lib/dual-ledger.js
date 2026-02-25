import fs from 'node:fs/promises';
import path from 'node:path';
import { nowIso } from './time.js';

async function ensureDir(dirPath) {
  await fs.mkdir(dirPath, { recursive: true });
}

async function appendJsonLine(filePath, payload) {
  await fs.appendFile(filePath, `${JSON.stringify(payload)}\n`, 'utf8');
}

async function readJsonLines(filePath) {
  try {
    const text = await fs.readFile(filePath, 'utf8');
    return text
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } catch (err) {
    if (err.code === 'ENOENT') return [];
    throw err;
  }
}

function paginate(items, { limit = 100, offset = 0 } = {}) {
  const boundedLimit = Math.min(Math.max(Number(limit) || 100, 1), 500);
  const boundedOffset = Math.max(Number(offset) || 0, 0);
  return {
    total: items.length,
    limit: boundedLimit,
    offset: boundedOffset,
    items: items.slice(boundedOffset, boundedOffset + boundedLimit)
  };
}

export class DualLedger {
  constructor({ rootDir }) {
    this.rootDir = rootDir;
    this.auditDir = path.join(rootDir, 'data', 'audit');
    this.eventDir = path.join(rootDir, 'data', 'events');
  }

  async init() {
    await ensureDir(this.auditDir);
    await ensureDir(this.eventDir);
  }

  auditPath(runId) {
    return path.join(this.auditDir, `${runId}.jsonl`);
  }

  eventPath(runId) {
    return path.join(this.eventDir, `${runId}.jsonl`);
  }

  async appendAudit(entry) {
    await appendJsonLine(this.auditPath(entry.run_id), {
      ...entry,
      persisted_at: nowIso()
    });
  }

  async appendEvent(event) {
    await appendJsonLine(this.eventPath(event.run_id), {
      ...event,
      persisted_at: nowIso()
    });
  }

  async listAudit(runId, opts = {}) {
    const all = await readJsonLines(this.auditPath(runId));
    return paginate(all, opts);
  }

  async listEvents(runId, opts = {}) {
    const all = await readJsonLines(this.eventPath(runId));
    return paginate(all, opts);
  }
}
