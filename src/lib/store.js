export function createStore() {
  return {
    agents: new Map(),
    connectorBindings: new Map(),
    runs: new Map(),
    pendingApprovals: new Map(),
    idempotencyResults: new Map(),
    eventsByRun: new Map(),
    auditByRun: new Map()
  };
}

export function addRunEvent(store, runId, event) {
  const list = store.eventsByRun.get(runId) || [];
  list.push(event);
  store.eventsByRun.set(runId, list);
}

export function addRunAudit(store, runId, entry) {
  const list = store.auditByRun.get(runId) || [];
  list.push(entry);
  store.auditByRun.set(runId, list);
}
