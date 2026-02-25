import { buildApp } from '../src/app.js';

function parseArgNumber(name, fallback) {
  const arg = process.argv.find((item) => item.startsWith(`--${name}=`));
  if (!arg) return fallback;
  const value = Number(arg.split('=')[1]);
  if (!Number.isFinite(value) || value <= 0) return fallback;
  return Math.floor(value);
}

function percentile(values, ratio) {
  if (!values.length) return 0;
  const idx = Math.min(values.length - 1, Math.max(0, Math.floor((values.length - 1) * ratio)));
  return values[idx];
}

async function run() {
  const iterations = parseArgNumber('iterations', 120);
  const warmup = parseArgNumber('warmup', 20);

  const app = buildApp({ logger: false, dbPath: ':memory:' });
  await app.ready();

  try {
    const plannerMs = [];
    const wallMs = [];

    for (let index = 0; index < warmup + iterations; index += 1) {
      const started = performance.now();
      const res = await app.inject({
        method: 'POST',
        url: '/v0/agent-blueprints/preview',
        payload: {
          workspace_id: 'wsp_mindverse_cn',
          kit_id: 'kit_office_ops_core',
          owners: ['usr_yingapple'],
          selected_connector_ids: ['con_feishu_official', 'con_mcp_gateway', 'con_a2a_gateway']
        }
      });
      const elapsed = performance.now() - started;

      if (res.statusCode !== 200) {
        console.error('benchmark request failed', res.statusCode, res.body);
        process.exit(1);
      }

      if (index < warmup) {
        continue;
      }

      const payload = res.json();
      plannerMs.push(Number(payload.planner_metrics?.elapsed_ms || 0));
      wallMs.push(elapsed);
    }

    plannerMs.sort((a, b) => a - b);
    wallMs.sort((a, b) => a - b);

    const summary = {
      version: 'v0',
      benchmark: 'agent-blueprint-preview',
      iterations,
      warmup,
      planner_ms: {
        min: plannerMs[0] || 0,
        p50: percentile(plannerMs, 0.5),
        p95: percentile(plannerMs, 0.95),
        max: plannerMs[plannerMs.length - 1] || 0
      },
      wall_ms: {
        min: Number((wallMs[0] || 0).toFixed(3)),
        p50: Number(percentile(wallMs, 0.5).toFixed(3)),
        p95: Number(percentile(wallMs, 0.95).toFixed(3)),
        max: Number((wallMs[wallMs.length - 1] || 0).toFixed(3))
      }
    };

    console.log(JSON.stringify(summary, null, 2));
  } finally {
    await app.close();
  }
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
