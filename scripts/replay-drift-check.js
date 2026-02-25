import { buildApp } from '../src/app.js';

function parseFlag(name, fallback = false) {
  const arg = process.argv.find((item) => item.startsWith(`--${name}=`));
  if (!arg) return fallback;
  const value = arg.split('=')[1];
  return value === '1' || value === 'true';
}

function parseNumber(name, fallback) {
  const arg = process.argv.find((item) => item.startsWith(`--${name}=`));
  if (!arg) return fallback;
  const value = Number(arg.split('=')[1]);
  if (!Number.isFinite(value)) return fallback;
  return value;
}

async function main() {
  const limit = Math.min(Math.max(parseNumber('limit', 40), 1), 100);
  const maxItemsPerStream = Math.min(Math.max(parseNumber('max-items-per-stream', 1200), 100), 10000);
  const sampleLimit = Math.min(Math.max(parseNumber('sample-limit', 20), 1), 100);
  const includePending = parseFlag('include-pending', false);
  const failOnInconclusive = parseFlag('fail-on-inconclusive', false);

  const app = buildApp({ logger: false });
  await app.ready();

  try {
    const qs = new URLSearchParams({
      limit: String(limit),
      max_items_per_stream: String(maxItemsPerStream),
      sample_limit: String(sampleLimit),
      include_pending: includePending ? 'true' : 'false',
      alert_on_inconclusive: failOnInconclusive ? 'true' : 'false'
    });

    const res = await app.inject({
      method: 'GET',
      url: `/v0/monitoring/replay-drift?${qs.toString()}`
    });

    if (res.statusCode !== 200) {
      console.error('replay drift check failed to fetch summary');
      console.error(res.body);
      process.exit(2);
    }

    const payload = res.json();
    console.log(JSON.stringify(payload, null, 2));

    if (payload.totals.inconsistent > 0) {
      console.error(`replay drift check failed: inconsistent runs=${payload.totals.inconsistent}`);
      process.exit(2);
    }

    if (failOnInconclusive && payload.totals.inconclusive > 0) {
      console.error(`replay drift check failed: inconclusive runs=${payload.totals.inconclusive}`);
      process.exit(2);
    }

    console.log('replay drift check passed');
  } finally {
    await app.close();
  }
}

main().catch((err) => {
  console.error('replay drift check failed');
  console.error(err?.stack || err?.message || err);
  process.exit(2);
});
