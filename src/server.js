import { buildApp } from './app.js';

const port = Number(process.env.PORT || 8080);
const host = process.env.HOST || '127.0.0.1';

const app = buildApp({ logger: true });

try {
  await app.listen({ port, host });
  app.log.info(`FlockMesh v0 listening on http://${host}:${port}`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
