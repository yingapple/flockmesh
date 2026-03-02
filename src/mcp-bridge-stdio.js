import { buildApp } from './app.js';
import { createMcpBridgeCore } from './lib/mcp-bridge-core.js';

const DEFAULT_PROTOCOL_VERSION = '2025-06-18';

const rootDir = process.env.FLOCKMESH_ROOT_DIR || process.cwd();
const workspaceId = process.env.FLOCKMESH_WORKSPACE_ID || 'wsp_mindverse_cn';
const actorId = process.env.FLOCKMESH_ACTOR_ID || 'usr_yingapple';

const app = buildApp({
  logger: false,
  rootDir,
  trustedDefaultActorId: actorId
});

await app.ready();

const bridge = createMcpBridgeCore({
  app,
  defaults: {
    workspaceId,
    actorId
  }
});

let initialized = false;
let protocolVersion = DEFAULT_PROTOCOL_VERSION;
let readBuffer = Buffer.alloc(0);
let shuttingDown = false;

function sendMessage(message) {
  const payload = Buffer.from(JSON.stringify(message), 'utf8');
  process.stdout.write(`Content-Length: ${payload.length}\r\n\r\n`);
  process.stdout.write(payload);
}

function sendResult(id, result) {
  sendMessage({
    jsonrpc: '2.0',
    id,
    result
  });
}

function sendError(id, code, message, data = undefined) {
  sendMessage({
    jsonrpc: '2.0',
    id,
    error: {
      code,
      message,
      ...(data !== undefined ? { data } : {})
    }
  });
}

function toolResult(payload, { isError = false } = {}) {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(payload, null, 2)
      }
    ],
    isError
  };
}

function methodNotFound(id, method) {
  sendError(id, -32601, `Method not found: ${method}`);
}

async function handleRequest(message) {
  const method = typeof message?.method === 'string' ? message.method : '';
  const id = Object.prototype.hasOwnProperty.call(message || {}, 'id') ? message.id : null;
  const isNotification = id === null;

  if (!method) {
    if (!isNotification) sendError(id, -32600, 'Invalid Request');
    return;
  }

  try {
    if (method === 'initialize') {
      const requestedProtocolVersion = String(message?.params?.protocolVersion || '').trim();
      protocolVersion = requestedProtocolVersion || DEFAULT_PROTOCOL_VERSION;
      initialized = true;
      if (!isNotification) {
        sendResult(id, {
          protocolVersion,
          capabilities: {
            tools: {
              listChanged: false
            }
          },
          serverInfo: {
            name: 'flockmesh-mcp-bridge',
            version: '0.1.0'
          },
          instructions: [
            'FlockMesh MCP bridge exposes enterprise workflow tools only.',
            'All mutating operations are policy-gated and audited by runtime.'
          ].join(' ')
        });
      }
      return;
    }

    if (method === 'notifications/initialized') {
      return;
    }

    if (!initialized) {
      if (!isNotification) sendError(id, -32002, 'Server not initialized');
      return;
    }

    if (method === 'ping') {
      if (!isNotification) sendResult(id, {});
      return;
    }

    if (method === 'tools/list') {
      if (!isNotification) {
        sendResult(id, {
          tools: bridge.listTools()
        });
      }
      return;
    }

    if (method === 'tools/call') {
      const name = String(message?.params?.name || '').trim();
      const args = message?.params?.arguments;

      try {
        const payload = await bridge.callTool(name, args);
        if (!isNotification) sendResult(id, toolResult(payload));
      } catch (err) {
        const data = {
          message: String(err?.message || err),
          ...(err?.statusCode ? { status_code: err.statusCode } : {}),
          ...(err?.payload ? { payload: err.payload } : {})
        };
        if (!isNotification) sendResult(id, toolResult(data, { isError: true }));
      }
      return;
    }

    if (!isNotification) {
      methodNotFound(id, method);
    }
  } catch (err) {
    if (!isNotification) {
      sendError(id, -32603, 'Internal error', {
        message: String(err?.message || err)
      });
    }
  }
}

function processReadBuffer() {
  while (true) {
    const headerEnd = readBuffer.indexOf('\r\n\r\n');
    if (headerEnd < 0) return;

    const header = readBuffer.slice(0, headerEnd).toString('utf8');
    const contentLengthLine = header
      .split('\r\n')
      .find((line) => line.toLowerCase().startsWith('content-length:'));
    if (!contentLengthLine) {
      readBuffer = Buffer.alloc(0);
      return;
    }

    const lengthValue = Number(contentLengthLine.split(':')[1]?.trim() || NaN);
    if (!Number.isFinite(lengthValue) || lengthValue < 0) {
      readBuffer = Buffer.alloc(0);
      return;
    }

    const bodyStart = headerEnd + 4;
    const bodyEnd = bodyStart + lengthValue;
    if (readBuffer.length < bodyEnd) return;

    const bodyBuffer = readBuffer.slice(bodyStart, bodyEnd);
    readBuffer = readBuffer.slice(bodyEnd);

    let parsed;
    try {
      parsed = JSON.parse(bodyBuffer.toString('utf8'));
    } catch {
      continue;
    }

    void handleRequest(parsed);
  }
}

process.stdin.on('data', (chunk) => {
  readBuffer = Buffer.concat([readBuffer, chunk]);
  processReadBuffer();
});

process.stdin.on('error', async () => {
  if (shuttingDown) return;
  shuttingDown = true;
  await app.close();
  process.exit(1);
});

process.stdin.on('end', async () => {
  if (shuttingDown) return;
  shuttingDown = true;
  await app.close();
  process.exit(0);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    await app.close();
    process.exit(0);
  });
}
