# FlockMesh

Agent-native collaboration infrastructure for the next generation organization.

## Why FlockMesh

Traditional collaboration tools are human-message-first. The next organization will be:

- Human + Agent mixed teams
- Agent capabilities as first-class org assets
- System connectivity managed as reusable runtime contracts
- Every important action auditable, replayable, and policy-controlled

FlockMesh is built to be the control plane and runtime mesh for this model.

## Product Thesis

In the next decade, joining an organization will mean configuring your role agents and connecting them to business systems. Channels and docs remain useful, but the center of execution shifts to agent playbooks and tool graphs.

## Core Modules

1. Agent Registry
- Role-based agent identity
- Prompt/version lifecycle
- Capability declarations and guardrails

2. Connector Hub
- MCP-native tool adapters
- Legacy API and webhook bridges
- Permissioned credential vault bindings

3. Collaboration Runtime
- Human-in-the-loop workflows
- Cross-agent delegation and escalation
- Event-sourced task and decision timeline

4. Governance Layer
- Policy as code for tools and data
- Full audit logs and replay
- Multi-tenant isolation

## MVP Scope (v0)

- Create/update/deprecate agent profiles
- Bind agents to tools through typed contracts
- Run one multi-agent workflow with approval gates
- Trace every step with structured logs
- Publish a minimal web console for team operations

## Project Docs

- Vision: `docs/vision.md`
- Architecture: `docs/architecture.md`
- Roadmap: `docs/roadmap.md`

## Inspiration & Signals

- OpenClaw vision and OSS implementation: https://github.com/openclaw/openclaw
- MCP ecosystem (Anthropic): https://www.anthropic.com/news/model-context-protocol
- Agent2Agent protocol (Google): https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/
- MCP under Linux Foundation AI governance: https://www.linuxfoundation.org/press/linux-foundation-launches-agent2agent-project-to-enable-secure-agent-to-agent-collaboration-at-scale
- AGENTS.md for repository-level agent instructions: https://github.com/openai/agents.md

## License

MIT
