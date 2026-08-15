# AgentGuard

AgentGuard is an offline, deterministic policy enforcement toolkit for AI-agent tool calls. It evaluates identity and session context, capability grants, approval state, sensitive-data egress, prompt-injection indicators, and policy rules before a tool invocation is allowed.

This independent project was inspired by the security ideas discussed in [Anthropic's Glasswing news](https://www.anthropic.com/glasswing). AgentGuard is not affiliated with, partnered with, sponsored by, or endorsed by Anthropic. “Glasswing” and “Anthropic” remain the property of their respective owners.

AgentGuard uses only the Go standard library, stores data in ordinary files, performs no network access, and produces deterministic decisions and replayable tamper-evident audit records.

## Quick start

```powershell
go build ./...
./agentguard sample-policy > policy.json
./agentguard sample-config > config.json
./agentguard validate -policy policy.json
./agentguard evaluate -policy policy.json -config config.json -request request.json -audit .agentguard/audit.jsonl
./agentguard verify-audit -audit .agentguard/audit.jsonl
./agentguard replay -policy policy.json -config config.json -audit .agentguard/audit.jsonl
```

## Architecture

- `guard` composes local classification, deterministic policy evaluation, and audit recording.
- `policy` strictly decodes versioned rules and applies deny-over-approval-over-allow precedence.
- `classify` detects sensitive egress, destination trust issues, and prompt-injection signals, with deterministic redaction.
- `identity` manages authenticated identities, sessions, anti-replay sequence/nonce state, and scoped capability grants.
- `approval` implements quorum, separation-of-duty, expiry, signature, and one-time consumption workflows.
- `audit` provides canonical JSON, a SHA-256 append-only hash chain, checkpoints, verification, and deterministic replay.
- `config`, `filestore`, and `report` provide strict runtime configuration, root-confined durable files, and JSON/text/HTML output.

Policies, requests, configuration, snapshots, and audit payloads reject malformed data; strict decoders reject unknown fields and trailing JSON values. Evaluation uses the request's explicit `evaluated_at` timestamp so replay does not depend on wall-clock time.

AgentGuard never initializes Git, contacts a remote service, or requires SQLite. All runtime behavior is available through standard-library-only Go packages and ordinary local files.

Run `agentguard help` for all commands and JSON schema guidance.
