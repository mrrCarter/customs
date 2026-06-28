# Sentinelayer Agent Handoff Prompt

You are executing "customs" autonomously.

Read files in this exact order:
1. docs/spec.md
2. docs/build-guide.md
3. prompts/execution-prompt.md
4. tasks/todo.md
5. .github/workflows/omar-gate.yml

Execution mode:
- Work PR-by-PR from tasks/todo.md.
- For each PR run Omar loop until P0/P1 are zero and quality checks pass.
- Keep commits scoped and deterministic.
- Stop only for blocking secrets/permission gaps.

Ticket trail (lean, only if the project has a board/Jira — do this on every PR, not every step):
- One ticket = one PR; put the ticket id in the PR body.
- On PR open -> move the ticket to In-review and comment the PR link.
- On merge + green -> move the ticket to Done and comment "merged, gate green".
- On gate fail -> move the ticket to Blocked with the finding.
- Post one short senti update per transition (same discipline as the ticket).

Coding agent profile:
- Selected agent: OpenAI Codex (codex)
- Prompt target: codex
- Suggested config path: AGENTS.md

Agent-specific guidance:
- Execute autonomously, one bounded PR at a time.
- Use deterministic ingest/spec context as primary source.
- Fail closed when scope or safety requirements are ambiguous.

GitHub Action contract:
- Sentinelayer token: not configured (BYOK mode).
- Keep provider credentials in your own environment (OPENAI_API_KEY / ANTHROPIC_API_KEY / GOOGLE_API_KEY).
- If you later adopt Omar Gate GitHub Action, set secrets.SENTINELAYER_TOKEN and wire sentinelayer_token accordingly.

Terminal command options:
- sentinel /omargate deep --path .
- sentinel /audit --path .
- sentinel /persona orchestrator --mode builder --path .
- sentinel /persona orchestrator --mode reviewer --path .
- sentinel /persona orchestrator --mode hardener --path .
- sentinel /apply --plan tasks/todo.md --path .
- Add --json to /omargate, /audit, /persona, or /apply for machine-readable CI output.

Workflow tuning options:
- BYOK workflow is guidance-only and does not call the Sentinelayer action.
- To enable Omar Gate later, set SENTINELAYER_TOKEN and configure scan_mode/severity_gate in workflow inputs.

Repo context:
- Target repo: not provided
- Workspace mode: new scaffold

## Multi-Agent Coordination (if session active)

1. Find the recent Senti session for this codebase: run `sl session list --path .` and `sl session list --remote --path .`; join the right room with `sl session join <id> --name <your-name> --role coder`.
2. When you have an agent grant, post agent updates with `sl session post-agent <id> "status: <update>" --agent <your-agent-id>` so they render as the agent, not the human relay.
3. Before implementation, post a short plan and file claims with `sl session say <id> "plan: <scope>; files: <paths>"`.
4. Claim shared files before editing with `lock: <file> - <intent>` and release them with `unlock: <file> - done`.
5. Run a background/secondary listener for replies with `sl session listen --session <id> --agent <your-name> --interval 60 --active-interval 5 --emit ndjson --no-presence`; this idles at 60s, switches to 5s after human activity, and avoids durable listener heartbeat noise. `session listen` is only a delivery cursor, not a grounding command; join or recap before acting. For your primary interactive listener, omit `--no-presence` so other participants can see you online. If background polling is unavailable, fall back to `sl session sync <id> --json` then `sl session read <id> --tail 20 --json` every 5 minutes.
6. For long-lived rooms, make sure exactly one visible participant owns the Senti daemon: `sl session daemon --session <id> --recap-interval 300 --checkpoint-interval 60`. If no durable recap/checkpoint is appearing, run `sl session recap now <id> --remote --agent <your-name> --json` before posting a long plan.
7. Use message actions for low-noise coordination before posting a new top-level message: `sl session react <id> ack --target-sequence <n>` only when an explicit ACK is useful, `sl session action <id> working_on --target-sequence <n>` for ownership, and `sl session reply <id> <sequence> "<message>"` / `sl session comment <id> <sequence> "<message>"` for threaded responses. Read receipts are automatic when you use `sl session read <id> --remote --agent <your-name>`; reserve `sl session view <id> <sequence>` for repair/backfill. Run `sl session actions` for the full list.
8. Search before asking peers to restate context: `sl session search <id> "<topic>" --limit 10`.
9. Run `sl review --diff` after each finished file or PR-ready diff and post the result summary back to the session.
10. Post findings through `sl session say <id> "finding: [P2] <title> in <file>:<line>"` with enough context for a peer to act.
11. Ask for help in-session instead of stopping on unexpected file changes, blocked context, or ambiguous ownership.
12. Offer non-conflicting follow-up work to peers when you finish your claimed scope or discover separable tasks.
13. Run `sl --help` when you hit an unfamiliar workflow before guessing at command syntax.
14. Leave the session when done with `sl session leave <id>` after posting the final status and verification evidence.

Start now and continue autonomously.
