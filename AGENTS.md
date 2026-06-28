# Sentinelayer OpenAI Codex Profile

Project: customs
Prompt target: codex

Rules:
- Read docs/spec.md, docs/build-guide.md, tasks/todo.md, and AGENT_HANDOFF_PROMPT.md in order.
- Work one PR scope at a time and keep changes deterministic.
- Run local checks before push: /omargate deep and /audit.
- Find the recent Senti session for this codebase: run `sl session list --path .` and `sl session list --remote --path .`; join the right room with `sl session join <id> --name <your-name> --role coder`.
- When you have an agent grant, post agent updates with `sl session post-agent <id> "status: <update>" --agent <your-agent-id>` so they render as the agent, not the human relay.
- Before implementation, post a short plan and file claims with `sl session say <id> "plan: <scope>; files: <paths>"`.
- Claim shared files before editing with `lock: <file> - <intent>` and release them with `unlock: <file> - done`.
- Run a background/secondary listener for replies with `sl session listen --session <id> --agent <your-name> --interval 60 --active-interval 5 --emit ndjson --no-presence`; this idles at 60s, switches to 5s after human activity, and avoids durable listener heartbeat noise. `session listen` is only a delivery cursor, not a grounding command; join or recap before acting. For your primary interactive listener, omit `--no-presence` so other participants can see you online. If background polling is unavailable, fall back to `sl session sync <id> --json` then `sl session read <id> --tail 20 --json` every 5 minutes.
- For long-lived rooms, make sure exactly one visible participant owns the Senti daemon: `sl session daemon --session <id> --recap-interval 300 --checkpoint-interval 60`. If no durable recap/checkpoint is appearing, run `sl session recap now <id> --remote --agent <your-name> --json` before posting a long plan.
- Use message actions for low-noise coordination before posting a new top-level message: `sl session react <id> ack --target-sequence <n>` only when an explicit ACK is useful, `sl session action <id> working_on --target-sequence <n>` for ownership, and `sl session reply <id> <sequence> "<message>"` / `sl session comment <id> <sequence> "<message>"` for threaded responses. Read receipts are automatic when you use `sl session read <id> --remote --agent <your-name>`; reserve `sl session view <id> <sequence>` for repair/backfill. Run `sl session actions` for the full list.
- Search before asking peers to restate context: `sl session search <id> "<topic>" --limit 10`.
- Run `sl review --diff` after each finished file or PR-ready diff and post the result summary back to the session.
- Post findings through `sl session say <id> "finding: [P2] <title> in <file>:<line>"` with enough context for a peer to act.
- Ask for help in-session instead of stopping on unexpected file changes, blocked context, or ambiguous ownership.
- Offer non-conflicting follow-up work to peers when you finish your claimed scope or discover separable tasks.
- Run `sl --help` when you hit an unfamiliar workflow before guessing at command syntax.
- Leave the session when done with `sl session leave <id>` after posting the final status and verification evidence.

