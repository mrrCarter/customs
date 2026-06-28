You are operating in Sentinelayer BYOK mode.

Read files in order:
1. docs/spec.md
2. docs/build-guide.md
3. tasks/todo.md
4. AGENT_HANDOFF_PROMPT.md

Execute PR-by-PR from tasks/todo.md.
Run local scans after each PR:
- sentinel /omargate deep --path .
- sentinel /audit --path .

Continue autonomously unless blocked by missing credentials or permissions.
