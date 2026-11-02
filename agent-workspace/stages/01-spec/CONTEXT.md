# Stage 1 — Spec: what exactly is to be built?

**One job:** turn one request, gap or verification finding into a task spec another agent can build without exploring. You do not write code.

## Inputs
- `_config/token-efficiency.md` (always).
- The request: the owner's words, or one row of a verification report (`output/<run>/` or a path you were given).
- `references/_index.md` → `references/architecture.md` and `references/task-map.md` (which files a kind of change touches).
- `_config/product-rules.md`; `_config/zscaler-sdk.md` if the task touches the Zscaler API.

## Process
1. Restate the outcome in one sentence a Zscaler admin would agree with.
2. List the user-visible behaviour (pages, controls, results) and the safety behaviour (gates, scope, secrets, untrusted input) it needs.
3. Name the files it will touch, from `references/task-map.md`; flag any shared file in `_config/shared-files.md`.
4. Name the SDK classes/methods it depends on and whether each is verified or must be marked assumed (`references/assumed.md`).
5. Write acceptance tests in words: each one a behaviour that fails today and must pass after.
6. Size it: one agent, one branch. If it's bigger, split it into several specs.

## Outputs
- `output/<run>/specs/<slug>.md` with sections: Outcome · Behaviour · Safety · Files · Zscaler API · Acceptance tests · Out of scope.

## Review gate
The coordinating session (and the owner, for anything that changes what the app may write) reads the spec and accepts, edits or rejects it before stage 2.
