# Token efficiency

Context is the cost. Every rule here cuts what an agent reads or writes without cutting what it proves.

## Reading
- Load only the files your stage's Inputs name, then the task map's files for your kind of change. Do not read whole large modules: grep for the symbol, then read the lines around it.
- Read a compiled reference (`architecture.md`, `assumed.md`) instead of sweeping the tree.
- Never re-read a file you just edited; the edit tool fails if the change did not apply.

## Running tests
- Run targeted files only, with `-q --tb=line -rf` (one line per failure). Pipe long output through `tail -n 30`.
- Never paste a full test log into a report or message; quote the failing test id and its one-line error.
- No per-branch full suite; stage 4 runs it once on the merged tree.

## Verifying
- Verify the diff (`git diff <base>...HEAD`), not the whole tree. Read unchanged code only where the diff calls it.
- One verifier per branch; ask it for a pass/fail list, not prose.

## Reporting
- Return ≤5 lines to the coordinator: branch, last commit, tests run and passed, anything left open. The detail lives in `output/<run>/<stage>/<slug>.md`.
- Coordinators wait for completion notices instead of polling status.

## Sessions and models
- Start a fresh session per run (wave); carry state in `output/<run>/` files, not in chat history.
- Mechanical stages (verify checklists, integrate merges, hosting checks) can use a cheaper model; build and spec stay on the strongest.
