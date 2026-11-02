# Git

- **Never work in the main checkout.** `git fetch origin <base>` then `git worktree add -b <branch> <path> origin/<base>`. Base and branch prefix come from your run's instructions (features `feat/<slug>`, fixes `fix/<slug>`, integration `integrate/<run>`).
- Commit early and often (a restart or a usage limit loses only uncommitted work); push with `git push -u origin <branch>`. Don't open or merge pull requests unless your stage says so.
- Every commit message ends with exactly these two lines:

  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01PZoBMCU4VakZfrFZrUH9uv
  ```
- Branch flow to production (stage 5 only, with the owner's go-ahead): integration → `dev` (squash PR) → `qa` (merge commit) → `main` (merge commit); then sync the session branch to `main`. Pull request bodies end with the Claude Code attribution footer used by earlier PRs.
- Never: force-push shared branches, rewrite pushed history, `git stash pop` (the stash list is shared across worktrees), change the remote URL, or commit secrets, scratch files, screenshots or generated tenant data.
