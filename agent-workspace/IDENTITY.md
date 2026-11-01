# Where am I?

**Open source.** Zscaler Made Easy is open-source software under the Apache License 2.0 (see LICENSE). It is built entirely from information provided by Zscaler (its public documentation, public API and open-source SDKs and Terraform providers) and by third parties. It is an independent project, not an official Zscaler product; Zscaler and related marks belong to Zscaler, Inc.

**Zscaler Made Easy** (repository `berserkerjay/Zscaler-Made-Easy`). A local FastAPI app (`dlp_api_server.py`) with a browser UI (`static/`) that **assesses, explains, builds, changes, backs up and audits** a customer's Zscaler tenant: ZIA, ZPA, Client Connector, ZDX, ZIdentity, Cloud & Branch Connector, AI Guard and the smaller Zscaler products. It runs on the admin's own machine (or in its Docker container, `zscaler-made-easy`, on port 8001), single-user by default; an optional team server mode adds accounts and per-tenant access.

This folder is the **agent workspace**: plain-text instructions that route an agent to exactly the context one step of work needs. You are an AI agent doing one stage of one task. Read `CONTEXT.md` next.

## What the app promises (never weaken)

- **Read-only by default.** A tenant write needs all four gates (write mode, a writer, a named assessor, a typed confirmation) and goes through the one write engine: plan → preview with a plan hash → re-read before each write → read-back → Undo → audit log naming the actor. New objects are created disabled or monitor-only unless the admin chooses otherwise.
- **Scope rule.** Read only what is ticked on the Scope page; anything else is a 400 before sign-in.
- **Local and locked.** Bound to localhost; UI token, origin and CSRF checks on every request; secrets live in the OS keychain.
- **No secrets anywhere:** not in logs, results, files, errors, exports or commits. A secret the admin must see is shown once and never stored.
- **Untrusted input** (uploads, tenant strings, fetched lists) is size-capped, parsed defensively, never executed, and escaped on every output.
- **Outbound calls** other than to the tenant are optional, off by default, declared in SECURITY.md, cached with their date, and fail safe to "unknown".
- **Unknown is never "match".** An analysis that cannot establish something says "unknown" and why.

## How work is done here

- **The LLM is a compiler, not a chatbot.** Each stage has inputs, numbered steps and outputs. Do the stage's one job; don't explore beyond the files the stage names.
- **Plain text between stages.** A stage writes its result as markdown in its run folder; the next stage reads that file, not your memory.
- **Every output is an edit surface.** The person reviewing can change a stage's output before the next stage reads it.
- **Human review gates** sit between stages (the coordinating session, and the owner before anything reaches `main`).

## Hard rules for every stage

- Never contact a real tenant or real Zscaler service from tests or tools; use the fakes and `sample_tenant.py`.
- Never name third-party tools, their authors or organisations in code, UI, docs, tests or commits (`_config/naming.md`).
- Never kill processes by pattern (`pkill -f`); stop what you started by its PID.
- Never weaken a test to make it pass; fix the cause or report it.
- Commit messages end with the two attribution lines in `_config/git.md`.
