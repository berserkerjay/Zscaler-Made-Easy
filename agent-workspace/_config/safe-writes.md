# Safe writes: the one engine

Every change to a tenant is a **Bulk changes operation type** on `admin_ops.py`, writing only through `pack_ops.py`. A builder, editor, restore or fix is a plugin module `ops_<name>.py` that calls `admin_ops.register(...)` at import (`load_plugins()` imports them all).

## register(type_name, *, family, product, label, hint, in_scope, plan, read_objects, handlers, verify=None, inverse=None, group="Build new", script="")
- `in_scope(scope) -> str | None`: why it is out of scope; checked before anything is read.
- `read_objects(client, scope, say, cancel)`: what the page's form can pick from (read-only).
- `plan(client, spec, scope, say, cancel)`: returns the prepared operation `{type, product, title, spec, items, groups[{key, handler, target}], warnings, blockers}`. Never writes. Everything the write will send must be in the plan, so the plan hash covers it.
- `handlers[name](run, group, units)`: performs the writes via `pack_ops`, marks `run.outcome`, sets `run.wrote_zia` when ZIA changed (one activation at the end).
- `verify(run)`: reads back `{checked, confirmed, mismatched, unread}`.
- `inverse(result)`: the operation that undoes it (the recorded Undo); return None when it can't be undone and say so in the preview.
- `group`: "Change existing", "Day-to-day admin" or "Build new"; `script`: the page form `static/ops_<name>.js`.

## What the engine does for you
Scope check → plan → preview with plan hash → (apply) re-plan and compare hash → four gates → re-read each object before its write → handlers → read-back → record with Undo → audit with actor. Stop is honoured between units.

## Your checklist for a new type
1. Payload fields match the SDK model (test it with a payload oracle).
2. Send an object back as read with only the changed fields (PUTs often replace the whole object).
3. Refuse Default, predefined and read-only objects with a reason.
4. Add the type to `tests/test_sbd_writes.py` DEFAULT_OFF with its reason, and any route to the safety tables (`scope-and-routes.md`).
5. A secret travels beside the operation, never inside the spec/plan (only a salted digest in the hash).
6. Name the builder in `static/explain.js` and list the module in `pyproject.toml`.
7. Tests: plan contents and hash, gates, conflict on re-read, read-back mismatch, Undo restores exactly, scope refusal, sample-tenant rehearsal refused on apply.
