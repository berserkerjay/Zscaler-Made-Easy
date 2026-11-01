# Adding an API route

Every new route in `dlp_api_server.py` must be registered in all of these, or a test fails:

| Where | What to add |
|---|---|
| `tests/test_scope_rule_routes.py` | The route with a body naming nothing in scope → expect 400 before any client is built (or EXEMPT with a reason when it reads no tenant) |
| `tests/test_write_safety_gates.py` | Classify it: a tenant write (must hit the gates) or read-only (with a reason, e.g. local settings) |
| `tests/test_api_contracts.py` | Its status codes on a fresh install |
| `team_routes.py` | Its team-mode rule: viewer / plan / apply / approve / admin, and which `profile_id` or stored object id it touches. A route with no rule is a 403 in team mode. Every id-bearing object (backup, job, plan, report, snapshot) must carry its tenant profile and be checked and filtered |
| `scope_permissions.py` | A Scope key if it reads a new area |
| `tests/openapi_snapshot.json` | Optional: additions are allowed without refreshing it |

## Rules
- Validate the body before sign-in; bad input or nothing in scope is a 400 with a plain message.
- Long reads run as jobs (the existing jobs pattern, polled via `/api/dlp-packs/jobs/{id}`) and honour Stop.
- Downloads go through authenticated `/api/` routes with `Cache-Control: no-store` and `nosniff`; never an unauthenticated link.
- A state-changing route that touches no tenant (local settings, imports) is still audited and, under SSO/team mode, needs a writer.
