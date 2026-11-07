# The app's reference library

**Open source.** Zscaler Made Easy is open-source software under the Apache License 2.0 (see LICENSE). It is built entirely from information provided by Zscaler (its public documentation, public API and open-source SDKs and Terraform providers) and by third parties. It is an independent project, not an official Zscaler product; Zscaler and related marks belong to Zscaler, Inc.

The app ships a small library of reference pages (`static/reference/`,
opened from the app's Reference menu). They explain how Zscaler's data
security fits together. Point the admin to the right page when a question
is "how should this work?" rather than "what is my tenant doing?"; the
tools answer the second kind.

The frameworks share five phases. Use the same words in answers:

| Phase | Plain meaning | Tools that show it in the tenant |
|---|---|---|
| Discover | Find where sensitive data and apps are | `data_flow`, `traffic_summary`, `traffic_logs_summary` |
| Detect | Recognise sensitive data in motion or at rest | `explain_dlp`, `dlp_incidents` |
| Enforce | Block, isolate or coach when a rule matches | `path_check`, `rule_precedence`, `ssl_coverage` |
| Respond | Follow up on incidents and alerts | `dlp_incidents`, `zdx_summary`, `case_notes` |
| Govern | Prove it, keep it current, see who changed what | `compliance_map`, `snapshot_diff`, `timeline`, `rbac_review`, `telemetry_review` |

| Page | What it covers | Send the admin there when |
|---|---|---|
| Data Security Portfolio Framework | Every data security capability by phase and channel (web, SaaS, endpoint, email, private apps) | They ask what they own, or what a channel needs |
| Portfolio Map | The same portfolio as one map, with what is retired or overlapping | They ask which product does what |
| Data Security Architect | Animated walk-throughs of how data moves through dictionaries, engines, rules and channels | They ask "why didn't DLP catch it?" in general terms (with data-security-flows.md) |
| Public GenAI Security Framework | Controls for generative AI use: discovery, prompt inspection, isolation, governance | The question is about GenAI apps or prompts |
| Public AI Security Framework | The wider AI picture: AI apps, agents, models and their data | The question is about AI beyond chat apps |
| Microsoft 365 Copilot Readiness Framework | What to have in place before turning on an assistant over company documents | They ask whether they are ready for an AI assistant over their files |
| The Framework Machine | How the frameworks themselves are built and kept current | They ask where the frameworks come from |

These pages describe good practice, not the admin's tenant. Never say the
tenant does something because a reference page says it should; check with a
tool and say which one answered.
