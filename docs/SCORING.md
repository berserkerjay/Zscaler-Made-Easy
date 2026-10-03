# How the assessment score is computed — and what it is not

One vocabulary is used everywhere the numbers appear: the dashboard tiles,
the Summary card, the section scores, the findings list, the Word report
and the JSON export. They are all built from the same summary
(`permissions.assessment_summary` on the server, `assessmentSummary` in
the browser for a report assembled after a dropped connection), so they
cannot disagree.

## What each check result means

The engine records four statuses. The summary adds one distinction inside
the last of them, because the tenant owner can do something about it.

| Class | Engine status | Meaning | In the score? |
|---|---|---|---|
| **Configured** | PASS | The setting matches Zscaler's recommendation. | Yes (numerator and denominator) |
| **Action required** | FAIL | The setting is missing or contradicts the recommendation. | Yes (denominator) |
| **Needs review** | REVIEW | The setting exists but differs from the recommendation, or a person has to judge it. | Yes (denominator) |
| **Not permitted** | INFO or ERROR whose detail is a 401/403 from the API | The API client's role does not include this feature, so the check could not run. Granting the permission restores coverage. | No |
| **Could not be checked** | ERROR | The check itself failed (timeout, unexpected answer). | No |
| **Not configured** (informational) | INFO | The feature is not licensed, not in use, or the check only reports what it found. | No |

## The score

```
score = configured ÷ (configured + action required + needs review) × 100
```

- The denominator is only what could be judged. Not-permitted,
  could-not-be-checked and informational results are outside it: they
  neither raise nor lower the score.
- **Channel ownership** (the Scope page, `channel_scope.py`): a channel
  marked *Zscaler* runs as usual; one marked *Alternative* or left unticked
  (a gap) has its checks never run and never read, because the assessment
  reads only what was put in scope. A check shared with a *Zscaler*
  channel still runs, except that a check which also reads another
  channel's own configuration (its rules: `CHANNEL_READS`, e.g. a GenAI
  check that reads the Web DLP rules) runs only when that channel is in
  scope too. A non-empty declaration whose entries cannot be read (a blank
  or unknown id, a null value) counts every channel as unticked. The
  declaration is saved on the tenant profile and comes back in the report
  as `channel_coverage` (dashboard insight, Word report section, JSON
  export). With no declaration at all (an MCP or CLI caller) every check
  in the selected scopes runs.
- **Prerequisites** (`channel_scope.PREREQUISITES`): a channel on Zscaler
  puts the channels it cannot work without in scope too, even when they
  were not ticked (or were marked *Alternative*). Their checks run and
  their endpoints may be read, and the Scope page, the Summary card, the
  dashboard and the Word report say why ("SSL/TLS Inspection: included
  because Inline Web DLP needs it"). The map:

  | When on Zscaler | Also assessed | Why |
  |---|---|---|
  | Inline Web DLP | SSL/TLS Inspection | Inline DLP only inspects what SSL inspection decrypts; without it, HTTPS uploads pass uninspected. |
  | GenAI Security | SSL/TLS Inspection | GenAI prompt and upload controls act on decrypted traffic; without SSL inspection the prompts are invisible. |
  | Device Control | Endpoint DLP | Device Control rules are Endpoint DLP rules, enforced by the Endpoint DLP module; without it installed, none fires. |

  The saved declaration is never rewritten: the prerequisites are derived
  on every run.
- **Checks outside the scope are hidden.** A check whose channel is
  neither in scope nor a prerequisite of something in scope has no row,
  no section, no score item and no coverage count anywhere: the results,
  the dashboard, the Word report, the compliance mapping, the benchmarks
  and the JSON export. One line counts them: "N checks are outside the
  selected scope and are not shown." A check that *is* in scope but
  failed, was refused or could not be read stays visible. An older saved
  report that still carries *Not in scope* rows has them dropped and
  counted the same way.
- **When nothing was scoreable the score is "Not assessed"**, not 100%
  and not 0%. This applies to the overall score and to every section: a
  section whose checks are all informational shows *Not measured* rather
  than *100% · Optimized*.
- The maturity label follows the score: ≥ 90 Optimized, ≥ 75 Managed,
  ≥ 50 Developing, ≥ 25 Initial, below that Ad Hoc.

Worked example from a real run: 311 checks; 89 configured, 20 action
required, 132 needs review, 70 informational or not permitted (2 of them
not permitted). Score = 89 ÷ (89 + 20 + 132) = 89 ÷ 241 = 37%, *Initial*.
70 checks are outside the score. The assessment is *partial*: 309 of 311
checks ran, 2 could not.

## Execution versus coverage

Two different questions get two different numbers:

- **Did the run finish?** The Completion tile: *Done* or *Partial*, with
  "309 of 311 assessed · 2 not permitted". It follows the live progress
  card while a run is in flight and is not a percentage that mixes
  "finished" with "allowed".
- **How much of the tenant could be judged?** The Summary card's coverage
  line: "Partial: 309 of 311 checks ran · 2 not permitted for this API
  client · score = 89 configured ÷ 241 scoreable (70 excluded)".

## States the interface distinguishes

| State | What you see |
|---|---|
| **Unassessed** (no run for this tenant) | Score "—", *Not assessed yet*, Completion "no run in this tab yet". |
| **Previous result** (the profile has a recorded run) | The previous score, labelled *Previous result · run &lt;date and time&gt;*. |
| **Running** | Completion follows the progress card ("42 of 311 checks run"); the score tile says *Assessing now*, keeping a previous score visible only under that label. |
| **Complete** | Score, maturity, *Assessed &lt;time&gt;*, Completion *Done · 311 checks assessed*. |
| **Partial** (some checks not permitted or could not be checked) | Completion *Partial · 309 of 311 assessed · 2 not permitted*; the affected rows are labelled *Not permitted* or *Could not be checked*; the Partial scan card says what to grant. |
| **Interrupted** (the connection dropped mid-run) | The report is built from the checks that finished, marked *(PARTIAL)*, and the coverage line says the numbers cover only those. |

## Where the same numbers appear

- JSON export: the `summary` object (`total`, `assessed`, `not_permitted`,
  `errors`, `informational`, `configured`, `action_required`,
  `needs_review`, `scored`, `excluded`, `score`, `maturity`, `state`,
  `score_formula`, `not_permitted_ids`, `hidden`, `hidden_note`), the
  report's `hidden_checks` and `hidden_note`, and the `channel_coverage`
  object (with `prerequisites`).
- Word report: the title table (*Assessed*, *Overall Score* with
  "configured of scoreable") and the executive summary sentence with the
  formula and the exclusions.
- The profile history keeps `score` (null when not assessed) and the
  check count per run.
