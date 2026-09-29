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
  `score_formula`, `not_permitted_ids`).
- Word report: the title table (*Assessed*, *Overall Score* with
  "configured of scoreable") and the executive summary sentence with the
  formula and the exclusions.
- The profile history keeps `score` (null when not assessed) and the
  check count per run.
