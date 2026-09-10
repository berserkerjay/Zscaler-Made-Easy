# Accessibility conformance (Section 508 / WCAG 2.1 AA)

DLP-Check's web interface is built to meet the Revised Section 508
Standards, which incorporate WCAG 2.0 Level AA, and it is tested against
WCAG 2.1 Level AA. This page says what was tested, how, what was found and
fixed, and what remains for a person to judge.

## What is covered

Every page a user can reach in a browser:

| Surface | Route | States audited |
|---|---|---|
| Assessment page | `/` | before a run, results shown, guide open |
| Assessment results tab | `/report/view` | results |
| Deploy Policy Packs | dialog on `/` | pack selection, preflight plan |
| Deploy flow diagram | `/report/flow` | plan rendered |
| Data Flow Map | `/report/dataflow` | overview and a traced path |
| SSL Inspection Flow | `/report/sslflow` | tenant with gaps |
| Advanced settings | `/report/advanced` | library, upload preview |
| Required API Access | `/permissions` | page |

Each state is audited twice, in the dark theme and in the light theme.

## How it is tested

* **Automated**: axe-core 4.x, run with Playwright against a local server
  with fake tenant data, rules `wcag2a`, `wcag2aa`, `wcag21a`, `wcag21aa`,
  `section508` and `best-practice`. The audit waits for the page's
  entrance animation to finish before measuring colours. The script is
  reproducible: start the app with `ZSCALER_UI_AUTH=0` and run
  `axe.run(document, {runOnly: {type: 'tag', values: [...]}})` in the
  browser console on each state above.
* **Structural checks in the test suite** (`tests/test_accessibility.py`):
  landmarks on every report page, real buttons for every card toggle,
  names on every form control, `role="group"` with a name on every
  interactive SVG, reduced-motion rules present.
* **Manual**: keyboard-only walk of the assessment page, the Deploy Policy
  Packs dialog and the report tabs; screen-reader spot checks of the
  results cards and the diagrams' text alternatives.

## Result of the last audit (2026-09-10)

| Surface | Dark | Light |
|---|---|---|
| Assessment page, before a run | 0 | 0 |
| Assessment page, results | 0 | 0 |
| Assessment results tab | 0 | 0 |
| Deploy Policy Packs, selection | 0 | 0 |
| Deploy Policy Packs, plan | 0 | 0 |
| Deploy flow diagram | 0 | 0 |
| Data Flow Map | 0 | 0 |
| SSL Inspection Flow | 0 | 0 |
| Advanced settings | 0 | 0 |
| Required API Access | 0 | 0 |

Numbers are axe violation nodes. The first audit of the same states, before
this work, reported 390.

## What was changed

* **Landmarks**: every report tab has a `header`, a `nav` for its actions
  and a `main` for its content; the assessment page has one banner and one
  main region.
* **Real controls**: card headings that expand and collapse now contain a
  `button` with `aria-expanded`; nothing interactive is a `div` or a
  heading with a click handler. Every `select` and text field has a label
  or `aria-label`. Scrollable regions are focusable.
* **Diagrams**: the deploy flow, SSL flow and data flow SVGs are
  `role="group"` with a name, their nodes are reachable with the keyboard,
  and every diagram has a text table beside it that carries the same
  information.
* **Colour and contrast**: a token set for both themes (`--dim`, `--well`,
  `--btn`, `--chip-*`, `--pass`, `--warn`, `--fail`) replaced ad-hoc
  colours; every text colour meets 4.5:1 on the surface it sits on,
  including the tinted chips inside coloured cards. Status is never
  conveyed by colour alone: every chip and node also carries a word.
* **Motion**: every animation and transition is neutralised under
  `prefers-reduced-motion: reduce`.
* **Heading order and titles**: one `h1` per page, no skipped levels,
  a descriptive `title` on every tab.
* **Focus**: a visible focus ring on every control in both themes; dialogs
  trap focus and return it on close.

## Known limitations

* The SVG diagrams are decorative summaries of the tables next to them;
  a screen reader user gets the same facts from the tables, not from the
  drawing.
* Word and Markdown exports inherit the structure of the report (headings,
  tables); their accessibility depends on the application that opens them.
* Automated tools cannot judge reading order, meaning of link text or
  the usefulness of alternative text. Those were checked by hand on the
  states listed above and should be rechecked when a new page is added.

## Reporting a problem

Open an issue in the repository with the page, the state, the assistive
technology and browser used, and what you expected. Accessibility problems
are treated as defects, not enhancements.
