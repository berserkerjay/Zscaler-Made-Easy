# Accessibility conformance (Section 508 / WCAG 2.1 AA)

Zscaler Made Easy's web interface is built to meet the Revised Section 508
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
| Log Analyzer | `/report/logs` | before an upload, results shown |
| Digest | `/report/digest` | latest digest shown |
| What does everything do? | `/help` | page |
| Evaluate All Rules reference | `/report/evalall` | page |
| Migrate from another DLP | `/report/vendor` | page |
| Data Security Architect | `/reference/data-security-architect` | page |

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

## Regression audit (2026-10-26, WCAG 2.2 AA)

axe-core 4.10 (`wcag2a`, `wcag2aa`, `wcag21a`, `wcag21aa`, `wcag22aa`,
`best-practice`) with Playwright against fake tenant data, both themes,
reduced motion on, on every page the app serves (35 routes) and on the
result states of SSL coverage, Improve my score, Self-healing, Browser
security, Device posture, ZPA overview, To-do, Policy exports and Bulk
changes, plus the Find anything dialog with results open. Every page also
had a keyboard walk (focus ring on each stop), a focus-trap and
focus-return check of Find anything and the app's own dialog, and a check
that no animation or smooth scroll runs under reduced motion. Result: 0
violations after the fixes below (the first pass found contrast failures on
every page in the dark theme and on most in the light one).

* **Colour tokens**: every text token is now at least 4.5:1 on the page,
  the card and the well in both themes, and every status colour on its own
  12% tint (dark `--accent`, `--fail`, `--chip-purple`, `--dim`; light
  `--accent`, `--pass`, `--warn`, `--fail`, `--dim`). Fills under white
  text use `--btn`, `--btn-danger`, `--btn-warn` or `--btn-ok`, never a
  text colour. `tests/test_accessibility.py` computes the ratios from the
  stylesheet, so a token edit that breaks AA fails the build.
* **Status chips** mix their tint into the opaque card, so a well or a
  tinted row under a chip cannot lower its contrast.
* **Reduced motion** also covers scripted scrolling: Chromium animates
  `scrollIntoView({behavior: 'smooth'})` even when the user asked for
  reduced motion, so every page turns those scrolls into instant ones.
* **Targets** (SC 2.5.8): every disclosure (`summary`) is at least 24px tall.
* Heading levels, a named region for the scrolling path animation and the
  Find anything results, sentence case on headings, buttons and labels,
  and Device posture's own explainer (it showed Improve my score's).

## Functionality and accessibility audit on the sample tenant (2026-10-29, WCAG 2.2 AA)

Every page the app serves (the assessment page, Simple mode, `/help`,
`/permissions`, every `/report/*` page and the five reference pages) was
opened in Chromium on the sample tenant (Larkspur Freight), with the
assessment run from the Scope page, in both themes with reduced motion on,
and measured with axe-core 4.10 (`wcag2a` to `wcag22aa`). Every button, tab
and disclosure was clicked; every Analyze, Read, Preview and Export ran;
every download was opened (Word with python-docx, Excel and PDF parsed);
the seven Simple mode tasks ran end to end; and the sample's change counter
stayed at zero with write mode off.

The checks are now tests, each a table over the route list the app itself
serves, so a new page is measured too:

| Check | WCAG 2.2 SC | Test |
|---|---|---|
| Loads with no script, console or HTTP error | 4.1.2 | `tests/test_accessibility.py::test_every_page_loads_without_errors_on_the_sample` |
| Every control has a name (Chrome's accessibility tree) | 4.1.2, 1.3.1 | `test_every_control_has_an_accessible_name` |
| Keyboard walk: focus visible at every stop, never stuck | 2.1.1, 2.1.2, 2.4.7 | `test_keyboard_focus_is_visible_and_never_trapped` |
| 24 px targets (inline and spacing exceptions) | 2.5.8 | `test_every_target_is_at_least_24px` |
| Text contrast against what is painted under it, both themes | 1.4.3 | `test_text_contrast_meets_aa_in_both_themes` |
| No control inside another; scrolling regions reachable | 4.1.2, 2.1.1 | `test_no_control_holds_another_control`, `test_every_scrolling_region_is_reachable_by_keyboard` |
| Job progress in a live region; title, language, h1 | 4.1.3, 2.4.2, 3.1.1 | `test_pages_with_jobs_announce_progress_in_a_live_region` |
| Nothing animates under reduced motion | 2.3.3, 2.2.2 | `test_nothing_animates_under_reduced_motion` |
| Results of the job pages render, reflow and keep contrast | 1.4.10, 1.4.3 | `test_every_result_renders_accessibly_and_reflows` |
| No sideways scroll at 320, 390, 640 (200% zoom) and 1280 px | 1.4.10, 1.4.4 | `tests/test_report_reflow.py::test_no_report_page_scrolls_sideways` |
| The sample tenant, Simple mode and the builder hand-offs work | 3.3.1, 3.2.4 | `tests/test_sample_tenant_browser.py` |
| Help text: every entry has its `/help` card, no dead link, every builder named | 2.4.4, 3.3.2 | `tests/test_explain.py` |

What was found and fixed: Run assessment on the Scope page refused the
sample tenant (it asked for sign-in details the sample does not need);
Find anything's notes were refused on the sample; seven functions had no
card on `/help`, so "Every function explained" on Beacon and How a
deployment works landed nowhere; the Bulk changes, Advanced settings,
Client Connector fleet, Live DLP feed and Path analyzer explainers did not
name sections those pages have (the thirteen builders among them); four
glyphs stayed colour emoji; `/help`, `/permissions` and the Path
analyzer's result scrolled sideways at 320 px (every auto-fit grid now caps
its track at the line width); the Word report said "Unknown" for the
organisation and used Title Case headings; the object picker's checkboxes
were 13 px targets; and the reference pages failed contrast, language,
nested controls, keyboard scrolling, 24 px targets, dialog names and
reflow, and linked a CSV file that is not served. The reference documents
are bundled as built elsewhere, so the app serves them with an
accessibility layer (`static/reference/reference_a11y.js`) instead of
editing their content.

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

* On the Data Security Portfolio Framework, a technique card of a
  channel the reader switched off is drawn at 20% opacity and cannot be
  focused or clicked. Its text is below 4.5:1 on purpose; SC 1.4.3 exempts
  inactive components, so it is accepted, not repaired.
* The reference documents' colour repair runs in the browser: it keeps
  each colour's hue and moves only its lightness until the text reaches
  AA, so a page printed without scripts shows the original colours.

## Reporting a problem

Open an issue in the repository with the page, the state, the assistive
technology and browser used, and what you expected. Accessibility problems
are treated as defects, not enhancements.
