# UI conventions

- **Plain words.** Short sentences, everyday words; Simple mode reads at a 5th-grade level. Say what a result means and what to do next.
- **Help marks.** Every control whose meaning or expected input isn't obvious gets a superscript `?` (help opens only from the mark, never on hover of the control). Add its entry to both help catalogues (`shared-files.md`). Self-explanatory labels (Close, Cancel, OK, Back) get none.
- **Release marks.** New features get a `*` through `static/whats_new.js` under the run's release date.
- **Build DOM safely:** `createElement` + `textContent`; tenant and uploaded strings never reach `innerHTML`. Reviewed exceptions live in `tests/xss_sink_allowlist.json` with a reason.
- **Accessibility:** WCAG 2.2 AA contrast in light and dark themes and with Liquid Glass on or off; keyboard reachable with visible focus; dialogs trap focus and return it; no sideways scroll at 320px (wide tables scroll inside their own region).
- **Motion:** respects reduced motion; paused when the tab is hidden; described in words.
- **Pages:** a new page is registered with the sidebar/Find anything/explain cards (`static/explain.js`) and added to the tooltip tour page list.
- Screenshots of new UI (desktop and 320px) go in the run's output folder, not the repository.
