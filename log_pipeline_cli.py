"""Command line for the traffic-log pipeline (read-only apart from saving a report).

  python log_pipeline_cli.py health          watcher and listener state, as JSON
  python log_pipeline_cli.py reports         the saved reports
  python log_pipeline_cli.py reindex         rebuild the saved-report catalogue (index.json) from the files on disk
  python log_pipeline_cli.py regen           make the watched folder's report now
  python log_pipeline_cli.py export NAME     print a saved report as CSV
  python log_pipeline_cli.py deliver NAME TARGET   send it through an enabled delivery target
  python log_pipeline_cli.py selftest        parse a built-in synthetic log line

Nothing here contacts a Zscaler tenant. Exit status 0 on success, 1 on a refusal.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, List, Optional


def _out(obj: Any) -> None:
    print(json.dumps(obj, indent=1, default=str))


def reindex() -> dict:
    """Rebuild <reports folder>/index.json from the saved reports on disk (local and read-only toward every report:
    a report is opened, never changed). Unreadable files are counted and named by file name only."""
    import os
    import safe_files
    import traffic_logs as tl
    rows = tl.list_saved()
    good = [r for r in rows if r.get("records") is not None]
    cat = {"reports": [{k: r.get(k) for k in ("name", "title", "at", "names", "records", "period")} for r in good],
           "unreadable": [r["name"] for r in rows if r.get("records") is None]}
    safe_files.private_makedirs(tl.saved_dir())
    safe_files.write_private_atomic(os.path.join(tl.saved_dir(), "index.json"), json.dumps(cat, indent=1, default=str))
    return {"indexed": len(good), "unreadable": len(cat["unreadable"])}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="log_pipeline_cli", description="Traffic-log pipeline (read-only).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("health", "reports", "reindex", "regen", "selftest"):
        sub.add_parser(n)
    sub.add_parser("export").add_argument("name")
    d = sub.add_parser("deliver")
    d.add_argument("name")
    d.add_argument("target")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "health":
            import syslog_listener
            import traffic_log_watch as tw
            import report_delivery as rd
            st = tw.get_state()
            ds = rd.get_settings()
            _out({"watch": {"settings": st["settings"], "last_run": st["last_run"], "next_run": st["next_run"]},
                  "listener": syslog_listener.status(),
                  "delivery": {"enabled": ds["enabled"], "targets": sorted(ds["targets"]), "libraries": ds["libraries"]}})
        elif a.cmd == "reports":
            import traffic_logs as tl
            _out(tl.list_saved())
        elif a.cmd == "reindex":
            _out(reindex())
        elif a.cmd == "regen":
            import traffic_log_watch as tw
            _out(tw.run(trigger="cli"))
        elif a.cmd == "export":
            import report_delivery as rd
            sys.stdout.write(rd.saved_report_csv(a.name)[1].decode("utf-8"))
        elif a.cmd == "deliver":
            import report_delivery as rd
            _out(rd.deliver_saved(a.target, a.name, trigger="cli"))
        elif a.cmd == "selftest":
            import log_analyzer
            rec = log_analyzer.parse_line("2024-01-01T00:00:00Z host app: connection closed")
            _out({"ok": bool(rec)})
            return 0 if rec else 1
    except Exception as e:  # noqa: BLE001 — a refusal is one line, never a traceback with settings in it
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
