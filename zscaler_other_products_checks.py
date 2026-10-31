#!/usr/bin/env python3
"""
Other Zscaler products — assessment checks
==========================================
Zero Trust Branch (ZTB), External Attack Surface Management (EASM),
Business Insights (ZBI), Zero Trust Cellular (ZCell) and Microsegmentation
(ZMS), each run only when its own Scope page key (ztb, easm, zbi, zcell,
zms) is ticked.

The reads and the judgements live in other_products.py (every request is
built by the installed SDK's own list/get method and sent through the
assessment client); this module turns its results into scored check
results. A product is read once per assessment run and shared by its
checks. A product the tenant does not have (the API answers 404) gives
"N/A — not licensed" (INFO, outside the score); a refused read is "Not
permitted", never judged.

All checks are read-only.
"""

import threading

import other_products as op
from dlp_assessment_full_auto import R
from zscaler_full_checks import guard_registry

_STATUS = {"PASS": R.PASS, "FAIL": R.FAIL, "REVIEW": R.WARN, "INFO": R.INFO, "ERROR": R.ERROR}
_LOCK = threading.Lock()


def _base(cl):
    """The run's client under the per-check read log (its `_cl`), where the
    product reads are cached for the run."""
    seen = 0
    while hasattr(cl, "__dict__") and "_cl" in vars(cl) and seen < 4:
        cl = vars(cl)["_cl"]
        seen += 1
    return cl


def _product(cl, product):
    """The product's read and check results, read once per run."""
    base = _base(cl)
    with _LOCK:   # held through the read: checks run in parallel, and a product is read once
        cache = vars(base).setdefault("_other_products_cache", {}) if hasattr(base, "__dict__") else {}
        hit = cache.get(product)
        if hit is None:
            hit = cache[product] = _read(cl, product)
    return hit


def _read(cl, product):
    try:
        prod = op.read_product(cl, product, op.ids_for(cl))
    except Exception as e:  # noqa: BLE001 — a failed read is reported, never raised into the run
        prod = {"product": product, "status": "error", "note": f"Not read ({type(e).__name__}).", "lists": {}}
    results = {r["id"]: r for r in op.evaluate(product, prod)}
    if prod.get("status") == "not_permitted":
        for r in results.values():
            r["detail"] = f"{prod.get('note')} Access denied (HTTP 403)."
    return prod, results


def _check(product, cid):
    def fn(cl):
        _prod, results = _product(cl, product)
        r = results.get(cid) or {"status": "INFO", "detail": "Not evaluated."}
        detail = r["detail"]
        if r.get("why"):
            detail += f" Why it matters: {r['why']}"
        if r.get("fix"):
            detail += f" Best Practice: {r['fix']}"
        if r.get("source"):
            detail += f" Source: {r['source']}"
        return R(_STATUS.get(r["status"], R.INFO), detail)
    fn.__name__ = f"check_{cid.replace('.', '_').lower()}"
    fn.__doc__ = f"{op.PRODUCTS[product]['label']}: {cid}"
    return fn


OTHER_REG = [(cid, op.PRODUCTS[product]["section"], title, _check(product, cid))
             for product in op.SCOPE_KEYS for cid, title, _fn in op.CHECKS[product]]
OTHER_REG = guard_registry(OTHER_REG)   # a refused read (HTTP 401/403) is "Not permitted", never judged

# The checks of each Scope page key (dlp_api_server._get_checks, beacon_scope).
BY_SCOPE = {product: [c for c in OTHER_REG if c[0].split(".", 1)[0].lower() == product] for product in op.SCOPE_KEYS}
