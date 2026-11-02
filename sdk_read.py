"""Plain reads over the Zscaler SDK's (result, response, error) tuples.

`call(fn, *args, **kw)` runs one SDK call and answers (body, error): the
wire body when the SDK keeps it (so fields its models do not declare
survive), else the result as plain data, made plain all the way down (the
SDK can leave its model objects inside a wire body). It never raises: a
refusal or an exception is the error text, worded by pack_ops."""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple


def wire(resp: Any) -> Any:
    fn = getattr(resp, "get_body", None)
    if not callable(fn):
        return None
    try:
        return fn()
    except Exception:  # noqa: BLE001
        return None


def deep(x: Any, depth: int = 0) -> Any:
    """Plain data all the way down (dicts, lists, scalars)."""
    if depth > 8:
        return None
    if isinstance(x, dict):
        return {k: deep(v, depth + 1) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [deep(v, depth + 1) for v in x]
    if isinstance(x, (str, int, float, bool)) or x is None:
        return x
    fn = getattr(x, "as_dict", None)
    if callable(fn):
        try:
            return deep(fn(), depth + 1)
        except Exception:  # noqa: BLE001
            return {}
    return str(x)


def error_text(err: Any) -> str:
    try:
        import pack_ops
        return pack_ops.describe_error(err)[:240]
    except Exception:  # noqa: BLE001
        return str(err)[:240]


def call(fn: Callable[..., Any], *args: Any, **kw: Any) -> Tuple[Any, Optional[str]]:
    """(the body as plain data, error text or None). Never raises."""
    try:
        ret = fn(*args, **kw)
    except Exception as e:  # noqa: BLE001 — a refusal is reported, never raised
        return None, f"{type(e).__name__}: {str(e)[:160]}"
    data, resp, err = (tuple(ret) + (None, None, None))[:3] if isinstance(ret, tuple) else (ret, None, None)
    if err:
        return None, error_text(err)
    body = wire(resp)
    if body is None:
        body = list(data) if isinstance(data, list) else data
    return deep(body), None


def items(body: Any, *keys: str) -> List[Dict[str, Any]]:
    """The list of objects inside an answer: a list, or an envelope's list under one of `keys`
    (a one-item list wrapping an envelope, as the SDK hands some answers back, too)."""
    if isinstance(body, list):
        if len(body) == 1 and isinstance(body[0], dict) and any(isinstance(body[0].get(k), list) for k in keys):
            body = body[0]
        else:
            return [x for x in body if isinstance(x, dict)]
    if isinstance(body, dict):
        for k in keys:
            if isinstance(body.get(k), list):
                return [x for x in body[k] if isinstance(x, dict)]
    return []
