#!/usr/bin/env python3
"""
Give every pack the same rule coverage on Endpoint, SaaS and Email DLP as
it has inline (Web DLP): for each Web rule, generate a matching rule on
each of the other three channels carrying the SAME engines. So if a pack
has five Web rules, each channel ends up with five rules, one per topic.

The Web rules are the canonical set. Existing Endpoint / SaaS / Email
rules are replaced by the fanned-out set so the counts line up exactly.
A pack with no Web rules (a channel-specific baseline such as the
Endpoint DLP baseline) is left untouched.

All generated rules are monitor-only and DISABLED — the app's convention
is to ship every rule off and let the operator enable it after review.

Run: python tools/fan_out_channels.py            # every pack
     python tools/fan_out_channels.py --check     # exit 1 if any pack is stale
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pack_channels as pc
from dlp_importer import _load_json, _resolve_configs, discover_packs

FAN_CHANNELS = (pc.ENDPOINT, pc.SAAS, pc.EMAIL)
SUFFIX = {pc.ENDPOINT: "Endpoint", pc.SAAS: "SaaS", pc.EMAIL: "Email"}
# Marks a rule this generator produced, so a re-run replaces its own
# output and never a hand-written channel rule.
GEN_KEY = "channel_mirror"


def _base_name(web_name: str) -> str:
    """A stem for the mirrored rule name, without the Web rule's trailing
    action word so the channel suffix reads cleanly."""
    stem = web_name
    for tail in ("-Monitor", "-Block", " Monitor", " Block"):
        if stem.endswith(tail):
            stem = stem[: -len(tail)]
            break
    return stem.strip()


def _mirror(web_rule: dict, channel: str) -> dict:
    """A monitor-only rule on `channel` carrying the Web rule's engines."""
    engines = list(web_rule.get("engines") or [])
    name = f"{_base_name(web_rule['name'])} [{SUFFIX[channel]}]"
    r: dict = {
        "name": name,
        "channel": channel,
        "description": (f"{pc.label(channel)}: the same detection as the inline rule "
                        f"\"{web_rule['name']}\" ({', '.join(engines) or 'no engines'}). "
                        "Monitor-only; enable after reviewing incidents."),
        "action": pc.default_action(channel),
        "state": "DISABLED",
        "severity": "RULE_SEVERITY_INFO",
        "engines": engines,
        GEN_KEY: True,
    }
    if channel == pc.ENDPOINT:
        # No data_transfer_method: the rule applies to every transfer method
        # (the provider only accepts a specific method, not "ANY").
        r.update({"device_trust_levels": list(pc.ENDPOINT_TRUST_LEVELS),
                  "user_risk_score_levels": list(pc.ENDPOINT_RISK_LEVELS),
                  "without_content_inspection": False, "eun_enabled": False, "rank": 7})
    elif channel == pc.SAAS:
        r.update({"saas_type": "OFLCASB_DLP_FILE", "tenants": "any", "collaboration_scope": ["ANY"], "rank": 7})
    elif channel == pc.EMAIL:
        r.update({"tenants": "any", "rank": 7})
    return r


def fan_out(policies: list) -> list:
    """Return policies with Endpoint/SaaS/Email mirrors regenerated from
    the Web rules. Web rules and any non-DLP rules are kept as-is; the
    previous generated mirrors (and any hand-written Endpoint/SaaS/Email
    rules) are dropped and rebuilt so counts match Web exactly."""
    web = [p for p in policies if pc.channel_of(p) == pc.WEB]
    if not web:
        return list(policies)   # channel-specific pack; nothing to mirror from
    kept = [p for p in policies if pc.channel_of(p) not in FAN_CHANNELS]
    mirrors = []
    for w in web:
        for ch in FAN_CHANNELS:
            mirrors.append(_mirror(w, ch))
    return kept + mirrors


def process(pack: dict, *, write: bool) -> tuple[bool, str]:
    configs = _resolve_configs(pack["dir"])
    path = os.path.join(configs, "dlp_policies.json")
    policies = _load_json(configs, "dlp_policies.json")
    new = fan_out(policies)
    changed = json.dumps(policies, sort_keys=True) != json.dumps(new, sort_keys=True)
    if changed and write:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(new, f, indent=2)
    counts = {ch: sum(1 for p in new if pc.channel_of(p) == ch) for ch in (pc.WEB,) + FAN_CHANNELS}
    return changed, f"web {counts[pc.WEB]}, endpoint {counts[pc.ENDPOINT]}, saas {counts[pc.SAAS]}, email {counts[pc.EMAIL]}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("packs", nargs="*", help="pack ids (default: all)")
    ap.add_argument("--check", action="store_true", help="exit 1 if any pack would change; write nothing")
    args = ap.parse_args(argv)
    known = {p["id"]: p for p in discover_packs()}
    ids = args.packs or sorted(known)
    stale = []
    for pid in ids:
        if pid not in known:
            print(f"unknown pack: {pid}", file=sys.stderr)
            return 2
        changed, summary = process(known[pid], write=not args.check)
        mark = "STALE" if (changed and args.check) else ("updated" if changed else "ok")
        print(f"{pid}: {summary} [{mark}]")
        if changed:
            stale.append(pid)
    if args.check and stale:
        print(f"\n{len(stale)} pack(s) are stale; run: python tools/fan_out_channels.py", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
