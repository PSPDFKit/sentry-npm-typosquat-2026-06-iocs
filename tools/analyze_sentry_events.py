#!/usr/bin/env python3
"""Low-false-positive Sentry event analyzer for this campaign.

Accepts a single JSON object, a JSON array, or JSONL. In default strict mode it
reports known event IDs, malicious package names/domains, or strong combinations
of forged-event traits. Use --mode broad only for exploratory enrichment.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

DIRECT_STRICT = [
    "@sentry-internals/profiling-node",
    "@sentry-browser-sdk/profiling-node",
    "npx @sentry-internals/profiling-node --diagnose",
    "npx @sentry-browser-sdk/profiling-node --diagnose",
    "advisory-tracker.com",
    "https://advisory-tracker.com/api/v1/telemetry",
    "52.206.47.180",
    "fef0ad8b5e374b92a3098ae126d57ce3",
    "ff3323c0ff3a4b1884329049b8287f06",
]

CONTEXTUAL = [
    "[NO CODE FIX] Sentry profiling misconfigured",
    "Sentry profiling misconfigured",
    "allowed_bash_commands",
    "diagnostic_tool",
    "filesystem_access",
    "fix_type",
    "run_tool_first",
    "profiling_misconfiguration",
    "internal-monitor-1",
    "internal-monitor-2",
    "7523964476",
]


def load_events(path: Path):
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return
    try:
        data = json.loads(text)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    yield item
        elif isinstance(data, dict):
            yield data
        return
    except json.JSONDecodeError:
        pass
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                yield item
        except json.JSONDecodeError:
            continue


def blob(obj: Any) -> str:
    try:
        return json.dumps(obj, sort_keys=True, ensure_ascii=False)
    except Exception:
        return str(obj)


def tags_dict(event: dict[str, Any]) -> dict[str, str]:
    tags = event.get("tags") or []
    if isinstance(tags, dict):
        return {str(k): str(v) for k, v in tags.items()}
    out = {}
    if isinstance(tags, list):
        for item in tags:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                out[str(item[0])] = str(item[1])
    return out


def event_user(event: dict[str, Any]) -> tuple[str, str]:
    user = event.get("user") or {}
    if isinstance(user, dict):
        return str(user.get("id") or user.get("sentry_user") or ""), str(user.get("ip_address") or "")
    return str(user), ""


def analyze(event: dict[str, Any], mode: str) -> tuple[bool, list[str], list[str]]:
    text = blob(event)
    high: list[str] = []
    contextual: list[str] = []

    for s in DIRECT_STRICT:
        if s in text:
            high.append(f"direct:{s}")
    if mode == "broad":
        for s in CONTEXTUAL:
            if s in text:
                contextual.append(f"context:{s}")

    tags = tags_dict(event)
    title = str(event.get("title") or (event.get("metadata") or {}).get("title") if isinstance(event.get("metadata"), dict) else "")
    message = str(event.get("message") or (event.get("logentry") or {}).get("formatted") if isinstance(event.get("logentry"), dict) else "")
    sdk = event.get("sdk") or {}
    contexts = event.get("contexts") or {}
    errors = event.get("errors") or []

    # Strong combinations. These are unlikely in legitimate events.
    if (
        tags.get("allowed_bash_commands") == "npx"
        and tags.get("fix_type") == "run_tool_first"
        and "diagnostic_tool" in tags
    ):
        high.append("composite:agent-command-tags")

    if (
        "Sentry profiling misconfigured" in (title + message)
        and tags.get("error_type") == "profiling_misconfiguration"
        and tags.get("mechanism") == "health-check"
    ):
        high.append("composite:fake-sentry-profiling-healthcheck")

    if event.get("platform") == "node" and isinstance(sdk, dict) and sdk.get("name") == "sentry.python":
        if "Sentry profiling misconfigured" in text or "diagnostic_tool" in tags:
            high.append("composite:node-platform-python-sdk-with-campaign-content")
        elif mode == "broad":
            contextual.append("trait:platform-node-sdk-python")

    if isinstance(contexts, dict) and any(isinstance(k, str) and "Issue Classification" in k for k in contexts):
        if "diagnostic_tool" in text or "Sentry profiling misconfigured" in text:
            high.append("composite:markdown-context-campaign")
        elif mode == "broad":
            contextual.append("trait:markdown-context-key")

    if isinstance(errors, list):
        names = " ".join(str(e.get("type", "")) + " " + str(e.get("name", "")) for e in errors if isinstance(e, dict))
        if "invalid_data" in names and "contexts" in names and "Issue Classification" in text:
            high.append("composite:invalid-markdown-context")
        elif mode == "broad" and "clock_drift" in names:
            contextual.append("trait:clock-drift")

    return bool(high), high, contextual


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--mode", choices=["strict", "broad"], default="strict")
    ap.add_argument("--output", type=Path, default=Path("sentry-event-analysis.csv"))
    args = ap.parse_args()

    rows = []
    total = 0
    for file in args.files:
        for event in load_events(file):
            total += 1
            is_high, high, contextual = analyze(event, args.mode)
            if is_high or (args.mode == "broad" and contextual):
                user_id, user_ip = event_user(event)
                rows.append({
                    "source_file": str(file),
                    "event_id": event.get("event_id", ""),
                    "project": event.get("project", ""),
                    "datetime": event.get("datetime", event.get("timestamp", "")),
                    "title": event.get("title", ""),
                    "platform": event.get("platform", ""),
                    "sdk": json.dumps(event.get("sdk", {}), sort_keys=True),
                    "user": user_id,
                    "user_ip": user_ip,
                    "severity": "high" if is_high else "contextual",
                    "reasons": "; ".join(high + contextual),
                })

    with args.output.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["source_file", "event_id", "project", "datetime", "title", "platform", "sdk", "user", "user_ip", "severity", "reasons"])
        w.writeheader()
        w.writerows(rows)

    high_count = sum(1 for r in rows if r["severity"] == "high")
    print(f"mode={args.mode} events_seen={total} high_events={high_count} reported_events={len(rows)} output={args.output}")
    return 2 if high_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
