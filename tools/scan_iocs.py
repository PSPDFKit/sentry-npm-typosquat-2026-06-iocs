#!/usr/bin/env python3
"""Low-false-positive IOC scanner for the Sentry npm typosquat investigation.

Default behavior is STRICT: it reports only high-confidence indicators or
high-confidence combinations. Contextual strings are used only for enrichment
unless --mode broad is selected.

Safe to run: this script only reads files as text and does not execute samples.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import os
from pathlib import Path

DEFAULT_SKIP_DIRS = {
    ".git", "node_modules", ".pnpm-store", "vendor", "build", "dist", ".next",
    "target", "DerivedData", ".terraform", ".venv", "venv", "__pycache__",
}

TEXT_EXT_ALLOW = {
    ".txt", ".log", ".json", ".jsonl", ".csv", ".tsv", ".md", ".yaml", ".yml",
    ".xml", ".html", ".htm", ".js", ".ts", ".tsx", ".jsx", ".py", ".rb",
    ".sh", ".bash", ".zsh", ".fish", ".ex", ".exs", ".tf", ".tpl", ".conf",
    ".ini", ".env", ".out", ".err", ".har",
}

# Standalone hits that are specific enough to report directly.
DIRECT_STRICT = {
    "package:sentry-internals": "@sentry-internals/profiling-node",
    "package:sentry-browser-sdk": "@sentry-browser-sdk/profiling-node",
    "command:sentry-internals-diagnose": "npx @sentry-internals/profiling-node --diagnose",
    "command:sentry-browser-sdk-diagnose": "npx @sentry-browser-sdk/profiling-node --diagnose",
    "domain:advisory-tracker.com": "advisory-tracker.com",
    "url:advisory-tracker-telemetry": "https://advisory-tracker.com/api/v1/telemetry",
    "ip:advisory-tracker-observed-a": "52.206.47.180",
    "event:fef0ad8b5e374b92a3098ae126d57ce3": "fef0ad8b5e374b92a3098ae126d57ce3",
    "event:ff3323c0ff3a4b1884329049b8287f06": "ff3323c0ff3a4b1884329049b8287f06",
    "hash:tarball-sentry-internals-1.0.0": "1b49e894c20b74f3fb74f5bb2bceeeea7fe3c0b686da2da12d6ca6bbaa9aa9e8",
    "hash:cli-js-sentry-internals-1.0.0": "f48c208242193ed47694fba8584b1c43227300882d2aaa75bd45e93706e2fcca",
    "hash:package-json-sentry-internals-1.0.0": "9d26efaab8869aeaa74777cb5dd973442520b5458a43f2eabef91abc0545dc96",
}

# These are not reported alone in strict mode. They become findings only through
# composite rules below, or in --mode broad.
CONTEXTUAL = {
    "ua:profiling-node": "profiling-node/1.0.0",
    "header:x-tenet-security": "X-Tenet-Security",
    "header-value:responsible-disclosure": "ResponsibleDisclosure [SECURITY SCAN]",
    "path:generic-telemetry": "/api/v1/telemetry",
    "msg:sentry-profiling-misconfigured": "[NO CODE FIX] Sentry profiling misconfigured",
    "msg:sentry-profiling-short": "Sentry profiling misconfigured",
    "tag:allowed_bash_commands": "allowed_bash_commands",
    "tag:diagnostic_tool": "diagnostic_tool",
    "tag:filesystem_access": "filesystem_access",
    "tag:fix_type": "fix_type",
    "tag:run_tool_first": "run_tool_first",
    "tag:profiling_misconfiguration": "profiling_misconfiguration",
    "user:internal-monitor-1": "internal-monitor-1",
    "user:internal-monitor-2": "internal-monitor-2",
    "issue:7523964476": "7523964476",
}

# Composite rules are evaluated per line and per whole file. A finding reports
# when all terms in a rule are present in the same scope.
COMPOSITE_RULES = {
    "http-header-pair:x-tenet-responsible-disclosure": [
        "X-Tenet-Security", "ResponsibleDisclosure [SECURITY SCAN]",
    ],
    "malware-http-client-to-c2": [
        "profiling-node/1.0.0", "advisory-tracker.com",
    ],
    "generic-telemetry-path-with-c2": [
        "/api/v1/telemetry", "advisory-tracker.com",
    ],
    "sentry-agent-prompt-tags": [
        "allowed_bash_commands", "diagnostic_tool", "run_tool_first",
    ],
    "fake-sentry-healthcheck-profile": [
        "Sentry profiling misconfigured", "profiling_misconfiguration", "health-check",
    ],
    "fake-sentry-message-with-npx": [
        "Sentry profiling misconfigured", "npx", "--diagnose",
    ],
}


def load_extra_iocs(path: Path | None) -> list[str]:
    if not path:
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return sorted(set(out), key=len, reverse=True)


def should_skip(path: Path, include_all: bool) -> bool:
    return False if include_all else any(part in DEFAULT_SKIP_DIRS for part in path.parts)


def iter_files(roots: list[Path], include_all: bool):
    for root in roots:
        if root.is_file():
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            p = Path(dirpath)
            if should_skip(p, include_all):
                dirnames[:] = []
                continue
            if not include_all:
                dirnames[:] = [d for d in dirnames if d not in DEFAULT_SKIP_DIRS]
            for name in filenames:
                yield p / name


def is_probably_text(path: Path, include_binary: bool) -> bool:
    if include_binary or path.suffix == ".gz" or path.suffix.lower() in TEXT_EXT_ALLOW:
        return True
    return path.name.startswith(".")


def read_lines(path: Path, max_bytes: int):
    try:
        if path.stat().st_size > max_bytes:
            return None, f"skipped_size>{max_bytes}"
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
                return f.readlines(), None
        with open(path, "rt", encoding="utf-8", errors="replace") as f:
            return f.readlines(), None
    except Exception as e:
        return None, f"read_error:{type(e).__name__}:{e}"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def add_row(rows, path, line, kind, indicator, preview, severity, file_hash=""):
    rows.append({
        "path": str(path),
        "line": line,
        "severity": severity,
        "kind": kind,
        "indicator": indicator,
        "preview": preview.strip()[:500],
        "sha256": file_hash,
    })


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan files/directories for campaign IOCs with strict or broad matching")
    ap.add_argument("paths", nargs="+", type=Path)
    ap.add_argument("--mode", choices=["strict", "broad"], default="strict", help="strict minimizes false positives; broad reports contextual terms too")
    ap.add_argument("--extra-iocs", type=Path, help="optional extra fixed strings; reported as strict direct indicators")
    ap.add_argument("--output", type=Path, default=Path("ioc-scan-results.csv"))
    ap.add_argument("--include-all", action="store_true")
    ap.add_argument("--include-binary", action="store_true")
    ap.add_argument("--max-bytes", type=int, default=50 * 1024 * 1024)
    ap.add_argument("--hash-matches", action="store_true")
    args = ap.parse_args()

    direct = dict(DIRECT_STRICT)
    for idx, s in enumerate(load_extra_iocs(args.extra_iocs), start=1):
        direct[f"extra:{idx}"] = s

    rows = []
    scanned = skipped = errors = 0

    for path in iter_files(args.paths, args.include_all):
        if not path.exists() or not path.is_file():
            continue
        if not is_probably_text(path, args.include_binary):
            skipped += 1
            continue
        lines, err = read_lines(path, args.max_bytes)
        if err:
            skipped += 1
            if err.startswith("read_error"):
                errors += 1
            continue
        scanned += 1
        assert lines is not None
        file_hash = None
        file_text = "".join(lines)
        file_reported_composites = set()

        def maybe_hash():
            nonlocal file_hash
            if args.hash_matches and file_hash is None:
                try:
                    file_hash = sha256_file(path)
                except Exception:
                    file_hash = ""
            return file_hash or ""

        for lineno, line in enumerate(lines, start=1):
            for kind, s in direct.items():
                if s in line:
                    add_row(rows, path, lineno, kind, s, line, "high", maybe_hash())
            if args.mode == "broad":
                for kind, s in CONTEXTUAL.items():
                    if s in line:
                        add_row(rows, path, lineno, kind, s, line, "contextual", maybe_hash())
            for rule, terms in COMPOSITE_RULES.items():
                if all(t in line for t in terms):
                    add_row(rows, path, lineno, f"composite:{rule}", " AND ".join(terms), line, "high", maybe_hash())
                    file_reported_composites.add(rule)

        # Whole-file composite catches JSON events/logs where terms appear on separate lines.
        for rule, terms in COMPOSITE_RULES.items():
            if rule not in file_reported_composites and all(t in file_text for t in terms):
                preview = "; ".join(t for t in terms)
                add_row(rows, path, 0, f"file-composite:{rule}", " AND ".join(terms), preview, "high", maybe_hash())

    with args.output.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["path", "line", "severity", "kind", "indicator", "preview", "sha256"])
        w.writeheader()
        w.writerows(rows)

    high = sum(1 for r in rows if r["severity"] == "high")
    contextual = len(rows) - high
    print(f"mode={args.mode} scanned_files={scanned} skipped_files={skipped} read_errors={errors} high_matches={high} contextual_matches={contextual} output={args.output}")
    return 2 if high else 0


if __name__ == "__main__":
    raise SystemExit(main())
