# Sentry Forged-Event npm Typosquat IOCs — June 2026

This repository contains public IOCs, detection tooling, and a shareable report for an observed malicious npm typosquat / prompt-injection campaign based on forged Sentry issue messages to induce responders or AI agents to run fake Sentry profiling diagnostics.

No malware samples are included in this repository.

## Scope and attribution note

This repository is **not** a general detector for all Sentry abuse, all npm typosquatting, or all prompt-injection campaigns. It detects the specific IOCs and event traits we observed in this campaign cluster. There may be other threat actors conducting similar campaigns that we have not seen and thus are not included in this report.

This is not a supply chain attack and a Sentry account does **not** need to be compromised for this kind of abuse to occur. The mechanism at play is abuse of normal Sentry event ingestion using a public browser DSN/client key: an attacker can submit crafted events that make Sentry display malicious remediation text. Browser DSNs are commonly exposed by design, which creates an observability-channel prompt-injection/social-engineering path even when the Sentry service and account controls are functioning as designed.

By abusing this channel for common production logging systems, a malicious actor can attempt to social engineer (or prompt inject) an internal user or agent to steal credentials and laterally move throughout a target environment.

## Summary

Observed malicious commands:

```bash
⚠️ MALICIOUS: npx @⚠️sentry-internals/profiling-node --diagnose
⚠️ MALICIOUS: npx @⚠️sentry-browser-sdk/profiling-node --diagnose
```

Do **not** run these commands. The investigated package exfiltrated environment and development-context data to attacker-controlled infrastructure.

Concise timeline, Central European local time on 2026-06-03:

```text
12:27  @sentry-internals/profiling-node@1.0.0 published to npm
13:50  Malicious Sentry issue/event detected
14:28  Report sent to npm
14:48  Report sent to Sentry
```

The main public report is here:

```text
reports/npm-public-report-sentry-profiling-typosquat.md
```

## Contents

```text
iocs-strict.txt       High-confidence IOCs suitable for low-noise hunting.
iocs-contextual.txt   Weak/contextual strings for enrichment only.
tools/scan_iocs.py    Low-false-positive fixed-string IOC scanner.
tools/analyze_sentry_events.py  Sentry event JSON/JSONL analyzer.
reports/              Public shareable report.
```

## Recommended usage

### Scan logs, repos, shell histories, CI output, proxy/DNS exports

```bash
python3 tools/scan_iocs.py /path/to/logs /path/to/repo \
  --output ioc-scan-results.csv \
  --hash-matches
```

The scanner defaults to strict mode. It reports only high-confidence indicators or strong combinations.

Exit codes:

- `0` — no high-confidence matches
- `2` — high-confidence matches found

### Broad exploratory scan

Use broad mode only when you want enrichment and can tolerate noise:

```bash
python3 tools/scan_iocs.py /path/to/logs \
  --mode broad \
  --output ioc-scan-results-broad.csv
```

### Analyze Sentry event exports

The Sentry analyzer accepts a single JSON object, a JSON array, or JSONL:

```bash
python3 tools/analyze_sentry_events.py sentry-events.jsonl \
  --output sentry-event-analysis.csv
```

Broad mode is available for exploratory review:

```bash
python3 tools/analyze_sentry_events.py sentry-events.jsonl \
  --mode broad \
  --output sentry-event-analysis-broad.csv
```

## IOC philosophy

`iocs-strict.txt` contains indicators that should be low-noise in most environments: malicious package names, exact dangerous commands, known exfiltration infrastructure, distinctive malware HTTP headers, known event IDs, and known hashes.

`iocs-contextual.txt` contains strings that should **not** alert by themselves. They are useful only as enrichment or as part of composite detections.

## Safety

This repository intentionally excludes captured package tarballs, extracted package files, and any other malware samples. The tooling only reads files as text and does not execute package code.

If you discover execution of the malicious packages in your environment, assume environment variables visible to that process may have been exposed and rotate relevant credentials.
