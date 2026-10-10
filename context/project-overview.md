# SentinelScan — Project Overview

## Overview

SentinelScan is an existing local Flask/SQLite application for authorized website
and GitHub source security assessments. It helps a developer inspect evidence,
prioritize findings, review remediation, and track results over time. It is an
academic assessment tool, not a security certification or proof of exploitability.

## Goals

1. Produce bounded, evidence-backed findings with explicit uncertainty.
2. Make the affected source and next remediation action easy to understand.
3. Preserve scan history, triage and reports across application restarts.
4. Measure detection changes honestly without rewriting evaluation ground truth.

## Core User Flow

1. Choose an authorized website or GitHub repository/branch (URL entry supported).
2. Optionally connect GitHub for repositories permitted by the user's token.
3. Run a bounded scan and inspect module coverage, errors and findings.
4. Open a finding: review evidence, confidence and its unified Recommendation.
5. Copy and review recommendations; implement changes outside SentinelScan.
6. Re-scan, compare results, verify remediation, update status and export reports.

## Features

- Website DAST; repository SAST, secrets, configuration and dependency checks.
- Optional local Semgrep/CodeQL and operator-enabled automatic local Ollama refinement after new scans.
- SQLite-backed dashboard, finding filters/status, scan history, comparison and trends.
- HTML/JSON/CSV reports; source context, suggested fixes, read-only recommendation viewer.

## Scope

Maintain this single application incrementally. Preserve existing integrations and
user data. New features/phases require a user request. Out of scope by default:
repository execution/builds, credential testing, automatic exploitation, automatic
patch application/merge, invented backend fixes for DAST, and a frontend stack rewrite.
Multi-user hosting/authentication is not an implemented product assumption.

## Success Criteria

- Existing scan and management flows work with AI disabled.
- Findings preserve redaction, provenance, uncertainty and human review.
- Changed detection has vulnerable, safe and protected regression examples.
- Tests use isolated data; measured limitations remain visible in documentation.
