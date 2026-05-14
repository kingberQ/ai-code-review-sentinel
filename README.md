# AI Code Review Sentinel

AI-first code review guardrails for remote engineering teams that want faster, more consistent review notes without handing all judgment to a model.

The CLI reads a unified git diff and returns structured findings. It has two layers: deterministic risk scanning that needs no API key, and optional OpenAI-compatible LLM review when `OPENAI_API_KEY` is configured.

## Problem

Code review automation becomes risky when every finding depends on a model. The useful pattern is to keep deterministic checks for known hazards, then let an LLM add context only inside a controlled review boundary.

This project demonstrates that split: predictable rules for common backend/security risks, optional AI review for explanation and prioritization, and Markdown or JSON output for humans, agents, or CI jobs.

## What It Demonstrates

- Deterministic scanning of unified git diffs
- Optional OpenAI-compatible review layer
- Markdown output for pull request comments
- JSON output for agents and CI consumption
- Checks for secrets, shell execution, SQL concatenation, auth bypasses, unsafe TLS, unsafe deserialization, prompt-injection-sensitive paths, and risky backend changes without tests
- A small review surface that can be inspected, extended, and wired into team workflows

## Quick Start

```bash
npm test
npm run demo
npm run demo:json
```

Scan a real diff:

```bash
git diff main...HEAD | node src/review.mjs --stdin
```

Run with an OpenAI-compatible model:

```bash
OPENAI_API_KEY=... \
OPENAI_MODEL=gpt-4.1-mini \
node src/review.mjs examples/sample.diff --ai
```

Optional provider variables:

```text
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-4.1-mini
```

## Output Modes

- Default: Markdown findings suitable for PR comments
- `--json`: structured findings for agents, dashboards, or CI gates
- `--ai`: deterministic scan plus optional LLM review

## Where This Fits

This pattern is useful for teams that need lightweight engineering quality gates:

- Remote teams that want consistent first-pass review notes
- Small teams without a dedicated security reviewer on every PR
- CI checks for risky backend or automation changes
- AI-assisted review workflows where deterministic guardrails should run before model commentary
- Internal agent workflows that need machine-readable risk findings

## Extension Ideas

- Add repository-specific rule packs
- Add severity thresholds for failing CI
- Add SARIF or GitHub annotations output
- Add Java/Spring Boot specific checks for risky controller, SQL, auth, and config changes
- Track findings over time for team quality metrics
- Combine with an LLM eval harness to test review prompt regressions

## Related Work

This repo is part of my public AI automation portfolio. More context: [GitHub profile](https://github.com/kingberQ) and [LinkedIn](https://www.linkedin.com/in/kingberq/).
