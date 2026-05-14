# AI Code Review Sentinel

AI-first code review guardrail for remote engineering teams.

The CLI reviews a unified git diff and returns structured findings. It works in
two modes:

- deterministic rule scan, no API key required
- optional OpenAI-compatible LLM review when `OPENAI_API_KEY` is configured

The goal is not to replace human review. The goal is to catch risky changes
early, produce consistent review notes, and give an AI reviewer a safe,
structured boundary.

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

## Checks

- hardcoded secrets and private keys
- shell execution and process spawning
- raw SQL string concatenation
- auth bypass and debug backdoors
- disabled TLS or certificate verification
- unsafe deserialization
- prompt-injection sensitive code paths
- missing tests for risky backend changes

## Output

Default output is Markdown for pull request comments. Use `--json` for agent or
CI consumption.

```bash
node src/review.mjs examples/sample.diff --json
```

## Why This Exists

AI code review is useful only when the model has guardrails. This project keeps
the deterministic safety checks separate from the optional model call, so teams
can run the same baseline checks in CI and use LLM review as an additional layer.
