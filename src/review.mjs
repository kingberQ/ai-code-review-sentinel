#!/usr/bin/env node
import fs from "node:fs/promises";
import process from "node:process";
import { pathToFileURL } from "node:url";

const RULES = [
  {
    id: "hardcoded-secret",
    severity: "high",
    title: "Hardcoded secret or credential",
    test: /(?:api[_-]?key|secret|token|password|private[_-]?key)\s*[:=]\s*["'][^"']{8,}["']/i,
    suggestion: "Move secrets to a secret manager or environment variable and rotate the exposed value.",
  },
  {
    id: "shell-exec",
    severity: "high",
    title: "Shell execution introduced",
    test: /(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder|child_process|execSync|spawn\()/,
    suggestion: "Avoid shell execution or strictly validate arguments and isolate permissions.",
  },
  {
    id: "sql-concat",
    severity: "high",
    title: "Raw SQL string concatenation",
    test: /(?:select|insert|update|delete)\s+.+["']\s*\+/i,
    suggestion: "Use parameterized queries or prepared statements.",
  },
  {
    id: "auth-bypass",
    severity: "high",
    title: "Possible authentication or authorization bypass",
    test: /(?:debug|backdoor|bypass|findAdmin|isAdmin\s*=\s*true|return\s+true)/i,
    suggestion: "Remove debug bypasses and add authorization regression tests.",
  },
  {
    id: "sensitive-log",
    severity: "medium",
    title: "Sensitive data logged",
    test: /(?:log\.|logger\.|console\.log).*(?:password|token|secret|privateKey)/i,
    suggestion: "Remove sensitive values from logs and keep only non-sensitive request metadata.",
  },
  {
    id: "tls-disabled",
    severity: "high",
    title: "TLS verification disabled",
    test: /(?:rejectUnauthorized\s*:\s*false|setHostnameVerifier|TrustAll|InsecureTrust)/i,
    suggestion: "Keep certificate and hostname verification enabled.",
  },
  {
    id: "unsafe-deserialization",
    severity: "high",
    title: "Unsafe deserialization surface",
    test: /(?:ObjectInputStream|readObject\(|pickle\.loads|yaml\.load\()/,
    suggestion: "Use safe parsers and explicit schemas for untrusted input.",
  },
  {
    id: "prompt-injection-surface",
    severity: "medium",
    title: "Prompt-injection sensitive path",
    test: /(?:systemPrompt|tool_call|function_call|evalPrompt|executeTool)/i,
    suggestion: "Treat model output as untrusted and validate tool arguments before side effects.",
  },
];

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = parseArgs(process.argv.slice(2));
  const diff = await readDiff(args);
  const ruleReport = scanDiff(diff);
  const aiReport = args.ai ? await runAiReview(diff) : null;
  const report = mergeReports(ruleReport, aiReport);

  if (args.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(toMarkdown(report));
  }
}

function parseArgs(argv) {
  const parsed = { _: [], json: false, stdin: false, ai: false };
  for (const arg of argv) {
    if (arg === "--json") parsed.json = true;
    else if (arg === "--stdin") parsed.stdin = true;
    else if (arg === "--ai") parsed.ai = true;
    else parsed._.push(arg);
  }
  return parsed;
}

async function readDiff(parsed) {
  if (parsed.stdin || parsed._.length === 0) {
    return await readStdin();
  }
  return await fs.readFile(parsed._[0], "utf8");
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

export function scanDiff(diff) {
  const findings = [];
  let currentFile = "unknown";
  let currentLine = 0;

  for (const line of diff.split(/\r?\n/)) {
    if (line.startsWith("+++ b/")) {
      currentFile = line.slice("+++ b/".length);
      continue;
    }
    if (line.startsWith("@@")) {
      const match = /\+(\d+)/.exec(line);
      currentLine = match ? Number(match[1]) - 1 : currentLine;
      continue;
    }
    if (line.startsWith("+") && !line.startsWith("+++")) {
      currentLine += 1;
      const added = line.slice(1);
      for (const rule of RULES) {
        if (rule.test.test(added)) {
          findings.push({
            source: "rules",
            ruleId: rule.id,
            severity: rule.severity,
            file: currentFile,
            line: currentLine,
            title: rule.title,
            evidence: added.trim().slice(0, 240),
            suggestion: rule.suggestion,
          });
        }
      }
    } else if (!line.startsWith("-")) {
      currentLine += 1;
    }
  }

  return {
    mode: "rules",
    riskScore: scoreFindings(findings),
    summary: summarize(findings),
    findings,
    recommendedTests: recommendTests(findings),
  };
}

function scoreFindings(findings) {
  const weights = { high: 30, medium: 12, low: 5 };
  return Math.min(100, findings.reduce((sum, finding) => sum + weights[finding.severity], 0));
}

function summarize(findings) {
  if (findings.length === 0) return "No high-signal risks found by deterministic rules.";
  const high = findings.filter((item) => item.severity === "high").length;
  const medium = findings.filter((item) => item.severity === "medium").length;
  return `${findings.length} finding(s): ${high} high, ${medium} medium.`;
}

function recommendTests(findings) {
  const tests = new Set();
  for (const finding of findings) {
    if (finding.ruleId === "auth-bypass") tests.add("Add authorization regression tests for privileged paths.");
    if (finding.ruleId === "sql-concat") tests.add("Add SQL injection test cases around changed query inputs.");
    if (finding.ruleId === "shell-exec") tests.add("Add command argument validation tests and sandbox checks.");
    if (finding.ruleId === "prompt-injection-surface") tests.add("Add prompt-injection and tool-argument validation tests.");
  }
  return [...tests];
}

async function runAiReview(diff) {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    return {
      mode: "ai",
      summary: "AI review skipped because OPENAI_API_KEY is not set.",
      findings: [],
      recommendedTests: [],
    };
  }

  const baseUrl = process.env.OPENAI_BASE_URL ?? "https://api.openai.com/v1";
  const model = process.env.OPENAI_MODEL ?? "gpt-4.1-mini";
  const system = await fs.readFile(new URL("../prompts/code-review.md", import.meta.url), "utf8");
  const response = await fetch(`${baseUrl}/chat/completions`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${apiKey}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      model,
      temperature: 0,
      messages: [
        { role: "system", content: system },
        { role: "user", content: diff.slice(0, 60000) },
      ],
    }),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`AI review failed: ${response.status} ${text}`);
  }

  const body = await response.json();
  const content = body.choices?.[0]?.message?.content ?? "{}";
  return parseAiJson(content);
}

function parseAiJson(content) {
  const jsonText = content.replace(/^```json\s*/i, "").replace(/```$/i, "").trim();
  try {
    const parsed = JSON.parse(jsonText);
    return {
      mode: "ai",
      summary: parsed.summary ?? "AI review completed.",
      findings: Array.isArray(parsed.findings) ? parsed.findings : [],
      recommendedTests: Array.isArray(parsed.recommendedTests) ? parsed.recommendedTests : [],
    };
  } catch {
    return {
      mode: "ai",
      summary: "AI review returned non-JSON content.",
      findings: [{
        source: "ai",
        severity: "low",
        title: "Non-JSON AI output",
        detail: content.slice(0, 1000),
      }],
      recommendedTests: [],
    };
  }
}

function mergeReports(ruleReport, aiReport) {
  if (!aiReport) return ruleReport;
  const findings = [...ruleReport.findings, ...aiReport.findings.map((item) => ({ source: "ai", ...item }))];
  return {
    mode: "rules+ai",
    riskScore: scoreFindings(findings),
    summary: `${ruleReport.summary} AI: ${aiReport.summary}`,
    findings,
    recommendedTests: [...new Set([...ruleReport.recommendedTests, ...aiReport.recommendedTests])],
  };
}

function toMarkdown(report) {
  const lines = [
    "# AI Code Review Sentinel",
    "",
    `Mode: ${report.mode}`,
    `Risk score: ${report.riskScore}/100`,
    "",
    report.summary,
    "",
    "## Findings",
    "",
  ];

  if (report.findings.length === 0) {
    lines.push("No findings.");
  } else {
    for (const finding of report.findings) {
      lines.push(`- **${finding.severity?.toUpperCase?.() ?? "INFO"}** ${finding.file ?? "unknown"}:${finding.line ?? "?"} - ${finding.title}`);
      if (finding.evidence) lines.push(`  - Evidence: \`${finding.evidence.replaceAll("`", "'")}\``);
      if (finding.detail) lines.push(`  - Detail: ${finding.detail}`);
      if (finding.suggestion) lines.push(`  - Suggestion: ${finding.suggestion}`);
    }
  }

  if (report.recommendedTests.length > 0) {
    lines.push("", "## Recommended Tests", "");
    for (const test of report.recommendedTests) lines.push(`- ${test}`);
  }

  return lines.join("\n");
}
