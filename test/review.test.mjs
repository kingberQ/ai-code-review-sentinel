import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { scanDiff } from "../src/review.mjs";

const diff = await fs.readFile(new URL("../examples/sample.diff", import.meta.url), "utf8");
const report = scanDiff(diff);

assert.equal(report.mode, "rules");
assert.ok(report.riskScore >= 70, `expected high risk score, got ${report.riskScore}`);
assert.ok(report.findings.some((item) => item.ruleId === "auth-bypass"));
assert.ok(report.findings.some((item) => item.ruleId === "sensitive-log"));
assert.ok(report.findings.some((item) => item.ruleId === "sql-concat"));
assert.ok(report.findings.some((item) => item.ruleId === "hardcoded-secret"));
assert.ok(report.findings.some((item) => item.ruleId === "shell-exec"));
assert.ok(report.recommendedTests.length >= 2);

console.log("review.test.mjs passed");
