# Security Gate Architecture

This document explains how the **Enterprise Security Gate** fits into the
existing GitHub Actions pipeline for the Employee Management service,
how it makes its PASS/FAIL decision, and how to extend it with new
scanners.

---

## 1. Why a separate Security Gate?

A pipeline with multiple independent scanners (CodeQL, Trivy, NVIDIA)
makes it hard to answer one question:

> **"Are we allowed to deploy this build?"**

Each tool has its own severity vocabulary, its own report format, and
its own ideas about "blocking". A naive `if failure()` per job means
the deploy step is only as strict as the *most lenient* scanner. The
Security Gate is a single, auditable point of decision that:

- **Normalises** scanner output to a common shape (`Finding`).
- **Evaluates** a single, versioned policy (`SecurityPolicy`).
- **Fails fast**: a non-zero exit blocks the deploy job.
- **Surfaces** a single human-readable summary
  (`SECURITY_GATE_REPORT.md`) for review.

---

## 2. Pipeline flow

```
┌────────┐    ┌─────────┐    ┌────────┐    ┌──────────────┐
│ build  │──▶│ codeql  │──▶ │ trivy  │──▶ │ nvidia-sec-  │
└────────┘    └─────────┘    └────────┘    │ agent        │
                                            └──────┬───────┘
                                                   │
                            ┌──────────────────────┼──────────────────────┐
                            ▼                      ▼                      ▼
                  codeql-results.sarif   trivy-report.json     security-report.json
                            │                      │                      │
                            └────────────┬─────────┴──────────────────────┘
                                         ▼
                            ┌────────────────────────┐
                            │    security-gate       │   ← runs the Java utility
                            │    (com.enterprise.    │      SecurityGate.java
                            │     securitygate)      │
                            └────────────┬───────────┘
                                         │
                            PASS / FAIL (exit 0 / 1)
                                         │
                                         ▼
                            ┌────────────────────────┐
                            │       deploy           │   ← needs security-gate
                            └────────────────────────┘
```

The `security-gate` job is declared with:

```yaml
needs: [codeql, trivy-scan, nvidia-security-agent]
```

and the `deploy` job is declared with:

```yaml
needs: [..., security-gate]
if: |
  ...
  needs.security-gate.result == 'success'
```

so the deploy step cannot run unless the gate succeeds.

---

## 3. Components

### 3.1 Java utility (`com.enterprise.securitygate`)

| Class                     | Role                                                                |
|---------------------------|---------------------------------------------------------------------|
| `SecurityGate`            | CLI entry point. Parses args, loads files, runs policy, exits 0/1. |
| `SecurityPolicy`          | Pure function `(List<Finding>) -> Decision`. Encodes the rules.     |
| `CodeQlSarifParser`       | Reads CodeQL SARIF v2.1, emits `Finding.Source.CODEQL` items.       |
| `TrivyJsonParser`         | Reads Trivy JSON, emits `Finding.Source.TRIVY` items.               |
| `NvidiaJsonParser`        | Reads NVIDIA `security-report.json`, emits `Finding.Source.NVIDIA`. |
| `ReportWriter`            | Renders `SECURITY_GATE_REPORT.md`.                                  |
| `JsonSummaryWriter`       | Renders `security-gate.json`.                                       |
| `Severity` / `Finding`    | Shared domain model.                                                |

The utility lives in the same Maven module as the application. The
workflow compiles it via `mvn compile` and runs it via
`java -cp target/classes …`. No additional build step is required.

### 3.2 Updated NVIDIA Security Agent

`scripts/security-agent.py` now writes **two** outputs:

- `reports/security-report.md` — human-readable Markdown triage (existing).
- `reports/security-report.json` — structured findings with the exact
  schema the Security Gate consumes. The schema matches the
  specification in the task brief:

  ```json
  {
    "status": "PASS",
    "critical": 0,
    "high": 2,
    "medium": 8,
    "riskScore": 32,
    "summary": "...",
    "recommendations": [ "..." ]
  }
  ```

### 3.3 Workflow glue

The new `security-gate` job in `.github/workflows/employee-pipeline.yml`:

1. Downloads the `codeql-sarif`, `trivy-reports`, and
   `nvidia-security-report` artifacts.
2. Compiles the Security Gate utility (`mvn -DskipTests compile`).
3. Runs `java … com.enterprise.securitygate.SecurityGate …`.
4. Uploads `SECURITY_GATE_REPORT.md` and `security-gate.json` as the
   `security-gate-report` artifact (90-day retention).
5. Exits non-zero on FAIL, which:
   - Marks the job red in the GitHub UI.
   - Cascades into the `deploy` job's `if:` predicate, so deploy
     is skipped.

---

## 4. Policy evaluation logic

### 4.1 Normalisation

Every parser emits `Finding` records with the same fields:

```
source       = CODEQL | TRIVY | NVIDIA
severity     = CRITICAL | HIGH | MEDIUM | LOW | INFO
category     = "sql-injection", "secret", "vuln", "rce", ...
ruleId       = "CVE-2024-12086", "java/sql-injection", ...
packageName  = "jackson-databind@2.17.1"
fix          = "2.17.2"   // best-effort remediation hint
description  = "DoS via deeply nested JSON"
```

Dedup is then applied on
`(source, severity, category, ruleId, packageName)`.

### 4.2 Rules

The default policy (in `SecurityPolicy.Builder`) implements the rules
from the task brief.

| Source  | Rule |
|---------|------|
| CodeQL  | Any **CRITICAL** ⇒ FAIL. |
| CodeQL  | Any **HIGH** whose category contains `rce`, `remote-code-execution`, `code-execution`, or `command-injection` ⇒ FAIL. |
| CodeQL  | Any finding whose category contains `sql-injection`, `command-injection`, `path-traversal`, `auth-bypass`, `hardcoded-credentials`, or `hardcoded-credential` ⇒ FAIL. |
| Trivy   | `CRITICAL > 0` ⇒ FAIL. |
| Trivy   | `HIGH > 5` ⇒ FAIL. |
| Trivy   | Any **CRITICAL** that is fixable (has a non-empty `FixedVersion`) ⇒ FAIL. |
| Trivy   | Any malware / virus finding ⇒ FAIL. |
| Trivy   | Any `secret` finding ⇒ FAIL. |
| NVIDIA  | `CRITICAL > 0` or `HIGH > 5` ⇒ FAIL. |

A `--strict` flag switches the policy to a **zero-tolerance** mode
(no Critical, no High) for organisations with stricter regulatory
requirements.

### 4.3 Output

- The console gets a compact PASS/FAIL banner with the blocking
  reasons (visible in the GitHub Actions run log).
- `SECURITY_GATE_REPORT.md` is uploaded as an artifact.
- `security-gate.json` is uploaded for downstream automation.

---

## 5. How to customise thresholds

The policy is built programmatically, so you have three options.

### 5.1 Use a built-in builder method

```java
SecurityPolicy p = SecurityPolicy.builder()
    .trivyThresholds(SecurityPolicy.SeverityThresholds.of(0, 10, 50, Integer.MAX_VALUE))
    .nvidiaThresholds(SecurityPolicy.SeverityThresholds.of(0, 0, 20, Integer.MAX_VALUE))
    .ignoredRules(List.of("CVE-2024-99999"))    // suppress false positives
    .build();
```

### 5.2 Use the `--strict` CLI flag

For enterprise compliance runs:

```bash
java -cp target/classes:… \
  com.enterprise.securitygate.SecurityGate \
  --codeql codeql-results.sarif --trivy trivy-report.json --nvidia security-report.json \
  --strict
```

### 5.3 Add organisation-specific policy knobs

Edit `SecurityPolicy.Builder` to add new fields (e.g.
`sonarBlockOnLongMethods`, `owaspBlockOnCvssAbove(double)`). The
policy is a single class with no external dependencies, so PRs
are small and reviewable.

---

## 6. How to add a new scanner

The gate is designed to be **scanner-agnostic**. To add e.g.
SonarQube, OWASP Dependency-Check, or Gitleaks:

1. **Add a parser** under `com.enterprise.securitygate`:
   ```java
   public final class SonarQubeJsonParser {
       public List<Finding> parse(Path json) throws IOException { … }
   }
   ```
2. **Use an existing `Finding.Source`** (`CODEQL`, `TRIVY`,
   `NVIDIA`) or add a new enum value. New values do not affect
   existing policies.
3. **In the workflow**, upload the scanner's report as an artifact
   in its own job.
4. **In `SecurityGate.main`**, add:
   ```java
   findings.addAll(new SonarQubeJsonParser().parse(parsed.sonar));
   ```
5. **Optionally** add a scanner-specific threshold in
   `SecurityPolicy.Builder` and reference it from `evaluate`.

The `Finding` model intentionally separates `category` (semantic
type — e.g. `sql-injection`) from `ruleId` (the scanner-specific
identifier). That makes "block on category X across all scanners"
trivially expressible in `SecurityPolicy` without coupling the
policy to a particular scanner.

---

## 7. Operational notes

- The gate exits with code `1` on FAIL, which is the GitHub Actions
  convention for blocking downstream jobs.
- The gate runs **even if its `needs:` jobs are skipped** because of
  `if: always()` — this is required for the gate to be the final
  authority. A scanned job that was skipped still has to clear the
  policy (with no findings, since the report is missing).
- The gate is **stateless**. It does not write to the GitHub
  repository, push commits, or open PRs. All state changes (e.g.
  pushing a comment on a PR) should be done by *separate* steps
  added to the gate job, not by the Java utility.
- The 90-day retention on `security-gate-report` is intentional:
  audit teams need access to historical gate decisions.

---

## 8. Files added or changed

| Path | Change |
|---|---|
| `.github/workflows/employee-pipeline.yml` | Added `security-gate` job, gated `deploy`, added CodeQL SARIF artifact, updated NVIDIA agent step to emit JSON. |
| `scripts/security-agent.py` | Now emits `security-report.json` alongside the Markdown. |
| `src/main/java/com/enterprise/securitygate/*.java` | New Security Gate Java utility (8 classes). |
| `src/test/java/com/enterprise/securitygate/SecurityPolicyTest.java` | Policy unit tests. |
| `reports/security-report.json` | Sample JSON output. |
| `reports/SECURITY_GATE_REPORT.md` | Sample Markdown report. |
| `docs/SECURITY_GATE.md` | This document. |
