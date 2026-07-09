# SonarQube Integration Architecture

This document explains how **SonarQube Community Edition (self-hosted)**
fits into the existing GitHub Actions pipeline for the Employee
Management service, how the Quality Gate is configured, and how to
operate the integration.

For the broader pipeline context, see [`SECURITY_GATE.md`](SECURITY_GATE.md).

---

## 1. Why SonarQube?

The pipeline already has two gates:

- **`test-coverage`** — JaCoCo, enforces 80% instruction coverage.
- **`security-gate`** — Java aggregator over CodeQL, Trivy, and NVIDIA.

Neither covers the **maintainability** axis: bugs, code smells, security
hotspots with rating < A, and per-new-code coverage on changed lines.
SonarQube fills that gap, and because it produces a single, externally
auditable PASS / FAIL decision, it is the right place to enforce the
"block on a class of issues" rules that the brief specifies.

The Quality Gate encodes all eight rules from the brief, so a single
check covers:

- Blocker and Critical issue counts.
- Security and Reliability ratings.
- New-code coverage.
- Duplication rate.
- New-bug count.

This is a **hard gate**: if the Quality Gate fails, every downstream
stage (CodeQL, Trivy, NVIDIA, Security Gate, Deploy) is skipped.

---

## 2. Pipeline flow

```
┌────────┐    ┌───────────────┐    ┌──────────────┐    ┌────────┐
│ build  │──▶ │ test-coverage │──▶ │  sonarqube   │──▶ │ codeql │
└────────┘    └───────────────┘    └──────────────┘    └────────┘
                │ JaCoCo XML         │ Quality Gate
                ▼                    │ fail ⇒ skip
          target/site/              │ downstream jobs
          jacoco/jacoco.xml         ▼
                              ┌─────────┐    ┌────────────────┐    ┌─────────┐
                              │  trivy  │──▶ │ nvidia-sec-    │──▶ │  gate   │──▶ deploy
                              └─────────┘    │ agent          │    └─────────┘
                                              └────────────────┘
```

The new `sonarqube` job is declared with:

```yaml
needs: test-coverage
```

and every downstream job (`codeql`, `trivy-scan`, `nvidia-security-agent`,
`nvidia-remediation-agent`, `security-gate`, `upload-reports`, `deploy`)
adds `sonarqube` to its `needs:`. When the SonarQube step exits
non-zero (gate failed), GitHub skips every dependent job.

---

## 3. Components

### 3.1 `sonar-project.properties`

Static, version-controlled SonarQube project configuration at the
repository root. It declares:

- `sonar.projectKey`, `sonar.projectName`, `sonar.projectDescription`
- `sonar.sources=src/main/java`, `sonar.tests=src/test/java`
- `sonar.java.binaries=target/classes`,
  `sonar.java.test.binaries=target/test-classes`
- `sonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml`
- `sonar.java.source=21`, `sonar.java.target=21`
- `sonar.sourceEncoding=UTF-8`
- Exclusions for `**/securitygate/**`, `**/dto/**`, and
  `**/*Application.java` — see the file for the rationale.

Dynamic values (`sonar.projectVersion`, `sonar.branch.name`) are
injected by the workflow as `-D` flags so the same properties file
works for any branch or commit.

### 3.2 Maven plugin (`org.sonarsource.scanner.maven:sonar-maven-plugin`)

Added to `pom.xml` under `<build><plugins>`. It has no bound
executions: the plugin is invoked only by the SonarQube workflow job
via `mvn ... sonar:sonar`. This keeps `mvn package` and `mvn verify`
unaffected.

The plugin reads `sonar-project.properties` and the project's
classpath automatically, so no special Maven configuration is needed
beyond declaring the plugin.

### 3.3 JaCoCo coverage integration

The JaCoCo `report-xml` execution in `pom.xml` already writes
`target/site/jacoco/jacoco.xml`. The SonarQube job downloads the
`coverage-reports` artifact (produced by `test-coverage`) and points
the scanner at the XML. No additional JaCoCo configuration is needed.

### 3.4 `sonarsource/sonarqube-quality-gate-action`

Official action that polls the SonarQube server for the report's
Quality Gate status and exits non-zero if the gate fails. The job's
last step uses its `conclusion` output to render a ✅ / ❌ summary
on the GitHub Actions run page.

---

## 4. Quality Gate rules

The Quality Gate is configured on the SonarQube server (UI: **Quality
Gates → Create**). For Community Edition, you create a single gate
named `Employee-Management-Prod` and set it as the default. The eight
conditions match the brief exactly:

| # | Condition (server-side) | Operator | Value | Maps to brief |
|---|---|---|---|---|
| 1 | `blocker_violations` | `>` | `0` | Blocker Issues > 0 |
| 2 | `critical_violations` | `>` | `0` | Critical Issues > 0 |
| 3 | `security_rating` | `>` | `1` | Security Rating < A (1 = A) |
| 4 | `reliability_rating` | `>` | `1` | Reliability Rating < A |
| 5 | `coverage` (new code) | `<` | `80` | Coverage < 80% |
| 6 | `duplicated_lines_density` | `>` | `3` | Duplicated Code > 3% |
| 7 | `new_bugs` | `>` | `0` | New Bugs detected |
| 8 | `new_reliability_rating` | `>` | `1` | New Reliability Rating < A |

`sonar.qualitygate.wait` is set to `true` by the
`sonarqube-quality-gate-action` so the workflow blocks until Sonar
returns a verdict, with a 300-second timeout.

---

## 5. Setup

### 5.1 Start SonarQube Community Edition with Docker

The official image is `sonarqube:community` (renamed from
`sonarqube:lts-community` in 2024). Run it once to bring the server
up:

```bash
docker run -d --name sonarqube \
  -p 9000:9000 \
  -v sonarqube_data:/opt/sonarqube/data \
  -v sonarqube_logs:/opt/sonarqube/logs \
  -v sonarqube_extensions:/opt/sonarqube/extensions \
  sonarqube:community
```

Wait for `http://localhost:9000` to become responsive. The default
credentials are `admin` / `admin`; the UI prompts you to rotate the
admin password on first login.

For production, put SonarQube behind a reverse proxy with TLS, and
restrict the network to the GitHub Actions runner IPs.

### 5.2 Generate a `SONAR_TOKEN`

1. Log in to SonarQube as an administrator.
2. **My Account → Security → Generate Tokens**.
3. Name: `github-actions-employee-management`.
4. Type: **Project Analysis Token** (scoped to
   `com.enterprise:employee-management`).
5. Click **Generate**, copy the token. **It is shown only once.**

### 5.3 Configure GitHub Secrets and Variables

In the GitHub repository UI:

- **Settings → Secrets and variables → Actions → New repository secret**:
  - Name: `SONAR_TOKEN`
  - Value: the token from §5.2.
- **Settings → Secrets and variables → Actions → Variables tab →
  New repository variable**:
  - Name: `SONAR_HOST_URL`
  - Value: the URL of the SonarQube server, e.g.
    `https://sonar.example.com` (no trailing slash).

The workflow reads `vars.SONAR_HOST_URL` and `secrets.SONAR_TOKEN` and
fails fast at the first SonarQube step if either is missing.

### 5.4 Configure the Quality Gate on the server

Follow §4. Once the gate is created and set as default, every analysis
is evaluated against it.

---

## 6. Running analysis locally

You can run the same scan the CI runs:

```bash
# 1. Run tests so JaCoCo produces target/site/jacoco/jacoco.xml
mvn -B -ntp verify

# 2. Run the SonarQube scanner
mvn -B -ntp -DskipTests \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.token=$SONAR_TOKEN \
  org.sonarsource.scanner.maven:sonar-maven-plugin:3.11.0.3922:sonar
```

The scanner picks up `sonar-project.properties` from the working
directory. After it completes, browse to
`http://localhost:9000/dashboard?id=com.enterprise%3Aemployee-management`
to see the results.

---

## 7. How the gate blocks the pipeline

The mechanism is GitHub's own **job dependency graph**, not a custom
script:

1. The `sonarqube` job runs `mvn sonar:sonar`, which uploads the
   analysis to the SonarQube server.
2. The `sonarqube-quality-gate-action` step polls the server. If the
   Quality Gate status is `ERROR` or `FAILED`, the step exits with
   code `1`.
3. GitHub marks the `sonarqube` job red.
4. Every job that lists `sonarqube` in its `needs:` is **skipped**
   because its required job did not succeed.
5. The `deploy` job's `if:` predicate (which already requires
   `security-gate.result == 'success'`) is doubly guarded: it is
   skipped both because `sonarqube` failed and because
   `security-gate` is now skipped.

A single Quality Gate failure therefore short-circuits the entire
post-Sonar pipeline, exactly as the brief requires.

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `401 Unauthorized` on `mvn sonar:sonar` | `SONAR_TOKEN` is missing or wrong scope. | Regenerate a **Project Analysis Token** scoped to the project key; update the GitHub secret. |
| `Quality Gate timeout` after 300s | Runner cannot reach `SONAR_HOST_URL`. | From the runner, `curl -I $SONAR_HOST_URL`; check firewall / VPN / DNS. |
| `Coverage is 0%` in the Sonar dashboard | `target/site/jacoco/jacoco.xml` is missing or empty. | Confirm `test-coverage` ran (it uploads the artifact); the Sonar job downloads it into `target/`. |
| `Failed to query JRE metadata` | Sonar plugin < 3.11 on Java 21. | Bump `sonar.plugin.version` in `pom.xml` to 3.11.0 or newer. |
| `scanner unable to access github API` | `GITHUB_TOKEN` lacks `actions: read`. | The job already requests `actions: read` in `permissions:`; if you copy the job, copy the permissions block too. |
| `analysis is too old` warning | Push event triggered but `fetch-depth: 0` is missing. | The job already passes `fetch-depth: 0` to `actions/checkout@v4`. |
| Pipeline never reaches SonarQube | A prior job failed. | The `sonarqube` job requires `test-coverage`; check the run graph for red jobs upstream. |

---

## 9. Files added or changed

| Path | Change |
|---|---|
| `sonar-project.properties` | New — SonarQube project config. |
| `pom.xml` | Added `sonar-maven-plugin`. No existing plugin/dependency removed. |
| `.github/workflows/employee-pipeline.yml` | Added `sonarqube` job; threaded it into every downstream `needs:`. |
| `README.md` | Added SonarQube to the stack and pipeline list. |
| `.gitignore` | Added `.scannerwork/`, `target/sonar/`. |
| `docs/SONARQUBE.md` | This document. |
