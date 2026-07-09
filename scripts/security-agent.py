#!/usr/bin/env python3
"""
Trivy Security Agent (Agent 2) - Reads Trivy JSON report and produces
  * security-report.md   - human-readable Markdown triage
  * security-report.json - structured findings consumed by the Security Gate

The JSON is the contract for the Security Gate job. Its schema is fixed:

    {
      "status": "PASS" | "FAIL",
      "critical": int,
      "high": int,
      "medium": int,
      "low": int,
      "riskScore": int,             // 0-100, higher = more risk
      "summary": "...",
      "recommendations": [ "..." ],
      "findings": [                 // raw correlated findings (optional but useful)
        { "id": ..., "severity": ..., "source": ..., "description": ..., "package": ..., "fix": ... }
      ],
      "generatedAt": "ISO-8601",
      "commit": "git-sha-or-empty"
    }

The status field is what the Security Gate inspects. The other fields are
used for the Markdown report and for downstream reporting.
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


NVIDIA_API_URL = os.environ.get(
    "NVIDIA_API_URL", "https://integrate.api.nvidia.com/v1/chat/completions"
)
NVIDIA_MODEL = os.environ.get("NVIDIA_MODEL", "meta/llama-3.1-70b-instruct")

# Risk-score weights for a 0-100 normalised risk score.
RISK_WEIGHTS = {"CRITICAL": 15, "HIGH": 7, "MEDIUM": 3, "LOW": 1}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def read_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return None


def git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL
        ).decode("utf-8").strip()
    except Exception:
        return os.environ.get("GITHUB_SHA", "")


def summarize_trivy(report_path: Path):
    """Return (counts_dict, list_of_finding_dicts)."""
    data = read_json(report_path)
    if not data:
        return {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, []

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    findings = []
    for result in data.get("Results", []) or []:
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities", []) or []:
            sev = (v.get("Severity") or "LOW").upper()
            counts[sev] = counts.get(sev, 0) + 1
            findings.append({
                "id": v.get("VulnerabilityID", ""),
                "severity": sev,
                "source": "trivy",
                "package": v.get("PkgName", ""),
                "installedVersion": v.get("InstalledVersion", ""),
                "fixedVersion": v.get("FixedVersion", ""),
                "fixable": bool(v.get("FixedVersion")),
                "target": target,
                "description": (v.get("Title") or v.get("Description") or "")[:200],
            })
        for s in result.get("Secrets", []) or []:
            findings.append({
                "id": s.get("RuleID", "secret"),
                "severity": "CRITICAL",
                "source": "trivy",
                "category": "secret",
                "target": target,
                "description": (s.get("Title") or "Secret detected")[:200],
            })
            counts["CRITICAL"] += 1
    return counts, findings


def compute_risk_score(counts: dict) -> int:
    raw = sum(counts.get(sev, 0) * w for sev, w in RISK_WEIGHTS.items())
    # Normalise to 0-100. 100 corresponds to 4 critical + 6 high + 8 medium
    # (raw = 60 + 42 + 24 = 126) which we treat as the saturation point.
    return min(100, round((raw / 126.0) * 100))


def call_nvidia(api_key: str, prompt: str) -> str:
    payload = {
        "model": NVIDIA_MODEL,
        "messages": [
            {"role": "system", "content": "You are a senior application security engineer."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 1500,
    }
    req = urllib.request.Request(
        NVIDIA_API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))["choices"][0]["message"]["content"]
    except (urllib.error.HTTPError, urllib.error.URLError, KeyError) as exc:
        return (
            "# Vulnerability Report\n\n"
            "## Critical\n- (none detected)\n\n## High\n- (none detected)\n\n"
            "## Medium\n- (none detected)\n\n## Low\n- (none detected)\n\n"
            "## Suggested Maven Dependency Updates\n"
            "- (no changes required)\n\n"
            "## Docker Recommendations\n"
            "- Use official, minimal base images (eclipse-temurin:21-jre-jammy)\n"
            "- Run as non-root user\n\n"
            "## Spring Recommendations\n"
            "- Enable CSRF protection where appropriate\n"
            "- Set security response headers (X-Content-Type-Options, X-Frame-Options)\n\n"
            f"_Note: NVIDIA NIM call failed: {exc}_"
        )


def build_prompt(trivy: str, pom: str, dockerfile: str, appyml: str) -> str:
    return f"""You are the TrivySecurityAgent. Review the Trivy findings and produce a STRICT
Markdown report.

# Vulnerability Report

## Critical
- <package> | CVE-xxxx-xxxx | <root cause> | <risk> | <remediation>

## High
- ...

## Medium
- ...

## Low
- ...

## Suggested Maven Dependency Updates
- groupId:artifactId:oldVersion -> newVersion

## Docker Recommendations
- <list>

## Spring Recommendations
- <list>

Trivy findings:
{trivy}

pom.xml (excerpt):
{pom[:2500]}

Dockerfile:
{dockerfile[:1500]}

application.yml:
{appyml[:1500]}

Return ONLY the markdown."""


# ---------------------------------------------------------------------------
# JSON report construction
# ---------------------------------------------------------------------------

def build_json_report(counts: dict, findings: list, status: str) -> dict:
    critical = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)
    medium = counts.get("MEDIUM", 0)
    low = counts.get("LOW", 0)

    recommendations = []
    fixable = [f for f in findings if f.get("fixable") and f.get("package")]
    for f in fixable[:5]:
        recommendations.append(
            f"Upgrade {f['package']} from {f.get('installedVersion','?')} "
            f"to {f.get('fixedVersion','latest')} ({f.get('id','')})"
        )
    if not recommendations:
        recommendations.append("No blocking vulnerabilities detected.")

    if status == "PASS":
        summary = "No blocking vulnerabilities detected."
    else:
        summary = (
            f"Pipeline blocked: {critical} critical and {high} high "
            f"vulnerabilities require remediation before deployment."
        )

    return {
        "status": status,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "riskScore": compute_risk_score(counts),
        "summary": summary,
        "recommendations": recommendations,
        "findings": findings[:50],  # cap to keep the artifact manageable
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "commit": git_commit(),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trivy", required=True)
    parser.add_argument("--pom", required=True)
    parser.add_argument("--dockerfile", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True,
                        help="Path to the Markdown report (security-report.md).")
    parser.add_argument("--json-output", default=None,
                        help="Path to the JSON report (security-report.json). "
                             "Defaults to <output-stem>.json next to --output.")
    args = parser.parse_args()

    api_key = os.environ.get("NVIDIA_API_KEY", "")

    # 1. Deterministic local triage from the Trivy JSON.
    trivy_path = Path(args.trivy)
    counts, findings = summarize_trivy(trivy_path)
    # NVIDIA Security Agent default policy mirrors the Security Gate's
    # Trivy policy: 0 critical, <= 5 high -> PASS.
    local_status = "PASS" if (counts.get("CRITICAL", 0) == 0
                              and counts.get("HIGH", 0) <= 5) else "FAIL"

    # 2. LLM-generated Markdown narrative.
    trivy_summary_text = "\n".join(
        f"- [{f.get('severity','')}] {f.get('id','')} {f.get('package','')}"
        f"@{f.get('installedVersion','')} -> {f.get('fixedVersion','n/a')}"
        for f in findings[:60]
    ) or "(no vulnerabilities)"

    prompt = build_prompt(
        trivy_summary_text,
        read_text(Path(args.pom)),
        read_text(Path(args.dockerfile)),
        read_text(Path(args.config)),
    )
    report_md = call_nvidia(api_key, prompt) if api_key else call_nvidia("fallback", prompt)

    # 3. Write the Markdown.
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report_md, encoding="utf-8")
    print(f"Wrote {out}")

    # 4. Write the structured JSON.
    json_path = Path(args.json_output) if args.json_output else out.with_suffix(".json")
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_report = build_json_report(counts, findings, local_status)
    json_path.write_text(json.dumps(json_report, indent=2), encoding="utf-8")
    print(f"Wrote {json_path} (status={local_status}, "
          f"critical={json_report['critical']}, high={json_report['high']}, "
          f"riskScore={json_report['riskScore']})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
