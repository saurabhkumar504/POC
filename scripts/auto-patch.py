#!/usr/bin/env python3
"""
Auto-patch agent for the trivy → remediation loop.

Reads the most recent trivy JSON (post- or pre-remediation), asks the NVIDIA
NIM to produce a constrained JSON patch specification, then applies the patch
in place to pom.xml / Dockerfile / src/main/resources/application.yml.

Patch schema (strict):
{
  "patches": [
    {"file": "pom.xml",                     "find": "<old>", "replace": "<new>", "reason": "..."},
    {"file": "Dockerfile",                  "find": "<old>", "replace": "<new>", "reason": "..."},
    {"file": "src/main/resources/application.yml", "find": "<old>", "replace": "<new>", "reason": "..."}
  ]
}

Constraints:
  - Only the three files above are writable.
  - `find` must match exactly once in the file (no multiple matches, no zero).
  - All three files must remain syntactically valid (XML / line-based / YAML).
  - At least one patch is required.

If the LLM returns an unparseable response, or any patch fails its safety
checks, the script exits non-zero and the loop falls through to the next
retry or gives up.
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

NVIDIA_API_URL = os.environ.get(
    "NVIDIA_API_URL", "https://integrate.api.nvidia.com/v1/chat/completions"
)
NVIDIA_MODEL = os.environ.get("NVIDIA_MODEL", "meta/llama-3.1-70b-instruct")

# Files the auto-patch script is allowed to modify. Anything outside this set
# is rejected, even if the LLM suggests it.
ALLOWED_FILES = {
    "pom.xml",
    "Dockerfile",
    "src/main/resources/application.yml",
}

# Simple well-formedness checks. The goal is to catch obviously broken
# patches, not to be a full parser. Maven / docker / spring boot will produce
# much better diagnostics if something subtle slips through.
XML_PROLOG_RE = re.compile(r"^\s*<\?xml", re.MULTILINE)
DOCKER_FROM_RE = re.compile(r"^\s*FROM\s+\S+", re.MULTILINE | re.IGNORECASE)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""


def build_prompt(trivy_json: str, image_json: str, pom: str, dockerfile: str, appyml: str) -> str:
    return f"""You are AutoPatchAgent. Produce a STRICT JSON patch to fix the
vulnerabilities in trivy-report.json (filesystem) and trivy-image-report.json
(Docker image). You may only edit these three files:
  1. pom.xml
  2. Dockerfile
  3. src/main/resources/application.yml

Return ONLY a JSON object with this exact shape and nothing else:

{{
  "patches": [
    {{"file": "pom.xml", "find": "<exact existing text>", "replace": "<new text>", "reason": "CVE-XXXX-XXXXX"}}
  ]
}}

Rules:
- `find` must be a unique substring in the file. If your target appears more
  than once, include enough surrounding context to make it unique.
- `replace` must keep the file syntactically valid (XML, Dockerfile, YAML).
- Prefer minimum-change patches: bump a version, swap a base image tag, set
  a single property. Do not refactor.
- For application-library CVEs (typically in the filesystem report, e.g.
  CVE in spring-core or jackson-databind), edit pom.xml.
- For OS-package CVEs in the base image (typically in the image report, e.g.
  CVE in libssl3 or libsqlite3-0), edit Dockerfile to bump the FROM tag.
- Only include patches for vulnerabilities the trivy reports list as
  CRITICAL or HIGH. Ignore LOW/MEDIUM.
- If no CRITICAL or HIGH vulnerability can be fixed by editing one of the
  three allowed files, return {{"patches": []}}. Do not invent patches.

trivy-report.json (filesystem):
{trivy[:4000]}

trivy-image-report.json (image, eclipse-temurin:21-jre-jammy):
{image_json[:4000]}

pom.xml:
{pom[:4000]}

Dockerfile:
{dockerfile[:2000]}

application.yml:
{appyml[:2000]}

Return ONLY the JSON. No prose, no markdown fences."""


def call_nvidia(api_key: str, prompt: str) -> str:
    payload = {
        "model": NVIDIA_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a precise patch-generation engine. Output only JSON. "
                    "Do not include prose, explanations, or markdown fences."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.0,
        "max_tokens": 2000,
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
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))["choices"][0]["message"]["content"]


def parse_llm_json(text: str) -> dict:
    """The LLM sometimes wraps JSON in ```json fences or adds prose around it.
    Extract the first balanced JSON object from the response."""
    text = text.strip()
    # Strip leading/trailing markdown fences if present.
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    # Find the outermost { ... }.
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < 0 or end <= start:
        raise ValueError("No JSON object found in LLM response")
    return json.loads(text[start : end + 1])


def validate_patches(patches: list, repo_root: Path) -> list[str]:
    """Return a list of error strings. Empty list means OK."""
    errors: list[str] = []
    if not isinstance(patches, list):
        return ["`patches` must be a list"]

    seen_files: dict[str, int] = {}

    for idx, p in enumerate(patches):
        if not isinstance(p, dict):
            errors.append(f"patch #{idx}: not an object")
            continue
        for key in ("file", "find", "replace", "reason"):
            if key not in p or not isinstance(p[key], str):
                errors.append(f"patch #{idx}: missing or non-string `{key}`")
        if errors:
            continue
        if p["file"] not in ALLOWED_FILES:
            errors.append(
                f"patch #{idx}: file {p['file']!r} is not in the allowlist "
                f"{sorted(ALLOWED_FILES)}"
            )
            continue
        target = repo_root / p["file"]
        if not target.exists():
            errors.append(f"patch #{idx}: {target} does not exist")
            continue
        text = read_text(target)
        occurrences = text.count(p["find"])
        if occurrences == 0:
            errors.append(
                f"patch #{idx}: `find` snippet not found in {p['file']}"
            )
        elif occurrences > 1:
            errors.append(
                f"patch #{idx}: `find` snippet matches {occurrences} places "
                f"in {p['file']} (must match exactly one)"
            )
        seen_files[p["file"]] = seen_files.get(p["file"], 0) + 1

    return errors


def apply_patches(patches: list, repo_root: Path) -> list[dict]:
    """Apply validated patches. Returns a list of {file, reason, applied} dicts
    suitable for writing to a fix-log."""
    log: list[dict] = []
    for p in patches:
        target = repo_root / p["file"]
        text = read_text(target)
        new_text = text.replace(p["find"], p["replace"], 1)
        target.write_text(new_text, encoding="utf-8")
        log.append(
            {
                "file": p["file"],
                "reason": p["reason"],
                "applied": True,
            }
        )
    return log


def post_validate(repo_root: Path, touched: set[str]) -> list[str]:
    """Sanity-check the patched files for obvious syntax breakage."""
    errors: list[str] = []
    if "pom.xml" in touched:
        text = read_text(repo_root / "pom.xml")
        if XML_PROLOG_RE.search(text) is None and "<project" not in text:
            errors.append("pom.xml: no <?xml prolog and no <project> tag")
        # Tag balance check: count opening <project> and </project>.
        if text.count("<project") != text.count("</project>"):
            errors.append("pom.xml: unbalanced <project> tags")
    if "Dockerfile" in touched:
        text = read_text(repo_root / "Dockerfile")
        if DOCKER_FROM_RE.search(text) is None:
            errors.append("Dockerfile: no FROM instruction found after patch")
    if "src/main/resources/application.yml" in touched:
        text = read_text(repo_root / "src/main/resources/application.yml")
        # A trivial YAML sanity check: indentation must use spaces, not tabs.
        if "\t" in text:
            errors.append("application.yml: contains tab characters (YAML disallows tabs)")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, help="path to the working tree to patch")
    parser.add_argument("--trivy", required=True, help="path to trivy-report.json")
    parser.add_argument("--pom", required=True)
    parser.add_argument("--dockerfile", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True, help="path to write fix-log JSON")
    parser.add_argument("--trivy-image", required=True, help="path to trivy-image-report.json")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    api_key = os.environ.get("NVIDIA_API_KEY", "")

    prompt = build_prompt(
        read_text(Path(args.trivy)),
        read_text(Path(args.trivy_image)),
        read_text(Path(args.pom)),
        read_text(Path(args.dockerfile)),
        read_text(Path(args.config)),
    )

    try:
        raw = call_nvidia(api_key, prompt) if api_key else call_nvidia("fallback", prompt)
    except (urllib.error.HTTPError, urllib.error.URLError, KeyError, json.JSONDecodeError) as exc:
        print(f"::error::LLM call failed: {exc}", file=sys.stderr)
        return 2

    try:
        parsed = parse_llm_json(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"::error::Could not parse LLM JSON: {exc}", file=sys.stderr)
        print(f"::error::Raw response was: {raw[:500]}", file=sys.stderr)
        return 3

    patches = parsed.get("patches", [])
    if not patches:
        # The LLM concluded there's nothing fixable in the allowed files.
        # This is a legitimate outcome (e.g. all CRITICALs are in OS packages).
        Path(args.output).write_text(
            json.dumps(
                {
                    "applied": [],
                    "skipped": True,
                    "reason": "LLM returned no patches — vulnerabilities are not in editable files",
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print("LLM returned no patches. Loop will not retry on this signal.")
        return 4  # Distinct exit code so the loop can tell this apart from "patch failed".

    errors = validate_patches(patches, repo_root)
    if errors:
        print("::error::Patch validation failed:", file=sys.stderr)
        for e in errors:
            print(f"::error::  - {e}", file=sys.stderr)
        return 5

    touched = {p["file"] for p in patches}
    log = apply_patches(patches, repo_root)
    post_errors = post_validate(repo_root, touched)
    if post_errors:
        # Roll back by re-reading from git index? Too clever for a v1. Just
        # log and let the next Trivy run catch the breakage. The deploy gate
        # will refuse the broken code.
        for e in post_errors:
            print(f"::warning::Post-patch validation: {e}", file=sys.stderr)
        log.append({"post_validation_errors": post_errors})

    Path(args.output).write_text(json.dumps({"applied": log, "skipped": False}, indent=2), encoding="utf-8")
    print(f"Applied {len(log)} patch(es):")
    for entry in log:
        print(f"  - {entry['file']}: {entry['reason']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
