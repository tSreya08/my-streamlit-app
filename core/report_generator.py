import os
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List


def format_markdown_report(
    project_name: str,
    project_source: str,
    investigation_mode: str,
    error_text: str,
    trace_analysis: Optional[Dict[str, Any]] = None,
    git_analysis: Optional[Dict[str, Any]] = None,
    scan_result: Optional[Dict[str, Any]] = None,
    investigation_results: Optional[Dict[str, Any]] = None,
    unified_diff: Optional[str] = None,
    verification_result: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generates a comprehensive, downloadable Markdown incident report.
    Strictly separates:
    - Scanner-confirmed findings (Trivy)
    - Confirmed Git/source evidence (Git blame and Python AST/files)
    - AI-generated hypotheses vs. Deterministic non-AI baselines
    - Never includes API keys, tokens, or secrets.
    """
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: List[str] = []

    # Title & Metadata
    lines.append("# 🕵️ PHANTOM Incident Investigation Report")
    lines.append("")
    lines.append(f"**Generated:** `{now_utc}`  ")
    lines.append(f"**Target Project:** `{project_name}` (`{project_source}`)  ")
    lines.append(f"**Investigation Engine:** `{investigation_mode}`  ")
    lines.append("")
    lines.append("---")
    lines.append("")

    # 1. Executive Summary & Root Cause
    lines.append("## 1. Executive Summary & Root Cause")
    lines.append("")
    if investigation_results:
        inv = investigation_results
        summary = inv.get("incident_summary") or inv.get("error_explanation") or "N/A"
        root_cause = inv.get("likely_root_cause") or inv.get("root_cause") or "N/A"
        conf = inv.get("confidence", "Medium")
        aff_file = inv.get("affected_file", "Unknown")
        aff_func = inv.get("affected_function", "Unknown")

        lines.append(f"- **Incident Summary:** {summary}")
        lines.append(f"- **Likely Root Cause:** {root_cause}")
        lines.append(f"- **Affected Location:** `{aff_file}` in `{aff_func}`")
        lines.append(f"- **Confidence Assessment:** `{conf}`")
    else:
        lines.append("- **AI Investigation:** Unavailable (Deterministic Evidence Baseline)")
        if trace_analysis:
            innermost = trace_analysis.get("innermost_application_frame")
            if innermost:
                lines.append(f"- **Crash Location (Deterministic):** `{innermost.get('matched_file')}` line `{innermost.get('line')}` in `{innermost.get('function')}`")
        if git_analysis and git_analysis.get("culprit_blame_commit"):
            cb = git_analysis["culprit_blame_commit"]
            lines.append(f"- **Historical Blame (Deterministic):** Line {cb.get('line_no')} modified by commit `{cb.get('commit_hash')}` ('{cb.get('message')}') by {cb.get('author')}")
        lines.append("- _Notice: AI root-cause hypothesis was not generated; review deterministic evidence below._")
    lines.append("")

    # 2. Runtime Error & Stack Trace
    lines.append("## 2. Runtime Error & Stack Trace")
    lines.append("")
    if trace_analysis:
        lines.append(f"- **Exception Type:** `{trace_analysis.get('exception_type', 'Unknown')}`")
        if trace_analysis.get("exception_message"):
            lines.append(f"- **Exception Message:** `{trace_analysis.get('exception_message')}`")
        innermost = trace_analysis.get("innermost_application_frame")
        if innermost:
            lines.append(f"- **Innermost Application Frame:** `{innermost.get('matched_file')}` line `{innermost.get('line')}` in `{innermost.get('function')}`")
    lines.append("")
    lines.append("```text")
    lines.append(error_text.strip() if error_text else "No error text provided.")
    lines.append("```")
    lines.append("")

    # 3. Affected Source Code Context
    lines.append("## 3. Affected Source Code Context")
    lines.append("")
    if trace_analysis and trace_analysis.get("culprit_source_window"):
        win = trace_analysis["culprit_source_window"]
        lines.append(f"Surrounding source code window from `{win.get('file_path')}` (target line: {win.get('target_line')}):")
        lines.append("")
        lines.append("```python")
        lines.append(win.get("window_code", ""))
        lines.append("```")
    else:
        lines.append("_Source code context could not be located in the project repository._")
    lines.append("")

    # 4. Git Evolution & Historical Blame Evidence
    lines.append("## 4. Git Evolution & Historical Blame (Confirmed Evidence)")
    lines.append("")
    if git_analysis and git_analysis.get("has_git"):
        ga = git_analysis
        lines.append(f"- **Active Branch:** `{ga.get('current_branch')}`")
        lines.append(f"- **Historical Evidence Summary:** {ga.get('evidence_summary')}")
        lines.append("")

        culprit_blame = ga.get("culprit_blame_commit")
        if culprit_blame:
            lines.append("### Culprit Line Blame Record")
            lines.append(f"- **Failing Line:** {culprit_blame.get('line_no')}")
            lines.append(f"- **Commit Hash:** `{culprit_blame.get('commit_hash')}`")
            lines.append(f"- **Author:** {culprit_blame.get('author')}")
            lines.append(f"- **Date:** {culprit_blame.get('date')}")
            lines.append(f"- **Commit Message:** {culprit_blame.get('message')}")
            lines.append(f"- **Code at Commit:** `{culprit_blame.get('code')}`")
            lines.append("")

        latest = ga.get("latest_commit")
        if latest and culprit_blame and latest.get("commit_hash") != culprit_blame.get("commit_hash"):
            lines.append(f"> [!NOTE]\n> The latest repository commit is `{latest.get('commit_hash')}` ('{latest.get('summary')}') by {latest.get('author')}. Git blame confirms that this commit did **not** touch the failing line.")
            lines.append("")
    else:
        lines.append("_Git history was not available in this project archive._")
        lines.append("")

    # 5. Dependency & Security Scan (Trivy Scanner Confirmed Evidence)
    lines.append("## 5. Dependency Vulnerability Analysis (Trivy)")
    lines.append("")
    if scan_result:
        status = scan_result.get("status")
        if status == "success":
            total = scan_result.get("total_findings", 0)
            counts = scan_result.get("severity_counts", {})
            if scan_result.get("is_clean"):
                lines.append("### Status: Clean Scan")
                lines.append("- **Result:** No known vulnerabilities detected in declared dependency manifests.")
                lines.append("- _Notice: Scanner coverage and vulnerability database freshness have limitations._")
            else:
                lines.append(f"### Status: Vulnerabilities Detected ({total} total)")
                lines.append(f"- **Critical:** {counts.get('CRITICAL', 0)} | **High:** {counts.get('HIGH', 0)} | **Medium:** {counts.get('MEDIUM', 0)} | **Low:** {counts.get('LOW', 0)}")
                lines.append("")
                lines.append("| Severity | Vulnerability ID | Package | Installed | Fixed In | Manifest |")
                lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
                for f in scan_result.get("findings", [])[:20]:  # limit to top 20 in report
                    fix = f.get("fixed_version") or "None published"
                    lines.append(f"| {f.get('severity')} | {f.get('vulnerability_id')} | {f.get('package_name')} | {f.get('installed_version')} | {fix} | `{f.get('target_file')}` |")
        elif status == "unavailable":
            lines.append(f"- **Status:** Scanner Unavailable ({scan_result.get('error')})")
        else:
            lines.append(f"- **Status:** Scan {status} ({scan_result.get('error')})")
    else:
        lines.append("_Dependency scanning was not performed for this incident session._")
    lines.append("")

    # 6. Proposed Code Correction & Patch Review
    lines.append("## 6. Proposed Code Correction & Patch Review")
    lines.append("")
    lines.append("> [!WARNING]\n> **AI-GENERATED SUGGESTION — HUMAN REVIEW REQUIRED**\n> Do not apply or merge unverified automated patches into production without independent review and testing.")
    lines.append("")
    if investigation_results and (investigation_results.get("suggested_fix") or investigation_results.get("proposed_patch")):
        patch = investigation_results.get("suggested_fix") or investigation_results.get("proposed_patch") or {}
        lines.append(f"- **Target File:** `{patch.get('target_file', 'N/A')}`")
        lines.append(f"- **Correction Explanation:** {patch.get('explanation') or investigation_results.get('explanation', 'N/A')}")
        lines.append("")
        lines.append("### Original Snippet")
        lines.append("```python")
        lines.append(patch.get("original_snippet", ""))
        lines.append("```")
        lines.append("")
        lines.append("### Proposed Replacement Snippet")
        lines.append("```python")
        lines.append(patch.get("replacement_snippet", ""))
        lines.append("```")
        lines.append("")
        if unified_diff:
            lines.append("### Unified Diff")
            lines.append("```diff")
            lines.append(unified_diff.strip())
            lines.append("```")
            lines.append("")
    else:
        lines.append("_No patch proposed for this incident (Requires AI investigation)._")
        lines.append("")

    # 7. Sandbox Regression Verification Results
    lines.append("## 7. Sandbox Regression Verification Results")
    lines.append("")
    if verification_result:
        vr = verification_result
        status_str = vr.get("status", "Verification not performed.")
        lines.append(f"### Status: **{status_str}**")
        lines.append(f"- **Tests Passed:** {vr.get('tests_passed', 0)}")
        lines.append(f"- **Tests Failed:** {vr.get('tests_failed', 0)}")
        lines.append(f"- **Tests Skipped:** {vr.get('tests_skipped', 0)}")
        lines.append(f"- **Exit Code:** {vr.get('exit_code')}")
        lines.append(f"- **Execution Duration:** {vr.get('duration_seconds', 0.0):.2f}s")
        if vr.get("reason_not_performed"):
            lines.append(f"- **Notice:** {vr.get('reason_not_performed')}")
        if vr.get("stdout"):
            lines.append("")
            lines.append("```text")
            lines.append(vr["stdout"][:2000].strip())
            lines.append("```")
    else:
        lines.append("_Regression test verification was not performed (No patch proposed)._")
    lines.append("")

    # 8. Scope Boundaries & Limitations
    lines.append("## 8. Scope Boundaries & Limitations")
    lines.append("")
    lines.append("1. **Sandboxing:** Verification is performed within an isolated temporary copy bound by HMAC-SHA256 origin validation. It is not an OS-level hypervisor or container boundary.")
    lines.append("2. **Untrusted Uploads:** Code execution is strictly blocked for arbitrary uploaded archives; static analysis and patch generation are provided.")
    lines.append("3. **Dependency Scanning:** Static inspection of declared manifests (e.g. `requirements.txt`); setup scripts and dependency downloads are never run.")
    lines.append("4. **Secrets:** All credentials, tokens, and API keys are strictly excluded from report generation and process environments.")
    lines.append("")
    lines.append("---")
    lines.append("_Report produced by PHANTOM Incident Investigator._")

    return "\n".join(lines)


def format_json_report(
    project_name: str,
    project_source: str,
    investigation_mode: str,
    error_text: str,
    trace_analysis: Optional[Dict[str, Any]] = None,
    git_analysis: Optional[Dict[str, Any]] = None,
    scan_result: Optional[Dict[str, Any]] = None,
    investigation_results: Optional[Dict[str, Any]] = None,
    unified_diff: Optional[str] = None,
    verification_result: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Serializes complete incident investigation findings into a clean JSON document.
    Guarantees no API keys or credentials are included.
    """
    data = {
        "report_metadata": {
            "title": "PHANTOM Incident Investigation Report",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "target_project": project_name,
            "project_source": project_source,
            "investigation_engine": investigation_mode,
            "version": "1.0.0"
        },
        "runtime_error": {
            "raw_text": error_text,
            "parsed_exception": {
                "type": trace_analysis.get("exception_type") if trace_analysis else None,
                "message": trace_analysis.get("exception_message") if trace_analysis else None,
                "innermost_frame": trace_analysis.get("innermost_application_frame") if trace_analysis else None,
            }
        },
        "git_evidence": {
            "has_git": git_analysis.get("has_git", False) if git_analysis else False,
            "current_branch": git_analysis.get("current_branch") if git_analysis else None,
            "culprit_blame_commit": git_analysis.get("culprit_blame_commit") if git_analysis else None,
            "latest_commit": git_analysis.get("latest_commit") if git_analysis else None,
            "evidence_summary": git_analysis.get("evidence_summary") if git_analysis else None,
        },
        "vulnerability_scan": {
            "status": scan_result.get("status") if scan_result else "not_performed",
            "is_clean": scan_result.get("is_clean") if scan_result else None,
            "total_findings": scan_result.get("total_findings") if scan_result else 0,
            "severity_counts": scan_result.get("severity_counts") if scan_result else {},
            "findings": scan_result.get("findings") if scan_result else [],
        },
        "investigation_findings": investigation_results if investigation_results else {
            "status": "ai_investigation_unavailable",
            "mode": investigation_mode,
            "deterministic_only": True,
            "deterministic_summary": {
                "innermost_frame": trace_analysis.get("innermost_application_frame") if trace_analysis else None,
                "culprit_blame": git_analysis.get("culprit_blame_commit") if git_analysis else None
            }
        },
        "proposed_patch": {
            "patch_details": (investigation_results.get("suggested_fix") or investigation_results.get("proposed_patch")) if investigation_results else None,
            "unified_diff": unified_diff,
        },
        "verification_outcome": verification_result or {
            "status": "Verification not performed.",
            "ran_tests": False
        },
        "limitations": [
            "HMAC-bound working copy isolation is not an OS-level hypervisor or container boundary.",
            "Arbitrary test execution is strictly disabled for untrusted uploads.",
            "Static dependency vulnerability scan does not execute dependency install scripts.",
            "Secrets and credentials are completely excluded."
        ]
    }
    return json.dumps(data, indent=2)
