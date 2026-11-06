import json
import pytest
from core.report_generator import format_markdown_report, format_json_report


def test_markdown_report_formatting():
    trace_analysis = {
        "exception_type": "ZeroDivisionError",
        "exception_message": "division by zero",
        "innermost_application_frame": {
            "matched_file": "payment.py",
            "line": 114,
            "function": "reconcile_batch"
        },
        "culprit_source_window": {
            "file_path": "payment.py",
            "target_line": 114,
            "window_code": "113:         # Calculate avg\n114: >>>     avg = total / len(settled)"
        }
    }
    git_analysis = {
        "has_git": True,
        "current_branch": "master",
        "evidence_summary": "Line 114 introduced in commit c3ab04e by Marcus Ray.",
        "culprit_blame_commit": {
            "line_no": 114,
            "commit_hash": "c3ab04e",
            "author": "Marcus Ray",
            "date": "2026-11-05 20:00:00",
            "message": "feat: Add average ticket calculation",
            "code": "avg = total / len(settled)"
        },
        "latest_commit": {
            "commit_hash": "e4296c5",
            "summary": "docs: Add method docstrings",
            "author": "Alice Dev"
        }
    }
    scan_result = {
        "status": "success",
        "is_clean": True,
        "total_findings": 0,
        "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "findings": []
    }
    investigation_results = {
        "incident_summary": "Empty batch causes division by zero.",
        "likely_root_cause": "reconcile_batch divides by len(settled) without zero check.",
        "affected_file": "payment.py",
        "affected_function": "reconcile_batch",
        "confidence": "High",
        "suggested_fix": {
            "target_file": "payment.py",
            "original_snippet": "avg = total / len(settled)",
            "replacement_snippet": "avg = (total / len(settled)) if settled else 0.0",
            "explanation": "Guard against division by zero."
        }
    }
    verification_result = {
        "status": "Tests passed.",
        "tests_passed": 5,
        "tests_failed": 0,
        "tests_skipped": 0,
        "exit_code": 0,
        "duration_seconds": 0.45,
        "stdout": "5 passed in 0.45s"
    }

    md = format_markdown_report(
        project_name="Payment Service",
        project_source="Built-in Sample",
        investigation_mode="Gemini 3.8 Flash",
        error_text="ZeroDivisionError: division by zero",
        trace_analysis=trace_analysis,
        git_analysis=git_analysis,
        scan_result=scan_result,
        investigation_results=investigation_results,
        unified_diff="--- a/payment.py\n+++ b/payment.py\n@@ -114 +114 @@\n-avg = total / len(settled)\n+avg = (total / len(settled)) if settled else 0.0",
        verification_result=verification_result
    )

    assert "# 🕵️ PHANTOM Incident Investigation Report" in md
    assert "ZeroDivisionError" in md
    assert "payment.py" in md
    assert "reconcile_batch" in md
    assert "c3ab04e" in md
    assert "Marcus Ray" in md
    assert "e4296c5" in md
    assert "Clean Scan" in md
    assert "Tests passed." in md
    assert "5" in md
    # Secrets check: no API keys or tokens
    assert "GEMINI_API_KEY" not in md
    assert "AIzaSy" not in md


def test_json_report_formatting():
    js_text = format_json_report(
        project_name="Shop Cart",
        project_source="Uploaded ZIP Archive",
        investigation_mode="Deterministic Baseline (Non-AI)",
        error_text="TypeError: unsupported operand type(s)",
        trace_analysis=None,
        git_analysis=None,
        scan_result=None,
        investigation_results={"likely_root_cause": "NoneType multiplication"},
        unified_diff=None,
        verification_result=None
    )

    data = json.loads(js_text)
    assert data["report_metadata"]["target_project"] == "Shop Cart"
    assert data["report_metadata"]["investigation_engine"] == "Deterministic Baseline (Non-AI)"
    assert data["investigation_findings"]["likely_root_cause"] == "NoneType multiplication"
    assert data["verification_outcome"]["status"] == "Verification not performed."
    assert len(data["limitations"]) > 0
